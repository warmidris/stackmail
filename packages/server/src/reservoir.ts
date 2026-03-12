/**
 * Inline StackFlow reservoir service.
 *
 * Replaces the external SF-node HTTP API with local signing and state tracking.
 * The server IS the reservoir: it holds channels with all agents and routes
 * HTLC payments between them.
 *
 * Pipe state is stored in the same SQLite DB as messages (different tables).
 */

import type { PendingPayment } from './types.js';
import { cvToValue, hexToCV, noneCV, principalCV, serializeCVBytes, someCV, uintCV } from '@stacks/transactions';
import type { ClarityValue } from '@stacks/transactions';
import { buildTransferMessage, sip018Sign, sip018Verify, type TransferState } from './sip018.js';

export interface VerifiedPayment {
  hashedSecret: string;
  incomingAmount: string;
  senderAddress: string;
}

export class ReservoirError extends Error {
  readonly statusCode: number;
  readonly reason: string;
  constructor(statusCode: number, message: string, reason: string) {
    super(message);
    this.name = 'ReservoirError';
    this.statusCode = statusCode;
    this.reason = reason;
  }
}

type DB = import('better-sqlite3').Database;

interface PipeRow {
  pipe_id: string;
  contract_id: string;
  pipe_key_json: string;
  server_balance: string;
  counterparty_balance: string;
  nonce: string;
  last_action: string | null;
  last_actor: string | null;
  last_hashed_secret: string | null;
  last_valid_after: string | null;
  last_server_signature: string | null;
  last_counterparty_signature: string | null;
}

interface OnChainPipeState {
  balance1: bigint;
  balance2: bigint;
  pending1: bigint;
  pending2: bigint;
  nonce: bigint;
}

function serializePrincipalForSort(principal: string): Buffer {
  return Buffer.from(serializeCVBytes(principalCV(principal)));
}

function canonicalPipePrincipals(a: string, b: string): { 'principal-1': string; 'principal-2': string } {
  const sa = serializePrincipalForSort(a);
  const sb = serializePrincipalForSort(b);
  for (let i = 0; i < Math.min(sa.length, sb.length); i++) {
    if (sa[i] < sb[i]) return { 'principal-1': a, 'principal-2': b };
    if (sa[i] > sb[i]) return { 'principal-1': b, 'principal-2': a };
  }
  return { 'principal-1': a, 'principal-2': b };
}

function normalizeHex32(value: string): string {
  const normalized = value.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new ReservoirError(400, 'hashedSecret must be a 32-byte hex string', 'invalid-hashed-secret');
  }
  return normalized;
}

function isContractPrincipal(value: string): boolean {
  return /^S[PT][0-9A-Z]{39}\.[a-zA-Z][a-zA-Z0-9-]{0,39}$/.test(value);
}

function chainIdToHiroApi(chainId: number): string {
  return chainId === 1 ? 'https://api.mainnet.hiro.so' : 'https://api.testnet.hiro.so';
}

function parseUintFromReadOnlyResult(result: string): bigint {
  try {
    if (result.startsWith('0x')) {
      const cv = hexToCV(result);
      const direct = extractUintFromCv(cv);
      if (direct != null) return direct;

      const value = cvToValue(cv) as unknown;
      if (typeof value === 'bigint' || typeof value === 'number' || typeof value === 'string') {
        return BigInt(value);
      }
      if (
        typeof value === 'object' &&
        value != null &&
        (value as { type?: unknown }).type === 'uint' &&
        (typeof (value as { value?: unknown }).value === 'bigint' ||
          typeof (value as { value?: unknown }).value === 'number' ||
          typeof (value as { value?: unknown }).value === 'string')
      ) {
        return BigInt((value as { value: bigint | number | string }).value);
      }
    }
  } catch {
    // Fall through to repr parsing.
  }

  const reprMatch = result.match(/u(\d+)/);
  if (reprMatch) return BigInt(reprMatch[1]);
  throw new ReservoirError(502, 'unexpected get-borrow-fee response format', 'borrow-fee-read-failed');
}

function extractUintFromCv(cv: ClarityValue): bigint | null {
  if (cv.type === 'uint') return BigInt((cv as { value: bigint | number | string }).value);
  if (cv.type === 'ok') return extractUintFromCv((cv as { value: ClarityValue }).value);
  return null;
}

interface PipeUpdateMeta {
  action?: string | null;
  actor?: string | null;
  hashedSecret?: string | null;
  validAfter?: string | null;
  serverSignature?: string | null;
  counterpartySignature?: string | null;
}

export class ReservoirService {
  private db: DB | null = null;
  private readonly serverAddress: string;
  private readonly signerAddress: string;
  private readonly reservoirContractId: string;
  private readonly serverPrivateKey: string;
  private readonly contractId: string;
  private readonly chainId: number;
  private readonly minFeeSats: bigint;
  private readonly messagePriceSats: bigint;

  constructor(config: {
    db: DB;
    serverAddress: string;
    signerAddress?: string;
    reservoirContractId?: string;
    serverPrivateKey: string;
    contractId: string;
    chainId: number;
    minFeeSats: string;
    messagePriceSats: string;
  }) {
    this.db = config.db;
    this.serverAddress = config.serverAddress;
    this.signerAddress = (config.signerAddress ?? config.serverAddress).trim();
    this.reservoirContractId = (config.reservoirContractId ?? '').trim();
    this.serverPrivateKey = config.serverPrivateKey;
    this.contractId = config.contractId;
    this.chainId = config.chainId;
    this.minFeeSats = BigInt(config.minFeeSats);
    this.messagePriceSats = BigInt(config.messagePriceSats);
    this.initTables();
  }

  async getTrackedTapState(counterparty: string): Promise<{
    contractId: string;
    pipeKey: { 'principal-1': string; 'principal-2': string; token: string | null };
    serverBalance: string;
    counterpartyBalance: string;
    nonce: string;
  } | null> {
    if (!this.contractId) return null;
    const principals = canonicalPipePrincipals(this.serverAddress, counterparty);
    const row = this.getLatestPipeRowForPrincipals(
      this.contractId,
      principals['principal-1'],
      principals['principal-2'],
    );
    if (!row) return null;

    const pipeKey = JSON.parse(row.pipe_key_json) as {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };

    return {
      contractId: row.contract_id,
      pipeKey,
      serverBalance: row.server_balance,
      counterpartyBalance: row.counterparty_balance,
      nonce: row.nonce,
    };
  }

  private initTables(): void {
    const db = this.assertDb();
    db.exec(`
      CREATE TABLE IF NOT EXISTS reservoir_pipes (
        pipe_id          TEXT PRIMARY KEY,
        contract_id      TEXT NOT NULL,
        pipe_key_json    TEXT NOT NULL,
        server_balance   TEXT NOT NULL DEFAULT '0',
        counterparty_balance TEXT NOT NULL DEFAULT '0',
        nonce            TEXT NOT NULL DEFAULT '0',
        last_action      TEXT,
        last_actor       TEXT,
        last_hashed_secret TEXT,
        last_valid_after TEXT,
        last_server_signature TEXT,
        last_counterparty_signature TEXT,
        updated_at       INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
      );
    `);

    const cols = db.prepare(`PRAGMA table_info('reservoir_pipes')`).all() as Array<{ name: string }>;
    const colSet = new Set(cols.map(c => c.name));
    const ensureColumn = (name: string, typeSql: string): void => {
      if (!colSet.has(name)) {
        db.exec(`ALTER TABLE reservoir_pipes ADD COLUMN ${name} ${typeSql};`);
      }
    };
    ensureColumn('last_action', 'TEXT');
    ensureColumn('last_actor', 'TEXT');
    ensureColumn('last_hashed_secret', 'TEXT');
    ensureColumn('last_valid_after', 'TEXT');
    ensureColumn('last_server_signature', 'TEXT');
    ensureColumn('last_counterparty_signature', 'TEXT');
  }

  private assertDb(): DB {
    if (!this.db) throw new Error('ReservoirService not initialized');
    return this.db;
  }

  private async fetchBorrowFeeFromReservoir(amount: bigint): Promise<bigint> {
    const [contractAddr, contractName] = this.reservoirContractId.split('.');
    if (!contractAddr || !contractName) {
      throw new ReservoirError(503, 'reservoir contract not configured', 'reservoir-contract-missing');
    }

    const argHex = '0x' + Buffer.from(serializeCVBytes(uintCV(amount))).toString('hex');
    const endpoint = `${chainIdToHiroApi(this.chainId)}/v2/contracts/call-read/${contractAddr}/${contractName}/get-borrow-fee`;
    let response: Response;
    try {
      response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          sender: this.serverAddress,
          arguments: [argHex],
        }),
      });
    } catch {
      throw new ReservoirError(503, 'failed to reach stacks read-only API for borrow fee', 'borrow-fee-read-failed');
    }

    if (!response.ok) {
      throw new ReservoirError(
        503,
        `failed to read borrow fee from reservoir (${response.status})`,
        'borrow-fee-read-failed',
      );
    }

    const payload = await response.json() as { okay?: boolean; result?: string };
    if (!payload.okay || typeof payload.result !== 'string') {
      throw new ReservoirError(503, 'reservoir get-borrow-fee read-only call failed', 'borrow-fee-read-failed');
    }

    return parseUintFromReadOnlyResult(payload.result);
  }

  /** Build canonical pipe ID matching StackFlow: "contractId|token|principal-1|principal-2" */
  private buildPipeId(
    contractId: string,
    pipeKey: { 'principal-1': string; 'principal-2': string; token?: string | null },
  ): string {
    const tokenPart = pipeKey.token ?? 'stx';
    return `${contractId}|${tokenPart}|${pipeKey['principal-1']}|${pipeKey['principal-2']}`;
  }

  private getPipeRow(pipeId: string): PipeRow | null {
    return this.assertDb()
      .prepare('SELECT * FROM reservoir_pipes WHERE pipe_id = ?')
      .get(pipeId) as PipeRow | null;
  }

  private getLatestPipeRowForPrincipals(contractId: string, principal1: string, principal2: string): PipeRow | null {
    const suffix = `|${principal1}|${principal2}`;
    return this.assertDb()
      .prepare(`
        SELECT *
        FROM reservoir_pipes
        WHERE contract_id = ?
          AND pipe_id LIKE ?
        ORDER BY updated_at DESC
        LIMIT 1
      `)
      .get(contractId, `%${suffix}`) as PipeRow | null;
  }

  private upsertPipe(
    pipeId: string,
    contractId: string,
    pipeKey: object,
    serverBalance: string,
    counterpartyBalance: string,
    nonce: string,
    meta: PipeUpdateMeta = {},
  ): void {
    this.assertDb().prepare(`
      INSERT INTO reservoir_pipes (
        pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce,
        last_action, last_actor, last_hashed_secret, last_valid_after,
        last_server_signature, last_counterparty_signature, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
      ON CONFLICT(pipe_id) DO UPDATE SET
        server_balance = excluded.server_balance,
        counterparty_balance = excluded.counterparty_balance,
        nonce = excluded.nonce,
        last_action = CASE
          WHEN excluded.last_action IS NULL THEN reservoir_pipes.last_action
          ELSE excluded.last_action
        END,
        last_actor = CASE
          WHEN excluded.last_actor IS NULL THEN reservoir_pipes.last_actor
          ELSE excluded.last_actor
        END,
        last_hashed_secret = CASE
          WHEN excluded.last_hashed_secret IS NULL THEN reservoir_pipes.last_hashed_secret
          ELSE excluded.last_hashed_secret
        END,
        last_valid_after = CASE
          WHEN excluded.last_valid_after IS NULL THEN reservoir_pipes.last_valid_after
          ELSE excluded.last_valid_after
        END,
        last_server_signature = CASE
          WHEN excluded.last_server_signature IS NULL THEN reservoir_pipes.last_server_signature
          ELSE excluded.last_server_signature
        END,
        last_counterparty_signature = CASE
          WHEN excluded.last_counterparty_signature IS NULL THEN reservoir_pipes.last_counterparty_signature
          ELSE excluded.last_counterparty_signature
        END,
        updated_at = excluded.updated_at
    `).run(
      pipeId,
      contractId,
      JSON.stringify(pipeKey),
      serverBalance,
      counterpartyBalance,
      nonce,
      meta.action ?? null,
      meta.actor ?? null,
      meta.hashedSecret ?? null,
      meta.validAfter ?? null,
      meta.serverSignature ?? null,
      meta.counterpartySignature ?? null,
    );
  }

  /**
   * Check the on-chain stackflow contract to see if a pipe exists between
   * `actor` and `this.serverAddress` for the given token.
   * Used to gate first-payment acceptance when no local DB record exists yet.
   */
  private async checkOnChainPipeExists(
    actor: string,
    pipeKey: { 'principal-1': string; 'principal-2': string; token?: string | null },
  ): Promise<boolean> {
    return (await this.getOnChainPipeState(actor, pipeKey)) != null;
  }

  private parsePipeReadOnlyResult(result: string): OnChainPipeState | null {
    try {
      const cv = hexToCV(result);
      let value: ClarityValue = cv;
      if (value.type === 'ok') {
        value = (value as unknown as { value: ClarityValue }).value;
      } else if (value.type === 'err') {
        return null;
      }
      if (value.type === 'none') return null;
      if (value.type === 'some') {
        value = (value as unknown as { value: ClarityValue }).value;
      }
      if (value.type !== 'tuple') return null;
      const tuple = (value as unknown as { value: Record<string, ClarityValue> }).value;

      const readUint = (field: string): bigint | null => {
        const item = tuple[field];
        if (!item) return null;
        return extractUintFromCv(item);
      };
      const readPendingAmount = (field: string): bigint => {
        const item = tuple[field];
        if (!item) return 0n;
        if (item.type === 'none') return 0n;
        if (item.type !== 'some') return 0n;
        const inner = (item as unknown as { value: ClarityValue }).value;
        if (inner.type !== 'tuple') return 0n;
        const amount = extractUintFromCv((inner as unknown as { value: Record<string, ClarityValue> }).value.amount);
        return amount ?? 0n;
      };

      const balance1 = readUint('balance-1');
      const balance2 = readUint('balance-2');
      const nonce = readUint('nonce');
      if (balance1 == null || balance2 == null || nonce == null) return null;

      return {
        balance1,
        balance2,
        pending1: readPendingAmount('pending-1'),
        pending2: readPendingAmount('pending-2'),
        nonce,
      };
    } catch {
      const b1m = result.match(/balance-1 u(\d+)/);
      const b2m = result.match(/balance-2 u(\d+)/);
      const p1m = result.match(/pending-1 \((?:some )?\(tuple \(amount u(\d+)\)/);
      const p2m = result.match(/pending-2 \((?:some )?\(tuple \(amount u(\d+)\)/);
      const ncm = result.match(/nonce u(\d+)/);
      if (!b1m || !b2m || !ncm) return null;
      return {
        balance1: BigInt(b1m[1]),
        balance2: BigInt(b2m[1]),
        pending1: p1m ? BigInt(p1m[1]) : 0n,
        pending2: p2m ? BigInt(p2m[1]) : 0n,
        nonce: BigInt(ncm[1]),
      };
    }
  }

  private async getOnChainPipeState(
    actor: string,
    pipeKey: { 'principal-1': string; 'principal-2': string; token?: string | null },
  ): Promise<OnChainPipeState | null> {
    try {
      const [contractAddr, contractName] = this.contractId.split('.');
      if (!contractAddr || !contractName) return null;

      const tokenCV = pipeKey.token != null ? someCV(principalCV(pipeKey.token)) : noneCV();
      const withCV = principalCV(this.serverAddress);

      const endpoint = `${chainIdToHiroApi(this.chainId)}/v2/contracts/call-read/${contractAddr}/${contractName}/get-pipe`;
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          sender: actor,
          arguments: [
            '0x' + Buffer.from(serializeCVBytes(tokenCV)).toString('hex'),
            '0x' + Buffer.from(serializeCVBytes(withCV)).toString('hex'),
          ],
        }),
      });

      if (!response.ok) return null;
      const payload = await response.json() as { okay?: boolean; result?: string };
      if (!payload.okay || typeof payload.result !== 'string') return null;
      return this.parsePipeReadOnlyResult(payload.result);
    } catch {
      return null;
    }
  }

  /**
   * Verify an incoming x402 payment proof.
   *
   * The proof is a JSON object (base64url-encoded) representing a StackFlow
   * state update from the sender's perspective where the server is the receiver:
   *   forPrincipal = server, withPrincipal = sender
   *   myBalance = server's new balance (increased by payment amount)
   *   theirBalance = sender's new balance (decreased)
   *   actor = sender
   *   hashedSecret = HTLC commitment
   *   theirSignature = sender's SIP-018 signature
   */
  async verifyIncomingPayment(proofRaw: string): Promise<VerifiedPayment> {
    let proof: Record<string, unknown>;
    try {
      try {
        proof = JSON.parse(Buffer.from(proofRaw, 'base64url').toString('utf-8')) as Record<string, unknown>;
      } catch {
        proof = JSON.parse(proofRaw) as Record<string, unknown>;
      }
    } catch {
      throw new ReservoirError(400, 'invalid payment header encoding', 'invalid-proof-encoding');
    }

    if (!this.serverPrivateKey) {
      throw new ReservoirError(
        503,
        'server payment verification key unavailable',
        'payment-verification-disabled',
      );
    }

    // Extract required fields
    const contractId = typeof proof['contractId'] === 'string' ? proof['contractId'] : this.contractId;
    const pipeKeyRaw = proof['pipeKey'];
    if (!pipeKeyRaw || typeof pipeKeyRaw !== 'object' || Array.isArray(pipeKeyRaw)) {
      throw new ReservoirError(400, 'payment proof missing pipeKey', 'missing-pipe-key');
    }
    const pipeKey = pipeKeyRaw as { 'principal-1': string; 'principal-2': string; token?: string | null };
    if (typeof pipeKey['principal-1'] !== 'string' || typeof pipeKey['principal-2'] !== 'string') {
      throw new ReservoirError(400, 'pipeKey principals must be strings', 'invalid-pipe-key');
    }
    if (pipeKey['principal-1'] === pipeKey['principal-2']) {
      throw new ReservoirError(400, 'pipeKey principals must be distinct', 'invalid-pipe-key');
    }
    if (pipeKey.token != null && typeof pipeKey.token !== 'string') {
      throw new ReservoirError(400, 'pipeKey token must be a principal or null', 'invalid-pipe-key');
    }
    let canonical: { 'principal-1': string; 'principal-2': string };
    try {
      canonical = canonicalPipePrincipals(pipeKey['principal-1'], pipeKey['principal-2']);
    } catch {
      throw new ReservoirError(400, 'pipeKey contains invalid principals', 'invalid-pipe-key');
    }
    if (
      canonical['principal-1'] !== pipeKey['principal-1'] ||
      canonical['principal-2'] !== pipeKey['principal-2']
    ) {
      throw new ReservoirError(402, 'pipeKey principals must be canonical', 'non-canonical-pipe-key');
    }
    if (
      pipeKey['principal-1'] !== this.serverAddress &&
      pipeKey['principal-2'] !== this.serverAddress
    ) {
      throw new ReservoirError(402, 'payment pipe does not include this server', 'pipe-mismatch');
    }

    const forPrincipal = typeof proof['forPrincipal'] === 'string' ? proof['forPrincipal'] : '';
    const withPrincipal = typeof proof['withPrincipal'] === 'string' ? proof['withPrincipal'] : '';
    const myBalance = typeof proof['myBalance'] === 'string' ? proof['myBalance'] : String(proof['myBalance'] ?? '');
    const theirBalance = typeof proof['theirBalance'] === 'string' ? proof['theirBalance'] : String(proof['theirBalance'] ?? '');
    const nonce = String(proof['nonce'] ?? '');
    const action = String(proof['action'] ?? '1');
    const actor = typeof proof['actor'] === 'string' ? proof['actor'] : '';
    const rawHashedSecret = typeof proof['hashedSecret'] === 'string' ? proof['hashedSecret'] : null;
    const hashedSecret = rawHashedSecret ? normalizeHex32(rawHashedSecret) : null;
    const theirSignature = typeof proof['theirSignature'] === 'string' ? proof['theirSignature'] : '';
    const validAfter = typeof proof['validAfter'] === 'string' ? proof['validAfter'] : null;

    if (!contractId) {
      throw new ReservoirError(400, 'payment proof missing contractId', 'missing-contract-id');
    }
    if (this.contractId && contractId !== this.contractId) {
      throw new ReservoirError(402, `unexpected contractId ${contractId}`, 'wrong-contract');
    }
    if (action !== '1') {
      throw new ReservoirError(402, 'incoming payment action must be transfer (1)', 'invalid-action');
    }
    if (!hashedSecret) {
      throw new ReservoirError(400, 'payment proof missing hashedSecret', 'missing-hashed-secret');
    }
    if (!withPrincipal) {
      throw new ReservoirError(400, 'payment proof missing withPrincipal', 'missing-with-principal');
    }
    if (!actor) {
      throw new ReservoirError(400, 'payment proof missing actor', 'missing-actor');
    }
    if (!theirSignature) {
      throw new ReservoirError(400, 'payment proof missing sender signature', 'missing-signature');
    }
    if (withPrincipal !== actor) {
      throw new ReservoirError(402, 'withPrincipal must match actor for incoming transfer', 'actor-mismatch');
    }
    if (actor === this.serverAddress) {
      throw new ReservoirError(402, 'server cannot be actor for incoming transfer', 'invalid-actor');
    }
    if (actor !== pipeKey['principal-1'] && actor !== pipeKey['principal-2']) {
      throw new ReservoirError(402, 'actor not part of payment pipe', 'actor-not-in-pipe');
    }

    // Verify server is the recipient
    if (forPrincipal !== this.serverAddress) {
      throw new ReservoirError(402, 'payment not addressed to this server', 'wrong-recipient');
    }

    // Check amount is sufficient
    let serverNewBalance: bigint;
    let senderNewBalance: bigint;
    let incomingNonce: bigint;
    try {
      serverNewBalance = BigInt(myBalance);
      senderNewBalance = BigInt(theirBalance);
      incomingNonce = BigInt(nonce);
    } catch {
      throw new ReservoirError(400, 'invalid balance or nonce values in proof', 'invalid-balances');
    }
    if (serverNewBalance < 0n || senderNewBalance < 0n) {
      throw new ReservoirError(400, 'balances must be non-negative', 'invalid-balances');
    }
    if (incomingNonce < 1n) {
      throw new ReservoirError(402, `nonce must be >= 1, got ${incomingNonce}`, 'invalid-nonce');
    }

    // Build and validate state
    const state: TransferState = {
      pipeKey,
      forPrincipal: this.serverAddress,
      myBalance,
      theirBalance,
      nonce,
      action,
      actor,
      hashedSecret,
      validAfter,
    };

    const pipeId = this.buildPipeId(contractId, pipeKey);
    const existing = this.getPipeRow(pipeId);

    let incomingAmount: bigint;
    if (existing) {
      const existingServerBalance = BigInt(existing.server_balance);
      const existingSenderBalance = BigInt(existing.counterparty_balance);
      const existingNonce = BigInt(existing.nonce);
      const existingTotal = existingServerBalance + existingSenderBalance;
      const incomingTotal = serverNewBalance + senderNewBalance;

      if (incomingNonce !== existingNonce + 1n) {
        throw new ReservoirError(402, `nonce must be ${existingNonce + 1n}, got ${incomingNonce}`, 'invalid-nonce');
      }
      if (incomingTotal !== existingTotal) {
        throw new ReservoirError(
          402,
          `payment proof total ${incomingTotal} does not match tracked total ${existingTotal}`,
          'invalid-total-balance',
        );
      }
      if (serverNewBalance <= existingServerBalance) {
        throw new ReservoirError(402, 'server balance did not increase', 'balance-not-increased');
      }

      incomingAmount = serverNewBalance - existingServerBalance;
    } else {
      // No DB record — derive the starting entitlement balances from on-chain pipe state.
      const onChainPipe = await this.getOnChainPipeState(actor, pipeKey);
      if (!onChainPipe) {
        throw new ReservoirError(402, `no tap found for sender ${actor}`, 'no-tap');
      }
      const serverIsPrincipal1 = pipeKey['principal-1'] === this.serverAddress;
      const initialServerBalance = serverIsPrincipal1
        ? onChainPipe.balance1 + onChainPipe.pending1
        : onChainPipe.balance2 + onChainPipe.pending2;
      const initialSenderBalance = serverIsPrincipal1
        ? onChainPipe.balance2 + onChainPipe.pending2
        : onChainPipe.balance1 + onChainPipe.pending1;
      const initialTotal = initialServerBalance + initialSenderBalance;
      const proofTotal = serverNewBalance + senderNewBalance;

      if (incomingNonce <= onChainPipe.nonce) {
        throw new ReservoirError(
          402,
          `nonce must be greater than on-chain nonce ${onChainPipe.nonce}, got ${incomingNonce}`,
          'invalid-nonce',
        );
      }
      if (proofTotal !== initialTotal) {
        throw new ReservoirError(
          402,
          `payment proof total ${proofTotal} does not match on-chain total ${initialTotal}`,
          'invalid-total-balance',
        );
      }
      if (serverNewBalance <= initialServerBalance) {
        throw new ReservoirError(402, 'server balance did not increase', 'balance-not-increased');
      }
      incomingAmount = serverNewBalance - initialServerBalance;
    }

    if (incomingAmount < this.messagePriceSats) {
      throw new ReservoirError(402, `payment too low: got ${incomingAmount}, need ${this.messagePriceSats}`, 'payment-too-low');
    }

    // Verify sender's SIP-018 signature
    const message = buildTransferMessage(state);
    const sigValid = await sip018Verify(contractId, message, theirSignature, actor, this.chainId);
    if (!sigValid) {
      throw new ReservoirError(402, 'invalid payment signature', 'invalid-signature');
    }

    // Update local pipe state
    this.upsertPipe(
      pipeId, contractId, pipeKey,
      myBalance,            // server's new balance
      theirBalance,         // sender's new balance
      nonce,
      {
        action,
        actor,
        hashedSecret,
        validAfter,
        counterpartySignature: theirSignature,
      },
    );

    return {
      hashedSecret,
      incomingAmount: incomingAmount.toString(),
      senderAddress: withPrincipal,
    };
  }

  /**
   * Create the server's outgoing payment commitment: server → recipient, locked
   * by the same hashedSecret for (incomingAmount - fee).
   *
   * Returns a PendingPayment signed by the server, or null if no channel exists.
   */
  async createOutgoingPayment(args: {
    hashedSecret: string;
    incomingAmount: string;
    recipientAddr: string;
    contractId: string;
  }): Promise<PendingPayment | null> {
    if (this.contractId && args.contractId !== this.contractId) {
      throw new ReservoirError(402, `unexpected contractId ${args.contractId}`, 'wrong-contract');
    }
    const outgoingHashedSecret = normalizeHex32(args.hashedSecret);
    const outgoingAmount = BigInt(args.incomingAmount) - this.minFeeSats;
    if (outgoingAmount <= 0n) return null;

    // Find the latest canonical pipe for server↔recipient, regardless of token.
    const principals = canonicalPipePrincipals(this.serverAddress, args.recipientAddr);
    const matchingPipe = this.getLatestPipeRowForPrincipals(
      args.contractId,
      principals['principal-1'],
      principals['principal-2'],
    );

    if (!matchingPipe) {
      // No channel open with recipient yet — deferred payment
      console.warn(`[reservoir] no pipe to recipient ${args.recipientAddr} — pendingPayment will be null`);
      return null;
    }

    const storedPipeKey = JSON.parse(matchingPipe.pipe_key_json) as {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };

    const currentServerBalance = BigInt(matchingPipe.server_balance);
    if (currentServerBalance < outgoingAmount) {
      console.warn(`[reservoir] insufficient server balance on pipe to ${args.recipientAddr}`);
      return null;
    }

    const nextServerBalance = (currentServerBalance - outgoingAmount).toString();
    const nextRecipientBalance = (BigInt(matchingPipe.counterparty_balance) + outgoingAmount).toString();
    const nextNonce = (BigInt(matchingPipe.nonce) + 1n).toString();

    // Server is the actor (forwarding payment)
    const state: TransferState = {
      pipeKey: storedPipeKey,
      forPrincipal: args.recipientAddr,  // from recipient's perspective
      myBalance: nextRecipientBalance,
      theirBalance: nextServerBalance,
      nonce: nextNonce,
      action: '1',
      actor: this.serverAddress,
      hashedSecret: outgoingHashedSecret,
      validAfter: null,
    };

    try {
      const message = buildTransferMessage(state);
      const serverSignature = await sip018Sign(
        args.contractId, message, this.serverPrivateKey, this.chainId,
      );

      const stateProof = {
        contractId: args.contractId,
        pipeKey: storedPipeKey,
        forPrincipal: args.recipientAddr,
        withPrincipal: this.serverAddress,
        signerAddress: this.signerAddress,
        myBalance: nextRecipientBalance,
        theirBalance: nextServerBalance,
        nonce: nextNonce,
        action: '1',
        actor: this.serverAddress,
        hashedSecret: outgoingHashedSecret,
        theirSignature: serverSignature,
      };

      // Update pipe state (HTLC locked — balance committed but not yet final)
      this.upsertPipe(
        matchingPipe.pipe_id, args.contractId, storedPipeKey,
        nextServerBalance,
        nextRecipientBalance,
        nextNonce,
        {
          action: '1',
          actor: this.serverAddress,
          hashedSecret: outgoingHashedSecret,
          validAfter: null,
          serverSignature,
        },
      );

      return {
        stateProof: stateProof as Record<string, unknown>,
        amount: outgoingAmount.toString(),
        hashedSecret: outgoingHashedSecret,
      };
    } catch (err) {
      console.warn('[reservoir] failed to sign outgoing payment:', err);
      return null;
    }
  }

  /**
   * Create reservoir-side signature and validated args for
   * create-tap-with-borrowed-liquidity.
   */
  async createTapWithBorrowedLiquidityParams(args: {
    borrower: string;
    token: string | null;
    tapAmount: string;
    tapNonce: string;
    borrowAmount: string;
    borrowFee?: string;
    myBalance: string;
    reservoirBalance: string;
    borrowNonce: string;
    mySignature: string;
  }): Promise<{
    borrowFee: string;
    reservoirSignature: string;
  }> {
    if (!this.serverPrivateKey) {
      throw new ReservoirError(503, 'reservoir signing key unavailable', 'reservoir-key-missing');
    }
    if (!this.contractId) {
      throw new ReservoirError(503, 'stackflow contract not configured', 'stackflow-contract-missing');
    }
    if (!this.reservoirContractId) {
      throw new ReservoirError(503, 'reservoir contract not configured', 'reservoir-contract-missing');
    }

    let tapAmount: bigint;
    let tapNonce: bigint;
    let borrowAmount: bigint;
    let myBalance: bigint;
    let reservoirBalance: bigint;
    let borrowNonce: bigint;
    try {
      tapAmount = BigInt(args.tapAmount);
      tapNonce = BigInt(args.tapNonce);
      borrowAmount = BigInt(args.borrowAmount);
      myBalance = BigInt(args.myBalance);
      reservoirBalance = BigInt(args.reservoirBalance);
      borrowNonce = BigInt(args.borrowNonce);
    } catch {
      throw new ReservoirError(400, 'invalid numeric argument in borrow params', 'invalid-borrow-params');
    }

    if (tapAmount <= 0n) throw new ReservoirError(400, 'tapAmount must be > 0', 'invalid-tap-amount');
    if (borrowAmount <= 0n) throw new ReservoirError(400, 'borrowAmount must be > 0', 'invalid-borrow-amount');
    if (args.borrowFee != null && args.borrowFee.trim() !== '') {
      let providedBorrowFee: bigint;
      try {
        providedBorrowFee = BigInt(args.borrowFee);
      } catch {
        throw new ReservoirError(400, 'borrowFee must be a valid integer', 'invalid-borrow-fee');
      }
      if (providedBorrowFee < 0n) {
        throw new ReservoirError(400, 'borrowFee must be >= 0', 'invalid-borrow-fee');
      }
    }
    if (borrowNonce <= tapNonce) throw new ReservoirError(400, 'borrowNonce must be > tapNonce', 'invalid-borrow-nonce');
    if (myBalance !== tapAmount) {
      throw new ReservoirError(400, 'myBalance must equal tapAmount for initial borrow', 'invalid-my-balance');
    }
    if (reservoirBalance !== borrowAmount) {
      throw new ReservoirError(400, 'reservoirBalance must equal borrowAmount for initial borrow', 'invalid-reservoir-balance');
    }

    const token = args.token == null || args.token.trim() === '' ? null : args.token.trim();
    if (token !== null && !isContractPrincipal(token)) {
      throw new ReservoirError(400, 'token must be a contract principal or null', 'invalid-token');
    }

    const reservoirPrincipal = this.reservoirContractId;
    const principals = canonicalPipePrincipals(args.borrower, reservoirPrincipal);
    const pipeKey = {
      'principal-1': principals['principal-1'],
      'principal-2': principals['principal-2'],
      token,
    };

    const userState: TransferState = {
      pipeKey,
      forPrincipal: args.borrower,
      myBalance: myBalance.toString(),
      theirBalance: reservoirBalance.toString(),
      nonce: borrowNonce.toString(),
      action: '2',
      actor: reservoirPrincipal,
      hashedSecret: null,
      validAfter: null,
    };
    const userMessage = buildTransferMessage(userState);
    const userSigOk = await sip018Verify(
      this.contractId,
      userMessage,
      args.mySignature,
      args.borrower,
      this.chainId,
    );
    if (!userSigOk) {
      throw new ReservoirError(401, 'invalid borrower signature', 'invalid-borrower-signature');
    }

    const reservoirState: TransferState = {
      pipeKey,
      forPrincipal: reservoirPrincipal,
      myBalance: reservoirBalance.toString(),
      theirBalance: myBalance.toString(),
      nonce: borrowNonce.toString(),
      action: '2',
      actor: reservoirPrincipal,
      hashedSecret: null,
      validAfter: null,
    };
    const reservoirMessage = buildTransferMessage(reservoirState);
    const reservoirSignature = await sip018Sign(
      this.contractId,
      reservoirMessage,
      this.serverPrivateKey,
      this.chainId,
    );
    const borrowFee = await this.fetchBorrowFeeFromReservoir(borrowAmount);

    // Persist the initial post-open state so the server can track the tap immediately.
    this.upsertPipe(
      this.buildPipeId(this.contractId, pipeKey),
      this.contractId,
      pipeKey,
      reservoirBalance.toString(),
      myBalance.toString(),
      borrowNonce.toString(),
      {
        action: '2',
        actor: reservoirPrincipal,
        hashedSecret: null,
        validAfter: null,
        serverSignature: reservoirSignature,
        counterpartySignature: args.mySignature,
      },
    );

    return {
      borrowFee: borrowFee.toString(),
      reservoirSignature,
    };
  }
}
