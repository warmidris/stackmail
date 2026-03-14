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
import type { RuntimeSettingsStore } from './settings.js';
import { cvToValue, hexToCV, noneCV, principalCV, serializeCVBytes, someCV, uintCV } from '@stacks/transactions';
import type { ClarityValue } from '@stacks/transactions';
import { PostConditionMode, broadcastTransaction, bufferCV, makeContractCall } from '@stacks/transactions';
import { createNetwork } from '@stacks/network';
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
  enforceable_secret: string | null;
  updated_at?: number;
}

interface PendingPipeStateRow {
  pipe_id: string;
  contract_id: string;
  pipe_key_json: string;
  server_balance: string;
  counterparty_balance: string;
  nonce: string;
  action: string | null;
  actor: string | null;
  hashed_secret: string | null;
  valid_after: string | null;
  server_signature: string | null;
  counterparty_signature: string | null;
  updated_at: number;
}

interface OnChainPipeState {
  balance1: bigint;
  balance2: bigint;
  pending1: bigint;
  pending2: bigint;
  pendingLeg1?: PendingLeg;
  pendingLeg2?: PendingLeg;
  nonce: bigint;
}

interface PendingLeg {
  amount: bigint;
  burnHeight: bigint | null;
}

const TARGET_RECEIVE_CAPACITY_MULTIPLIER = 20n;

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

function chainIdToStacksNetwork(chainId: number): 'mainnet' | 'testnet' {
  return chainId === 1 ? 'mainnet' : 'testnet';
}

function hexToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.replace(/^0x/, ''), 'hex'));
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

async function fetchCurrentBurnBlockHeight(chainId: number): Promise<bigint | null> {
  try {
    const response = await fetch(`${chainIdToHiroApi(chainId)}/v2/info`);
    if (!response.ok) return null;
    const payload = await response.json() as Record<string, unknown>;
    const raw = payload['burn_block_height'] ?? payload['burnBlockHeight'];
    if (typeof raw === 'number' || typeof raw === 'string' || typeof raw === 'bigint') {
      return BigInt(raw);
    }
    return null;
  } catch {
    return null;
  }
}

interface PipeUpdateMeta {
  action?: string | null;
  actor?: string | null;
  hashedSecret?: string | null;
  validAfter?: string | null;
  serverSignature?: string | null;
  counterpartySignature?: string | null;
  enforceableSecret?: string | null;
}

interface ParsedPaymentProof {
  proofRaw: string;
  contractId: string;
  pipeKey: { 'principal-1': string; 'principal-2': string; token: string | null };
  pipeId: string;
  myBalance: string;
  theirBalance: string;
  nonce: string;
  action: string;
  actor: string;
  hashedSecret: string | null;
  theirSignature: string | null;
  validAfter: string | null;
}

export class ReservoirService {
  private db: DB | null = null;
  private readonly serverAddress: string;
  private readonly signerAddress: string;
  private readonly reservoirContractId: string;
  private readonly serverPrivateKey: string;
  private readonly contractId: string;
  private readonly chainId: number;
  private readonly settings: RuntimeSettingsStore;
  private readonly network: ReturnType<typeof createNetwork>;

  constructor(config: {
    db: DB;
    settings: RuntimeSettingsStore;
    serverAddress: string;
    signerAddress?: string;
    reservoirContractId?: string;
    serverPrivateKey: string;
    contractId: string;
    chainId: number;
  }) {
    this.db = config.db;
    this.settings = config.settings;
    this.serverAddress = config.serverAddress;
    this.signerAddress = (config.signerAddress ?? config.serverAddress).trim();
    this.reservoirContractId = (config.reservoirContractId ?? '').trim();
    this.serverPrivateKey = config.serverPrivateKey;
    this.contractId = config.contractId;
    this.chainId = config.chainId;
    this.network = createNetwork({ network: chainIdToStacksNetwork(config.chainId) });
    this.initTables();
  }

  async getTrackedTapState(counterparty: string): Promise<{
    contractId: string;
    pipeKey: { 'principal-1': string; 'principal-2': string; token: string | null };
    serverBalance: string;
    counterpartyBalance: string;
    settledServerBalance?: string;
    settledCounterpartyBalance?: string;
    pendingServerBalance?: string;
    pendingCounterpartyBalance?: string;
    nonce: string;
  } | null> {
    if (!this.contractId) return null;
    const principals = canonicalPipePrincipals(this.serverAddress, counterparty);
    const row = this.getLatestPipeStateForPrincipals(
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

    const onChainPipe = await this.getOnChainPipeState(counterparty, pipeKey);
    const currentBurnHeight = onChainPipe ? await fetchCurrentBurnBlockHeight(this.chainId) : null;
    const matureAmount = (leg: PendingLeg | undefined, fallbackAmount: bigint): { settledAdd: bigint; pending: bigint } => {
      if (!leg) return { settledAdd: 0n, pending: fallbackAmount };
      if (leg.amount <= 0n) return { settledAdd: 0n, pending: 0n };
      if (currentBurnHeight != null && leg.burnHeight != null && currentBurnHeight >= leg.burnHeight) {
        return { settledAdd: leg.amount, pending: 0n };
      }
      return { settledAdd: 0n, pending: leg.amount };
    };
    const serverIsPrincipal1 = pipeKey['principal-1'] === this.serverAddress;
    const serverPending = matureAmount(serverIsPrincipal1 ? onChainPipe?.pendingLeg1 : onChainPipe?.pendingLeg2, serverIsPrincipal1 ? (onChainPipe?.pending1 ?? 0n) : (onChainPipe?.pending2 ?? 0n));
    const counterpartyPending = matureAmount(serverIsPrincipal1 ? onChainPipe?.pendingLeg2 : onChainPipe?.pendingLeg1, serverIsPrincipal1 ? (onChainPipe?.pending2 ?? 0n) : (onChainPipe?.pending1 ?? 0n));
    const settledServerBalance = onChainPipe
      ? ((serverIsPrincipal1 ? onChainPipe.balance1 : onChainPipe.balance2) + serverPending.settledAdd).toString()
      : undefined;
    const settledCounterpartyBalance = onChainPipe
      ? ((serverIsPrincipal1 ? onChainPipe.balance2 : onChainPipe.balance1) + counterpartyPending.settledAdd).toString()
      : undefined;
    const pendingServerBalance = onChainPipe
      ? serverPending.pending.toString()
      : undefined;
    const pendingCounterpartyBalance = onChainPipe
      ? counterpartyPending.pending.toString()
      : undefined;

    return {
      contractId: row.contract_id,
      pipeKey,
      serverBalance: row.server_balance,
      counterpartyBalance: row.counterparty_balance,
      settledServerBalance,
      settledCounterpartyBalance,
      pendingServerBalance,
      pendingCounterpartyBalance,
      nonce: row.nonce,
    };
  }

  private async getCurrentOnChainTapSnapshot(counterparty: string, token: string | null): Promise<{
    pipeId: string;
    pipeKey: { 'principal-1': string; 'principal-2': string; token: string | null };
    serverBalance: bigint;
    counterpartyBalance: bigint;
    nonce: bigint;
    hasUnmaturedPending: boolean;
  }> {
    const principals = canonicalPipePrincipals(this.serverAddress, counterparty);
    const pipeKey = {
      'principal-1': principals['principal-1'],
      'principal-2': principals['principal-2'],
      token,
    };
    const pipeId = this.buildPipeId(this.contractId, pipeKey);
    const onChainPipe = await this.getOnChainPipeState(counterparty, pipeKey);
    if (!onChainPipe) {
      throw new ReservoirError(404, `no tap found for ${counterparty}`, 'no-tap');
    }

    const currentBurnHeight = await fetchCurrentBurnBlockHeight(this.chainId);
    const isPendingActive = (leg: PendingLeg | undefined): boolean => {
      if (!leg || leg.amount <= 0n) return false;
      if (currentBurnHeight != null && leg.burnHeight != null && currentBurnHeight >= leg.burnHeight) {
        return false;
      }
      return true;
    };

    const serverIsPrincipal1 = pipeKey['principal-1'] === this.serverAddress;
    const serverBalance = serverIsPrincipal1
      ? onChainPipe.balance1 + onChainPipe.pending1
      : onChainPipe.balance2 + onChainPipe.pending2;
    const counterpartyBalance = serverIsPrincipal1
      ? onChainPipe.balance2 + onChainPipe.pending2
      : onChainPipe.balance1 + onChainPipe.pending1;

    return {
      pipeId,
      pipeKey,
      serverBalance,
      counterpartyBalance,
      nonce: onChainPipe.nonce,
      hasUnmaturedPending: isPendingActive(onChainPipe.pendingLeg1) || isPendingActive(onChainPipe.pendingLeg2),
    };
  }

  private getCurrentTrackedTapSnapshot(counterparty: string, token: string | null): {
    pipeId: string;
    pipeKey: { 'principal-1': string; 'principal-2': string; token: string | null };
    serverBalance: bigint;
    counterpartyBalance: bigint;
    nonce: bigint;
  } {
    if (!this.contractId) {
      throw new ReservoirError(503, 'stackflow contract not configured', 'stackflow-contract-missing');
    }
    const principals = canonicalPipePrincipals(this.serverAddress, counterparty);
    const row = this.getLatestPipeStateForPrincipals(
      this.contractId,
      principals['principal-1'],
      principals['principal-2'],
    );
    if (!row) {
      throw new ReservoirError(404, `no tap found for ${counterparty}`, 'no-tap');
    }

    const pipeKey = JSON.parse(row.pipe_key_json) as {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };
    if (pipeKey.token !== token) {
      throw new ReservoirError(409, 'tracked tap token did not match the requested refresh token', 'tap-token-mismatch');
    }

    return {
      pipeId: row.pipe_id,
      pipeKey,
      serverBalance: BigInt(row.server_balance),
      counterpartyBalance: BigInt(row.counterparty_balance),
      nonce: BigInt(row.nonce),
    };
  }

  private getLastRefreshAt(borrower: string): number | null {
    const db = this.assertDb();
    const row = db.prepare(`
      SELECT last_refreshed_at
      FROM reservoir_refreshes
      WHERE borrower = ?
    `).get(borrower) as { last_refreshed_at: number } | undefined;
    return row?.last_refreshed_at ?? null;
  }

  private recordRefreshAt(borrower: string, refreshedAt: number): void {
    const db = this.assertDb();
    db.prepare(`
      INSERT INTO reservoir_refreshes (borrower, last_refreshed_at)
      VALUES (?, ?)
      ON CONFLICT(borrower) DO UPDATE SET
        last_refreshed_at = excluded.last_refreshed_at
    `).run(borrower, refreshedAt);
  }

  private assertNoOptimisticPendingStates(pipeId: string, enforceableNonce: bigint): void {
    const latestPending = this.getLatestPendingPipeRow(pipeId);
    if (latestPending && BigInt(latestPending.nonce) > enforceableNonce) {
      throw new ReservoirError(
        409,
        'tap has outstanding off-chain message state; settle or cancel messages before changing liquidity',
        'tap-has-pending-states',
      );
    }
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
        enforceable_secret TEXT,
        updated_at       INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS reservoir_pending_states (
        pipe_id          TEXT NOT NULL,
        nonce            TEXT NOT NULL,
        contract_id      TEXT NOT NULL,
        pipe_key_json    TEXT NOT NULL,
        server_balance   TEXT NOT NULL,
        counterparty_balance TEXT NOT NULL,
        action           TEXT,
        actor            TEXT,
        hashed_secret    TEXT,
        valid_after      TEXT,
        server_signature TEXT,
        counterparty_signature TEXT,
        updated_at       INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000),
        PRIMARY KEY (pipe_id, nonce)
      );
      CREATE INDEX IF NOT EXISTS idx_pending_pipe_updated ON reservoir_pending_states (pipe_id, updated_at DESC);

      CREATE TABLE IF NOT EXISTS reservoir_refreshes (
        borrower          TEXT PRIMARY KEY,
        last_refreshed_at INTEGER NOT NULL
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
    ensureColumn('enforceable_secret', 'TEXT');
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

  private parseIncomingPaymentProof(proofRaw: string): ParsedPaymentProof {
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
    const canonical = canonicalPipePrincipals(pipeKey['principal-1'], pipeKey['principal-2']);
    if (
      canonical['principal-1'] !== pipeKey['principal-1'] ||
      canonical['principal-2'] !== pipeKey['principal-2']
    ) {
      throw new ReservoirError(402, 'pipeKey principals must be canonical', 'non-canonical-pipe-key');
    }

    return {
      proofRaw,
      contractId,
      pipeKey: {
        'principal-1': pipeKey['principal-1'],
        'principal-2': pipeKey['principal-2'],
        token: pipeKey.token == null ? null : pipeKey.token,
      },
      pipeId: this.buildPipeId(contractId, pipeKey),
      myBalance: typeof proof['myBalance'] === 'string' ? proof['myBalance'] : String(proof['myBalance'] ?? ''),
      theirBalance: typeof proof['theirBalance'] === 'string' ? proof['theirBalance'] : String(proof['theirBalance'] ?? ''),
      nonce: String(proof['nonce'] ?? ''),
      action: String(proof['action'] ?? '1'),
      actor: typeof proof['actor'] === 'string' ? proof['actor'] : '',
      hashedSecret: typeof proof['hashedSecret'] === 'string' ? normalizeHex32(proof['hashedSecret']) : null,
      theirSignature: typeof proof['theirSignature'] === 'string' ? proof['theirSignature'] : null,
      validAfter: typeof proof['validAfter'] === 'string' ? proof['validAfter'] : null,
    };
  }

  private getPipeRow(pipeId: string): PipeRow | null {
    return this.assertDb()
      .prepare('SELECT * FROM reservoir_pipes WHERE pipe_id = ?')
      .get(pipeId) as PipeRow | null;
  }

  private getPendingPipeRows(pipeId: string): PendingPipeStateRow[] {
    return this.assertDb()
      .prepare('SELECT * FROM reservoir_pending_states WHERE pipe_id = ? ORDER BY CAST(nonce AS INTEGER) DESC, updated_at DESC')
      .all(pipeId) as PendingPipeStateRow[];
  }

  private getLatestPendingPipeRow(pipeId: string): PendingPipeStateRow | null {
    return this.assertDb()
      .prepare(`
        SELECT *
        FROM reservoir_pending_states
        WHERE pipe_id = ?
        ORDER BY CAST(nonce AS INTEGER) DESC, updated_at DESC
        LIMIT 1
      `)
      .get(pipeId) as PendingPipeStateRow | null;
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

  private getLatestPendingPipeRowForPrincipals(contractId: string, principal1: string, principal2: string): PendingPipeStateRow | null {
    const suffix = `|${principal1}|${principal2}`;
    return this.assertDb()
      .prepare(`
        SELECT *
        FROM reservoir_pending_states
        WHERE contract_id = ?
          AND pipe_id LIKE ?
        ORDER BY CAST(nonce AS INTEGER) DESC, updated_at DESC
        LIMIT 1
      `)
      .get(contractId, `%${suffix}`) as PendingPipeStateRow | null;
  }

  private chooseLatestRow(enforceable: PipeRow | null, pending: PendingPipeStateRow | null): PipeRow | PendingPipeStateRow | null {
    if (!enforceable) return pending;
    if (!pending) return enforceable;
    const en = BigInt(enforceable.nonce);
    const pn = BigInt(pending.nonce);
    if (pn > en) return pending;
    if (pn < en) return enforceable;
    return (pending.updated_at ?? 0) >= (enforceable.updated_at ?? 0) ? pending : enforceable;
  }

  private getLatestPipeState(pipeId: string): PipeRow | PendingPipeStateRow | null {
    return this.chooseLatestRow(this.getPipeRow(pipeId), this.getLatestPendingPipeRow(pipeId));
  }

  private getLatestPipeStateForPrincipals(contractId: string, principal1: string, principal2: string): PipeRow | PendingPipeStateRow | null {
    return this.chooseLatestRow(
      this.getLatestPipeRowForPrincipals(contractId, principal1, principal2),
      this.getLatestPendingPipeRowForPrincipals(contractId, principal1, principal2),
    );
  }

  private getEnforceablePipeRowForCounterparty(counterparty: string): PipeRow | null {
    if (!this.contractId) return null;
    const principals = canonicalPipePrincipals(this.serverAddress, counterparty);
    return this.getLatestPipeRowForPrincipals(
      this.contractId,
      principals['principal-1'],
      principals['principal-2'],
    );
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
        last_server_signature, last_counterparty_signature, enforceable_secret, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
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
        enforceable_secret = CASE
          WHEN excluded.enforceable_secret IS NULL THEN reservoir_pipes.enforceable_secret
          ELSE excluded.enforceable_secret
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
      meta.enforceableSecret ?? null,
    );
  }

  private upsertPendingState(
    pipeId: string,
    contractId: string,
    pipeKey: object,
    serverBalance: string,
    counterpartyBalance: string,
    nonce: string,
    meta: PipeUpdateMeta = {},
  ): void {
    this.assertDb().prepare(`
      INSERT INTO reservoir_pending_states (
        pipe_id, nonce, contract_id, pipe_key_json, server_balance, counterparty_balance,
        action, actor, hashed_secret, valid_after, server_signature, counterparty_signature, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
      ON CONFLICT(pipe_id, nonce) DO UPDATE SET
        contract_id = excluded.contract_id,
        pipe_key_json = excluded.pipe_key_json,
        server_balance = excluded.server_balance,
        counterparty_balance = excluded.counterparty_balance,
        action = excluded.action,
        actor = excluded.actor,
        hashed_secret = excluded.hashed_secret,
        valid_after = excluded.valid_after,
        server_signature = excluded.server_signature,
        counterparty_signature = excluded.counterparty_signature,
        updated_at = excluded.updated_at
    `).run(
      pipeId,
      nonce,
      contractId,
      JSON.stringify(pipeKey),
      serverBalance,
      counterpartyBalance,
      meta.action ?? null,
      meta.actor ?? null,
      meta.hashedSecret ?? null,
      meta.validAfter ?? null,
      meta.serverSignature ?? null,
      meta.counterpartySignature ?? null,
    );
  }

  private deletePendingStatesAtOrBelowNonce(pipeId: string, nonce: string): void {
    this.assertDb()
      .prepare('DELETE FROM reservoir_pending_states WHERE pipe_id = ? AND CAST(nonce AS INTEGER) <= CAST(? AS INTEGER)')
      .run(pipeId, nonce);
  }

  async cancelMessage(args: {
    paymentProof: string;
    senderAddr: string;
    recipientAddr: string;
    incomingAmount: string;
    fee: string;
    recipientPendingPayment: PendingPayment | null;
  }): Promise<void> {
    const parsed = this.parseIncomingPaymentProof(args.paymentProof);
    const refundAmount = BigInt(args.incomingAmount) - BigInt(args.fee);
    if (refundAmount <= 0n) return;

    const senderLatest = this.getLatestPipeState(parsed.pipeId);
    if (!senderLatest) {
      throw new ReservoirError(404, 'sender pipe not found for cancellation', 'sender-pipe-not-found');
    }
    const senderCurrentServerBalance = BigInt(senderLatest.server_balance);
    const senderCurrentCounterpartyBalance = BigInt(senderLatest.counterparty_balance);
    if (senderCurrentServerBalance < refundAmount) {
      throw new ReservoirError(409, 'insufficient server balance to refund sender', 'refund-insufficient-balance');
    }

    const senderNextServerBalance = (senderCurrentServerBalance - refundAmount).toString();
    const senderNextCounterpartyBalance = (senderCurrentCounterpartyBalance + refundAmount).toString();
    const senderNextNonce = (BigInt(senderLatest.nonce) + 1n).toString();
    const senderMessage = buildTransferMessage({
      pipeKey: parsed.pipeKey,
      forPrincipal: args.senderAddr,
      myBalance: senderNextCounterpartyBalance,
      theirBalance: senderNextServerBalance,
      nonce: senderNextNonce,
      action: '1',
      actor: this.serverAddress,
      hashedSecret: null,
      validAfter: null,
    });
    const senderServerSignature = await sip018Sign(parsed.contractId, senderMessage, this.serverPrivateKey, this.chainId);
    this.upsertPendingState(
      parsed.pipeId,
      parsed.contractId,
      parsed.pipeKey,
      senderNextServerBalance,
      senderNextCounterpartyBalance,
      senderNextNonce,
      {
        action: '1',
        actor: this.serverAddress,
        hashedSecret: null,
        validAfter: null,
        serverSignature: senderServerSignature,
      },
    );

    if (!args.recipientPendingPayment) return;

    const principals = canonicalPipePrincipals(this.serverAddress, args.recipientAddr);
    const recipientLatest = this.getLatestPipeStateForPrincipals(
      parsed.contractId,
      principals['principal-1'],
      principals['principal-2'],
    );
    if (!recipientLatest) {
      throw new ReservoirError(404, 'recipient pipe not found for cancellation rollback', 'recipient-pipe-not-found');
    }
    const recipientPipeKey = JSON.parse(recipientLatest.pipe_key_json) as {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };
    const recipientCurrentServerBalance = BigInt(recipientLatest.server_balance);
    const recipientCurrentCounterpartyBalance = BigInt(recipientLatest.counterparty_balance);
    if (recipientCurrentCounterpartyBalance < refundAmount) {
      throw new ReservoirError(409, 'recipient pending balance is too low to reverse cancellation', 'recipient-reversal-insufficient');
    }
    const recipientNextServerBalance = (recipientCurrentServerBalance + refundAmount).toString();
    const recipientNextCounterpartyBalance = (recipientCurrentCounterpartyBalance - refundAmount).toString();
    const recipientNextNonce = (BigInt(recipientLatest.nonce) + 1n).toString();
    const recipientMessage = buildTransferMessage({
      pipeKey: recipientPipeKey,
      forPrincipal: args.recipientAddr,
      myBalance: recipientNextCounterpartyBalance,
      theirBalance: recipientNextServerBalance,
      nonce: recipientNextNonce,
      action: '1',
      actor: this.serverAddress,
      hashedSecret: null,
      validAfter: null,
    });
    const recipientServerSignature = await sip018Sign(parsed.contractId, recipientMessage, this.serverPrivateKey, this.chainId);
    this.upsertPendingState(
      this.buildPipeId(parsed.contractId, recipientPipeKey),
      parsed.contractId,
      recipientPipeKey,
      recipientNextServerBalance,
      recipientNextCounterpartyBalance,
      recipientNextNonce,
      {
        action: '1',
        actor: this.serverAddress,
        hashedSecret: null,
        validAfter: null,
        serverSignature: recipientServerSignature,
      },
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
      const readPendingLeg = (field: string): PendingLeg => {
        const item = tuple[field];
        if (!item) return { amount: 0n, burnHeight: null };
        if (item.type === 'none') return { amount: 0n, burnHeight: null };
        if (item.type !== 'some') return { amount: 0n, burnHeight: null };
        const inner = (item as unknown as { value: ClarityValue }).value;
        if (inner.type !== 'tuple') return { amount: 0n, burnHeight: null };
        const value = (inner as unknown as { value: Record<string, ClarityValue> }).value;
        const amount = extractUintFromCv(value.amount) ?? 0n;
        const burnHeight = value['burn-height'] ? extractUintFromCv(value['burn-height']) : null;
        return { amount, burnHeight };
      };

      const balance1 = readUint('balance-1');
      const balance2 = readUint('balance-2');
      const nonce = readUint('nonce');
      if (balance1 == null || balance2 == null || nonce == null) return null;

      const pendingLeg1 = readPendingLeg('pending-1');
      const pendingLeg2 = readPendingLeg('pending-2');
      return {
        balance1,
        balance2,
        pending1: pendingLeg1.amount,
        pending2: pendingLeg2.amount,
        pendingLeg1,
        pendingLeg2,
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
        pendingLeg1: { amount: p1m ? BigInt(p1m[1]) : 0n, burnHeight: null },
        pendingLeg2: { amount: p2m ? BigInt(p2m[1]) : 0n, burnHeight: null },
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
    const settings = this.settings.get();
    if (!this.serverPrivateKey) {
      throw new ReservoirError(
        503,
        'server payment verification key unavailable',
        'payment-verification-disabled',
      );
    }

    const parsed = this.parseIncomingPaymentProof(proofRaw);
    const proof = (() => {
      try {
        return JSON.parse(Buffer.from(proofRaw, 'base64url').toString('utf-8')) as Record<string, unknown>;
      } catch {
        return JSON.parse(proofRaw) as Record<string, unknown>;
      }
    })();

    // Extract required fields
    const contractId = parsed.contractId;
    const pipeKey = parsed.pipeKey;
    if (
      pipeKey['principal-1'] !== this.serverAddress &&
      pipeKey['principal-2'] !== this.serverAddress
    ) {
      throw new ReservoirError(402, 'payment pipe does not include this server', 'pipe-mismatch');
    }

    const forPrincipal = typeof proof['forPrincipal'] === 'string' ? proof['forPrincipal'] : '';
    const withPrincipal = typeof proof['withPrincipal'] === 'string' ? proof['withPrincipal'] : '';
    const myBalance = parsed.myBalance;
    const theirBalance = parsed.theirBalance;
    const nonce = parsed.nonce;
    const action = parsed.action;
    const actor = parsed.actor;
    const hashedSecret = parsed.hashedSecret;
    const theirSignature = parsed.theirSignature ?? '';
    const validAfter = parsed.validAfter;

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

    const pipeId = parsed.pipeId;
    const existing = this.getLatestPipeState(pipeId);

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

    const messagePriceSats = BigInt(settings.messagePriceSats);
    if (incomingAmount < messagePriceSats) {
      throw new ReservoirError(402, `payment too low: got ${incomingAmount}, need ${messagePriceSats}`, 'payment-too-low');
    }

    // Verify sender's SIP-018 signature
    const message = buildTransferMessage(state);
    const sigValid = await sip018Verify(contractId, message, theirSignature, actor, this.chainId);
    if (!sigValid) {
      throw new ReservoirError(402, 'invalid payment signature', 'invalid-signature');
    }

    // Track this as a pending state until the HTLC secret is revealed.
    this.upsertPendingState(
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

  async recordCompletedIncomingPayment(args: { paymentProof: string; secret: string }): Promise<void> {
    const parsed = this.parseIncomingPaymentProof(args.paymentProof);
    this.upsertPipe(
      parsed.pipeId,
      parsed.contractId,
      parsed.pipeKey,
      parsed.myBalance,
      parsed.theirBalance,
      parsed.nonce,
      {
        action: parsed.action,
        actor: parsed.actor || null,
        hashedSecret: parsed.hashedSecret,
        validAfter: parsed.validAfter,
        counterpartySignature: parsed.theirSignature,
        enforceableSecret: args.secret,
      },
    );
    this.deletePendingStatesAtOrBelowNonce(parsed.pipeId, parsed.nonce);
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
    const settings = this.settings.get();
    if (this.contractId && args.contractId !== this.contractId) {
      throw new ReservoirError(402, `unexpected contractId ${args.contractId}`, 'wrong-contract');
    }
    const outgoingHashedSecret = normalizeHex32(args.hashedSecret);
    const outgoingAmount = BigInt(args.incomingAmount) - BigInt(settings.minFeeSats);
    if (outgoingAmount <= 0n) return null;

    // Find the latest canonical pipe for server↔recipient, regardless of token.
    const principals = canonicalPipePrincipals(this.serverAddress, args.recipientAddr);
    const matchingPipe = this.getLatestPipeStateForPrincipals(
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
      this.upsertPendingState(
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

  async createAddFundsParams(args: {
    user: string;
    token: string | null;
    amount: string;
    myBalance: string;
    reservoirBalance: string;
    nonce: string;
    mySignature: string;
  }): Promise<{ reservoirSignature: string }> {
    if (!this.serverPrivateKey) {
      throw new ReservoirError(503, 'reservoir signing key unavailable', 'reservoir-key-missing');
    }
    if (!this.contractId) {
      throw new ReservoirError(503, 'stackflow contract not configured', 'stackflow-contract-missing');
    }
    if (!this.reservoirContractId) {
      throw new ReservoirError(503, 'reservoir contract not configured', 'reservoir-contract-missing');
    }

    const token = args.token == null || args.token.trim() === '' ? null : args.token.trim();
    if (token !== null && !isContractPrincipal(token)) {
      throw new ReservoirError(400, 'token must be a contract principal or null', 'invalid-token');
    }

    let amount: bigint;
    let myBalance: bigint;
    let reservoirBalance: bigint;
    let nonce: bigint;
    try {
      amount = BigInt(args.amount);
      myBalance = BigInt(args.myBalance);
      reservoirBalance = BigInt(args.reservoirBalance);
      nonce = BigInt(args.nonce);
    } catch {
      throw new ReservoirError(400, 'invalid numeric argument in add-funds params', 'invalid-add-funds-params');
    }
    if (amount <= 0n) {
      throw new ReservoirError(400, 'amount must be > 0', 'invalid-add-funds-amount');
    }

    const current = await this.getCurrentOnChainTapSnapshot(args.user, token);
    this.assertNoOptimisticPendingStates(current.pipeId, current.nonce);
    if (current.hasUnmaturedPending) {
      throw new ReservoirError(
        409,
        'tap has an on-chain pending deposit that has not matured yet',
        'tap-has-onchain-pending',
      );
    }
    if (nonce !== current.nonce + 1n) {
      throw new ReservoirError(400, `nonce must be ${current.nonce + 1n}`, 'invalid-add-funds-nonce');
    }
    if (myBalance !== current.counterpartyBalance + amount) {
      throw new ReservoirError(400, 'myBalance must equal current balance plus deposit amount', 'invalid-my-balance');
    }
    if (reservoirBalance !== current.serverBalance) {
      throw new ReservoirError(400, 'reservoirBalance must equal the current reservoir balance', 'invalid-reservoir-balance');
    }

    const userState: TransferState = {
      pipeKey: current.pipeKey,
      forPrincipal: args.user,
      myBalance: myBalance.toString(),
      theirBalance: reservoirBalance.toString(),
      nonce: nonce.toString(),
      action: '2',
      actor: args.user,
      hashedSecret: null,
      validAfter: null,
    };
    const userSigOk = await sip018Verify(
      this.contractId,
      buildTransferMessage(userState),
      args.mySignature,
      args.user,
      this.chainId,
    );
    if (!userSigOk) {
      throw new ReservoirError(401, 'invalid depositor signature', 'invalid-depositor-signature');
    }

    const reservoirState: TransferState = {
      pipeKey: current.pipeKey,
      forPrincipal: this.reservoirContractId,
      myBalance: reservoirBalance.toString(),
      theirBalance: myBalance.toString(),
      nonce: nonce.toString(),
      action: '2',
      actor: args.user,
      hashedSecret: null,
      validAfter: null,
    };
    const reservoirSignature = await sip018Sign(
      this.contractId,
      buildTransferMessage(reservoirState),
      this.serverPrivateKey,
      this.chainId,
    );
    return { reservoirSignature };
  }

  async createBorrowLiquidityParams(args: {
    borrower: string;
    token: string | null;
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

    const token = args.token == null || args.token.trim() === '' ? null : args.token.trim();
    if (token !== null && !isContractPrincipal(token)) {
      throw new ReservoirError(400, 'token must be a contract principal or null', 'invalid-token');
    }

    let borrowAmount: bigint;
    let myBalance: bigint;
    let reservoirBalance: bigint;
    let borrowNonce: bigint;
    try {
      borrowAmount = BigInt(args.borrowAmount);
      myBalance = BigInt(args.myBalance);
      reservoirBalance = BigInt(args.reservoirBalance);
      borrowNonce = BigInt(args.borrowNonce);
    } catch {
      throw new ReservoirError(400, 'invalid numeric argument in borrow params', 'invalid-borrow-params');
    }
    if (borrowAmount <= 0n) {
      throw new ReservoirError(400, 'borrowAmount must be > 0', 'invalid-borrow-amount');
    }

    const current = this.getCurrentTrackedTapSnapshot(args.borrower, token);
    if (borrowNonce !== current.nonce + 1n) {
      throw new ReservoirError(400, `borrowNonce must be ${current.nonce + 1n}`, 'invalid-borrow-nonce');
    }
    const settings = this.settings.get();
    const maxBorrowPerTap = BigInt(settings.maxBorrowPerTap);
    const targetReceiveLiquidity = BigInt(settings.messagePriceSats) * TARGET_RECEIVE_CAPACITY_MULTIPLIER;
    if (targetReceiveLiquidity > maxBorrowPerTap) {
      throw new ReservoirError(
        400,
        `refresh target would exceed the reservoir offer cap for a single tap (${maxBorrowPerTap})`,
        'borrow-cap-exceeded',
      );
    }
    if (current.serverBalance >= targetReceiveLiquidity) {
      throw new ReservoirError(
        409,
        'receive capacity is already at or above the default target',
        'capacity-already-sufficient',
      );
    }
    const requiredBorrowAmount = targetReceiveLiquidity - current.serverBalance;
    if (borrowAmount !== requiredBorrowAmount) {
      throw new ReservoirError(
        400,
        `borrowAmount must exactly refresh receive capacity to the default target (${requiredBorrowAmount})`,
        'invalid-refresh-amount',
      );
    }
    if (myBalance !== current.counterpartyBalance) {
      throw new ReservoirError(400, 'myBalance must equal the current user balance', 'invalid-my-balance');
    }
    if (reservoirBalance !== targetReceiveLiquidity) {
      throw new ReservoirError(
        400,
        'reservoirBalance must equal the default receive-capacity target',
        'invalid-reservoir-balance',
      );
    }
    const refreshCapacityCooldownMs = settings.refreshCapacityCooldownMs;
    if (refreshCapacityCooldownMs > 0) {
      const lastRefreshedAt = this.getLastRefreshAt(args.borrower);
      if (lastRefreshedAt != null) {
        const nextRefreshAt = lastRefreshedAt + refreshCapacityCooldownMs;
        if (Date.now() < nextRefreshAt) {
          throw new ReservoirError(
            429,
            `receive capacity refresh is on cooldown until ${new Date(nextRefreshAt).toISOString()}`,
            'refresh-cooldown-active',
          );
        }
      }
    }

    let providedBorrowFee: bigint | null = null;
    if (args.borrowFee != null && args.borrowFee.trim() !== '') {
      try {
        providedBorrowFee = BigInt(args.borrowFee);
      } catch {
        throw new ReservoirError(400, 'borrowFee must be a valid integer', 'invalid-borrow-fee');
      }
    }
    const borrowFee = await this.fetchBorrowFeeFromReservoir(borrowAmount);
    if (providedBorrowFee != null && providedBorrowFee < borrowFee) {
      throw new ReservoirError(400, 'borrowFee is lower than the reservoir minimum', 'invalid-borrow-fee');
    }

    const userState: TransferState = {
      pipeKey: current.pipeKey,
      forPrincipal: args.borrower,
      myBalance: myBalance.toString(),
      theirBalance: reservoirBalance.toString(),
      nonce: borrowNonce.toString(),
      action: '2',
      actor: this.reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const userSigOk = await sip018Verify(
      this.contractId,
      buildTransferMessage(userState),
      args.mySignature,
      args.borrower,
      this.chainId,
    );
    if (!userSigOk) {
      throw new ReservoirError(401, 'invalid borrower signature', 'invalid-borrower-signature');
    }

    const reservoirState: TransferState = {
      pipeKey: current.pipeKey,
      forPrincipal: this.reservoirContractId,
      myBalance: reservoirBalance.toString(),
      theirBalance: myBalance.toString(),
      nonce: borrowNonce.toString(),
      action: '2',
      actor: this.reservoirContractId,
      hashedSecret: null,
      validAfter: null,
    };
    const reservoirSignature = await sip018Sign(
      this.contractId,
      buildTransferMessage(reservoirState),
      this.serverPrivateKey,
      this.chainId,
    );
    this.recordRefreshAt(args.borrower, Date.now());
    return {
      borrowFee: borrowFee.toString(),
      reservoirSignature,
    };
  }

  async syncTapState(args: {
    counterparty: string;
    token: string | null;
    userBalance: string;
    reservoirBalance: string;
    nonce: string;
    action?: string | null;
    actor?: string | null;
    counterpartySignature?: string | null;
    serverSignature?: string | null;
  }): Promise<void> {
    const token = args.token == null || args.token.trim() === '' ? null : args.token.trim();
    if (token !== null && !isContractPrincipal(token)) {
      throw new ReservoirError(400, 'token must be a contract principal or null', 'invalid-token');
    }
    const current = await this.getCurrentOnChainTapSnapshot(args.counterparty, token);
    if (current.counterpartyBalance.toString() !== args.userBalance || current.serverBalance.toString() !== args.reservoirBalance) {
      throw new ReservoirError(409, 'on-chain tap balances do not match the provided sync state yet', 'tap-sync-balance-mismatch');
    }
    if (current.nonce.toString() !== args.nonce) {
      throw new ReservoirError(409, 'on-chain tap nonce does not match the provided sync state yet', 'tap-sync-nonce-mismatch');
    }
    this.upsertPipe(
      current.pipeId,
      this.contractId,
      current.pipeKey,
      args.reservoirBalance,
      args.userBalance,
      args.nonce,
      {
        action: args.action ?? null,
        actor: args.actor ?? null,
        hashedSecret: null,
        validAfter: null,
        serverSignature: args.serverSignature ?? null,
        counterpartySignature: args.counterpartySignature ?? null,
      },
    );
    this.deletePendingStatesAtOrBelowNonce(current.pipeId, args.nonce);
  }

  async submitDisputeForCounterparty(counterparty: string): Promise<{
    txid: string;
    nonce: string;
    pipeId: string;
  }> {
    if (!this.serverPrivateKey) {
      throw new ReservoirError(503, 'reservoir signing key unavailable', 'reservoir-key-missing');
    }
    if (!this.contractId) {
      throw new ReservoirError(503, 'stackflow contract not configured', 'stackflow-contract-missing');
    }

    const row = this.getEnforceablePipeRowForCounterparty(counterparty);
    if (!row) {
      throw new ReservoirError(404, `no enforceable pipe state for ${counterparty}`, 'no-enforceable-pipe-state');
    }

    const pipeKey = JSON.parse(row.pipe_key_json) as {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };
    const withPrincipal = pipeKey['principal-1'] === this.serverAddress
      ? pipeKey['principal-2']
      : pipeKey['principal-1'];

    if (!withPrincipal || withPrincipal !== counterparty) {
      throw new ReservoirError(400, 'stored pipe state does not match the requested counterparty', 'invalid-pipe-state');
    }

    const mySignature = row.last_server_signature;
    const theirSignature = row.last_counterparty_signature;
    if (!mySignature || !theirSignature) {
      throw new ReservoirError(409, 'stored pipe state is missing dispute signatures', 'missing-dispute-signatures');
    }

    const [contractAddress, contractName] = this.contractId.split('.');
    if (!contractAddress || !contractName) {
      throw new ReservoirError(503, 'stackflow contract not configured', 'stackflow-contract-missing');
    }

    const tokenArg = pipeKey.token
      ? someCV(principalCV(pipeKey.token))
      : noneCV();
    const secretArg = row.enforceable_secret
      ? someCV(bufferCV(hexToBytes(row.enforceable_secret)))
      : noneCV();
    const validAfterArg = row.last_valid_after
      ? someCV(uintCV(BigInt(row.last_valid_after)))
      : noneCV();

    const tx = await makeContractCall({
      network: this.network,
      senderKey: this.serverPrivateKey,
      contractAddress,
      contractName,
      functionName: 'dispute-closure-for',
      functionArgs: [
        principalCV(this.serverAddress),
        tokenArg,
        principalCV(withPrincipal),
        uintCV(BigInt(row.server_balance)),
        uintCV(BigInt(row.counterparty_balance)),
        bufferCV(hexToBytes(mySignature)),
        bufferCV(hexToBytes(theirSignature)),
        uintCV(BigInt(row.nonce)),
        uintCV(BigInt(row.last_action ?? '1')),
        principalCV(row.last_actor ?? this.serverAddress),
        secretArg,
        validAfterArg,
      ],
      postConditionMode: PostConditionMode.Allow,
      validateWithAbi: false,
    });

    const result = await broadcastTransaction({
      transaction: tx,
      network: this.network,
    });

    if ('reason' in result) {
      throw new ReservoirError(
        502,
        `dispute broadcast failed: ${result.reason}${result.error ? ` (${result.error})` : ''}`,
        'dispute-broadcast-failed',
      );
    }

    return {
      txid: result.txid,
      nonce: row.nonce,
      pipeId: row.pipe_id,
    };
  }
}
