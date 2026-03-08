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
}

export class ReservoirService {
  private db: DB | null = null;
  private readonly serverAddress: string;
  private readonly serverPrivateKey: string;
  private readonly contractId: string;
  private readonly chainId: number;
  private readonly minFeeSats: bigint;
  private readonly messagePriceSats: bigint;

  constructor(config: {
    db: DB;
    serverAddress: string;
    serverPrivateKey: string;
    contractId: string;
    chainId: number;
    minFeeSats: string;
    messagePriceSats: string;
  }) {
    this.db = config.db;
    this.serverAddress = config.serverAddress;
    this.serverPrivateKey = config.serverPrivateKey;
    this.contractId = config.contractId;
    this.chainId = config.chainId;
    this.minFeeSats = BigInt(config.minFeeSats);
    this.messagePriceSats = BigInt(config.messagePriceSats);
    this.initTables();
  }

  private initTables(): void {
    this.assertDb().exec(`
      CREATE TABLE IF NOT EXISTS reservoir_pipes (
        pipe_id          TEXT PRIMARY KEY,
        contract_id      TEXT NOT NULL,
        pipe_key_json    TEXT NOT NULL,
        server_balance   TEXT NOT NULL DEFAULT '0',
        counterparty_balance TEXT NOT NULL DEFAULT '0',
        nonce            TEXT NOT NULL DEFAULT '0',
        updated_at       INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
      );
    `);
  }

  private assertDb(): DB {
    if (!this.db) throw new Error('ReservoirService not initialized');
    return this.db;
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

  private upsertPipe(
    pipeId: string,
    contractId: string,
    pipeKey: object,
    serverBalance: string,
    counterpartyBalance: string,
    nonce: string,
  ): void {
    this.assertDb().prepare(`
      INSERT INTO reservoir_pipes (pipe_id, contract_id, pipe_key_json, server_balance, counterparty_balance, nonce, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, unixepoch('now') * 1000)
      ON CONFLICT(pipe_id) DO UPDATE SET
        server_balance = excluded.server_balance,
        counterparty_balance = excluded.counterparty_balance,
        nonce = excluded.nonce,
        updated_at = excluded.updated_at
    `).run(pipeId, contractId, JSON.stringify(pipeKey), serverBalance, counterpartyBalance, nonce);
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

    // Dev/bypass mode: when no server key is configured, accept a simple proof
    // format { hashedSecret, forPrincipal|actor, amount } without SIP-018 verification.
    if (!this.serverPrivateKey) {
      const hashedSecret = typeof proof['hashedSecret'] === 'string' ? proof['hashedSecret'] : null;
      if (!hashedSecret) {
        throw new ReservoirError(400, 'payment proof missing hashedSecret', 'missing-hashed-secret');
      }
      const senderAddress = (
        typeof proof['forPrincipal'] === 'string' ? proof['forPrincipal'] :
        typeof proof['actor'] === 'string' ? proof['actor'] : 'unknown'
      );
      const incomingAmount = (
        typeof proof['amount'] === 'string' ? proof['amount'] :
        this.messagePriceSats.toString()
      );
      return { hashedSecret, incomingAmount, senderAddress };
    }

    // Extract required fields
    const contractId = typeof proof['contractId'] === 'string' ? proof['contractId'] : this.contractId;
    const pipeKeyRaw = proof['pipeKey'];
    if (!pipeKeyRaw || typeof pipeKeyRaw !== 'object' || Array.isArray(pipeKeyRaw)) {
      throw new ReservoirError(400, 'payment proof missing pipeKey', 'missing-pipe-key');
    }
    const pipeKey = pipeKeyRaw as { 'principal-1': string; 'principal-2': string; token?: string | null };

    const forPrincipal = typeof proof['forPrincipal'] === 'string' ? proof['forPrincipal'] : '';
    const withPrincipal = typeof proof['withPrincipal'] === 'string' ? proof['withPrincipal'] : '';
    const myBalance = typeof proof['myBalance'] === 'string' ? proof['myBalance'] : String(proof['myBalance'] ?? '');
    const theirBalance = typeof proof['theirBalance'] === 'string' ? proof['theirBalance'] : String(proof['theirBalance'] ?? '');
    const nonce = String(proof['nonce'] ?? '');
    const action = String(proof['action'] ?? '1');
    const actor = typeof proof['actor'] === 'string' ? proof['actor'] : '';
    const hashedSecret = typeof proof['hashedSecret'] === 'string' ? proof['hashedSecret'] : null;
    const theirSignature = typeof proof['theirSignature'] === 'string' ? proof['theirSignature'] : '';
    const validAfter = typeof proof['validAfter'] === 'string' ? proof['validAfter'] : null;

    if (!hashedSecret) {
      throw new ReservoirError(400, 'payment proof missing hashedSecret', 'missing-hashed-secret');
    }
    if (!actor) {
      throw new ReservoirError(400, 'payment proof missing actor', 'missing-actor');
    }
    if (!theirSignature) {
      throw new ReservoirError(400, 'payment proof missing sender signature', 'missing-signature');
    }

    // Verify server is the recipient
    if (forPrincipal && forPrincipal !== this.serverAddress) {
      throw new ReservoirError(402, 'payment not addressed to this server', 'wrong-recipient');
    }

    // Check amount is sufficient
    let serverNewBalance: bigint;
    let senderNewBalance: bigint;
    try {
      serverNewBalance = BigInt(myBalance);
      senderNewBalance = BigInt(theirBalance);
    } catch {
      throw new ReservoirError(400, 'invalid balance values in proof', 'invalid-balances');
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
      const existingNonce = BigInt(existing.nonce);
      const incomingNonce = BigInt(nonce);

      if (incomingNonce !== existingNonce + 1n) {
        throw new ReservoirError(402, `nonce must be ${existingNonce + 1n}, got ${incomingNonce}`, 'invalid-nonce');
      }
      if (serverNewBalance <= existingServerBalance) {
        throw new ReservoirError(402, 'server balance did not increase', 'balance-not-increased');
      }

      incomingAmount = serverNewBalance - existingServerBalance;
    } else {
      // New pipe: derive amount from balance increase (myBalance is server's new total)
      // We assume the initial balance came from agent's channel setup
      incomingAmount = serverNewBalance;
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
    );

    return {
      hashedSecret,
      incomingAmount: incomingAmount.toString(),
      senderAddress: withPrincipal || actor,
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
    const outgoingAmount = BigInt(args.incomingAmount) - this.minFeeSats;
    if (outgoingAmount <= 0n) return null;

    // Find the server→recipient pipe
    // We need both principals to look up the canonical pipeKey
    const [p1, p2] = [this.serverAddress, args.recipientAddr].sort();
    const pipeKey = { 'principal-1': p1, 'principal-2': p2, token: null as string | null };

    // Look for any matching pipe across known tokens
    const matchingPipe = this.assertDb().prepare(`
      SELECT * FROM reservoir_pipes
      WHERE contract_id = ?
        AND (
          (pipe_key_json LIKE ? AND pipe_key_json LIKE ?)
        )
      LIMIT 1
    `).get(args.contractId, `%"${p1}"%`, `%"${p2}"%`) as PipeRow | null;

    if (!matchingPipe) {
      // No channel open with recipient yet — deferred payment
      console.warn(`[reservoir] no pipe to recipient ${args.recipientAddr} — pendingPayment will be null`);
      return null;
    }

    const storedPipeKey = JSON.parse(matchingPipe.pipe_key_json) as typeof pipeKey;
    const isServerP1 = storedPipeKey['principal-1'] === this.serverAddress;

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
      hashedSecret: args.hashedSecret,
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
        myBalance: nextRecipientBalance,
        theirBalance: nextServerBalance,
        nonce: nextNonce,
        action: '1',
        actor: this.serverAddress,
        hashedSecret: args.hashedSecret,
        theirSignature: serverSignature,
      };

      // Update pipe state (HTLC locked — balance committed but not yet final)
      this.upsertPipe(
        matchingPipe.pipe_id, args.contractId, storedPipeKey,
        isServerP1 ? nextServerBalance : nextRecipientBalance,
        isServerP1 ? nextRecipientBalance : nextServerBalance,
        nextNonce,
      );

      return {
        stateProof: stateProof as Record<string, unknown>,
        amount: outgoingAmount.toString(),
        hashedSecret: args.hashedSecret,
      };
    } catch (err) {
      console.warn('[reservoir] failed to sign outgoing payment:', err);
      return null;
    }
  }

  /**
   * Mark a payment as settled after the recipient reveals R.
   * For the PoC, logs the revealed secret for audit purposes.
   * Full on-chain settlement (reveal-preimage) can be added later.
   */
  async settlePayment(args: {
    paymentId: string;
    secret: string;
    hashedSecret: string;
  }): Promise<void> {
    console.log('[reservoir] payment settled', {
      paymentId: args.paymentId,
      hashedSecret: args.hashedSecret,
      secret: args.secret,
    });
    // TODO: submit reveal-preimage on-chain for both inbound and outbound HTLCs
    // This removes the time-lock and finalizes balances on-chain if disputed.
  }
}
