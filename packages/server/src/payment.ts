/**
 * Payment service — wraps StackFlow node HTTP API.
 *
 * In the new design, the sender generates R and includes hashedSecret in their
 * StackFlow state update. The server's job is to:
 *   1. Verify the incoming payment proof (sender → server, locked by hashedSecret)
 *   2. Create an outgoing payment commitment (server → recipient, same hashedSecret, minus fee)
 *   3. When recipient reveals R: settle both sides
 */

import type { Config, PendingPayment } from './types.js';

export class PaymentError extends Error {
  readonly statusCode: number;
  readonly reason: string;
  constructor(statusCode: number, message: string, reason: string) {
    super(message);
    this.name = 'PaymentError';
    this.statusCode = statusCode;
    this.reason = reason;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === 'object' && !Array.isArray(v);
}

export interface VerifiedPayment {
  hashedSecret: string;
  incomingAmount: string;
  senderAddress: string;
}

export class PaymentService {
  private readonly config: Config;

  constructor(config: Config) {
    this.config = config;
  }

  /**
   * Verify an x402 indirect payment proof from the sender.
   * The proof must be a direct StackFlow transfer state update with a hashedSecret.
   * Server calls its StackFlow node counterparty endpoint to validate and co-sign.
   *
   * Returns the hashedSecret (to use for outgoing payment) and verified amount.
   */
  async verifyIncomingPayment(proofRaw: string): Promise<VerifiedPayment> {
    let proof: unknown;
    try {
      // Accept base64url or raw JSON
      try {
        proof = JSON.parse(Buffer.from(proofRaw, 'base64url').toString('utf-8'));
      } catch {
        proof = JSON.parse(proofRaw);
      }
    } catch {
      throw new PaymentError(400, 'invalid payment header encoding', 'invalid-proof-encoding');
    }

    if (!isRecord(proof)) {
      throw new PaymentError(400, 'payment proof must be a JSON object', 'invalid-proof');
    }

    const hashedSecret = proof['hashedSecret'];
    if (typeof hashedSecret !== 'string' || !hashedSecret) {
      throw new PaymentError(400, 'payment proof missing hashedSecret', 'missing-hashed-secret');
    }

    const forPrincipal = proof['forPrincipal'] ?? proof['actor'];
    if (typeof forPrincipal !== 'string') {
      throw new PaymentError(400, 'payment proof missing forPrincipal', 'invalid-proof');
    }

    // Verify by submitting to our StackFlow node counterparty endpoint.
    // The node checks the sender's signature, validates balances, and co-signs.
    let sfResponse: Record<string, unknown>;
    try {
      const res = await fetch(`${this.config.stackflowNodeUrl}/counterparty/transfer`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(proof),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as Record<string, unknown>;
        throw new PaymentError(402, `payment verification failed: ${body['reason'] ?? res.status}`, 'payment-rejected');
      }

      sfResponse = await res.json() as Record<string, unknown>;
    } catch (err) {
      if (err instanceof PaymentError) throw err;
      throw new PaymentError(502, 'could not reach StackFlow node', 'stackflow-unavailable');
    }

    if (!sfResponse['ok'] && sfResponse['mySignature'] === undefined) {
      throw new PaymentError(402, 'StackFlow node rejected payment', 'payment-rejected');
    }

    // Extract the amount from the proof — this is the sender's transfer amount
    const amount = proof['amount'] ?? proof['myBalance'];
    const incomingAmount = typeof amount === 'string' ? amount :
      typeof amount === 'number' ? String(amount) : this.config.messagePriceSats;

    return {
      hashedSecret: hashedSecret as string,
      incomingAmount,
      senderAddress: forPrincipal as string,
    };
  }

  /**
   * Create the server's outgoing payment commitment: server → recipient, locked
   * by the same hashedSecret, for (incomingAmount - fee).
   *
   * Calls the StackFlow node to sign a state update on the server→recipient channel.
   * Returns a PendingPayment to store alongside the message.
   *
   * NOTE: Requires an open StackFlow channel between server and recipient.
   * If no channel exists, returns null (deferred payment model).
   */
  async createOutgoingPayment(args: {
    hashedSecret: string;
    incomingAmount: string;
    recipientAddr: string;
    contractId: string;
  }): Promise<PendingPayment | null> {
    const outgoingAmount = (BigInt(args.incomingAmount) - BigInt(this.config.minFeeSats)).toString();
    if (BigInt(outgoingAmount) <= 0n) return null;

    // Build a transfer payload for server → recipient on the existing channel
    const transferPayload = {
      contractId: args.contractId,
      forPrincipal: this.config.serverStxAddress,
      withPrincipal: args.recipientAddr,
      action: 1,
      amount: outgoingAmount,
      hashedSecret: args.hashedSecret,
    };

    try {
      const res = await fetch(`${this.config.stackflowNodeUrl}/counterparty/transfer`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(transferPayload),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        // Non-fatal: no channel open yet. Store null, settle later.
        console.warn(`outgoing payment creation failed for ${args.recipientAddr}: ${res.status}`);
        return null;
      }

      const stateProof = await res.json() as Record<string, unknown>;
      return {
        stateProof,
        amount: outgoingAmount,
        hashedSecret: args.hashedSecret,
      };
    } catch {
      // Non-fatal: StackFlow node unreachable
      console.warn('could not create outgoing payment, will store null');
      return null;
    }
  }

  /**
   * Settle both sides of the payment after the recipient reveals R.
   * Calls the StackFlow node's forwarding reveal endpoint with the secret.
   */
  async settlePayment(args: {
    paymentId: string;
    secret: string;
    hashedSecret: string;
  }): Promise<void> {
    try {
      const res = await fetch(`${this.config.stackflowNodeUrl}/forwarding/reveal`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ paymentId: args.paymentId, secret: args.secret }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({})) as Record<string, unknown>;
        console.error('payment settlement failed', args.paymentId, body);
      }
    } catch (err) {
      // Non-fatal — can retry
      console.error('payment settlement error', args.paymentId, err);
    }
  }
}
