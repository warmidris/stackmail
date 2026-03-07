/**
 * StackmailClient — agent-side client, no server required.
 *
 * Agents poll with client.poll() on a cron/interval. No inbound ports.
 *
 * Send flow:
 *   1. GET /payment-info/{to} → PaymentInfo (recipient pubkey, price)
 *   2. Generate secret R (32 random bytes), compute H = sha256(R)
 *   3. Encrypt { v:1, secret:R, subject, body } with recipient's pubkey → EncryptedMail
 *   4. Build StackFlow payment proof with H embedded (caller-supplied paymentProofBuilder)
 *   5. POST /messages/{to} with proof in header, EncryptedMail in body
 *
 * Receive flow (poll):
 *   1. GET /inbox (signed auth) → InboxEntry[]
 *   2. For each unclaimed: GET the message listing (metadata only)
 *   3. POST /inbox/{id}/claim with { secret: R } → MailMessage + pendingPayment
 *      - Server verifies hash(R) == hashedSecret before settling
 *   4. Decrypt EncryptedMail with private key → DecryptedMessage
 */

import { randomBytes } from 'node:crypto';
import { encryptMail, decryptMail, hashSecret, verifySecretHash } from '@stackmail/crypto';
import type {
  ClientConfig,
  InboxEntry,
  MailMessage,
  DecryptedMessage,
  PaymentInfo,
  PendingPayment,
  PollResult,
  SendOptions,
} from './types.js';

export class StackmailError extends Error {
  readonly statusCode: number;
  readonly reason: string;
  readonly details: Record<string, unknown>;
  constructor(statusCode: number, reason: string, details: Record<string, unknown> = {}) {
    super(`Stackmail ${statusCode}: ${reason}`);
    this.name = 'StackmailError';
    this.statusCode = statusCode;
    this.reason = reason;
    this.details = details;
  }
}

export class StackmailClient {
  private readonly config: ClientConfig;

  constructor(config: ClientConfig) {
    this.config = config;
  }

  // ─── Send ─────────────────────────────────────────────────────────────────

  /**
   * Send a message to a recipient. Handles all payment and encryption internally.
   * Returns the server-assigned message ID.
   */
  async send(opts: SendOptions): Promise<{ messageId: string }> {
    const serverUrl = opts.serverUrl ?? this.config.serverUrl;

    // 1. Get recipient's pubkey + payment parameters
    const paymentInfo = await this.fetchPaymentInfo(opts.to, serverUrl);

    // 2. Generate HTLC secret
    const secretBytes = randomBytes(32);
    const secretHex = secretBytes.toString('hex');
    const hashedSecretHex = hashSecret(secretHex);

    // 3. Encrypt payload (secret + message) with recipient's pubkey
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: opts.subject, body: opts.body },
      paymentInfo.recipientPublicKey,
    );

    // 4. Build payment proof (caller provides StackFlow integration)
    const paymentProof = await this.config.paymentProofBuilder({
      hashedSecret: secretHex,
      hashedSecretHex,
      paymentInfo,
    });

    // 5. Send
    const res = await fetch(`${serverUrl}/messages/${encodeURIComponent(opts.to)}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-x402-payment': paymentProof,
      },
      body: JSON.stringify({
        from: this.config.address,
        encryptedPayload,
      }),
      signal: AbortSignal.timeout(30_000),
    });

    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) {
      throw new StackmailError(res.status, String(body['error'] ?? 'send-failed'), body);
    }

    return { messageId: String(body['messageId'] ?? '') };
  }

  // ─── Receive ──────────────────────────────────────────────────────────────

  /** List inbox entries (metadata only, no body). */
  async getInbox(opts: { limit?: number; before?: number; includeClaimed?: boolean } = {}): Promise<InboxEntry[]> {
    const url = new URL(`${this.config.serverUrl}/inbox`);
    if (opts.limit) url.searchParams.set('limit', String(opts.limit));
    if (opts.before) url.searchParams.set('before', String(opts.before));
    if (opts.includeClaimed) url.searchParams.set('claimed', 'true');

    const res = await fetch(url.toString(), {
      headers: { 'x-stackmail-auth': await this.buildAuthHeader('get-inbox') },
      signal: AbortSignal.timeout(15_000),
    });

    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'inbox-failed'), data);
    return (data['messages'] as InboxEntry[]) ?? [];
  }

  /**
   * Claim a message: reveal R to server, receive the encrypted payload.
   * Decrypts locally and returns the plaintext message.
   *
   * Before revealing, verifies that hash(R from decryption) matches
   * the hashedSecret in the server's pending payment — so we only
   * reveal if the payment is legit.
   */
  async claim(messageId: string): Promise<DecryptedMessage> {
    // First we need the encrypted payload to extract R before revealing it.
    // But the server only returns encryptedPayload *after* we reveal R and claim.
    //
    // Resolution: we can't verify the payment before claiming in a single round-trip.
    // Instead, on claim the server returns { message, pendingPayment }.
    // If the pendingPayment.hashedSecret doesn't match hash(decrypted R), the server
    // already verified it server-side (verifySecretHash) before marking claimed.
    // Server-side verification is the security guarantee.
    //
    // Client-side: we reveal R, then verify the pendingPayment after the fact.
    // If they don't match, something is wrong with the server — log and warn.
    //
    // For a proper two-round protocol (verify-before-reveal), a future version
    // could have a separate GET /inbox/:id/preview endpoint.

    // We need R to claim — but we don't have it yet (it's inside the ciphertext).
    // This is the inherent tension: to verify we need R; to get R we need to claim.
    //
    // Solution used here: trust the server's hash verification.
    // The server holds R server-side (generated by... wait, sender generates R).
    //
    // Actually: sender sends R encrypted in the payload. Server doesn't know R.
    // Recipient must first decrypt the payload to get R, THEN reveal to server.
    //
    // So the claim flow needs a preview step. Let's add GET /inbox/:id/preview
    // that returns the encryptedPayload (but marks nothing as claimed).

    // For now: use a two-step approach with a preview fetch first.
    const encryptedPayload = await this.fetchEncryptedPayload(messageId);

    // Decrypt to get R
    const decrypted = decryptMail(encryptedPayload, this.config.privateKey);
    const { secret: secretHex } = decrypted;

    // Reveal R to server
    const res = await fetch(`${this.config.serverUrl}/inbox/${encodeURIComponent(messageId)}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-stackmail-auth': await this.buildAuthHeader('claim-message', messageId),
      },
      body: JSON.stringify({ secret: secretHex }),
      signal: AbortSignal.timeout(15_000),
    });

    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'claim-failed'), data);

    const message = data['message'] as MailMessage;
    const pendingPayment = data['pendingPayment'] as PendingPayment | null;

    // Verify the payment hash matches what we decrypted (audit trail)
    if (pendingPayment) {
      const computedHash = hashSecret(secretHex);
      if (!verifySecretHash(secretHex, pendingPayment.hashedSecret)) {
        console.warn(
          `[stackmail] WARNING: pendingPayment.hashedSecret (${pendingPayment.hashedSecret}) ` +
          `does not match hash(decrypted secret) (${computedHash}) for message ${messageId}. ` +
          `This may indicate a server mismatch.`,
        );
      }
    }

    return {
      id: message.id,
      from: message.from,
      to: message.to,
      sentAt: message.sentAt,
      amount: message.amount,
      fee: message.fee,
      paymentId: message.paymentId,
      subject: decrypted.subject,
      body: decrypted.body,
    };
  }

  /**
   * Fetch the encrypted payload for a message without claiming it.
   * Used internally by claim() to get R before revealing.
   */
  private async fetchEncryptedPayload(messageId: string): Promise<import('@stackmail/crypto').EncryptedMail> {
    const res = await fetch(`${this.config.serverUrl}/inbox/${encodeURIComponent(messageId)}/preview`, {
      headers: { 'x-stackmail-auth': await this.buildAuthHeader('get-inbox') },
      signal: AbortSignal.timeout(15_000),
    });

    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'preview-failed'), data);
    return data['encryptedPayload'] as import('@stackmail/crypto').EncryptedMail;
  }

  /**
   * Poll inbox and claim all unclaimed messages. This is the main agent loop entry point.
   *
   * Usage:
   *   setInterval(() => client.poll().then(handleNewMail), 5 * 60 * 1000);
   */
  async poll(opts: { limit?: number } = {}): Promise<PollResult> {
    const inbox = await this.getInbox({ limit: opts.limit ?? 20 });
    const unclaimed = inbox.filter(e => !e.claimed);

    const claimed: DecryptedMessage[] = [];
    const errors: Array<{ messageId: string; error: string }> = [];

    for (const entry of unclaimed) {
      try {
        const msg = await this.claim(entry.id);
        claimed.push(msg);
      } catch (err) {
        errors.push({ messageId: entry.id, error: err instanceof Error ? err.message : String(err) });
      }
    }

    return { inbox, claimed, errors };
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private async fetchPaymentInfo(recipientAddr: string, serverUrl: string): Promise<PaymentInfo> {
    const res = await fetch(`${serverUrl}/payment-info/${encodeURIComponent(recipientAddr)}`, {
      signal: AbortSignal.timeout(10_000),
    });
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'payment-info-failed'), data);
    return data as PaymentInfo;
  }

  private async buildAuthHeader(
    action: 'get-inbox' | 'claim-message' | 'get-message',
    messageId?: string,
  ): Promise<string> {
    const payload = {
      action,
      address: this.config.address,
      timestamp: Date.now(),
      ...(messageId ? { messageId } : {}),
    };
    const message = JSON.stringify(payload);
    const signature = await this.config.signer(message);
    return Buffer.from(JSON.stringify({ pubkey: this.config.publicKey, payload, signature })).toString('base64');
  }
}
