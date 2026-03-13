/**
 * StackmailClient — agent-side client, no server required.
 *
 * Agents poll with client.poll() on a cron/interval. No inbound ports.
 *
 * Send flow:
 *   1. Caller supplies recipient's public key (look up from Stacks tx history via Hiro API)
 *   2. GET /status → server address + message price
 *   3. Generate secret R (32 random bytes), compute H = sha256(R)
 *   4. Encrypt { v:1, secret:R, subject, body } with recipient's pubkey → EncryptedMail
 *   5. Build StackFlow payment proof with H embedded (caller-supplied paymentProofBuilder)
 *   6. POST /messages/{to} with proof in header, EncryptedMail in body
 *
 * Receive flow (poll):
 *   1. GET /inbox (signed auth) → InboxEntry[]
 *   2. For each unclaimed: GET /inbox/{id}/preview to fetch encryptedPayload + pendingPayment + H
 *   3. Decrypt payload, verify hash(R) == H and verify pendingPayment signature (if present)
 *   4. POST /inbox/{id}/claim with { secret: R } → MailMessage + pendingPayment
 *   5. Save claim proof artifact locally for later dispute handling
 */

import { randomBytes } from 'node:crypto';
import { encryptMail, decryptMail, hashSecret, verifySecretHash } from '@stackmail/crypto';
import { verifyPendingPaymentProof } from './sip018.js';
import type {
  ClaimProofRecord,
  ClientConfig,
  InboxEntry,
  MailMessage,
  DecryptedMessage,
  PaymentInfo,
  PendingPayment,
  PollResult,
  PreparedLiquidityAction,
  SendOptions,
  SendResult,
  TapStateView,
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
  private inboxSessionToken: string | null = null;
  private inboxSessionExpiresAt = 0;
  private authAudience: string | null = null;

  constructor(config: ClientConfig) {
    this.config = config;
  }

  async getTapState(): Promise<TapStateView | null> {
    const res = await fetch(`${this.config.serverUrl}/tap/state`, {
      headers: await this.buildInboxHeaders('get-inbox'),
      signal: AbortSignal.timeout(15_000),
    });
    this.captureInboxSession(res);
    const data = await res.json().catch(() => ({})) as { tap?: TapStateView | null } & Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'tap-state-failed'), data);
    return data.tap ?? null;
  }

  async prepareAddFunds(amount: string): Promise<PreparedLiquidityAction> {
    if (!this.config.sip018Signer) {
      throw new StackmailError(400, 'sip018-signer-required', { operation: 'prepareAddFunds' });
    }
    const status = await this.fetchFullServerStatus(this.config.serverUrl);
    const tap = await this.getTapState();
    if (!tap) {
      throw new StackmailError(404, 'no-tap', { operation: 'prepareAddFunds' });
    }
    const nextMyBalance = (BigInt(tap.myBalance) + BigInt(amount)).toString();
    const nextReservoirBalance = tap.serverBalance;
    const nextNonce = (BigInt(tap.nonce) + 1n).toString();
    const pipeKey = this.canonicalPipeKey(tap.token, this.config.address, status.reservoirContract);
    const mySignature = await this.config.sip018Signer({
      contractId: status.sfContract,
      forPrincipal: this.config.address,
      myBalance: nextMyBalance,
      theirBalance: nextReservoirBalance,
      nonce: nextNonce,
      action: '2',
      actor: this.config.address,
      token: tap.token,
      principal1: pipeKey['principal-1'],
      principal2: pipeKey['principal-2'],
    });
    const res = await fetch(`${this.config.serverUrl}/tap/add-funds-params`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        user: this.config.address,
        token: tap.token,
        amount,
        myBalance: nextMyBalance,
        reservoirBalance: nextReservoirBalance,
        nonce: nextNonce,
        mySignature,
      }),
      signal: AbortSignal.timeout(20_000),
    });
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'prepare-add-funds-failed'), data);
    return {
      reservoirContract: status.reservoirContract,
      stackflowContract: status.sfContract,
      chainId: status.chainId,
      token: tap.token,
      functionName: 'add-funds',
      amount,
      myBalance: nextMyBalance,
      reservoirBalance: nextReservoirBalance,
      nonce: nextNonce,
      mySignature,
      reservoirSignature: String(data['reservoirSignature'] ?? ''),
    };
  }

  async prepareBorrowMoreLiquidity(amount: string): Promise<PreparedLiquidityAction> {
    if (!this.config.sip018Signer) {
      throw new StackmailError(400, 'sip018-signer-required', { operation: 'prepareBorrowMoreLiquidity' });
    }
    const status = await this.fetchFullServerStatus(this.config.serverUrl);
    const tap = await this.getTapState();
    if (!tap) {
      throw new StackmailError(404, 'no-tap', { operation: 'prepareBorrowMoreLiquidity' });
    }
    const nextMyBalance = tap.myBalance;
    const nextReservoirBalance = (BigInt(tap.serverBalance) + BigInt(amount)).toString();
    const nextNonce = (BigInt(tap.nonce) + 1n).toString();
    const reservoir = status.reservoirContract;
    const pipeKey = this.canonicalPipeKey(tap.token, this.config.address, reservoir);
    const mySignature = await this.config.sip018Signer({
      contractId: status.sfContract,
      forPrincipal: this.config.address,
      myBalance: nextMyBalance,
      theirBalance: nextReservoirBalance,
      nonce: nextNonce,
      action: '2',
      actor: reservoir,
      token: tap.token,
      principal1: pipeKey['principal-1'],
      principal2: pipeKey['principal-2'],
    });
    const res = await fetch(`${this.config.serverUrl}/tap/borrow-more-params`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        borrower: this.config.address,
        token: tap.token,
        borrowAmount: amount,
        myBalance: nextMyBalance,
        reservoirBalance: nextReservoirBalance,
        borrowNonce: nextNonce,
        mySignature,
      }),
      signal: AbortSignal.timeout(20_000),
    });
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'prepare-borrow-failed'), data);
    return {
      reservoirContract: status.reservoirContract,
      stackflowContract: status.sfContract,
      chainId: status.chainId,
      token: tap.token,
      functionName: 'borrow-liquidity',
      amount,
      fee: String(data['borrowFee'] ?? ''),
      myBalance: nextMyBalance,
      reservoirBalance: nextReservoirBalance,
      nonce: nextNonce,
      mySignature,
      reservoirSignature: String(data['reservoirSignature'] ?? ''),
    };
  }

  async syncTapState(args: {
    token: string | null;
    myBalance: string;
    reservoirBalance: string;
    nonce: string;
    action: string;
    actor: string;
    mySignature: string;
    reservoirSignature: string;
  }): Promise<void> {
    const res = await fetch(`${this.config.serverUrl}/tap/sync-state`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(await this.buildInboxHeaders('get-inbox')),
      },
      body: JSON.stringify({
        user: this.config.address,
        token: args.token,
        myBalance: args.myBalance,
        reservoirBalance: args.reservoirBalance,
        nonce: args.nonce,
        action: args.action,
        actor: args.actor,
        mySignature: args.mySignature,
        reservoirSignature: args.reservoirSignature,
      }),
      signal: AbortSignal.timeout(20_000),
    });
    this.captureInboxSession(res);
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'tap-sync-failed'), data);
  }

  // ─── Send ─────────────────────────────────────────────────────────────────

  /**
   * Send a message to a recipient. Handles all payment and encryption internally.
   * Returns the server-assigned message ID.
   */
  async send(opts: SendOptions): Promise<SendResult> {
    const serverUrl = opts.serverUrl ?? this.config.serverUrl;

    // 1. Get server config (address, price)
    const serverConfig = await this.fetchServerConfig(serverUrl);
    const paymentInfo: PaymentInfo = {
      recipientPublicKey: opts.recipientPublicKey,
      amount:             serverConfig.messagePriceSats,
      fee:                serverConfig.minFeeSats,
      recipientAmount:    String(BigInt(serverConfig.messagePriceSats) - BigInt(serverConfig.minFeeSats)),
      stackflowNodeUrl:   serverConfig.stackflowNodeUrl ?? '',
      serverAddress:      serverConfig.serverAddress,
    };

    // 2. Generate HTLC secret
    const secretBytes = randomBytes(32);
    const secretHex = secretBytes.toString('hex');
    const hashedSecretHex = hashSecret(secretHex);

    // 3. Encrypt payload (secret + message) with recipient's pubkey
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: opts.subject, body: opts.body },
      opts.recipientPublicKey,
    );

    // 4. Build payment proof (caller provides StackFlow integration)
    const paymentProof = await this.config.paymentProofBuilder({
      hashedSecret: hashedSecretHex,
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
        fromPublicKey: this.config.publicKey,
        encryptedPayload,
      }),
      signal: AbortSignal.timeout(30_000),
    });

    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) {
      throw new StackmailError(res.status, String(body['error'] ?? 'send-failed'), body);
    }

    return {
      messageId: String(body['messageId'] ?? ''),
      deferred: Boolean(body['deferred']),
      deferredReason: typeof body['reason'] === 'string'
        ? body['reason'] as SendResult['deferredReason']
        : undefined,
    };
  }

  // ─── Receive ──────────────────────────────────────────────────────────────

  /** List inbox entries (metadata only, no body). */
  async getInbox(opts: { limit?: number; before?: number; includeClaimed?: boolean } = {}): Promise<InboxEntry[]> {
    const url = new URL(`${this.config.serverUrl}/inbox`);
    if (opts.limit) url.searchParams.set('limit', String(opts.limit));
    if (opts.before) url.searchParams.set('before', String(opts.before));
    if (opts.includeClaimed) url.searchParams.set('claimed', 'true');

    const res = await fetch(url.toString(), {
      headers: await this.buildInboxHeaders('get-inbox'),
      signal: AbortSignal.timeout(15_000),
    });
    this.captureInboxSession(res);

    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'inbox-failed'), data);
    return (data['messages'] as InboxEntry[]) ?? [];
  }

  /**
   * Claim a message:
   *   1) preview + decrypt to obtain secret R,
   *   2) verify the server's pending payment commitment,
   *   3) reveal R and fetch confirmed message.
   */
  async claim(messageId: string): Promise<DecryptedMessage> {
    const preview = await this.fetchPreview(messageId);
    const encryptedPayload = preview.encryptedPayload;

    // Decrypt to get R
    const decrypted = decryptMail(encryptedPayload, this.config.privateKey);
    const { secret: secretHex } = decrypted;
    const computedHash = hashSecret(secretHex);
    const pendingPayment = preview.pendingPayment;

    if (!verifySecretHash(secretHex, preview.hashedSecret)) {
      throw new StackmailError(409, 'secret-hash-mismatch', {
        messageId,
        previewHashedSecret: preview.hashedSecret,
        computedHash,
      });
    }

    let proofVerified: boolean | null = null;
    let verificationError: string | undefined;
    if (pendingPayment) {
      const verification = await verifyPendingPaymentProof({
        pendingPayment,
        recipientAddress: this.config.address,
        chainId: this.config.chainId,
      });
      if (!verification.ok) {
        throw new StackmailError(409, 'pending-payment-invalid', {
          messageId,
          reason: verification.reason,
        });
      }
      proofVerified = true;
    }

    // Reveal R to server
    const res = await fetch(`${this.config.serverUrl}/inbox/${encodeURIComponent(messageId)}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(await this.buildInboxHeaders('claim-message', messageId)),
      },
      body: JSON.stringify({ secret: secretHex }),
      signal: AbortSignal.timeout(15_000),
    });
    this.captureInboxSession(res);

    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'claim-failed'), data);

    const message = data['message'] as MailMessage;
    const claimedPendingPayment = data['pendingPayment'] as PendingPayment | null;

    // Claim response should not mutate the commitment we verified in preview.
    if (pendingPayment) {
      if (!claimedPendingPayment) {
        proofVerified = false;
        verificationError = 'claim response missing pending payment from preview';
      } else {
        const previewState = JSON.stringify(pendingPayment.stateProof);
        const claimedState = JSON.stringify(claimedPendingPayment.stateProof);
        if (
          pendingPayment.hashedSecret !== claimedPendingPayment.hashedSecret ||
          pendingPayment.amount !== claimedPendingPayment.amount ||
          previewState !== claimedState
        ) {
          proofVerified = false;
          verificationError = 'claim response pending payment does not match preview';
        }
      }
    }

    const claimProof: ClaimProofRecord = {
      messageId,
      paymentId: message.paymentId,
      recipient: this.config.address,
      secret: secretHex,
      hashedSecret: preview.hashedSecret,
      claimedAt: Date.now(),
      pendingPayment,
      proofVerified,
      verificationError,
    };

    if (this.config.saveClaimProof) {
      try {
        await this.config.saveClaimProof(claimProof);
      } catch (err) {
        console.warn(
          `[stackmail] failed to persist claim proof for message ${messageId}: ${
            err instanceof Error ? err.message : String(err)
          }`,
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
      claimProof,
    };
  }

  /**
   * Fetch preview data for a message without claiming it.
   * Used by claim() to verify pending payment before revealing the secret.
   */
  private async fetchPreview(messageId: string): Promise<{
    encryptedPayload: import('@stackmail/crypto').EncryptedMail;
    pendingPayment: PendingPayment | null;
    hashedSecret: string;
  }> {
    const res = await fetch(`${this.config.serverUrl}/inbox/${encodeURIComponent(messageId)}/preview`, {
      headers: await this.buildInboxHeaders('get-message', messageId),
      signal: AbortSignal.timeout(15_000),
    });
    this.captureInboxSession(res);

    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'preview-failed'), data);
    return {
      encryptedPayload: data['encryptedPayload'] as import('@stackmail/crypto').EncryptedMail,
      pendingPayment: (data['pendingPayment'] as PendingPayment | null) ?? null,
      hashedSecret: String(data['hashedSecret'] ?? ''),
    };
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

  private async fetchServerConfig(serverUrl: string): Promise<{
    messagePriceSats: string;
    minFeeSats: string;
    stackflowNodeUrl?: string;
    serverAddress: string;
  }> {
    const full = await this.fetchFullServerStatus(serverUrl);
    return {
      messagePriceSats: full.messagePriceSats,
      minFeeSats: full.minFeeSats,
      stackflowNodeUrl: full.stackflowNodeUrl,
      serverAddress: full.serverAddress,
    };
  }

  private async fetchFullServerStatus(serverUrl: string): Promise<{
    messagePriceSats: string;
    minFeeSats: string;
    stackflowNodeUrl?: string;
    serverAddress: string;
    reservoirContract: string;
    sfContract: string;
    chainId: number;
  }> {
    const res = await fetch(`${serverUrl}/status`, { signal: AbortSignal.timeout(10_000) });
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'status-failed'), data);
    return {
      messagePriceSats: String(data['messagePriceSats'] ?? '1000'),
      minFeeSats:       String(data['minFeeSats']       ?? '100'),
      stackflowNodeUrl: data['stackflowNodeUrl'] as string | undefined,
      serverAddress:    String(data['serverAddress'] ?? ''),
      reservoirContract: String(data['reservoirContract'] ?? data['serverAddress'] ?? ''),
      sfContract: String(data['sfContract'] ?? ''),
      chainId: Number(data['chainId'] ?? this.config.chainId ?? 1),
    };
  }

  private canonicalPipeKey(token: string | null, a: string, b: string): { 'principal-1': string; 'principal-2': string; token: string | null } {
    if (b.includes('.')) {
      return { token, 'principal-1': a, 'principal-2': b };
    }
    return a < b
      ? { token, 'principal-1': a, 'principal-2': b }
      : { token, 'principal-1': b, 'principal-2': a };
  }

  private async buildAuthHeader(
    action: 'get-inbox' | 'claim-message' | 'get-message',
    messageId?: string,
  ): Promise<string> {
    const audience = await this.getAuthAudience();
    const payload = {
      action,
      address: this.config.address,
      timestamp: Date.now(),
      audience,
      ...(messageId ? { messageId } : {}),
    };
    const message = JSON.stringify(payload);
    const signature = await this.config.signer(message);
    return Buffer.from(JSON.stringify({ pubkey: this.config.publicKey, payload, signature })).toString('base64');
  }

  private async getAuthAudience(): Promise<string> {
    if (this.authAudience) return this.authAudience;
    const res = await fetch(`${this.config.serverUrl}/status`, { signal: AbortSignal.timeout(10_000) });
    const data = await res.json().catch(() => ({})) as Record<string, unknown>;
    if (!res.ok) throw new StackmailError(res.status, String(data['error'] ?? 'status-failed'), data);
    this.authAudience = String(data['authAudience'] ?? data['serverAddress'] ?? 'Stackmail');
    return this.authAudience;
  }

  private async buildInboxHeaders(
    action: 'get-inbox' | 'claim-message' | 'get-message',
    messageId?: string,
  ): Promise<Record<string, string>> {
    if (this.inboxSessionToken && Date.now() < this.inboxSessionExpiresAt) {
      return { 'x-stackmail-session': this.inboxSessionToken };
    }
    return { 'x-stackmail-auth': await this.buildAuthHeader(action, messageId) };
  }

  private captureInboxSession(res: Response): void {
    const token = res.headers.get('x-stackmail-session');
    const expiresAtRaw = res.headers.get('x-stackmail-session-expires-at');
    const expiresAt = expiresAtRaw ? Number(expiresAtRaw) : 0;
    if (token && Number.isFinite(expiresAt) && expiresAt > Date.now()) {
      this.inboxSessionToken = token;
      this.inboxSessionExpiresAt = expiresAt;
    }
  }
}
