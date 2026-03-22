/**
 * Mailslot HTTP server factory.
 *
 * Extracted from index.ts so it can be imported in tests without auto-starting.
 * Use createMailServer(config, store, paymentService) to get an http.Server.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, dirname, resolve } from 'node:path';

import type { Config, RuntimeSettings, EncryptedMail } from './types.js';
import type { MessageStore } from './store.js';
import type { RuntimeSettingsStore } from './settings.js';
import { PaymentError } from './payment.js';
import type { VerifiedPayment } from './payment.js';
import type { PendingPayment } from './types.js';
import type { DeferredReason } from './types.js';

export interface IPaymentService {
  verifyIncomingPayment(proofRaw: string): Promise<VerifiedPayment>;
  createOutgoingPayment(args: {
    hashedSecret: string;
    incomingAmount: string;
    recipientAddr: string;
    contractId: string;
  }): Promise<PendingPayment | null>;
  createTapWithBorrowedLiquidityParams(args: {
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
  }>;
  createAddFundsParams?(args: {
    user: string;
    token: string | null;
    amount: string;
    myBalance: string;
    reservoirBalance: string;
    nonce: string;
    mySignature: string;
  }): Promise<{ reservoirSignature: string }>;
  createBorrowLiquidityParams?(args: {
    borrower: string;
    token: string | null;
    borrowAmount: string;
    borrowFee?: string;
    myBalance: string;
    reservoirBalance: string;
    borrowNonce: string;
    mySignature: string;
  }): Promise<{ borrowFee: string; reservoirSignature: string }>;
  createWithdrawFundsParams?(args: {
    user: string;
    token: string | null;
    amount: string;
    myBalance: string;
    reservoirBalance: string;
    nonce: string;
    mySignature: string;
  }): Promise<{ reservoirSignature: string }>;
  createCloseTapParams?(args: {
    user: string;
    token: string | null;
    myBalance: string;
    reservoirBalance: string;
    nonce: string;
    mySignature: string;
  }): Promise<{ reservoirSignature: string }>;
  getTrackedTapState?(counterparty: string): Promise<{
    contractId: string;
    pipeKey: {
      'principal-1': string;
      'principal-2': string;
    token: string | null;
    };
    serverBalance: string;
    counterpartyBalance: string;
    settledServerBalance?: string;
    settledCounterpartyBalance?: string;
    pendingServerBalance?: string;
    pendingCounterpartyBalance?: string;
    nonce: string;
  } | null>;
  getTapLifecycleState?(counterparty: string): Promise<{
    status: 'never-opened' | 'active' | 'closing' | 'closed';
    nextTapNonce: string;
    nextBorrowNonce: string;
  }>;
  getTapRebalanceRequest?(counterparty: string): Promise<{
    token: string | null;
    amount: string;
    myBalance: string;
    reservoirBalance: string;
    nonce: string;
  } | null>;
  recordCompletedIncomingPayment?(args: { paymentProof: string; secret: string }): Promise<void>;
  cancelMessage?(args: {
    paymentProof: string;
    senderAddr: string;
    recipientAddr: string;
    incomingAmount: string;
    fee: string;
    recipientPendingPayment: PendingPayment | null;
  }): Promise<void>;
  syncTapState?(args: {
    counterparty: string;
    token: string | null;
    userBalance: string;
    reservoirBalance: string;
    nonce: string;
    action?: string | null;
    actor?: string | null;
    counterpartySignature?: string | null;
    serverSignature?: string | null;
  }): Promise<void>;
  submitDisputeForCounterparty?(counterparty: string): Promise<{
    txid: string;
    nonce: string;
    pipeId: string;
  }>;
  submitReturnLiquidityToReservoir?(counterparty: string): Promise<{
    txid: string;
    nonce: string;
    pipeId: string;
  }>;
}
import { verifyInboxAuth, verifyInboxSessionToken, issueInboxSessionToken, pubkeyToStxAddress, AuthError, AUTH_DOMAIN, getAuthAudience } from './auth.js';
import { verifySecretHash } from '@mailslot/crypto';

export function createMailServer(
  config: Config,
  store: MessageStore,
  paymentService: IPaymentService,
  settingsStore: RuntimeSettingsStore,
): ReturnType<typeof createServer> {
  const sfContractId = config.sfContractId;
  const pipeCounterparty = config.reservoirContractId || config.serverStxAddress;
  const __filename = fileURLToPath(import.meta.url);
  const WEB_DIR = join(dirname(__filename), '..', 'web');
  const WEB_DIR_RESOLVED = resolve(WEB_DIR);
  const rateLimitBuckets = new Map<string, { windowStart: number; count: number }>();

  function currentSettings(): RuntimeSettings {
    return settingsStore.get();
  }

  function getClientIp(req: IncomingMessage): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      return forwarded.split(',')[0]?.trim() || 'unknown';
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function rateLimitKey(category: string, req: IncomingMessage): string {
    return `${category}:${getClientIp(req)}`;
  }

  function consumeRateLimit(key: string, max: number): { allowed: boolean; retryAfterSeconds: number } {
    const now = Date.now();
    const bucket = rateLimitBuckets.get(key);
    if (!bucket || now - bucket.windowStart >= config.rateLimitWindowMs) {
      rateLimitBuckets.set(key, { windowStart: now, count: 1 });
      return { allowed: true, retryAfterSeconds: Math.ceil(config.rateLimitWindowMs / 1000) };
    }
    if (bucket.count >= max) {
      const retryAfterMs = Math.max(1000, config.rateLimitWindowMs - (now - bucket.windowStart));
      return { allowed: false, retryAfterSeconds: Math.ceil(retryAfterMs / 1000) };
    }
    bucket.count += 1;
    return { allowed: true, retryAfterSeconds: Math.ceil((config.rateLimitWindowMs - (now - bucket.windowStart)) / 1000) };
  }

  function rateLimitCategory(path: string): { category: string; max: number } | null {
    if (path === '/health' || path === '/status' || path === '/' || path === '/ui' || path.startsWith('/assets/')) {
      return null;
    }
    if (path.startsWith('/admin/')) {
      return { category: 'admin', max: config.rateLimitAdminMax };
    }
    if (path === '/hooks/dispute') {
      return { category: 'hook', max: config.rateLimitAdminMax };
    }
    if (path.startsWith('/messages/')) {
      return { category: 'send', max: config.rateLimitSendMax };
    }
    if (path === '/inbox' || path.startsWith('/inbox/') || path === '/tap/state' || path.startsWith('/tap/')) {
      return { category: 'auth', max: config.rateLimitAuthMax };
    }
    return { category: 'default', max: config.rateLimitMax };
  }

  function isAllowedOrigin(origin: string, url: URL): boolean {
    if (origin === `${url.protocol}//${url.host}`) return true;
    return config.allowedOrigins.includes(origin);
  }

  function applyCors(req: IncomingMessage, res: ServerResponse, url: URL): boolean {
    const origin = req.headers.origin;
    if (!origin) return true;
    if (!isAllowedOrigin(origin, url)) {
      if ((req.method?.toUpperCase() ?? 'GET') === 'OPTIONS') {
        json(res, 403, { error: 'origin-not-allowed' });
        return false;
      }
      json(res, 403, { error: 'origin-not-allowed' });
      return false;
    }
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Headers', 'content-type, authorization, x-mailslot-auth, x-mailslot-session, x-mailslot-payment, x-x402-payment, x-mailslot-webhook-token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Expose-Headers', 'x-mailslot-session, x-mailslot-session-expires-at');
    return true;
  }

  function extractWebhookCounterparty(payload: Record<string, unknown>): string | null {
    const candidates = [
      payload['counterparty'],
      payload['address'],
      payload['wallet'],
      payload['sender'],
      payload['recipient'],
      payload['senderAddress'],
      payload['recipientAddress'],
      payload['counterpartyAddress'],
    ];
    for (const candidate of candidates) {
      if (typeof candidate === 'string' && /^S[PT][0-9A-Z]{39}$/.test(candidate)) return candidate;
    }
    return null;
  }

  function respondTypedServiceError(res: ServerResponse, err: unknown): boolean {
    if (
      err instanceof PaymentError ||
      (typeof err === 'object' &&
        err != null &&
        typeof (err as { statusCode?: unknown }).statusCode === 'number' &&
        typeof (err as { reason?: unknown }).reason === 'string')
    ) {
      const typed = err as { statusCode: number; reason: string; message: string };
      json(res, typed.statusCode, { error: typed.reason, message: typed.message });
      return true;
    }
    return false;
  }

  function buildPaymentInfo(recipientAddr: string, recipientPublicKey: string) {
    const settings = currentSettings();
    const amount = BigInt(settings.messagePriceSats);
    const fee = BigInt(settings.minFeeSats);
    const recipientAmount = amount > fee ? amount - fee : 0n;
    return {
      recipientPublicKey,
      amount: amount.toString(),
      fee: fee.toString(),
      recipientAmount: recipientAmount.toString(),
      stackflowNodeUrl: config.stackflowNodeUrl,
      serverAddress: pipeCounterparty,
      recipientAddr,
    };
  }

  async function activateDeferredMessages(recipientAddr: string): Promise<void> {
    if (!sfContractId) return;
    const now = Date.now();
    const settings = currentSettings();
    await store.expireDeferredMessages(now);
    const deferred = await store.getDeferredMessagesForRecipient(recipientAddr, now, settings.maxPendingPerRecipient);
    for (const message of deferred) {
      const pendingPayment = await paymentService.createOutgoingPayment({
        hashedSecret: message.hashedSecret,
        incomingAmount: message.amount,
        recipientAddr,
        contractId: sfContractId,
      });
      if (!pendingPayment) break;
      await store.activateDeferredMessage(message.id, recipientAddr, pendingPayment);
    }
  }

  async function determineDeferredReason(recipientAddr: string): Promise<DeferredReason> {
    const tracked = await paymentService.getTrackedTapState?.(recipientAddr);
    return tracked == null ? 'no-recipient-tap' : 'insufficient-recipient-liquidity';
  }

  function reservoirAdminAddress(): string | null {
    const [address] = (config.reservoirContractId ?? '').split('.');
    return address && /^S[PT][0-9A-Z]{38,40}$/.test(address) ? address : null;
  }

  async function requireAdminAuth(req: IncomingMessage, res: ServerResponse): Promise<string | null> {
    const authHeader = req.headers['x-mailslot-auth'];
    if (!authHeader) {
      json(res, 401, { error: 'auth-required', message: 'x-mailslot-auth header required' });
      return null;
    }
    try {
      const auth = await verifyInboxAuth(
        Array.isArray(authHeader) ? authHeader[0] : authHeader,
        config,
        store,
      );
      if (auth.payload.action !== 'admin-settings') {
        json(res, 403, { error: 'auth-action-mismatch', message: 'expected action admin-settings' });
        return null;
      }
      const adminAddress = reservoirAdminAddress();
      if (!adminAddress || auth.payload.address !== adminAddress) {
        json(res, 403, { error: 'admin-required', message: 'Only the reservoir deployer may update runtime settings' });
        return null;
      }
      return auth.payload.address;
    } catch (err) {
      if (err instanceof AuthError) {
        json(res, err.statusCode, { error: err.reason, message: err.message });
        return null;
      }
      throw err;
    }
  }

  async function handleGetAdminSettings(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const admin = await requireAdminAuth(req, res);
    if (!admin) return;
    return json(res, 200, { ok: true, admin, settings: currentSettings() });
  }

  async function handleGetAdminStats(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const admin = await requireAdminAuth(req, res);
    if (!admin) return;
    const stats = await store.getStats();
    return json(res, 200, { ok: true, admin, stats });
  }

  async function handleUpdateAdminSettings(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const admin = await requireAdminAuth(req, res);
    if (!admin) return;

    let body: string;
    try {
      body = await readBody(req, 16_384);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const patch: Partial<RuntimeSettings> = {};
    if (parsed['messagePriceSats'] != null) patch.messagePriceSats = String(parsed['messagePriceSats']);
    if (parsed['minFeeSats'] != null) patch.minFeeSats = String(parsed['minFeeSats']);
    if (parsed['maxPendingPerSender'] != null) patch.maxPendingPerSender = Number(parsed['maxPendingPerSender']);
    if (parsed['maxPendingPerRecipient'] != null) patch.maxPendingPerRecipient = Number(parsed['maxPendingPerRecipient']);
    if (parsed['maxDeferredPerSender'] != null) patch.maxDeferredPerSender = Number(parsed['maxDeferredPerSender']);
    if (parsed['maxDeferredPerRecipient'] != null) patch.maxDeferredPerRecipient = Number(parsed['maxDeferredPerRecipient']);
    if (parsed['maxDeferredGlobal'] != null) patch.maxDeferredGlobal = Number(parsed['maxDeferredGlobal']);
    if (parsed['deferredMessageTtlMs'] != null) patch.deferredMessageTtlMs = Number(parsed['deferredMessageTtlMs']);
    if (parsed['maxBorrowPerTap'] != null) patch.maxBorrowPerTap = String(parsed['maxBorrowPerTap']);
    if (parsed['receiveCapacityMultiplier'] != null) patch.receiveCapacityMultiplier = Number(parsed['receiveCapacityMultiplier']);
    if (parsed['rebalanceThresholdPct'] != null) patch.rebalanceThresholdPct = Number(parsed['rebalanceThresholdPct']);
    if (parsed['refreshCapacityCooldownMs'] != null) patch.refreshCapacityCooldownMs = Number(parsed['refreshCapacityCooldownMs']);

    try {
      const next = settingsStore.update(patch);
      return json(res, 200, { ok: true, admin, settings: next });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return json(res, 400, { error: 'invalid-runtime-settings', message });
    }
  }

  async function handleDisputeWebhook(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!config.disputeWebhookToken) {
      return json(res, 503, { error: 'dispute-webhook-disabled' });
    }
    const tokenHeader = req.headers['x-mailslot-webhook-token'];
    const authHeader = req.headers.authorization;
    const token = typeof tokenHeader === 'string'
      ? tokenHeader
      : (typeof authHeader === 'string' && authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '');
    if (!token || token !== config.disputeWebhookToken) {
      return json(res, 401, { error: 'invalid-webhook-token' });
    }

    let body: string;
    try {
      body = await readBody(req, 65_536);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let payload: Record<string, unknown>;
    try {
      payload = body ? JSON.parse(body) as Record<string, unknown> : {};
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const counterparty = extractWebhookCounterparty(payload);
    if (!counterparty) {
      return json(res, 400, { error: 'missing-counterparty' });
    }
    if (typeof paymentService.submitDisputeForCounterparty !== 'function') {
      return json(res, 503, { error: 'dispute-submission-unavailable' });
    }

    console.warn('[mailslot] dispute webhook received', {
      counterparty,
      event: typeof payload['event'] === 'string' ? payload['event'] : null,
      txid: typeof payload['txid'] === 'string' ? payload['txid'] : null,
    });

    try {
      const submitted = await paymentService.submitDisputeForCounterparty(counterparty);
      return json(res, 200, {
        ok: true,
        counterparty,
        submitted: true,
        txid: submitted.txid,
        nonce: submitted.nonce,
        pipeId: submitted.pipeId,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  // ─── Handlers ──────────────────────────────────────────────────────────────

  async function handleSend(req: IncomingMessage, res: ServerResponse, to: string): Promise<void> {
    const paymentHeader = req.headers['x-x402-payment'] ?? req.headers['x-mailslot-payment'];
    if (!paymentHeader) {
      const settings = currentSettings();
      return json(res, 402, {
        error: 'payment-required',
        accepts: [{ mode: 'direct', scheme: 'stackflow' }],
        amount: settings.messagePriceSats,
        stackflowNodeUrl: config.stackflowNodeUrl,
        serverAddress: pipeCounterparty,
      });
    }

    const proofRaw = Array.isArray(paymentHeader) ? paymentHeader[0] : paymentHeader;

    let verified: VerifiedPayment;
    try {
      verified = await paymentService.verifyIncomingPayment(proofRaw);
    } catch (err) {
      if (err instanceof PaymentError) {
        return json(res, err.statusCode, { error: err.reason, message: err.message });
      }
      throw err;
    }

    let body: string;
    try {
      body = await readBody(req, config.maxEncryptedBytes + 1024);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: { encryptedPayload: unknown; from: string; fromPublicKey?: string };
    try {
      data = JSON.parse(body) as typeof data;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    if (!data.from || typeof data.from !== 'string') {
      return json(res, 400, { error: 'from-required', message: 'sender STX address required in body.from' });
    }
    if (data.from !== verified.senderAddress) {
      return json(res, 400, {
        error: 'sender-mismatch',
        message: 'body.from must match the sender authenticated by the payment proof',
      });
    }
    if (data.fromPublicKey != null) {
      if (typeof data.fromPublicKey !== 'string' || !/^0[23][0-9a-f]{64}$/i.test(data.fromPublicKey)) {
        return json(res, 400, {
          error: 'invalid-from-public-key',
          message: 'body.fromPublicKey must be a compressed secp256k1 public key hex string',
        });
      }
      const normalizedPubkey = data.fromPublicKey.toLowerCase();
      const derivedMainnet = pubkeyToStxAddress(normalizedPubkey);
      const derivedTestnet = pubkeyToStxAddress(normalizedPubkey, true);
      if (derivedMainnet !== data.from && derivedTestnet !== data.from) {
        return json(res, 400, {
          error: 'sender-public-key-mismatch',
          message: 'body.fromPublicKey does not match body.from',
        });
      }
      await store.savePublicKey(data.from, normalizedPubkey);
    }

    if (!data.encryptedPayload || typeof data.encryptedPayload !== 'object') {
      return json(res, 400, { error: 'encrypted-payload-required' });
    }

    const enc = data.encryptedPayload as {
      v?: unknown;
      epk?: unknown;
      iv?: unknown;
      data?: unknown;
    };
    if (
      enc.v !== 1 ||
      typeof enc.epk !== 'string' ||
      typeof enc.iv !== 'string' ||
      typeof enc.data !== 'string'
    ) {
      return json(res, 400, { error: 'invalid-encrypted-payload', message: 'encryptedPayload must be a v1 ECIES cipher object with fields: v, epk, iv, data' });
    }

    const encryptedPayload = enc as EncryptedMail;

    const encSize = Buffer.byteLength(encryptedPayload.data, 'hex') / 2;
    if (encSize > config.maxEncryptedBytes) {
      return json(res, 413, { error: 'payload-too-large' });
    }

    const settings = currentSettings();
    // Per-sender HTLC cap: prevent spam by limiting unclaimed messages
    const pendingCount = await store.countPendingFromSender(verified.senderAddress, to);
    if (pendingCount >= settings.maxPendingPerSender) {
      return json(res, 429, {
        error: 'too-many-pending',
        message: `Too many unclaimed messages from this sender (limit: ${settings.maxPendingPerSender})`,
      });
    }
    const recipientPendingCount = await store.countPendingToRecipient(to);
    if (recipientPendingCount >= settings.maxPendingPerRecipient) {
      return json(res, 429, {
        error: 'recipient-inbox-full',
        message: `Recipient inbox already has too many unclaimed messages (limit: ${settings.maxPendingPerRecipient})`,
      });
    }

    const pendingPayment = sfContractId
      ? await paymentService.createOutgoingPayment({
          hashedSecret: verified.hashedSecret,
          incomingAmount: verified.incomingAmount,
          recipientAddr: to,
          contractId: sfContractId,
        })
      : null;

    if (sfContractId && pendingPayment == null) {
      const deferredPerSender = await store.countDeferredFromSender(verified.senderAddress, to);
      if (deferredPerSender >= settings.maxDeferredPerSender) {
        return json(res, 429, {
          error: 'too-many-deferred-from-sender',
          message: `Too many deferred messages from this sender (limit: ${settings.maxDeferredPerSender})`,
        });
      }
      const deferredPerRecipient = await store.countDeferredToRecipient(to);
      if (deferredPerRecipient >= settings.maxDeferredPerRecipient) {
        return json(res, 429, {
          error: 'too-many-deferred-for-recipient',
          message: `Recipient already has too many deferred messages (limit: ${settings.maxDeferredPerRecipient})`,
        });
      }
      const deferredGlobal = await store.countDeferredGlobal();
      if (deferredGlobal >= settings.maxDeferredGlobal) {
        return json(res, 429, {
          error: 'deferred-queue-full',
          message: `Server deferred queue is full (limit: ${settings.maxDeferredGlobal})`,
        });
      }

      const deferredReason = await determineDeferredReason(to);
      const msgId = randomUUID();
      await store.saveMessage({
        id: msgId,
        from: verified.senderAddress,
        to,
        sentAt: Date.now(),
        amount: verified.incomingAmount,
        fee: settings.minFeeSats,
        paymentId: proofRaw,
        hashedSecret: verified.hashedSecret,
        encryptedPayload,
        pendingPayment: null,
        deliveryState: 'deferred',
        deferredReason,
        deferredUntil: Date.now() + settings.deferredMessageTtlMs,
        claimed: false,
        paymentSettled: false,
      });
      return json(res, 202, {
        ok: true,
        deferred: true,
        reason: deferredReason,
        messageId: msgId,
      });
    }

    const msgId = randomUUID();
    await store.saveMessage({
      id: msgId,
      from: verified.senderAddress,
      to,
      sentAt: Date.now(),
      amount: verified.incomingAmount,
      fee: settings.minFeeSats,
      paymentId: proofRaw,
      hashedSecret: verified.hashedSecret,
      encryptedPayload,
      pendingPayment,
      deliveryState: 'ready',
      claimed: false,
      paymentSettled: false,
    });

    return json(res, 200, { ok: true, messageId: msgId });
  }

  async function handleGetInbox(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'get-inbox' });
    if (!auth) return;
    await activateDeferredMessages(auth.payload.address);

    const limit = parseInt(url.searchParams.get('limit') ?? '50', 10);
    const before = url.searchParams.get('before') ? parseInt(url.searchParams.get('before')!, 10) : undefined;
    const includeClaimed = url.searchParams.get('claimed') === 'true';

    const entries = await store.getInbox(auth.payload.address, { limit, before, includeClaimed });
    return json(res, 200, { messages: entries });
  }

  async function handlePreview(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'get-message', messageId: msgId });
    if (!auth) return;

    const stored = await store.markMessagePreviewed(msgId, auth.payload.address, Date.now());
    if (!stored) return json(res, 404, { error: 'not-found' });
    if (stored.claimed) return json(res, 409, { error: 'already-claimed' });
    if ((stored.deliveryState !== 'ready' && stored.deliveryState !== 'previewed') || stored.pendingPayment == null) {
      return json(res, 409, {
        error: 'message-not-ready',
        message: 'message is still waiting for recipient liquidity or tap setup',
      });
    }

    return json(res, 200, {
      messageId: stored.id,
      from: stored.from,
      sentAt: stored.sentAt,
      amount: stored.amount,
      encryptedPayload: stored.encryptedPayload,
      pendingPayment: stored.pendingPayment,
      hashedSecret: stored.hashedSecret,
    });
  }

  async function handleGetMessage(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'get-message', messageId: msgId });
    if (!auth) return;

    const msg = await store.getClaimedMessage(msgId, auth.payload.address);
    if (!msg) return json(res, 404, { error: 'not-found' });
    return json(res, 200, { message: msg });
  }

  async function handleCancelMessage(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'cancel-message', messageId: msgId });
    if (!auth) return;

    const stored = await store.getMessageForSender(msgId, auth.payload.address);
    if (!stored) return json(res, 404, { error: 'not-found' });
    if (stored.claimed || stored.deliveryState === 'settled') {
      return json(res, 409, { error: 'already-claimed', message: 'message has already been claimed' });
    }
    if (stored.deliveryState === 'previewed') {
      return json(res, 409, { error: 'already-previewed', message: 'message can no longer be cancelled after preview' });
    }
    if (stored.deliveryState === 'cancelled') {
      return json(res, 409, { error: 'already-cancelled' });
    }

    try {
      await paymentService.cancelMessage?.({
        paymentProof: stored.paymentId,
        senderAddr: stored.from,
        recipientAddr: stored.to,
        incomingAmount: stored.amount,
        fee: stored.fee,
        recipientPendingPayment: stored.pendingPayment,
      });
    } catch (err) {
      if (err instanceof PaymentError) {
        return json(res, err.statusCode, { error: err.reason, message: err.message });
      }
      if (err instanceof Error && 'statusCode' in err && 'reason' in err) {
        const e = err as Error & { statusCode: number; reason: string };
        return json(res, e.statusCode, { error: e.reason, message: e.message });
      }
      throw err;
    }
    const cancelled = await store.cancelMessageBySender(msgId, auth.payload.address, Date.now());
    if (!cancelled) return json(res, 404, { error: 'not-found' });
    return json(res, 200, { ok: true, messageId: msgId, deliveryState: cancelled.deliveryState });
  }

  async function handleClaim(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'claim-message', messageId: msgId });
    if (!auth) return;

    let body: string;
    try {
      body = await readBody(req, 256);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: { secret: string };
    try {
      data = JSON.parse(body) as typeof data;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    if (!data.secret || typeof data.secret !== 'string') {
      return json(res, 400, { error: 'secret-required', message: 'POST body must contain { secret: "0x..." }' });
    }

    const stored = await store.getMessage(msgId, auth.payload.address);
    if (!stored) return json(res, 404, { error: 'not-found' });
    if (stored.claimed) return json(res, 409, { error: 'already-claimed' });
    if ((stored.deliveryState !== 'ready' && stored.deliveryState !== 'previewed') || stored.pendingPayment == null) {
      return json(res, 409, {
        error: 'message-not-ready',
        message: 'message is still waiting for recipient liquidity or tap setup',
      });
    }

    if (!verifySecretHash(data.secret, stored.hashedSecret)) {
      return json(res, 400, { error: 'invalid-secret', message: 'hash(secret) does not match payment hashedSecret' });
    }

    let message;
    try {
      message = await store.claimMessage(msgId, auth.payload.address);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg === 'message-not-found') return json(res, 404, { error: 'not-found' });
      if (msg === 'already-claimed') return json(res, 409, { error: 'already-claimed' });
      throw err;
    }

    await store.recordSettlement({
      messageId: stored.id,
      paymentId: stored.paymentId,
      recipientAddr: auth.payload.address,
      hashedSecret: stored.hashedSecret,
      secret: data.secret,
      pendingPayment: stored.pendingPayment,
      settledAt: Date.now(),
    });
    await paymentService.recordCompletedIncomingPayment?.({
      paymentProof: stored.paymentId,
      secret: data.secret,
    });

    return json(res, 200, {
      message,
      pendingPayment: stored.pendingPayment,
    });
  }

  async function handleTapBorrowParams(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!sfContractId) {
      return json(res, 503, { error: 'stackflow-contract-missing' });
    }

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const borrower = typeof data['borrower'] === 'string' ? data['borrower'] : '';
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const tapAmount = String(data['tapAmount'] ?? '');
    const tapNonce = String(data['tapNonce'] ?? '');
    const borrowAmount = String(data['borrowAmount'] ?? '');
    const borrowFeeRaw = data['borrowFee'];
    const borrowFee = typeof borrowFeeRaw === 'string' ? borrowFeeRaw.trim() : '';
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const borrowNonce = String(data['borrowNonce'] ?? '');
    const mySignature = typeof data['mySignature'] === 'string' ? data['mySignature'] : '';

    if (token === '__invalid__' || !borrower || !tapAmount || !tapNonce || !borrowAmount || !myBalance || !reservoirBalance || !borrowNonce || !mySignature) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required borrow params' });
    }

    try {
      const signed = await paymentService.createTapWithBorrowedLiquidityParams({
        borrower,
        token: token || null,
        tapAmount,
        tapNonce,
        borrowAmount,
        borrowFee: borrowFee || undefined,
        myBalance,
        reservoirBalance,
        borrowNonce,
        mySignature,
      });
      return json(res, 200, {
        ok: true,
        stackflowContractId: sfContractId,
        token: token || null,
        tapAmount,
        tapNonce,
        borrowAmount,
        borrowFee: signed.borrowFee,
        myBalance,
        reservoirBalance,
        borrowNonce,
        reservoirSignature: signed.reservoirSignature,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapAddFundsParams(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (typeof paymentService.createAddFundsParams !== 'function') {
      return json(res, 503, { error: 'tap-liquidity-management-unavailable' });
    }

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const user = typeof data['user'] === 'string' ? data['user'] : '';
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const amount = String(data['amount'] ?? '');
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const nonce = String(data['nonce'] ?? '');
    const mySignature = typeof data['mySignature'] === 'string' ? data['mySignature'] : '';
    if (token === '__invalid__' || !user || !amount || !myBalance || !reservoirBalance || !nonce || !mySignature) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required add-funds params' });
    }

    try {
      const signed = await paymentService.createAddFundsParams({
        user,
        token: token || null,
        amount,
        myBalance,
        reservoirBalance,
        nonce,
        mySignature,
      });
      return json(res, 200, {
        ok: true,
        amount,
        nonce,
        myBalance,
        reservoirBalance,
        reservoirSignature: signed.reservoirSignature,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapBorrowMoreParams(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (typeof paymentService.createBorrowLiquidityParams !== 'function') {
      return json(res, 503, { error: 'tap-liquidity-management-unavailable' });
    }

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const borrower = typeof data['borrower'] === 'string' ? data['borrower'] : '';
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const borrowAmount = String(data['borrowAmount'] ?? '');
    const borrowFeeRaw = data['borrowFee'];
    const borrowFee = typeof borrowFeeRaw === 'string' ? borrowFeeRaw.trim() : '';
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const borrowNonce = String(data['borrowNonce'] ?? '');
    const mySignature = typeof data['mySignature'] === 'string' ? data['mySignature'] : '';
    if (token === '__invalid__' || !borrower || !borrowAmount || !myBalance || !reservoirBalance || !borrowNonce || !mySignature) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required borrow-liquidity params' });
    }

    try {
      const signed = await paymentService.createBorrowLiquidityParams({
        borrower,
        token: token || null,
        borrowAmount,
        borrowFee: borrowFee || undefined,
        myBalance,
        reservoirBalance,
        borrowNonce,
        mySignature,
      });
      return json(res, 200, {
        ok: true,
        borrowAmount,
        borrowFee: signed.borrowFee,
        myBalance,
        reservoirBalance,
        borrowNonce,
        reservoirSignature: signed.reservoirSignature,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapSyncState(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (typeof paymentService.syncTapState !== 'function') {
      return json(res, 503, { error: 'tap-liquidity-management-unavailable' });
    }
    const auth = await requireAuth(req, res, { action: 'get-inbox' });
    if (!auth) return;

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const user = typeof data['user'] === 'string' ? data['user'] : '';
    if (!user || user !== auth.payload.address) {
      return json(res, 403, { error: 'auth-address-mismatch', message: 'sync state address must match the authenticated wallet' });
    }
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const nonce = String(data['nonce'] ?? '');
    const action = data['action'] == null ? null : String(data['action']);
    const actor = data['actor'] == null ? null : String(data['actor']);
    const mySignature = data['mySignature'] == null ? null : String(data['mySignature']);
    const reservoirSignature = data['reservoirSignature'] == null ? null : String(data['reservoirSignature']);
    if (token === '__invalid__' || !myBalance || !reservoirBalance || !nonce) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required tap sync params' });
    }

    try {
      await paymentService.syncTapState({
        counterparty: user,
        token: token || null,
        userBalance: myBalance,
        reservoirBalance,
        nonce,
        action,
        actor,
        counterpartySignature: mySignature,
        serverSignature: reservoirSignature,
      });
      return json(res, 200, { ok: true });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapWithdrawParams(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (typeof paymentService.createWithdrawFundsParams !== 'function') {
      return json(res, 503, { error: 'tap-liquidity-management-unavailable' });
    }

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const user = typeof data['user'] === 'string' ? data['user'] : '';
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const amount = String(data['amount'] ?? '');
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const nonce = String(data['nonce'] ?? '');
    const mySignature = typeof data['mySignature'] === 'string' ? data['mySignature'] : '';
    if (token === '__invalid__' || !user || !amount || !myBalance || !reservoirBalance || !nonce || !mySignature) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required withdraw params' });
    }

    try {
      const signed = await paymentService.createWithdrawFundsParams({
        user,
        token: token || null,
        amount,
        myBalance,
        reservoirBalance,
        nonce,
        mySignature,
      });
      return json(res, 200, {
        ok: true,
        amount,
        myBalance,
        reservoirBalance,
        nonce,
        reservoirSignature: signed.reservoirSignature,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapRebalance(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (
      typeof paymentService.createWithdrawFundsParams !== 'function' ||
      typeof paymentService.submitReturnLiquidityToReservoir !== 'function'
    ) {
      return json(res, 503, { error: 'tap-liquidity-management-unavailable' });
    }
    const auth = await requireAuth(req, res, { action: 'get-inbox' });
    if (!auth) return;

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const user = typeof data['user'] === 'string' ? data['user'] : '';
    if (!user || user !== auth.payload.address) {
      return json(res, 403, { error: 'auth-address-mismatch', message: 'rebalance address must match the authenticated wallet' });
    }
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const amount = String(data['amount'] ?? '');
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const nonce = String(data['nonce'] ?? '');
    const mySignature = typeof data['mySignature'] === 'string' ? data['mySignature'] : '';
    if (token === '__invalid__' || !amount || !myBalance || !reservoirBalance || !nonce || !mySignature) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required rebalance params' });
    }

    try {
      const signed = await paymentService.createWithdrawFundsParams({
        user,
        token: token || null,
        amount,
        myBalance,
        reservoirBalance,
        nonce,
        mySignature,
      });
      const submitted = await paymentService.submitReturnLiquidityToReservoir(user);
      return json(res, 200, {
        ok: true,
        amount,
        myBalance,
        reservoirBalance,
        nonce,
        reservoirSignature: signed.reservoirSignature,
        txid: submitted.txid,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapCloseParams(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (typeof paymentService.createCloseTapParams !== 'function') {
      return json(res, 503, { error: 'tap-liquidity-management-unavailable' });
    }

    let body: string;
    try {
      body = await readBody(req, 4096);
    } catch {
      return json(res, 413, { error: 'body-too-large' });
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(body) as Record<string, unknown>;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    const user = typeof data['user'] === 'string' ? data['user'] : '';
    const tokenRaw = data['token'];
    const token = typeof tokenRaw === 'string' ? tokenRaw.trim() : (tokenRaw == null ? null : '__invalid__');
    const myBalance = String(data['myBalance'] ?? '');
    const reservoirBalance = String(data['reservoirBalance'] ?? '');
    const nonce = String(data['nonce'] ?? '');
    const mySignature = typeof data['mySignature'] === 'string' ? data['mySignature'] : '';
    if (token === '__invalid__' || !user || !myBalance || !reservoirBalance || !nonce || !mySignature) {
      return json(res, 400, { error: 'invalid-params', message: 'missing required close params' });
    }

    try {
      const signed = await paymentService.createCloseTapParams({
        user,
        token: token || null,
        myBalance,
        reservoirBalance,
        nonce,
        mySignature,
      });
      return json(res, 200, {
        ok: true,
        myBalance,
        reservoirBalance,
        nonce,
        reservoirSignature: signed.reservoirSignature,
      });
    } catch (err) {
      if (respondTypedServiceError(res, err)) return;
      throw err;
    }
  }

  async function handleTapState(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'get-inbox' });
    if (!auth) return;

    const tap = typeof paymentService.getTrackedTapState === 'function'
      ? await paymentService.getTrackedTapState(auth.payload.address)
      : null;
    const lifecycle = typeof paymentService.getTapLifecycleState === 'function'
      ? await paymentService.getTapLifecycleState(auth.payload.address)
      : {
          status: tap ? 'active' : 'never-opened',
          nextTapNonce: tap?.nonce ?? '0',
          nextBorrowNonce: tap ? (BigInt(tap.nonce) + 1n).toString() : '1',
        };
    const rebalance = typeof paymentService.getTapRebalanceRequest === 'function'
      ? await paymentService.getTapRebalanceRequest(auth.payload.address)
      : null;

    return json(res, 200, {
      ok: true,
      lifecycle,
      rebalance,
      tap: tap == null
        ? null
        : {
            contractId: tap.contractId,
            token: tap.pipeKey.token,
            pipeKey: tap.pipeKey,
            serverBalance: tap.serverBalance,
            myBalance: tap.counterpartyBalance,
            sendCapacity: tap.counterpartyBalance,
            receiveLiquidity: tap.serverBalance,
            settledServerBalance: tap.settledServerBalance,
            settledMyBalance: tap.settledCounterpartyBalance,
            pendingServerBalance: tap.pendingServerBalance,
            pendingMyBalance: tap.pendingCounterpartyBalance,
            nonce: tap.nonce,
          },
    });
  }

  async function handlePaymentInfo(res: ServerResponse, recipientAddr: string): Promise<void> {
    const recipientPublicKey = await store.getPublicKey(recipientAddr);
    if (!recipientPublicKey) {
      return json(res, 404, {
        error: 'recipient-not-found',
        message: 'recipient has not registered a Mailslot inbox public key yet',
      });
    }
    return json(res, 200, buildPaymentInfo(recipientAddr, recipientPublicKey));
  }

  // ─── Request router ─────────────────────────────────────────────────────────

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const method = req.method?.toUpperCase() ?? 'GET';
    const path = url.pathname;

    if (!applyCors(req, res, url)) return;
    if (method === 'OPTIONS') {
      res.writeHead(204); res.end(); return;
    }

    const limit = rateLimitCategory(path);
    if (limit) {
      const verdict = consumeRateLimit(rateLimitKey(limit.category, req), limit.max);
      if (!verdict.allowed) {
        res.setHeader('Retry-After', String(verdict.retryAfterSeconds));
        return json(res, 429, { error: 'rate-limit-exceeded', category: limit.category });
      }
    }

    if (method === 'GET' && path === '/health') {
      return json(res, 200, { ok: true });
    }

    // Status endpoint
    if (method === 'GET' && path === '/status') {
      const settings = currentSettings();
      return json(res, 200, {
        ok: true,
        serverAddress: pipeCounterparty,
        signerAddress: config.serverStxAddress,
        reservoirContract: config.reservoirContractId,
        sfContract: config.sfContractId,
        messagePriceSats: settings.messagePriceSats,
        minFeeSats: settings.minFeeSats,
        runtimeSettings: settings,
        network: config.chainId === 1 ? 'mainnet' : 'testnet',
        chainId: config.chainId,
        authDomain: AUTH_DOMAIN,
        authAudience: getAuthAudience(config),
        enableBrowserDecryptKey: config.enableBrowserDecryptKey,
        supportedToken: config.supportedToken || null,
        sfVersion: '0.6.0',
      });
    }

    if (method === 'POST' && path === '/hooks/dispute') {
      return handleDisputeWebhook(req, res);
    }

    if (method === 'GET' && path === '/tap/state') {
      return handleTapState(req, res);
    }

    if (method === 'GET' && path === '/admin/settings') {
      return handleGetAdminSettings(req, res);
    }

    if (method === 'POST' && path === '/admin/settings') {
      return handleUpdateAdminSettings(req, res);
    }

    if (method === 'GET' && path === '/admin/stats') {
      return handleGetAdminStats(req, res);
    }

    const paymentInfoMatch = path.match(/^\/payment-info\/([^/]+)$/);
    if (method === 'GET' && paymentInfoMatch) {
      return handlePaymentInfo(res, decodeURIComponent(paymentInfoMatch[1]));
    }

    // Serve web UI (index.html + Vite-built assets + public files like llms.txt)
    if (method === 'GET' && (path === '/' || path === '/ui' || path.startsWith('/assets/') || path === '/llms.txt')) {
      try {
        const filePath = path === '/' || path === '/ui'
          ? join(WEB_DIR, 'index.html')
          : join(WEB_DIR, path.slice(1)); // strip leading /
        const resolvedPath = resolve(filePath);
        if (!resolvedPath.startsWith(WEB_DIR_RESOLVED + '/') && resolvedPath !== WEB_DIR_RESOLVED) {
          return json(res, 403, { error: 'forbidden' });
        }
        const data = await readFile(resolvedPath);
        const ct = filePath.endsWith('.html') ? 'text/html; charset=utf-8'
                 : filePath.endsWith('.js') || filePath.endsWith('.mjs') ? 'application/javascript'
                 : filePath.endsWith('.css') ? 'text/css'
                 : filePath.endsWith('.svg') ? 'image/svg+xml'
                 : filePath.endsWith('.txt') ? 'text/plain; charset=utf-8'
                 : 'application/octet-stream';
        res.writeHead(200, { 'content-type': ct, 'content-length': data.length });
        res.end(data);
      } catch {
        res.writeHead(503, { 'content-type': 'text/plain' });
        res.end('Web UI not available');
      }
      return;
    }

    const sendMatch = path.match(/^\/messages\/([^/]+)$/);
    if (method === 'POST' && sendMatch) {
      return handleSend(req, res, decodeURIComponent(sendMatch[1]));
    }

    const cancelMatch = path.match(/^\/messages\/([^/]+)\/cancel$/);
    if (method === 'POST' && cancelMatch) {
      return handleCancelMessage(req, res, decodeURIComponent(cancelMatch[1]));
    }

    if (method === 'GET' && path === '/inbox') {
      return handleGetInbox(req, res, url);
    }

    const previewMatch = path.match(/^\/inbox\/([^/]+)\/preview$/);
    if (method === 'GET' && previewMatch) {
      return handlePreview(req, res, decodeURIComponent(previewMatch[1]));
    }

    const getMessageMatch = path.match(/^\/inbox\/([^/]+)$/);
    if (method === 'GET' && getMessageMatch) {
      return handleGetMessage(req, res, decodeURIComponent(getMessageMatch[1]));
    }

    const claimMatch = path.match(/^\/inbox\/([^/]+)\/claim$/);
    if (method === 'POST' && claimMatch) {
      return handleClaim(req, res, decodeURIComponent(claimMatch[1]));
    }

    if (method === 'POST' && path === '/tap/borrow-params') {
      return handleTapBorrowParams(req, res);
    }

    if (method === 'POST' && path === '/tap/add-funds-params') {
      return handleTapAddFundsParams(req, res);
    }

    if (method === 'POST' && path === '/tap/borrow-more-params') {
      return handleTapBorrowMoreParams(req, res);
    }

    if (method === 'POST' && path === '/tap/withdraw-params') {
      return handleTapWithdrawParams(req, res);
    }

    if (method === 'POST' && path === '/tap/rebalance') {
      return handleTapRebalance(req, res);
    }

    if (method === 'POST' && path === '/tap/close-params') {
      return handleTapCloseParams(req, res);
    }

    if (method === 'POST' && path === '/tap/sync-state') {
      return handleTapSyncState(req, res);
    }

    return json(res, 404, { error: 'not-found' });
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────

  async function requireAuth(
    req: IncomingMessage,
    res: ServerResponse,
    expected: { action: 'get-inbox' | 'claim-message' | 'get-message' | 'cancel-message'; messageId?: string },
  ): Promise<Awaited<ReturnType<typeof verifyInboxAuth>> | null> {
    const sessionHeader = req.headers['x-mailslot-session'];
    if (sessionHeader) {
      try {
        const session = verifyInboxSessionToken(Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader, config);
        const refreshed = issueInboxSessionToken(session.address, config);
        res.setHeader('x-mailslot-session', refreshed.token);
        res.setHeader('x-mailslot-session-expires-at', String(refreshed.expiresAt));
        return {
          payload: {
            action: expected.action,
            address: session.address,
            timestamp: Date.now(),
            ...(expected.messageId != null ? { messageId: expected.messageId } : {}),
          },
          pubkeyHex: '',
        };
      } catch (err) {
        if (err instanceof AuthError) {
          json(res, err.statusCode, { error: err.reason, message: err.message });
          return null;
        }
        throw err;
      }
    }

    const authHeader = req.headers['x-mailslot-auth'];
    if (!authHeader) {
      json(res, 401, { error: 'auth-required', message: 'x-mailslot-auth or x-mailslot-session header required' });
      return null;
    }

    try {
      const auth = await verifyInboxAuth(
        Array.isArray(authHeader) ? authHeader[0] : authHeader,
        config,
        store,
      );
      await store.savePublicKey(auth.payload.address, auth.pubkeyHex);
      const session = issueInboxSessionToken(auth.payload.address, config);
      res.setHeader('x-mailslot-session', session.token);
      res.setHeader('x-mailslot-session-expires-at', String(session.expiresAt));
      if (auth.payload.action !== expected.action) {
        json(res, 403, { error: 'auth-action-mismatch', message: `expected action ${expected.action}` });
        return null;
      }
      if (expected.messageId != null && auth.payload.messageId !== expected.messageId) {
        json(res, 403, { error: 'auth-message-id-mismatch', message: 'messageId in auth payload does not match route' });
        return null;
      }
      return auth;
    } catch (err) {
      if (err instanceof AuthError) {
        json(res, err.statusCode, { error: err.reason, message: err.message });
        return null;
      }
      throw err;
    }
  }

  const server = createServer((req, res) => {
    handleRequest(req, res).catch(err => {
      console.error('unhandled error', err);
      json(res, 500, { error: 'internal-error' });
    });
  });
  return server;
}

function json(res: ServerResponse, status: number, body: unknown): void {
  if (res.writableEnded) return;
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(data),
  });
  res.end(data);
}

async function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) { reject(new Error('body-too-large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}
