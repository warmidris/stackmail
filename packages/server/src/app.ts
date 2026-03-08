/**
 * Stackmail HTTP server factory.
 *
 * Extracted from index.ts so it can be imported in tests without auto-starting.
 * Use createMailServer(config, store, paymentService) to get an http.Server.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';

import type { Config } from './types.js';
import type { MessageStore } from './store.js';
import { PaymentService, PaymentError } from './payment.js';
import { verifyInboxAuth, AuthError } from './auth.js';
import { hashSecret, verifySecretHash } from '@stackmail/crypto';

export function createMailServer(
  config: Config,
  store: MessageStore,
  paymentService: PaymentService,
  sfContractId = '',
): ReturnType<typeof createServer> {

  // ─── Handlers ──────────────────────────────────────────────────────────────

  async function handlePaymentInfo(res: ServerResponse, recipientAddr: string): Promise<void> {
    const recipientPublicKey = await store.getPublicKey(recipientAddr);

    if (!recipientPublicKey) {
      return json(res, 404, {
        error: 'recipient-not-found',
        message: 'Recipient has not registered with this mailbox server. They must check their inbox first.',
      });
    }

    return json(res, 200, {
      recipientPublicKey,
      amount: config.messagePriceSats,
      fee: config.minFeeSats,
      recipientAmount: (BigInt(config.messagePriceSats) - BigInt(config.minFeeSats)).toString(),
      stackflowNodeUrl: config.stackflowNodeUrl,
      serverAddress: config.serverStxAddress,
    });
  }

  async function handleSend(req: IncomingMessage, res: ServerResponse, to: string): Promise<void> {
    const paymentHeader = req.headers['x-x402-payment'] ?? req.headers['x-stackmail-payment'];
    if (!paymentHeader) {
      return json(res, 402, {
        error: 'payment-required',
        accepts: [{ mode: 'direct', scheme: 'stackflow' }],
        amount: config.messagePriceSats,
        stackflowNodeUrl: config.stackflowNodeUrl,
        serverAddress: config.serverStxAddress,
      });
    }

    const proofRaw = Array.isArray(paymentHeader) ? paymentHeader[0] : paymentHeader;

    let verified: Awaited<ReturnType<PaymentService['verifyIncomingPayment']>>;
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

    let data: { encryptedPayload: unknown; from: string };
    try {
      data = JSON.parse(body) as typeof data;
    } catch {
      return json(res, 400, { error: 'invalid-json' });
    }

    if (!data.from || typeof data.from !== 'string') {
      return json(res, 400, { error: 'from-required', message: 'sender STX address required in body.from' });
    }

    if (!data.encryptedPayload || typeof data.encryptedPayload !== 'object') {
      return json(res, 400, { error: 'encrypted-payload-required' });
    }

    const enc = data.encryptedPayload as { v?: unknown; epk?: unknown; iv?: unknown; data?: unknown };
    if (enc.v !== 1 || typeof enc.epk !== 'string' || typeof enc.iv !== 'string' || typeof enc.data !== 'string') {
      return json(res, 400, { error: 'invalid-encrypted-payload', message: 'encryptedPayload must be EncryptedMail v1' });
    }

    const encryptedPayload = enc as { v: 1; epk: string; iv: string; data: string };

    const encSize = Buffer.byteLength(enc.data as string, 'hex') / 2;
    if (encSize > config.maxEncryptedBytes) {
      return json(res, 413, { error: 'payload-too-large' });
    }

    const pendingPayment = sfContractId
      ? await paymentService.createOutgoingPayment({
          hashedSecret: verified.hashedSecret,
          incomingAmount: verified.incomingAmount,
          recipientAddr: to,
          contractId: sfContractId,
        })
      : null;

    const msgId = randomUUID();
    await store.saveMessage({
      id: msgId,
      from: data.from,
      to,
      sentAt: Date.now(),
      amount: verified.incomingAmount,
      fee: config.minFeeSats,
      paymentId: proofRaw,
      hashedSecret: verified.hashedSecret,
      encryptedPayload,
      pendingPayment,
      claimed: false,
      paymentSettled: false,
    });

    return json(res, 200, { ok: true, messageId: msgId });
  }

  async function handleGetInbox(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const auth = await requireAuth(req, res);
    if (!auth) return;

    const limit = parseInt(url.searchParams.get('limit') ?? '50', 10);
    const before = url.searchParams.get('before') ? parseInt(url.searchParams.get('before')!, 10) : undefined;
    const includeClaimed = url.searchParams.get('claimed') === 'true';

    const entries = await store.getInbox(auth.payload.address, { limit, before, includeClaimed });
    return json(res, 200, { messages: entries });
  }

  async function handlePreview(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res);
    if (!auth) return;

    const stored = await store.getMessage(msgId, auth.payload.address);
    if (!stored) return json(res, 404, { error: 'not-found' });
    if (stored.claimed) return json(res, 409, { error: 'already-claimed' });

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
    const auth = await requireAuth(req, res);
    if (!auth) return;

    const msg = await store.getClaimedMessage(msgId, auth.payload.address);
    if (!msg) return json(res, 404, { error: 'not-found' });
    return json(res, 200, { message: msg });
  }

  async function handleClaim(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res);
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

    paymentService.settlePayment({
      paymentId: stored.paymentId,
      secret: data.secret,
      hashedSecret: stored.hashedSecret,
    }).then(() => store.markPaymentSettled(stored.paymentId)).catch(err => {
      console.error('payment settlement error', stored.paymentId, err);
    });

    return json(res, 200, {
      message,
      pendingPayment: stored.pendingPayment,
    });
  }

  // ─── Request router ─────────────────────────────────────────────────────────

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const method = req.method?.toUpperCase() ?? 'GET';
    const path = url.pathname;

    if (method === 'GET' && path === '/health') {
      return json(res, 200, { ok: true });
    }

    const paymentInfoMatch = path.match(/^\/payment-info\/([^/]+)$/);
    if (method === 'GET' && paymentInfoMatch) {
      return handlePaymentInfo(res, decodeURIComponent(paymentInfoMatch[1]));
    }

    const sendMatch = path.match(/^\/messages\/([^/]+)$/);
    if (method === 'POST' && sendMatch) {
      return handleSend(req, res, decodeURIComponent(sendMatch[1]));
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

    return json(res, 404, { error: 'not-found' });
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────

  async function requireAuth(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<Awaited<ReturnType<typeof verifyInboxAuth>> | null> {
    const authHeader = req.headers['x-stackmail-auth'];
    if (!authHeader) {
      json(res, 401, { error: 'auth-required', message: 'x-stackmail-auth header required' });
      return null;
    }

    try {
      return await verifyInboxAuth(
        Array.isArray(authHeader) ? authHeader[0] : authHeader,
        config,
        store,
      );
    } catch (err) {
      if (err instanceof AuthError) {
        json(res, err.statusCode, { error: err.reason, message: err.message });
        return null;
      }
      throw err;
    }
  }

  return createServer((req, res) => {
    handleRequest(req, res).catch(err => {
      console.error('unhandled error', err);
      json(res, 500, { error: 'internal-error' });
    });
  });
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
