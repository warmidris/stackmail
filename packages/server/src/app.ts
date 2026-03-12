/**
 * Stackmail HTTP server factory.
 *
 * Extracted from index.ts so it can be imported in tests without auto-starting.
 * Use createMailServer(config, store, paymentService) to get an http.Server.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join, dirname, resolve } from 'node:path';

import type { Config } from './types.js';
import type { MessageStore } from './store.js';
import { PaymentError } from './payment.js';
import type { VerifiedPayment } from './payment.js';
import type { PendingPayment } from './types.js';

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
  getTrackedTapState?(counterparty: string): Promise<{
    contractId: string;
    pipeKey: {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };
    serverBalance: string;
    counterpartyBalance: string;
    nonce: string;
  } | null>;
}
import { verifyInboxAuth, AuthError, AUTH_DOMAIN } from './auth.js';
import { verifySecretHash } from '@stackmail/crypto';

export function createMailServer(
  config: Config,
  store: MessageStore,
  paymentService: IPaymentService,
): ReturnType<typeof createServer> {
  const sfContractId = config.sfContractId;
  const pipeCounterparty = config.reservoirContractId || config.serverStxAddress;
  const __filename = fileURLToPath(import.meta.url);
  const WEB_DIR = join(dirname(__filename), '..', 'web');
  const WEB_DIR_RESOLVED = resolve(WEB_DIR);

  // ─── Handlers ──────────────────────────────────────────────────────────────

  async function handleSend(req: IncomingMessage, res: ServerResponse, to: string): Promise<void> {
    const paymentHeader = req.headers['x-x402-payment'] ?? req.headers['x-stackmail-payment'];
    if (!paymentHeader) {
      return json(res, 402, {
        error: 'payment-required',
        accepts: [{ mode: 'direct', scheme: 'stackflow' }],
        amount: config.messagePriceSats,
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

    let data: { encryptedPayload: unknown; from: string };
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

    // Per-sender HTLC cap: prevent spam by limiting unclaimed messages
    const pendingCount = await store.countPendingFromSender(verified.senderAddress, to);
    if (pendingCount >= config.maxPendingPerSender) {
      return json(res, 429, {
        error: 'too-many-pending',
        message: `Too many unclaimed messages from this sender (limit: ${config.maxPendingPerSender})`,
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

    const msgId = randomUUID();
    await store.saveMessage({
      id: msgId,
      from: verified.senderAddress,
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
    const auth = await requireAuth(req, res, { action: 'get-inbox' });
    if (!auth) return;

    const limit = parseInt(url.searchParams.get('limit') ?? '50', 10);
    const before = url.searchParams.get('before') ? parseInt(url.searchParams.get('before')!, 10) : undefined;
    const includeClaimed = url.searchParams.get('claimed') === 'true';

    const entries = await store.getInbox(auth.payload.address, { limit, before, includeClaimed });
    return json(res, 200, { messages: entries });
  }

  async function handlePreview(req: IncomingMessage, res: ServerResponse, msgId: string): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'get-message', messageId: msgId });
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
    const auth = await requireAuth(req, res, { action: 'get-message', messageId: msgId });
    if (!auth) return;

    const msg = await store.getClaimedMessage(msgId, auth.payload.address);
    if (!msg) return json(res, 404, { error: 'not-found' });
    return json(res, 200, { message: msg });
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

    await store.markPaymentSettled(stored.paymentId);

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
      if (err instanceof PaymentError) {
        return json(res, err.statusCode, { error: err.reason, message: err.message });
      }
      throw err;
    }
  }

  async function handleTapState(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const auth = await requireAuth(req, res, { action: 'get-inbox' });
    if (!auth) return;

    const tap = typeof paymentService.getTrackedTapState === 'function'
      ? await paymentService.getTrackedTapState(auth.payload.address)
      : null;

    return json(res, 200, {
      ok: true,
      tap: tap == null
        ? null
        : {
            contractId: tap.contractId,
            token: tap.pipeKey.token,
            pipeKey: tap.pipeKey,
            serverBalance: tap.serverBalance,
            myBalance: tap.counterpartyBalance,
            nonce: tap.nonce,
          },
    });
  }

  // ─── Request router ─────────────────────────────────────────────────────────

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    const method = req.method?.toUpperCase() ?? 'GET';
    const path = url.pathname;

    // CORS for web UI
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'content-type, x-stackmail-auth, x-stackmail-payment, x-x402-payment');
    if (method === 'OPTIONS') {
      res.writeHead(204); res.end(); return;
    }

    if (method === 'GET' && path === '/health') {
      return json(res, 200, { ok: true });
    }

    // Status endpoint
    if (method === 'GET' && path === '/status') {
      return json(res, 200, {
        ok: true,
        serverAddress: pipeCounterparty,
        signerAddress: config.serverStxAddress,
        reservoirContract: config.reservoirContractId,
        sfContract: config.sfContractId,
        messagePriceSats: config.messagePriceSats,
        minFeeSats: config.minFeeSats,
        network: config.chainId === 1 ? 'mainnet' : 'testnet',
        chainId: config.chainId,
        authDomain: AUTH_DOMAIN,
        sfVersion: '0.6.0',
      });
    }

    if (method === 'GET' && path === '/tap/state') {
      return handleTapState(req, res);
    }

    // Serve web UI (index.html + Vite-built assets)
    if (method === 'GET' && (path === '/' || path === '/ui' || path.startsWith('/assets/'))) {
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

    return json(res, 404, { error: 'not-found' });
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────

  async function requireAuth(
    req: IncomingMessage,
    res: ServerResponse,
    expected: { action: 'get-inbox' | 'claim-message' | 'get-message'; messageId?: string },
  ): Promise<Awaited<ReturnType<typeof verifyInboxAuth>> | null> {
    const authHeader = req.headers['x-stackmail-auth'];
    if (!authHeader) {
      json(res, 401, { error: 'auth-required', message: 'x-stackmail-auth header required' });
      return null;
    }

    try {
      const auth = await verifyInboxAuth(
        Array.isArray(authHeader) ? authHeader[0] : authHeader,
        config,
        store,
      );
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
