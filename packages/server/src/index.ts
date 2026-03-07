/**
 * Stackmail server — HTTP entry point
 *
 * API:
 *   GET  /health
 *   GET  /payment-info/:addr   → PaymentInfo (price, recipient pubkey, server addr)
 *   POST /messages/:addr       → send a message (x402 payment in header, encrypted payload in body)
 *   GET  /inbox                → list inbox (auth required)
 *   GET  /inbox/:id            → get claimed message (auth required)
 *   POST /inbox/:id/claim      → claim message by revealing R (auth required)
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { loadConfig } from './types.js';
import { SqliteMessageStore } from './store.js';
import { PaymentService, PaymentError } from './payment.js';
import { verifyInboxAuth, AuthError } from './auth.js';
import { hashSecret, verifySecretHash } from '@stackmail/crypto';

const config = loadConfig();
const store = new SqliteMessageStore(config.dbFile);
const paymentService = new PaymentService(config);

// Default StackFlow contract for outgoing payments — configurable
const SF_CONTRACT_ID = process.env.STACKMAIL_SF_CONTRACT_ID ?? '';

async function main(): Promise<void> {
  await mkdir(dirname(config.dbFile), { recursive: true });
  await store.init();
  console.log('stackmail: database ready');

  const server = createServer((req, res) => {
    handleRequest(req, res).catch(err => {
      console.error('unhandled error', err);
      json(res, 500, { error: 'internal-error' });
    });
  });

  server.listen(config.port, config.host, () => {
    console.log(`stackmail: listening on ${config.host}:${config.port}`);
  });
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  const method = req.method?.toUpperCase() ?? 'GET';
  const path = url.pathname;

  // GET /health
  if (method === 'GET' && path === '/health') {
    return json(res, 200, { ok: true });
  }

  // GET /payment-info/:addr
  const paymentInfoMatch = path.match(/^\/payment-info\/([^/]+)$/);
  if (method === 'GET' && paymentInfoMatch) {
    return handlePaymentInfo(res, decodeURIComponent(paymentInfoMatch[1]));
  }

  // POST /messages/:addr
  const sendMatch = path.match(/^\/messages\/([^/]+)$/);
  if (method === 'POST' && sendMatch) {
    return handleSend(req, res, decodeURIComponent(sendMatch[1]));
  }

  // GET /inbox
  if (method === 'GET' && path === '/inbox') {
    return handleGetInbox(req, res, url);
  }

  // GET /inbox/:id/preview  — returns encryptedPayload without claiming
  const previewMatch = path.match(/^\/inbox\/([^/]+)\/preview$/);
  if (method === 'GET' && previewMatch) {
    return handlePreview(req, res, decodeURIComponent(previewMatch[1]));
  }

  // GET /inbox/:id
  const getMessageMatch = path.match(/^\/inbox\/([^/]+)$/);
  if (method === 'GET' && getMessageMatch) {
    return handleGetMessage(req, res, decodeURIComponent(getMessageMatch[1]));
  }

  // POST /inbox/:id/claim
  const claimMatch = path.match(/^\/inbox\/([^/]+)\/claim$/);
  if (method === 'POST' && claimMatch) {
    return handleClaim(req, res, decodeURIComponent(claimMatch[1]));
  }

  return json(res, 404, { error: 'not-found' });
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async function handlePaymentInfo(res: ServerResponse, recipientAddr: string): Promise<void> {
  const recipientPublicKey = await store.getPublicKey(recipientAddr);

  if (!recipientPublicKey) {
    // Recipient hasn't authenticated with this server yet — their pubkey is unknown.
    // They must check their inbox at least once before anyone can send to them.
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
  // Require x402 payment header
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

  // Verify payment with StackFlow node
  let verified: Awaited<ReturnType<PaymentService['verifyIncomingPayment']>>;
  try {
    verified = await paymentService.verifyIncomingPayment(proofRaw);
  } catch (err) {
    if (err instanceof PaymentError) {
      return json(res, err.statusCode, { error: err.reason, message: err.message });
    }
    throw err;
  }

  // Parse request body: { encryptedPayload: EncryptedMail }
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

  // Check payload size
  const encSize = Buffer.byteLength(enc.data as string, 'hex') / 2;
  if (encSize > config.maxEncryptedBytes) {
    return json(res, 413, { error: 'payload-too-large' });
  }

  // Create outgoing payment (server → recipient, same hashlock)
  const pendingPayment = SF_CONTRACT_ID
    ? await paymentService.createOutgoingPayment({
        hashedSecret: verified.hashedSecret,
        incomingAmount: verified.incomingAmount,
        recipientAddr: to,
        contractId: SF_CONTRACT_ID,
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
    paymentId: proofRaw, // store raw proof as paymentId for now; replace with extracted nonce in production
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

  // Return encrypted payload + pending payment so client can decrypt R,
  // verify the payment commitment, then reveal R via /claim
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

  // Recipient provides R (the secret preimage)
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

  // Look up the message to get stored hashedSecret
  const stored = await store.getMessage(msgId, auth.payload.address);
  if (!stored) return json(res, 404, { error: 'not-found' });
  if (stored.claimed) return json(res, 409, { error: 'already-claimed' });

  // Verify hash(secret) == hashedSecret
  if (!verifySecretHash(data.secret, stored.hashedSecret)) {
    return json(res, 400, { error: 'invalid-secret', message: 'hash(secret) does not match payment hashedSecret' });
  }

  // Claim (marks as claimed, returns MailMessage with encryptedPayload)
  let message;
  try {
    message = await store.claimMessage(msgId, auth.payload.address);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === 'message-not-found') return json(res, 404, { error: 'not-found' });
    if (msg === 'already-claimed') return json(res, 409, { error: 'already-claimed' });
    throw err;
  }

  // Settle both payment channels (non-blocking — failure is logged, not fatal)
  paymentService.settlePayment({
    paymentId: stored.paymentId,
    secret: data.secret,
    hashedSecret: stored.hashedSecret,
  }).then(() => store.markPaymentSettled(stored.paymentId)).catch(err => {
    console.error('payment settlement error', stored.paymentId, err);
  });

  // Return the message including the encrypted payload.
  // Recipient decrypts locally with their private key.
  return json(res, 200, {
    message,
    pendingPayment: stored.pendingPayment,
  });
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

main().catch(err => {
  console.error('fatal:', err);
  process.exit(1);
});
