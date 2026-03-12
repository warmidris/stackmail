/**
 * Integration test: full HTTP send → preview → claim → decrypt flow.
 *
 * Spins up a real HTTP server on a random port. Uses a MockPaymentService
 * so tests don't require a real StackFlow network.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, generateKeyPairSync, createSign, createECDH } from 'node:crypto';
import { AddressInfo } from 'node:net';
import { createMailServer, type IPaymentService } from './app.js';
import { SqliteMessageStore } from './store.js';
import { pubkeyToStxAddress } from './auth.js';
import { encryptMail, decryptMail, hashSecret } from '@stackmail/crypto';
import type { Config } from './types.js';
import type { PendingPayment } from './types.js';
import type { VerifiedPayment } from './payment.js';
import type { Server } from 'node:http';

// ─── Mock payment service ──────────────────────────────────────────────────────

class MockPaymentService implements IPaymentService {
  trackedTapState: Awaited<ReturnType<NonNullable<IPaymentService['getTrackedTapState']>>> = null;

  async verifyIncomingPayment(proofRaw: string): Promise<VerifiedPayment> {
    let proof: Record<string, unknown>;
    try {
      try {
        proof = JSON.parse(Buffer.from(proofRaw, 'base64url').toString('utf-8')) as Record<string, unknown>;
      } catch {
        proof = JSON.parse(proofRaw) as Record<string, unknown>;
      }
    } catch {
      throw new Error('invalid-proof-encoding');
    }
    const hashedSecret = proof['hashedSecret'] as string;
    const senderAddress = (proof['forPrincipal'] ?? proof['actor'] ?? 'SP_SENDER') as string;
    const amount = (proof['amount'] ?? proof['incomingAmount'] ?? '1000') as string;
    if (!hashedSecret) throw Object.assign(new Error('missing hashedSecret'), { statusCode: 400, reason: 'missing-hashed-secret' });
    return { hashedSecret, incomingAmount: amount, senderAddress };
  }

  async createOutgoingPayment(): Promise<PendingPayment | null> {
    return null;
  }

  async createTapWithBorrowedLiquidityParams(_: {
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
  }): Promise<{ borrowFee: string; reservoirSignature: string }> {
    return { borrowFee: '0', reservoirSignature: '0x' + '00'.repeat(65) };
  }

  async getTrackedTapState(): Promise<{
    contractId: string;
    pipeKey: {
      'principal-1': string;
      'principal-2': string;
      token: string | null;
    };
    serverBalance: string;
    counterpartyBalance: string;
    nonce: string;
  } | null> {
    return this.trackedTapState;
  }
}

// ─── Test keypair helpers ─────────────────────────────────────────────────────

function generateSecp256k1Keypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const uncompressed = spkiDer.subarray(spkiDer.length - 65);
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);
  const prefix = y[31] % 2 === 0 ? 0x02 : 0x03;
  const compressedPubkeyHex = Buffer.concat([Buffer.from([prefix]), x]).toString('hex');
  return { privateKey, compressedPubkeyHex };
}

function signMessage(message: string, privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']): string {
  const signer = createSign('SHA256');
  signer.update(message);
  return signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('hex');
}

function buildAuthHeader(opts: {
  pubkey: string;
  action: string;
  address: string;
  messageId?: string;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
}): string {
  const payload = {
    action: opts.action,
    address: opts.address,
    timestamp: Date.now(),
    ...(opts.messageId ? { messageId: opts.messageId } : {}),
  };
  const signature = signMessage(JSON.stringify(payload), opts.privateKey);
  return Buffer.from(JSON.stringify({ pubkey: opts.pubkey, payload, signature })).toString('base64');
}

// ─── Test setup ───────────────────────────────────────────────────────────────

const senderEcdh = createECDH('secp256k1');
senderEcdh.generateKeys();
const senderPubkeyHex = senderEcdh.getPublicKey('hex', 'compressed');

const recipientSignKeypair = generateSecp256k1Keypair();
const recipientEcdhForEncrypt = createECDH('secp256k1');
recipientEcdhForEncrypt.generateKeys();
const recipientEncryptPrivkeyHex = recipientEcdhForEncrypt.getPrivateKey('hex');
const recipientEncryptPubkeyHex = recipientEcdhForEncrypt.getPublicKey('hex', 'compressed');

const recipientAddress = pubkeyToStxAddress(recipientSignKeypair.compressedPubkeyHex);

const serverConfig: Config = {
  host: '127.0.0.1',
  port: 0,
  dbBackend: 'sqlite',
  dbFile: ':memory:',
  maxEncryptedBytes: 65536,
  authTimestampTtlMs: 300_000,
  stackflowNodeUrl: '',
  serverStxAddress: 'SP_SERVER',
  serverPrivateKey: '',
  sfContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow',
  reservoirContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
  chainId: 1,
  messagePriceSats: '1000',
  minFeeSats: '100',
  maxPendingPerSender: 5,
};

let server: Server;
let baseUrl: string;
let store: SqliteMessageStore;
let paymentService: MockPaymentService;

beforeAll(async () => {
  store = new SqliteMessageStore(':memory:');
  await store.init();

  paymentService = new MockPaymentService();
  server = createMailServer(serverConfig, store, paymentService);

  await new Promise<void>(resolve => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close(err => err ? reject(err) : resolve());
  });
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('GET /health', () => {
  it('returns ok', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean };
    expect(body.ok).toBe(true);
  });
});

describe('GET /tap/state', () => {
  it('returns tracked channel state for the authenticated mailbox owner', async () => {
    paymentService.trackedTapState = {
      contractId: serverConfig.sfContractId,
      pipeKey: {
        'principal-1': recipientAddress,
        'principal-2': serverConfig.reservoirContractId,
        token: null,
      },
      serverBalance: '1200',
      counterpartyBalance: '8800',
      nonce: '3',
    };

    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/tap/state`, {
      headers: { 'x-stackmail-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      ok: boolean;
      tap: { contractId: string; serverBalance: string; myBalance: string; nonce: string; token: string | null };
    };
    expect(body.ok).toBe(true);
    expect(body.tap.contractId).toBe(serverConfig.sfContractId);
    expect(body.tap.serverBalance).toBe('1200');
    expect(body.tap.myBalance).toBe('8800');
    expect(body.tap.nonce).toBe('3');
    expect(body.tap.token).toBeNull();
  });
});

describe('full send → inbox → preview → claim flow', () => {
  let messageId: string;

  it('step 1: GET /inbox authenticates successfully', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-stackmail-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { messages: unknown[] };
    expect(Array.isArray(body.messages)).toBe(true);
  });

  it('step 2: POST /messages/:addr sends a message', async () => {
    // Sender already has recipient's pubkey (looked up from blockchain, not server)
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: 'Integration test', body: 'Hello from integration test' },
      recipientEncryptPubkeyHex,
    );

    const proof = JSON.stringify({
      hashedSecret: hashedSecretHex,
      forPrincipal: pubkeyToStxAddress(senderPubkeyHex),
      amount: '1000',
    });

    const res = await fetch(`${baseUrl}/messages/${recipientAddress}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-x402-payment': proof,
      },
      body: JSON.stringify({
        from: pubkeyToStxAddress(senderPubkeyHex),
        encryptedPayload,
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; messageId: string };
    expect(body.ok).toBe(true);
    expect(typeof body.messageId).toBe('string');
    messageId = body.messageId;
  });

  it('step 3: GET /inbox shows the new message as unclaimed', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-stackmail-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { messages: Array<{ id: string; claimed: boolean }> };
    expect(body.messages.length).toBeGreaterThan(0);
    const entry = body.messages.find(m => m.id === messageId);
    expect(entry).toBeDefined();
    expect(entry?.claimed).toBe(false);
  });

  it('step 4: GET /inbox/:id/preview returns encrypted payload', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-message',
      address: recipientAddress,
      messageId,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/inbox/${messageId}/preview`, {
      headers: { 'x-stackmail-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.messageId).toBe(messageId);
    expect(body.encryptedPayload).toBeDefined();
    const enc = body.encryptedPayload as { v: number; epk: string; iv: string; data: string };
    expect(enc.v).toBe(1);
    expect(typeof enc.epk).toBe('string');
  });

  it('step 5: POST /inbox/:id/claim with wrong secret returns 400', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'claim-message',
      address: recipientAddress,
      messageId,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/inbox/${messageId}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-stackmail-auth': authHeader,
      },
      body: JSON.stringify({ secret: randomBytes(32).toString('hex') }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('invalid-secret');
  });

  it('step 6: full preview → decrypt → claim round-trip succeeds', async () => {
    const previewAuth = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-message',
      address: recipientAddress,
      messageId,
      privateKey: recipientSignKeypair.privateKey,
    });
    const previewRes = await fetch(`${baseUrl}/inbox/${messageId}/preview`, {
      headers: { 'x-stackmail-auth': previewAuth },
    });
    expect(previewRes.status).toBe(200);
    const preview = await previewRes.json() as { encryptedPayload: { v: 1; epk: string; iv: string; data: string } };

    const decrypted = decryptMail(preview.encryptedPayload, recipientEncryptPrivkeyHex);
    expect(decrypted.subject).toBe('Integration test');
    expect(decrypted.body).toBe('Hello from integration test');
    const secretHex = decrypted.secret;

    const claimAuth = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'claim-message',
      address: recipientAddress,
      messageId,
      privateKey: recipientSignKeypair.privateKey,
    });
    const claimRes = await fetch(`${baseUrl}/inbox/${messageId}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-stackmail-auth': claimAuth,
      },
      body: JSON.stringify({ secret: secretHex }),
    });
    expect(claimRes.status).toBe(200);
    const claimed = await claimRes.json() as { message: { id: string } };
    expect(claimed.message.id).toBe(messageId);
  });

  it('step 7: claiming same message again returns 409', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'claim-message',
      address: recipientAddress,
      messageId,
      privateKey: recipientSignKeypair.privateKey,
    });
    const claimRes = await fetch(`${baseUrl}/inbox/${messageId}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-stackmail-auth': authHeader,
      },
      body: JSON.stringify({ secret: randomBytes(32).toString('hex') }),
    });
    expect(claimRes.status).toBe(409);
    const body = await claimRes.json() as { error: string };
    expect(body.error).toBe('already-claimed');
  });
});

describe('auth error cases', () => {
  it('GET /inbox without auth returns 401', async () => {
    const res = await fetch(`${baseUrl}/inbox`);
    expect(res.status).toBe(401);
  });

  it('GET /inbox with invalid auth header returns 401', async () => {
    const res = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-stackmail-auth': 'not-valid-base64-json' },
    });
    expect(res.status).toBe(401);
  });

  it('GET /inbox with wrong auth action returns 403', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'claim-message',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });
    const res = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-stackmail-auth': authHeader },
    });
    expect(res.status).toBe(403);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('auth-action-mismatch');
  });
});

describe('tap borrow params endpoint', () => {
  it('returns 400 for missing params', async () => {
    const res = await fetch(`${baseUrl}/tap/borrow-params`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ borrower: recipientAddress }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('invalid-params');
  });

  it('returns signed params for valid input', async () => {
    const res = await fetch(`${baseUrl}/tap/borrow-params`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        borrower: recipientAddress,
        tapAmount: '1000',
        tapNonce: '0',
        borrowAmount: '1000',
        borrowFee: '100',
        myBalance: '1000',
        reservoirBalance: '1000',
        borrowNonce: '1',
        mySignature: '0x' + '11'.repeat(65),
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { ok: boolean; reservoirSignature?: string };
    expect(body.ok).toBe(true);
    expect(typeof body.reservoirSignature).toBe('string');
  });
});

describe('sender identity binding', () => {
  it('rejects send when body.from does not match payment sender identity', async () => {
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: 'Integration test', body: 'Spoofed sender attempt' },
      recipientEncryptPubkeyHex,
    );

    const realSender = pubkeyToStxAddress(senderPubkeyHex);
    const spoofedSender = recipientAddress;
    const proof = JSON.stringify({
      hashedSecret: hashedSecretHex,
      forPrincipal: realSender,
      amount: '1000',
    });

    const res = await fetch(`${baseUrl}/messages/${recipientAddress}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-x402-payment': proof,
      },
      body: JSON.stringify({
        from: spoofedSender,
        encryptedPayload,
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('sender-mismatch');
  });
});

describe('claim finalization', () => {
  it('marks payment as settled when claim succeeds', async () => {
    const finalizeStore = new SqliteMessageStore(':memory:');
    await finalizeStore.init();
    const finalizeService = new MockPaymentService();
    const finalizeServer = createMailServer(serverConfig, finalizeStore, finalizeService);
    await new Promise<void>(r => finalizeServer.listen(0, '127.0.0.1', () => r()));
    const finalizeUrl = `http://127.0.0.1:${(finalizeServer.address() as AddressInfo).port}`;

    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: 'Finalize test', body: 'mark settled on claim' },
      recipientEncryptPubkeyHex,
    );
    const senderAddress = pubkeyToStxAddress(senderPubkeyHex);
    const proof = JSON.stringify({
      hashedSecret: hashedSecretHex,
      forPrincipal: senderAddress,
      amount: '1000',
    });

    const sendRes = await fetch(`${finalizeUrl}/messages/${recipientAddress}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-x402-payment': proof,
      },
      body: JSON.stringify({
        from: senderAddress,
        encryptedPayload,
      }),
    });
    expect(sendRes.status).toBe(200);
    const sendBody = await sendRes.json() as { messageId: string };
    const messageId = sendBody.messageId;

    const claimAuth = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'claim-message',
      address: recipientAddress,
      messageId,
      privateKey: recipientSignKeypair.privateKey,
    });
    const claimRes = await fetch(`${finalizeUrl}/inbox/${messageId}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-stackmail-auth': claimAuth,
      },
      body: JSON.stringify({ secret: secretHex }),
    });
    expect(claimRes.status).toBe(200);

    const stored = await finalizeStore.getMessage(messageId, recipientAddress);
    expect(stored?.paymentSettled).toBe(true);

    await new Promise<void>((r, j) => finalizeServer.close(e => e ? j(e) : r()));
  });
});

describe('per-sender HTLC cap', () => {
  it('rejects when sender exceeds maxPendingPerSender unclaimed messages', async () => {
    const capStore = new SqliteMessageStore(':memory:');
    await capStore.init();

    // Use a payment service that always approves with same hashedSecret + distinct secrets
    const capService = new MockPaymentService();
    const capConfig = { ...serverConfig, maxPendingPerSender: 2 };
    const capServer = createMailServer(capConfig, capStore, capService);
    await new Promise<void>(r => capServer.listen(0, '127.0.0.1', () => r()));
    const capUrl = `http://127.0.0.1:${(capServer.address() as AddressInfo).port}`;

    const capRecipient = pubkeyToStxAddress(recipientSignKeypair.compressedPubkeyHex);

    const sendMsg = async () => {
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const enc = encryptMail({ v: 1, secret: secretHex, body: 'hi' }, recipientEncryptPubkeyHex);
      const proof = JSON.stringify({ hashedSecret: hashedSecretHex, forPrincipal: 'SP_SENDER', amount: '1000' });
      return fetch(`${capUrl}/messages/${capRecipient}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-x402-payment': proof },
        body: JSON.stringify({ from: 'SP_SENDER', encryptedPayload: enc }),
      });
    };

    // First two messages should succeed
    expect((await sendMsg()).status).toBe(200);
    expect((await sendMsg()).status).toBe(200);
    // Third should be rejected
    const res = await sendMsg();
    expect(res.status).toBe(429);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('too-many-pending');

    await new Promise<void>((r, j) => capServer.close(e => e ? j(e) : r()));
  });
});
