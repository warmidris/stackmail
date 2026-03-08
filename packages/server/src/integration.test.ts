/**
 * Integration test: full HTTP send → preview → claim → decrypt flow.
 *
 * Spins up a real HTTP server on a random port. Mocks fetch so that
 * StackFlow node calls return success without a real SF network.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { randomBytes, generateKeyPairSync, createSign, createECDH } from 'node:crypto';
import { AddressInfo } from 'node:net';
import { createMailServer } from './app.js';
import { SqliteMessageStore } from './store.js';
import { PaymentService } from './payment.js';
import { pubkeyToStxAddress } from './auth.js';
import { encryptMail, decryptMail, hashSecret } from '@stackmail/crypto';
import type { Config } from './types.js';
import type { Server } from 'node:http';

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

// Generate a sender keypair (using ECDH for raw privkey access needed for decryption)
const senderEcdh = createECDH('secp256k1');
senderEcdh.generateKeys();
const senderPrivkeyHex = senderEcdh.getPrivateKey('hex');
const senderPubkeyHex = senderEcdh.getPublicKey('hex', 'compressed');

// Generate a recipient keypair (needs signing capability for auth + decryption)
const recipientSignKeypair = generateSecp256k1Keypair();
const recipientEcdh = createECDH('secp256k1');
// We need the same key for both signing and decryption. Use the signing key's
// raw private key extracted from PKCS#8 DER for the ECDH decryption.
// Instead, use two separate key systems: ECDH for encryption, signing keypair for auth.
// In a real client, these would be the same key; here we use ECDH for encryption.
const recipientEcdhForEncrypt = createECDH('secp256k1');
recipientEcdhForEncrypt.generateKeys();
const recipientEncryptPrivkeyHex = recipientEcdhForEncrypt.getPrivateKey('hex');
const recipientEncryptPubkeyHex = recipientEcdhForEncrypt.getPublicKey('hex', 'compressed');

// The recipient's STX address is derived from the SIGNING key (used in auth)
const recipientAddress = pubkeyToStxAddress(recipientSignKeypair.compressedPubkeyHex);

const serverConfig: Config = {
  host: '127.0.0.1',
  port: 0, // random port
  dbBackend: 'sqlite',
  dbFile: ':memory:',
  maxEncryptedBytes: 65536,
  authTimestampTtlMs: 300_000,
  stackflowNodeUrl: 'http://localhost:8787',
  serverStxAddress: 'SP_SERVER',
  messagePriceSats: '1000',
  minFeeSats: '100',
};

let server: Server;
let baseUrl: string;
let store: SqliteMessageStore;

// Mock fetch so StackFlow node calls succeed without a real network.
// Save the real fetch first so test HTTP calls still go through.
const realFetch = globalThis.fetch;
vi.stubGlobal('fetch', async (url: RequestInfo | URL, opts?: RequestInit) => {
  const urlStr = String(url);
  // Route SF node API calls to mock responses
  if (urlStr.includes('/counterparty/transfer')) {
    return new Response(JSON.stringify({ ok: true, mySignature: 'mocked-sig' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  if (urlStr.includes('/forwarding/reveal')) {
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }
  // Everything else (including calls to our test server) uses the real fetch
  return realFetch(url as RequestInfo, opts);
});

beforeAll(async () => {
  store = new SqliteMessageStore(':memory:');
  await store.init();

  const paymentService = new PaymentService(serverConfig);
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

describe('GET /payment-info/:addr', () => {
  it('returns 404 when recipient has no pubkey registered', async () => {
    const res = await fetch(`${baseUrl}/payment-info/SP1UNKNOWN`);
    expect(res.status).toBe(404);
  });

  it('returns payment info after recipient registers (via auth)', async () => {
    // Register recipient's encryption pubkey by calling GET /inbox (auth stores pubkey)
    // We pre-seed the store directly for this test
    await store.savePublicKey(recipientAddress, recipientEncryptPubkeyHex);

    const res = await fetch(`${baseUrl}/payment-info/${recipientAddress}`);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, unknown>;
    expect(body.recipientPublicKey).toBe(recipientEncryptPubkeyHex);
    expect(body.amount).toBe('1000');
  });
});

describe('full send → inbox → preview → claim flow', () => {
  let messageId: string;

  it('step 1: GET /inbox authenticates and registers pubkey', async () => {
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
    expect(body.messages).toHaveLength(0);

    // Pubkey should now be stored
    const stored = await store.getPublicKey(recipientAddress);
    expect(stored).toBe(recipientSignKeypair.compressedPubkeyHex);
  });

  it('step 2: POST /messages/:addr sends a message', async () => {
    // Seed recipient's encryption pubkey so the server can return payment info
    await store.savePublicKey(recipientAddress, recipientEncryptPubkeyHex);

    // Generate secret + encrypt
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: 'Integration test', body: 'Hello from integration test' },
      recipientEncryptPubkeyHex,
    );

    // Build a mock payment proof
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
      action: 'get-inbox',
      address: recipientAddress,
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
    // Get encrypted payload via preview
    const previewAuth = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });
    const previewRes = await fetch(`${baseUrl}/inbox/${messageId}/preview`, {
      headers: { 'x-stackmail-auth': previewAuth },
    });
    expect(previewRes.status).toBe(200);
    const preview = await previewRes.json() as { encryptedPayload: { v: 1; epk: string; iv: string; data: string } };

    // Decrypt to get the secret
    const decrypted = decryptMail(preview.encryptedPayload, recipientEncryptPrivkeyHex);
    expect(decrypted.subject).toBe('Integration test');
    expect(decrypted.body).toBe('Hello from integration test');
    const secretHex = decrypted.secret;

    // Claim with the real secret
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
    // Try to get secret again via preview (should say already-claimed)
    const previewRes = await fetch(`${baseUrl}/inbox/${messageId}/preview`, {
      headers: { 'x-stackmail-auth': authHeader },
    });
    expect(previewRes.status).toBe(409);
    const body = await previewRes.json() as { error: string };
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
});
