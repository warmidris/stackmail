/**
 * Integration test: full HTTP send → preview → claim → decrypt flow.
 *
 * Spins up a real HTTP server on a random port. Uses a MockPaymentService
 * so tests don't require a real StackFlow network.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID, generateKeyPairSync, createSign, createECDH } from 'node:crypto';
import { AddressInfo } from 'node:net';
import { request as httpRequest } from 'node:http';
import { createMailServer, type IPaymentService } from './app.js';
import { SqliteMessageStore } from './store.js';
import { pubkeyToStxAddress } from './auth.js';
import { encryptMail, decryptMail, hashSecret } from '@mailslot/crypto';
import type { Config, StoredMessage } from './types.js';
import type { PendingPayment } from './types.js';
import type { VerifiedPayment } from './payment.js';
import type { Server } from 'node:http';
import { RuntimeSettingsStore } from './settings.js';
import { runtimeSettingsFromConfig } from './types.js';

// ─── Mock payment service ──────────────────────────────────────────────────────

class MockPaymentService implements IPaymentService {
  trackedTapState: Awaited<ReturnType<NonNullable<IPaymentService['getTrackedTapState']>>> = null;
  outgoingPaymentEnabled = true;
  completedIncomingPayments: Array<{ paymentProof: string; secret: string }> = [];
  cancelledMessages: Array<{ paymentProof: string; senderAddr: string; recipientAddr: string; incomingAmount: string; fee: string }> = [];
  submittedDisputes: Array<string> = [];

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

  async createOutgoingPayment(args: {
    hashedSecret: string;
    incomingAmount: string;
    recipientAddr: string;
    contractId: string;
  }): Promise<PendingPayment | null> {
    if (!this.outgoingPaymentEnabled) return null;
    return {
      stateProof: {
        contractId: args.contractId,
        pipeKey: {
          'principal-1': args.recipientAddr,
          'principal-2': 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
          token: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
        },
        forPrincipal: args.recipientAddr,
        withPrincipal: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
        myBalance: '900',
        theirBalance: '100',
        nonce: '1',
        action: '1',
        actor: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
        hashedSecret: args.hashedSecret,
        theirSignature: '0x' + '11'.repeat(65),
      },
      amount: String(BigInt(args.incomingAmount) - 100n),
      hashedSecret: args.hashedSecret,
    };
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
    settledServerBalance?: string;
    settledCounterpartyBalance?: string;
    pendingServerBalance?: string;
    pendingCounterpartyBalance?: string;
    nonce: string;
  } | null> {
    return this.trackedTapState;
  }

  async recordCompletedIncomingPayment(args: { paymentProof: string; secret: string }): Promise<void> {
    this.completedIncomingPayments.push(args);
  }

  async cancelMessage(args: {
    paymentProof: string;
    senderAddr: string;
    recipientAddr: string;
    incomingAmount: string;
    fee: string;
    recipientPendingPayment: PendingPayment | null;
  }): Promise<void> {
    this.cancelledMessages.push({
      paymentProof: args.paymentProof,
      senderAddr: args.senderAddr,
      recipientAddr: args.recipientAddr,
      incomingAmount: args.incomingAmount,
      fee: args.fee,
    });
  }

  async submitDisputeForCounterparty(counterparty: string): Promise<{ txid: string; nonce: string; pipeId: string }> {
    this.submittedDisputes.push(counterparty);
    return {
      txid: '0xdispute',
      nonce: this.trackedTapState?.nonce ?? '0',
      pipeId: 'mock-pipe',
    };
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
  audience?: string;
  messageId?: string;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
}): string {
  const payload = {
    action: opts.action,
    address: opts.address,
    timestamp: Date.now(),
    audience: opts.audience ?? 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
    ...(opts.messageId ? { messageId: opts.messageId } : {}),
  };
  const signature = signMessage(JSON.stringify(payload), opts.privateKey);
  return Buffer.from(JSON.stringify({ pubkey: opts.pubkey, payload, signature })).toString('base64');
}

async function rawJsonRequest(url: string, init: {
  method: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = httpRequest({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method: init.method,
      headers: init.headers,
    }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf-8');
        let body: unknown = text;
        try {
          body = JSON.parse(text);
        } catch {
          // keep raw body
        }
        resolve({ status: res.statusCode ?? 0, body });
      });
    });
    req.on('error', reject);
    if (init.body) req.write(init.body);
    req.end();
  });
}

function makeMessage(overrides: Partial<StoredMessage> = {}): StoredMessage {
  return {
    id: randomUUID(),
    from: 'SP1SENDER',
    to: 'SP1RECIPIENT',
    sentAt: Date.now(),
    amount: '1000',
    fee: '100',
    paymentId: 'pay-' + randomUUID(),
    hashedSecret: 'abc123hashedsecret',
    encryptedPayload: { v: 1, epk: '02' + 'aa'.repeat(32), iv: 'bb'.repeat(12), data: 'cc'.repeat(48) },
    pendingPayment: { stateProof: { nonce: 1, sig: 'abc' }, amount: '900', hashedSecret: 'abc123hashedsecret' },
    deliveryState: 'ready',
    claimed: false,
    paymentSettled: false,
    ...overrides,
  };
}

// ─── Test setup ───────────────────────────────────────────────────────────────

const senderSignKeypair = generateSecp256k1Keypair();
const senderPubkeyHex = senderSignKeypair.compressedPubkeyHex;

const recipientSignKeypair = generateSecp256k1Keypair();
const recipientEcdhForEncrypt = createECDH('secp256k1');
recipientEcdhForEncrypt.generateKeys();
const recipientEncryptPrivkeyHex = recipientEcdhForEncrypt.getPrivateKey().toString('hex').padStart(64, '0');
const recipientEncryptPubkeyHex = recipientEcdhForEncrypt.getPublicKey('hex', 'compressed');

const recipientAddress = pubkeyToStxAddress(recipientSignKeypair.compressedPubkeyHex);

const serverConfig: Config = {
  host: '127.0.0.1',
  port: 0,
  dbBackend: 'sqlite',
  dbFile: ':memory:',
  maxEncryptedBytes: 65536,
  authTimestampTtlMs: 300_000,
  authAudience: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
  stackflowNodeUrl: '',
  serverStxAddress: 'SP_SERVER',
  serverPrivateKey: '',
  sfContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-stackflow',
  reservoirContractId: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
  chainId: 1,
  messagePriceSats: '1000',
  minFeeSats: '100',
  maxPendingPerSender: 5,
  maxPendingPerRecipient: 20,
  maxDeferredPerSender: 5,
  maxDeferredPerRecipient: 20,
  maxDeferredGlobal: 200,
  deferredMessageTtlMs: 86_400_000,
  maxBorrowPerTap: '100000',
  receiveCapacityMultiplier: 20,
  refreshCapacityCooldownMs: 86_400_000,
  inboxSessionTtlMs: 300_000,
  allowedOrigins: [],
  rateLimitWindowMs: 60_000,
  rateLimitMax: 120,
  rateLimitAuthMax: 60,
  rateLimitSendMax: 20,
  rateLimitAdminMax: 10,
  enableBrowserDecryptKey: false,
  supportedToken: '',
};

let server: Server;
let baseUrl: string;
let store: SqliteMessageStore;
let paymentService: MockPaymentService;
let settingsStore: RuntimeSettingsStore;

beforeAll(async () => {
  store = new SqliteMessageStore(':memory:');
  await store.init();

  paymentService = new MockPaymentService();
  const { default: Database } = await import('better-sqlite3');
  const db = new Database(':memory:');
  settingsStore = new RuntimeSettingsStore(db, runtimeSettingsFromConfig(serverConfig));
  server = createMailServer(serverConfig, store, paymentService, settingsStore);

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

describe('admin endpoints', () => {
  // Each admin test spins up its own server with the admin keypair as reservoir deployer.
  const adminKeypair = generateSecp256k1Keypair();
  const adminAddress = pubkeyToStxAddress(adminKeypair.compressedPubkeyHex);

  async function withAdminServer(
    fn: (opts: { baseUrl: string; store: SqliteMessageStore }) => Promise<void>,
  ): Promise<void> {
    const customConfig: Config = {
      ...serverConfig,
      reservoirContractId: `${adminAddress}.sm-reservoir`,
      sfContractId: `${adminAddress}.sm-stackflow`,
      authAudience: `${adminAddress}.sm-reservoir`,
    };
    const customStore = new SqliteMessageStore(':memory:');
    await customStore.init();
    const customService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const customDb = new Database(':memory:');
    const customSettings = new RuntimeSettingsStore(customDb, runtimeSettingsFromConfig(customConfig));
    const customServer = createMailServer(customConfig, customStore, customService, customSettings);
    await new Promise<void>(resolve => customServer.listen(0, '127.0.0.1', () => resolve()));
    const addr = customServer.address() as AddressInfo;
    const customBaseUrl = `http://127.0.0.1:${addr.port}`;
    try {
      await fn({ baseUrl: customBaseUrl, store: customStore });
    } finally {
      await new Promise<void>((resolve, reject) => customServer.close(err => err ? reject(err) : resolve()));
    }
  }

  function adminAuth() {
    return buildAuthHeader({
      pubkey: adminKeypair.compressedPubkeyHex,
      action: 'admin-settings',
      address: adminAddress,
      audience: `${adminAddress}.sm-reservoir`,
      privateKey: adminKeypair.privateKey,
    });
  }

  // ─── POST /admin/settings ───────────────────────────────────────────────

  it('allows the reservoir deployer to update runtime settings', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      const res = await rawJsonRequest(`${baseUrl}/admin/settings`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-mailslot-auth': adminAuth(),
        },
        body: JSON.stringify({
          messagePriceSats: '2500',
          minFeeSats: '250',
          maxPendingPerSender: 7,
        }),
      });
      expect(res.status).toBe(200);
      const body = res.body as { ok: boolean; settings: Record<string, unknown> };
      expect(body.ok).toBe(true);
      expect(body.settings.messagePriceSats).toBe('2500');
      expect(body.settings.minFeeSats).toBe('250');
      expect(body.settings.maxPendingPerSender).toBe(7);
    });
  });

  it('updated settings are reflected in /status', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      await rawJsonRequest(`${baseUrl}/admin/settings`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-mailslot-auth': adminAuth(),
        },
        body: JSON.stringify({ messagePriceSats: '9999' }),
      });

      const statusRes = await rawJsonRequest(`${baseUrl}/status`, { method: 'GET' });
      expect(statusRes.status).toBe(200);
      const statusBody = statusRes.body as { messagePriceSats: string };
      expect(statusBody.messagePriceSats).toBe('9999');
    });
  });

  // ─── GET /admin/settings ────────────────────────────────────────────────

  it('GET /admin/settings returns current settings', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      const res = await rawJsonRequest(`${baseUrl}/admin/settings`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': adminAuth() },
      });
      expect(res.status).toBe(200);
      const body = res.body as { ok: boolean; admin: string; settings: Record<string, unknown> };
      expect(body.ok).toBe(true);
      expect(body.admin).toBe(adminAddress);
      expect(body.settings).toHaveProperty('messagePriceSats');
      expect(body.settings).toHaveProperty('minFeeSats');
    });
  });

  // ─── GET /admin/stats ───────────────────────────────────────────────────

  it('GET /admin/stats returns zeros on empty server', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      const res = await rawJsonRequest(`${baseUrl}/admin/stats`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': adminAuth() },
      });
      expect(res.status).toBe(200);
      const body = res.body as { ok: boolean; stats: Record<string, unknown> };
      expect(body.ok).toBe(true);
      expect(body.stats.totalMailboxes).toBe(0);
      expect(body.stats.totalMessages).toBe(0);
      expect(body.stats.messagesClaimed).toBe(0);
      expect(body.stats.messagesUnclaimed).toBe(0);
      expect(body.stats.totalVolume).toBe('0');
      expect(body.stats.totalFees).toBe('0');
      expect(body.stats.uniqueSenders).toBe(0);
      expect(body.stats.uniqueRecipients).toBe(0);
    });
  });

  it('GET /admin/stats reflects saved mailboxes and messages', async () => {
    await withAdminServer(async ({ baseUrl, store: adminStore }) => {
      // Seed some data
      await adminStore.savePublicKey('SP1ALICE', '02' + 'aa'.repeat(32));
      await adminStore.savePublicKey('SP1BOB', '02' + 'bb'.repeat(32));
      await adminStore.saveMessage(makeMessage({ from: 'SP1SENDER1', to: 'SP1ALICE', amount: '5000', fee: '500' }));
      await adminStore.saveMessage(makeMessage({ from: 'SP1SENDER2', to: 'SP1BOB', amount: '3000', fee: '300' }));
      const claimable = makeMessage({ from: 'SP1SENDER1', to: 'SP1BOB', amount: '2000', fee: '200' });
      await adminStore.saveMessage(claimable);
      await adminStore.claimMessage(claimable.id, 'SP1BOB');

      const res = await rawJsonRequest(`${baseUrl}/admin/stats`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': adminAuth() },
      });
      expect(res.status).toBe(200);
      const body = res.body as { ok: boolean; stats: Record<string, unknown> };
      expect(body.stats.totalMailboxes).toBe(2);
      expect(body.stats.totalMessages).toBe(3);
      expect(body.stats.messagesClaimed).toBe(1);
      expect(body.stats.messagesUnclaimed).toBe(2);
      expect(body.stats.totalVolume).toBe('10000');
      expect(body.stats.totalFees).toBe('1000');
      expect(body.stats.uniqueSenders).toBe(2);
      expect(body.stats.uniqueRecipients).toBe(2);
    });
  });

  // ─── Auth failure cases ─────────────────────────────────────────────────

  it('rejects admin requests without auth header', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      for (const endpoint of ['/admin/settings', '/admin/stats']) {
        const res = await rawJsonRequest(`${baseUrl}${endpoint}`, { method: 'GET' });
        expect(res.status).toBe(401);
        expect((res.body as { error: string }).error).toBe('auth-required');
      }
    });
  });

  it('rejects admin requests from non-admin address', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      const nonAdminKeypair = generateSecp256k1Keypair();
      const nonAdminAddress = pubkeyToStxAddress(nonAdminKeypair.compressedPubkeyHex);
      const auth = buildAuthHeader({
        pubkey: nonAdminKeypair.compressedPubkeyHex,
        action: 'admin-settings',
        address: nonAdminAddress,
        audience: `${adminAddress}.sm-reservoir`,
        privateKey: nonAdminKeypair.privateKey,
      });

      const res = await rawJsonRequest(`${baseUrl}/admin/settings`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': auth },
      });
      expect(res.status).toBe(403);
      expect((res.body as { error: string }).error).toBe('admin-required');
    });
  });

  it('rejects admin requests with wrong action', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      const wrongActionAuth = buildAuthHeader({
        pubkey: adminKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: adminAddress,
        audience: `${adminAddress}.sm-reservoir`,
        privateKey: adminKeypair.privateKey,
      });

      const res = await rawJsonRequest(`${baseUrl}/admin/settings`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': wrongActionAuth },
      });
      expect(res.status).toBe(403);
      expect((res.body as { error: string }).error).toBe('auth-action-mismatch');
    });
  });

  it('POST /admin/settings rejects invalid JSON body', async () => {
    await withAdminServer(async ({ baseUrl }) => {
      const res = await rawJsonRequest(`${baseUrl}/admin/settings`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-mailslot-auth': adminAuth(),
        },
        body: 'not-json{{{',
      });
      expect(res.status).toBe(400);
      expect((res.body as { error: string }).error).toBe('invalid-json');
    });
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
      settledServerBalance: '1000',
      settledCounterpartyBalance: '8000',
      pendingServerBalance: '200',
      pendingCounterpartyBalance: '800',
      nonce: '3',
    };

    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/tap/state`, {
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      ok: boolean;
      tap: {
        contractId: string;
        serverBalance: string;
        myBalance: string;
        sendCapacity: string;
        receiveLiquidity: string;
        settledServerBalance?: string;
        settledMyBalance?: string;
        pendingServerBalance?: string;
        pendingMyBalance?: string;
        nonce: string;
        token: string | null;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.tap.contractId).toBe(serverConfig.sfContractId);
    expect(body.tap.serverBalance).toBe('1200');
    expect(body.tap.myBalance).toBe('8800');
    expect(body.tap.sendCapacity).toBe('8800');
    expect(body.tap.receiveLiquidity).toBe('1200');
    expect(body.tap.settledServerBalance).toBe('1000');
    expect(body.tap.settledMyBalance).toBe('8000');
    expect(body.tap.pendingServerBalance).toBe('200');
    expect(body.tap.pendingMyBalance).toBe('800');
    expect(body.tap.nonce).toBe('3');
    expect(body.tap.token).toBeNull();
  });
});

describe('recipient public key registration', () => {
  it('persists the inbox auth pubkey and exposes it via GET /payment-info/:addr', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const inboxRes = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(inboxRes.status).toBe(200);

    const paymentInfoRes = await fetch(`${baseUrl}/payment-info/${recipientAddress}`);
    expect(paymentInfoRes.status).toBe(200);
    const paymentInfo = await paymentInfoRes.json() as {
      recipientPublicKey: string;
      amount: string;
      fee: string;
      recipientAmount: string;
      serverAddress: string;
    };
    expect(paymentInfo.recipientPublicKey).toBe(recipientSignKeypair.compressedPubkeyHex);
    expect(paymentInfo.amount).toBe(serverConfig.messagePriceSats);
    expect(paymentInfo.fee).toBe(serverConfig.minFeeSats);
    expect(paymentInfo.recipientAmount).toBe('900');
    expect(paymentInfo.serverAddress).toBe(serverConfig.reservoirContractId);
  });

  it('persists the sender pubkey when a message includes fromPublicKey', async () => {
    const senderAddress = pubkeyToStxAddress(senderPubkeyHex);
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = await encryptMail(
      { v: 1, secret: secretHex, body: 'Reply path registration test' },
      recipientEncryptPubkeyHex,
    );

    const proof = JSON.stringify({
      hashedSecret: hashedSecretHex,
      forPrincipal: senderAddress,
      amount: '1000',
    });

    const sendRes = await fetch(`${baseUrl}/messages/${recipientAddress}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-x402-payment': proof,
      },
      body: JSON.stringify({
        from: senderAddress,
        fromPublicKey: senderPubkeyHex,
        encryptedPayload,
      }),
    });
    expect(sendRes.status).toBe(200);

    const paymentInfoRes = await fetch(`${baseUrl}/payment-info/${senderAddress}`);
    expect(paymentInfoRes.status).toBe(200);
    const paymentInfo = await paymentInfoRes.json() as { recipientPublicKey: string };
    expect(paymentInfo.recipientPublicKey).toBe(senderPubkeyHex);
  });
});

describe('full send → inbox → preview → claim flow', () => {
  let messageId: string;
  let inboxSessionToken = '';

  it('step 1: GET /inbox authenticates successfully', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(res.status).toBe(200);
    inboxSessionToken = res.headers.get('x-mailslot-session') ?? '';
    expect(inboxSessionToken).toBeTruthy();
    const body = await res.json() as { messages: unknown[] };
    expect(Array.isArray(body.messages)).toBe(true);
  });

  it('step 2: POST /messages/:addr sends a message', async () => {
    // Sender already has recipient's pubkey (looked up from blockchain, not server)
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = await encryptMail(
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
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { messages: Array<{ id: string; claimed: boolean }> };
    expect(body.messages.length).toBeGreaterThan(0);
    const entry = body.messages.find(m => m.id === messageId);
    expect(entry).toBeDefined();
    expect(entry?.claimed).toBe(false);
  });

  it('step 4: GET /inbox/:id/preview returns encrypted payload', async () => {
    const res = await fetch(`${baseUrl}/inbox/${messageId}/preview`, {
      headers: { 'x-mailslot-session': inboxSessionToken },
    });
    expect(res.status).toBe(200);
    const refreshedSession = res.headers.get('x-mailslot-session') ?? '';
    expect(refreshedSession).toBeTruthy();
    inboxSessionToken = refreshedSession;
    const body = await res.json() as Record<string, unknown>;
    expect(body.messageId).toBe(messageId);
    expect(body.encryptedPayload).toBeDefined();
    const stored = await store.getMessage(messageId, recipientAddress);
    expect(stored?.deliveryState).toBe('previewed');
    const enc = body.encryptedPayload as {
      v: number;
      epk: string;
      iv: string;
      data: string;
    };
    expect(enc.v).toBe(1);
    expect(typeof enc.epk).toBe('string');
    expect(typeof enc.iv).toBe('string');
    expect(typeof enc.data).toBe('string');
  });

  it('step 5: POST /inbox/:id/claim with wrong secret returns 400', async () => {
    const res = await fetch(`${baseUrl}/inbox/${messageId}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-mailslot-session': inboxSessionToken,
      },
      body: JSON.stringify({ secret: randomBytes(32).toString('hex') }),
    });
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('invalid-secret');
  });

  it('step 6: full preview → decrypt → claim round-trip succeeds', async () => {
    const previewRes = await fetch(`${baseUrl}/inbox/${messageId}/preview`, {
      headers: { 'x-mailslot-session': inboxSessionToken },
    });
    expect(previewRes.status).toBe(200);
    inboxSessionToken = previewRes.headers.get('x-mailslot-session') ?? inboxSessionToken;
    const preview = await previewRes.json() as {
      encryptedPayload: { v: 1; epk: string; iv: string; data: string };
    };

    const decrypted = await decryptMail(preview.encryptedPayload, recipientEncryptPrivkeyHex);
    expect(decrypted.subject).toBe('Integration test');
    expect(decrypted.body).toBe('Hello from integration test');
    const secretHex = decrypted.secret;

    const claimRes = await fetch(`${baseUrl}/inbox/${messageId}/claim`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-mailslot-session': inboxSessionToken,
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
        'x-mailslot-auth': authHeader,
      },
      body: JSON.stringify({ secret: randomBytes(32).toString('hex') }),
    });
    expect(claimRes.status).toBe(409);
    const body = await claimRes.json() as { error: string };
    expect(body.error).toBe('already-claimed');
  });
});

describe('recipient tap requirement', () => {
  it('defers sending when the server cannot create the outgoing recipient payment, then activates later', async () => {
    paymentService.outgoingPaymentEnabled = false;
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = await encryptMail(
      { v: 1, secret: secretHex, body: 'Should fail without recipient tap' },
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
        fromPublicKey: senderPubkeyHex,
        encryptedPayload,
      }),
    });

    expect(res.status).toBe(202);
    const body = await res.json() as { deferred: boolean; reason: string; messageId: string };
    expect(body.deferred).toBe(true);
    expect(['no-recipient-tap', 'insufficient-recipient-liquidity']).toContain(body.reason);

    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });
    const inboxBefore = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(inboxBefore.status).toBe(200);
    const inboxBeforeBody = await inboxBefore.json() as { messages: Array<{ id: string }> };
    expect(inboxBeforeBody.messages.some(m => m.id === body.messageId)).toBe(false);

    paymentService.outgoingPaymentEnabled = true;
    const inboxAfter = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(inboxAfter.status).toBe(200);
    const inboxAfterBody = await inboxAfter.json() as { messages: Array<{ id: string }> };
    expect(inboxAfterBody.messages.some(m => m.id === body.messageId)).toBe(true);
  });
});

describe('auth error cases', () => {
  it('GET /inbox without auth returns 401', async () => {
    const res = await fetch(`${baseUrl}/inbox`);
    expect(res.status).toBe(401);
  });

  it('GET /inbox with invalid auth header returns 401', async () => {
    const res = await fetch(`${baseUrl}/inbox`, {
      headers: { 'x-mailslot-auth': 'not-valid-base64-json' },
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
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(res.status).toBe(403);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('auth-action-mismatch');
  });
});

describe('GET /tap/state', () => {
  it('returns null tap when no tracked state exists', async () => {
    paymentService.trackedTapState = null;

    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });

    const res = await rawJsonRequest(`${baseUrl}/tap/state`, {
      method: 'GET',
      headers: { 'x-mailslot-auth': authHeader },
    });
    expect(res.status).toBe(200);
    const body = res.body as { ok: boolean; tap: unknown };
    expect(body.ok).toBe(true);
    expect(body.tap).toBeNull();
  });

  it('rejects unauthenticated requests', async () => {
    const res = await rawJsonRequest(`${baseUrl}/tap/state`, { method: 'GET' });
    expect(res.status).toBe(401);
  });
});

describe('POST /tap/add-funds-params', () => {
  it('returns 503 when createAddFundsParams is not implemented', async () => {
    // Default MockPaymentService doesn't define createAddFundsParams
    const res = await rawJsonRequest(`${baseUrl}/tap/add-funds-params`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        user: recipientAddress,
        amount: '5000',
        myBalance: '1000',
        reservoirBalance: '9000',
        nonce: '1',
        mySignature: '0x' + '11'.repeat(65),
      }),
    });
    expect(res.status).toBe(503);
    const body = res.body as { error: string };
    expect(body.error).toBe('tap-liquidity-management-unavailable');
  });

  it('returns signed params when service method is available', async () => {
    const addFundsService = new MockPaymentService();
    (addFundsService as unknown as Record<string, unknown>).createAddFundsParams = async () => ({
      reservoirSignature: '0x' + 'ff'.repeat(65),
    });
    const addFundsStore = new SqliteMessageStore(':memory:');
    await addFundsStore.init();
    const { default: Database } = await import('better-sqlite3');
    const addFundsDb = new Database(':memory:');
    const addFundsSettings = new RuntimeSettingsStore(addFundsDb, runtimeSettingsFromConfig(serverConfig));
    const addFundsServer = createMailServer(serverConfig, addFundsStore, addFundsService, addFundsSettings);
    await new Promise<void>(r => addFundsServer.listen(0, '127.0.0.1', () => r()));
    const addFundsUrl = `http://127.0.0.1:${(addFundsServer.address() as AddressInfo).port}`;

    try {
      const res = await rawJsonRequest(`${addFundsUrl}/tap/add-funds-params`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          user: recipientAddress,
          amount: '5000',
          myBalance: '1000',
          reservoirBalance: '9000',
          nonce: '1',
          mySignature: '0x' + '11'.repeat(65),
        }),
      });
      expect(res.status).toBe(200);
      const body = res.body as { ok: boolean; reservoirSignature: string; amount: string };
      expect(body.ok).toBe(true);
      expect(body.reservoirSignature).toBe('0x' + 'ff'.repeat(65));
      expect(body.amount).toBe('5000');
    } finally {
      await new Promise<void>((r, j) => addFundsServer.close(e => e ? j(e) : r()));
    }
  });

  it('returns 400 for missing params', async () => {
    const svc = new MockPaymentService();
    (svc as unknown as Record<string, unknown>).createAddFundsParams = async () => ({
      reservoirSignature: '0x' + 'ff'.repeat(65),
    });
    const s = new SqliteMessageStore(':memory:');
    await s.init();
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const ss = new RuntimeSettingsStore(db, runtimeSettingsFromConfig(serverConfig));
    const srv = createMailServer(serverConfig, s, svc, ss);
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;

    try {
      const res = await rawJsonRequest(`${url}/tap/add-funds-params`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ user: recipientAddress }), // missing required fields
      });
      expect(res.status).toBe(400);
      expect((res.body as { error: string }).error).toBe('invalid-params');
    } finally {
      await new Promise<void>((r, j) => srv.close(e => e ? j(e) : r()));
    }
  });
});

describe('POST /tap/borrow-more-params', () => {
  it('returns 503 when createBorrowLiquidityParams is not implemented', async () => {
    const res = await rawJsonRequest(`${baseUrl}/tap/borrow-more-params`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        borrower: recipientAddress,
        borrowAmount: '1000',
        myBalance: '1000',
        reservoirBalance: '1000',
        borrowNonce: '1',
        mySignature: '0x' + '11'.repeat(65),
      }),
    });
    expect(res.status).toBe(503);
    expect((res.body as { error: string }).error).toBe('tap-liquidity-management-unavailable');
  });

  it('returns signed borrow params when available', async () => {
    const svc = new MockPaymentService();
    (svc as unknown as Record<string, unknown>).createBorrowLiquidityParams = async () => ({
      borrowFee: '50',
      reservoirSignature: '0x' + 'ee'.repeat(65),
    });
    const s = new SqliteMessageStore(':memory:');
    await s.init();
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const ss = new RuntimeSettingsStore(db, runtimeSettingsFromConfig(serverConfig));
    const srv = createMailServer(serverConfig, s, svc, ss);
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;

    try {
      const res = await rawJsonRequest(`${url}/tap/borrow-more-params`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          borrower: recipientAddress,
          borrowAmount: '1000',
          myBalance: '1000',
          reservoirBalance: '1000',
          borrowNonce: '1',
          mySignature: '0x' + '11'.repeat(65),
        }),
      });
      expect(res.status).toBe(200);
      const body = res.body as { ok: boolean; borrowFee: string; reservoirSignature: string };
      expect(body.ok).toBe(true);
      expect(body.borrowFee).toBe('50');
      expect(body.reservoirSignature).toBe('0x' + 'ee'.repeat(65));
    } finally {
      await new Promise<void>((r, j) => srv.close(e => e ? j(e) : r()));
    }
  });
});

describe('POST /tap/sync-state', () => {
  it('returns 503 when syncTapState is not implemented', async () => {
    const authHeader = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-inbox',
      address: recipientAddress,
      privateKey: recipientSignKeypair.privateKey,
    });
    const res = await rawJsonRequest(`${baseUrl}/tap/sync-state`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-mailslot-auth': authHeader,
      },
      body: JSON.stringify({
        user: recipientAddress,
        myBalance: '1000',
        reservoirBalance: '9000',
        nonce: '5',
      }),
    });
    expect(res.status).toBe(503);
    expect((res.body as { error: string }).error).toBe('tap-liquidity-management-unavailable');
  });

  it('syncs state for authenticated user', async () => {
    const svc = new MockPaymentService();
    let syncedArgs: Record<string, unknown> | null = null;
    (svc as unknown as Record<string, unknown>).syncTapState = async (args: Record<string, unknown>) => {
      syncedArgs = args;
    };
    const s = new SqliteMessageStore(':memory:');
    await s.init();
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const ss = new RuntimeSettingsStore(db, runtimeSettingsFromConfig(serverConfig));
    const srv = createMailServer(serverConfig, s, svc, ss);
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;

    try {
      const authHeader = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: recipientAddress,
        privateKey: recipientSignKeypair.privateKey,
      });
      const res = await rawJsonRequest(`${url}/tap/sync-state`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-mailslot-auth': authHeader,
        },
        body: JSON.stringify({
          user: recipientAddress,
          myBalance: '5000',
          reservoirBalance: '5000',
          nonce: '10',
        }),
      });
      expect(res.status).toBe(200);
      expect((res.body as { ok: boolean }).ok).toBe(true);
      expect(syncedArgs).not.toBeNull();
      expect((syncedArgs as unknown as Record<string, unknown>).counterparty).toBe(recipientAddress);
      expect((syncedArgs as unknown as Record<string, unknown>).userBalance).toBe('5000');
      expect((syncedArgs as unknown as Record<string, unknown>).nonce).toBe('10');
    } finally {
      await new Promise<void>((r, j) => srv.close(e => e ? j(e) : r()));
    }
  });

  it('rejects sync when user address does not match auth', async () => {
    const svc = new MockPaymentService();
    (svc as unknown as Record<string, unknown>).syncTapState = async () => {};
    const s = new SqliteMessageStore(':memory:');
    await s.init();
    const { default: Database } = await import('better-sqlite3');
    const db = new Database(':memory:');
    const ss = new RuntimeSettingsStore(db, runtimeSettingsFromConfig(serverConfig));
    const srv = createMailServer(serverConfig, s, svc, ss);
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;

    try {
      const authHeader = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: recipientAddress,
        privateKey: recipientSignKeypair.privateKey,
      });
      const res = await rawJsonRequest(`${url}/tap/sync-state`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-mailslot-auth': authHeader,
        },
        body: JSON.stringify({
          user: 'SP_DIFFERENT_USER',
          myBalance: '5000',
          reservoirBalance: '5000',
          nonce: '10',
        }),
      });
      expect(res.status).toBe(403);
      expect((res.body as { error: string }).error).toBe('auth-address-mismatch');
    } finally {
      await new Promise<void>((r, j) => srv.close(e => e ? j(e) : r()));
    }
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
    const encryptedPayload = await encryptMail(
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
  it('marks payment as settled and stores the revealed secret when claim succeeds', async () => {
    const finalizeStore = new SqliteMessageStore(':memory:');
    await finalizeStore.init();
    const finalizeService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const finalizeDb = new Database(':memory:');
    const finalizeSettings = new RuntimeSettingsStore(finalizeDb, runtimeSettingsFromConfig(serverConfig));
    const finalizeServer = createMailServer(serverConfig, finalizeStore, finalizeService, finalizeSettings);
    await new Promise<void>(r => finalizeServer.listen(0, '127.0.0.1', () => r()));
    const finalizeUrl = `http://127.0.0.1:${(finalizeServer.address() as AddressInfo).port}`;

    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = await encryptMail(
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
        'x-mailslot-auth': claimAuth,
      },
      body: JSON.stringify({ secret: secretHex }),
    });
    expect(claimRes.status).toBe(200);

    const stored = await finalizeStore.getMessage(messageId, recipientAddress);
    expect(stored?.paymentSettled).toBe(true);
    expect(stored?.deliveryState).toBe('settled');
    const settlement = await finalizeStore.getSettlement(messageId);
    expect(settlement?.paymentId).toBe(proof);
    expect(settlement?.secret).toBe(secretHex);
    expect(settlement?.hashedSecret).toBe(hashedSecretHex);
    expect(finalizeService.completedIncomingPayments).toEqual([{ paymentProof: proof, secret: secretHex }]);

    await new Promise<void>((r, j) => finalizeServer.close(e => e ? j(e) : r()));
  });
});

describe('sender cancel', () => {
  it('allows sender cancel before preview and blocks cancel after preview', async () => {
    const cancelStore = new SqliteMessageStore(':memory:');
    await cancelStore.init();
    const cancelService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const cancelDb = new Database(':memory:');
    const cancelSettings = new RuntimeSettingsStore(cancelDb, runtimeSettingsFromConfig(serverConfig));
    const cancelServer = createMailServer(serverConfig, cancelStore, cancelService, cancelSettings);
    await new Promise<void>(r => cancelServer.listen(0, '127.0.0.1', () => r()));
    const cancelUrl = `http://127.0.0.1:${(cancelServer.address() as AddressInfo).port}`;

    const senderAddress = pubkeyToStxAddress(senderPubkeyHex);
    const sendMessage = async (bodyText: string) => {
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const encryptedPayload = await encryptMail(
        { v: 1, secret: secretHex, body: bodyText },
        recipientEncryptPubkeyHex,
      );
      const proof = JSON.stringify({
        contractId: serverConfig.sfContractId,
        pipeKey: {
          'principal-1': senderAddress,
          'principal-2': 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-reservoir',
          token: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
        },
        forPrincipal: senderAddress,
        withPrincipal: senderAddress,
        myBalance: '1000',
        theirBalance: '0',
        nonce: '1',
        action: '1',
        actor: senderAddress,
        hashedSecret: hashedSecretHex,
        theirSignature: '0x' + '22'.repeat(65),
        amount: '1000',
      });
      const sendRes = await fetch(`${cancelUrl}/messages/${recipientAddress}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-x402-payment': proof,
        },
        body: JSON.stringify({
          from: senderAddress,
          fromPublicKey: senderPubkeyHex,
          encryptedPayload,
        }),
      });
      expect(sendRes.status).toBe(200);
      const sendBody = await sendRes.json() as { messageId: string };
      return sendBody.messageId;
    };

    const cancellableId = await sendMessage('cancellable');
    const cancelAuth = buildAuthHeader({
      pubkey: senderPubkeyHex,
      action: 'cancel-message',
      address: senderAddress,
      messageId: cancellableId,
      privateKey: senderSignKeypair.privateKey,
    });
    const cancelRes = await fetch(`${cancelUrl}/messages/${cancellableId}/cancel`, {
      method: 'POST',
      headers: { 'x-mailslot-auth': cancelAuth },
    });
    expect(cancelRes.status).toBe(200);
    const cancelled = await cancelStore.getMessageForSender(cancellableId, senderAddress);
    expect(cancelled?.deliveryState).toBe('cancelled');
    expect(cancelService.cancelledMessages).toHaveLength(1);
    expect(cancelService.cancelledMessages[0]?.senderAddr).toBe(senderAddress);

    const previewedId = await sendMessage('preview first');
    const inboxAuth = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-message',
      address: recipientAddress,
      messageId: previewedId,
      privateKey: recipientSignKeypair.privateKey,
    });
    const previewRes = await fetch(`${cancelUrl}/inbox/${previewedId}/preview`, {
      headers: { 'x-mailslot-auth': inboxAuth },
    });
    expect(previewRes.status).toBe(200);

    const cancelAfterPreviewAuth = buildAuthHeader({
      pubkey: senderPubkeyHex,
      action: 'cancel-message',
      address: senderAddress,
      messageId: previewedId,
      privateKey: senderSignKeypair.privateKey,
    });
    const cancelAfterPreviewRes = await fetch(`${cancelUrl}/messages/${previewedId}/cancel`, {
      method: 'POST',
      headers: { 'x-mailslot-auth': cancelAfterPreviewAuth },
    });
    expect(cancelAfterPreviewRes.status).toBe(409);
    const errorBody = await cancelAfterPreviewRes.json() as { error: string };
    expect(errorBody.error).toBe('already-previewed');

    await new Promise<void>((r, j) => cancelServer.close(e => e ? j(e) : r()));
  });
});

describe('per-sender HTLC cap', () => {
  it('rejects when sender exceeds maxPendingPerSender unclaimed messages', async () => {
    const capStore = new SqliteMessageStore(':memory:');
    await capStore.init();

    // Use a payment service that always approves with same hashedSecret + distinct secrets
    const capService = new MockPaymentService();
    const capConfig = { ...serverConfig, maxPendingPerSender: 2 };
    const { default: Database } = await import('better-sqlite3');
    const capDb = new Database(':memory:');
    const capSettings = new RuntimeSettingsStore(capDb, runtimeSettingsFromConfig(capConfig));
    const capServer = createMailServer(capConfig, capStore, capService, capSettings);
    await new Promise<void>(r => capServer.listen(0, '127.0.0.1', () => r()));
    const capUrl = `http://127.0.0.1:${(capServer.address() as AddressInfo).port}`;

    const capRecipient = pubkeyToStxAddress(recipientSignKeypair.compressedPubkeyHex);

    const sendMsg = async () => {
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const enc = await encryptMail({ v: 1, secret: secretHex, body: 'hi' }, recipientEncryptPubkeyHex);
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

  it('rejects when recipient inbox exceeds maxPendingPerRecipient unclaimed messages', async () => {
    const capStore = new SqliteMessageStore(':memory:');
    await capStore.init();

    const capService = new MockPaymentService();
    const capConfig = { ...serverConfig, maxPendingPerRecipient: 2 };
    const { default: Database } = await import('better-sqlite3');
    const capDb = new Database(':memory:');
    const capSettings = new RuntimeSettingsStore(capDb, runtimeSettingsFromConfig(capConfig));
    const capServer = createMailServer(capConfig, capStore, capService, capSettings);
    await new Promise<void>(r => capServer.listen(0, '127.0.0.1', () => r()));
    const capUrl = `http://127.0.0.1:${(capServer.address() as AddressInfo).port}`;

    const capRecipient = pubkeyToStxAddress(recipientSignKeypair.compressedPubkeyHex);

    const sendMsg = async (sender: string) => {
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const enc = await encryptMail({ v: 1, secret: secretHex, body: `hi from ${sender}` }, recipientEncryptPubkeyHex);
      const proof = JSON.stringify({ hashedSecret: hashedSecretHex, forPrincipal: sender, amount: '1000' });
      return fetch(`${capUrl}/messages/${capRecipient}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-x402-payment': proof },
        body: JSON.stringify({ from: sender, encryptedPayload: enc }),
      });
    };

    expect((await sendMsg('SP_SENDER_1')).status).toBe(200);
    expect((await sendMsg('SP_SENDER_2')).status).toBe(200);
    const res = await sendMsg('SP_SENDER_3');
    expect(res.status).toBe(429);
    const body = await res.json() as { error: string };
    expect(body.error).toBe('recipient-inbox-full');

    await new Promise<void>((r, j) => capServer.close(e => e ? j(e) : r()));
  });
});

describe('deferred message expiration', () => {
  it('expired deferred messages are cleaned up when recipient checks inbox', async () => {
    const deferStore = new SqliteMessageStore(':memory:');
    await deferStore.init();
    const deferService = new MockPaymentService();
    // Disable outgoing payment → messages will be deferred
    deferService.outgoingPaymentEnabled = false;
    const deferConfig: Config = {
      ...serverConfig,
      deferredMessageTtlMs: 1, // 1ms TTL — will expire immediately
    };
    const { default: Database } = await import('better-sqlite3');
    const deferDb = new Database(':memory:');
    const deferSettings = new RuntimeSettingsStore(deferDb, runtimeSettingsFromConfig(deferConfig));
    const deferServer = createMailServer(deferConfig, deferStore, deferService, deferSettings);
    await new Promise<void>(r => deferServer.listen(0, '127.0.0.1', () => r()));
    const deferUrl = `http://127.0.0.1:${(deferServer.address() as AddressInfo).port}`;

    try {
      // Send a message — it will be deferred (no recipient tap)
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const enc = await encryptMail(
        { v: 1, secret: secretHex, body: 'deferred test' },
        recipientEncryptPubkeyHex,
      );
      const proof = JSON.stringify({
        hashedSecret: hashedSecretHex,
        forPrincipal: 'SP_SENDER',
        amount: '1000',
      });
      const sendRes = await rawJsonRequest(`${deferUrl}/messages/${recipientAddress}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-x402-payment': proof,
        },
        body: JSON.stringify({ from: 'SP_SENDER', encryptedPayload: enc }),
      });
      expect(sendRes.status).toBe(202);
      const sendBody = sendRes.body as { messageId: string; deferred?: boolean };
      expect(sendBody.deferred).toBe(true);

      // Verify it exists in the store as deferred
      expect(await deferStore.countDeferredGlobal()).toBe(1);

      // Small delay to ensure TTL passes
      await new Promise(r => setTimeout(r, 10));

      // Check inbox — this triggers activateDeferredMessages → expireDeferredMessages
      const authHeader = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: recipientAddress,
        privateKey: recipientSignKeypair.privateKey,
      });
      const inboxRes = await rawJsonRequest(`${deferUrl}/inbox`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });
      expect(inboxRes.status).toBe(200);

      // After inbox check, expired deferred messages should be cleaned up
      expect(await deferStore.countDeferredGlobal()).toBe(0);
    } finally {
      await new Promise<void>((r, j) => deferServer.close(e => e ? j(e) : r()));
    }
  });

  it('deferred messages within TTL are not expired', async () => {
    const deferStore = new SqliteMessageStore(':memory:');
    await deferStore.init();
    const deferService = new MockPaymentService();
    deferService.outgoingPaymentEnabled = false;
    const deferConfig: Config = {
      ...serverConfig,
      deferredMessageTtlMs: 86_400_000, // 24h — won't expire
    };
    const { default: Database } = await import('better-sqlite3');
    const deferDb = new Database(':memory:');
    const deferSettings = new RuntimeSettingsStore(deferDb, runtimeSettingsFromConfig(deferConfig));
    const deferServer = createMailServer(deferConfig, deferStore, deferService, deferSettings);
    await new Promise<void>(r => deferServer.listen(0, '127.0.0.1', () => r()));
    const deferUrl = `http://127.0.0.1:${(deferServer.address() as AddressInfo).port}`;

    try {
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const enc = await encryptMail(
        { v: 1, secret: secretHex, body: 'long TTL test' },
        recipientEncryptPubkeyHex,
      );
      const proof = JSON.stringify({
        hashedSecret: hashedSecretHex,
        forPrincipal: 'SP_SENDER',
        amount: '1000',
      });
      const sendRes = await rawJsonRequest(`${deferUrl}/messages/${recipientAddress}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-x402-payment': proof,
        },
        body: JSON.stringify({ from: 'SP_SENDER', encryptedPayload: enc }),
      });
      expect(sendRes.status).toBe(202);
      expect(await deferStore.countDeferredGlobal()).toBe(1);

      // Check inbox — should NOT expire the deferred message
      const authHeader = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: recipientAddress,
        privateKey: recipientSignKeypair.privateKey,
      });
      await rawJsonRequest(`${deferUrl}/inbox`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });

      // Message should still be deferred
      expect(await deferStore.countDeferredGlobal()).toBe(1);
    } finally {
      await new Promise<void>((r, j) => deferServer.close(e => e ? j(e) : r()));
    }
  });
});

describe('security hardening', () => {
  it('reports auth audience and browser decrypt policy in /status', async () => {
    const res = await fetch(`${baseUrl}/status`);
    expect(res.status).toBe(200);
    const body = await res.json() as { authAudience?: string; enableBrowserDecryptKey?: boolean };
    expect(body.authAudience).toBe(serverConfig.authAudience);
    expect(body.enableBrowserDecryptKey).toBe(false);
  });

  it('rejects disallowed browser origins', async () => {
    const res = await fetch(`${baseUrl}/status`, {
      headers: { origin: 'https://evil.example' },
    });
    expect(res.status).toBe(403);
    const body = await res.json() as { error?: string };
    expect(body.error).toBe('origin-not-allowed');
  });

  it('accepts dispute webhooks only with the configured token', async () => {
    const hookStore = new SqliteMessageStore(':memory:');
    await hookStore.init();
    const hookService = new MockPaymentService();
    hookService.trackedTapState = {
      contractId: serverConfig.sfContractId,
      pipeKey: {
        'principal-1': recipientAddress,
        'principal-2': serverConfig.reservoirContractId,
        token: 'SP3QFYVTMS0PRJT3K3GMDW9DGR33TDHENSDWVNQMR.sm-test-token',
      },
      serverBalance: '100',
      counterpartyBalance: '900',
      nonce: '7',
    };
    const hookConfig: Config = {
      ...serverConfig,
      disputeWebhookToken: 'hook-secret',
    };
    const { default: Database } = await import('better-sqlite3');
    const hookDb = new Database(':memory:');
    const hookSettings = new RuntimeSettingsStore(hookDb, runtimeSettingsFromConfig(hookConfig));
    const hookServer = createMailServer(hookConfig, hookStore, hookService, hookSettings);
    await new Promise<void>(r => hookServer.listen(0, '127.0.0.1', () => r()));
    const hookUrl = `http://127.0.0.1:${(hookServer.address() as AddressInfo).port}`;

    const unauthorized = await rawJsonRequest(`${hookUrl}/hooks/dispute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ counterparty: recipientAddress }),
    });
    expect(unauthorized.status).toBe(401);

    const authorized = await rawJsonRequest(`${hookUrl}/hooks/dispute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-mailslot-webhook-token': 'hook-secret',
      },
      body: JSON.stringify({ event: 'force-close-detected', counterparty: recipientAddress }),
    });
    expect(authorized.status).toBe(200);
    const body = authorized.body as {
      ok?: boolean;
      submitted?: boolean;
      counterparty?: string;
      txid?: string;
      nonce?: string;
      pipeId?: string;
    };
    expect(body.ok).toBe(true);
    expect(body.submitted).toBe(true);
    expect(body.counterparty).toBe(recipientAddress);
    expect(body.txid).toBe('0xdispute');
    expect(body.nonce).toBe('7');
    expect(body.pipeId).toBe('mock-pipe');
    expect(hookService.submittedDisputes).toEqual([recipientAddress]);

    await new Promise<void>((r, j) => hookServer.close(e => e ? j(e) : r()));
  });
});

// ─── Rate limiting ──────────────────────────────────────────────────────────

describe('rate limiting', () => {
  it('enforces rate limits and returns 429 with Retry-After header', async () => {
    const rlConfig: Config = {
      ...serverConfig,
      rateLimitSendMax: 2,
      rateLimitWindowMs: 60_000,
    };
    const rlStore = new SqliteMessageStore(':memory:');
    await rlStore.init();
    const rlService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const rlDb = new Database(':memory:');
    const rlSettings = new RuntimeSettingsStore(rlDb, runtimeSettingsFromConfig(rlConfig));
    const rlServer = createMailServer(rlConfig, rlStore, rlService, rlSettings);
    await new Promise<void>(r => rlServer.listen(0, '127.0.0.1', () => r()));
    const rlUrl = `http://127.0.0.1:${(rlServer.address() as AddressInfo).port}`;

    try {
      const sendReq = () => rawJsonRequest(`${rlUrl}/messages/${recipientAddress}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}', // Will fail validation, but rate limit is checked first
      });

      // First two requests should pass rate limit (may fail with 400/402 — that's fine, not 429)
      const r1 = await sendReq();
      expect(r1.status).not.toBe(429);
      const r2 = await sendReq();
      expect(r2.status).not.toBe(429);

      // Third should be rate limited
      const r3 = await sendReq();
      expect(r3.status).toBe(429);
      expect((r3.body as { error: string; category: string }).error).toBe('rate-limit-exceeded');
      expect((r3.body as { category: string }).category).toBe('send');
    } finally {
      await new Promise<void>((r, j) => rlServer.close(e => e ? j(e) : r()));
    }
  });

  it('does not rate limit exempt paths like /health and /status', async () => {
    const rlConfig: Config = {
      ...serverConfig,
      rateLimitMax: 1, // Very low limit
    };
    const rlStore = new SqliteMessageStore(':memory:');
    await rlStore.init();
    const rlService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const rlDb = new Database(':memory:');
    const rlSettings = new RuntimeSettingsStore(rlDb, runtimeSettingsFromConfig(rlConfig));
    const rlServer = createMailServer(rlConfig, rlStore, rlService, rlSettings);
    await new Promise<void>(r => rlServer.listen(0, '127.0.0.1', () => r()));
    const rlUrl = `http://127.0.0.1:${(rlServer.address() as AddressInfo).port}`;

    try {
      // Health and status should never be rate limited regardless of how many requests
      for (let i = 0; i < 5; i++) {
        const health = await rawJsonRequest(`${rlUrl}/health`, { method: 'GET' });
        expect(health.status).toBe(200);
        const status = await rawJsonRequest(`${rlUrl}/status`, { method: 'GET' });
        expect(status.status).toBe(200);
      }
    } finally {
      await new Promise<void>((r, j) => rlServer.close(e => e ? j(e) : r()));
    }
  });

  it('applies auth rate limit category to inbox requests', async () => {
    const rlConfig: Config = {
      ...serverConfig,
      rateLimitAuthMax: 2,
    };
    const rlStore = new SqliteMessageStore(':memory:');
    await rlStore.init();
    const rlService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const rlDb = new Database(':memory:');
    const rlSettings = new RuntimeSettingsStore(rlDb, runtimeSettingsFromConfig(rlConfig));
    const rlServer = createMailServer(rlConfig, rlStore, rlService, rlSettings);
    await new Promise<void>(r => rlServer.listen(0, '127.0.0.1', () => r()));
    const rlUrl = `http://127.0.0.1:${(rlServer.address() as AddressInfo).port}`;

    try {
      const authHeader = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: recipientAddress,
        privateKey: recipientSignKeypair.privateKey,
      });

      // First two pass
      for (let i = 0; i < 2; i++) {
        const r = await rawJsonRequest(`${rlUrl}/inbox`, {
          method: 'GET',
          headers: { 'x-mailslot-auth': authHeader },
        });
        expect(r.status).toBe(200);
      }

      // Third is rate limited
      const r3 = await rawJsonRequest(`${rlUrl}/inbox`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });
      expect(r3.status).toBe(429);
      expect((r3.body as { category: string }).category).toBe('auth');
    } finally {
      await new Promise<void>((r, j) => rlServer.close(e => e ? j(e) : r()));
    }
  });
});

// ─── Inbox query parameters ─────────────────────────────────────────────────

describe('inbox query parameters', () => {
  it('respects limit, before, and claimed query params', async () => {
    const qStore = new SqliteMessageStore(':memory:');
    await qStore.init();
    const qService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const qDb = new Database(':memory:');
    const qSettings = new RuntimeSettingsStore(qDb, runtimeSettingsFromConfig(serverConfig));
    const qServer = createMailServer(serverConfig, qStore, qService, qSettings);
    await new Promise<void>(r => qServer.listen(0, '127.0.0.1', () => r()));
    const qUrl = `http://127.0.0.1:${(qServer.address() as AddressInfo).port}`;

    try {
      const now = Date.now();
      // Seed messages at different times
      const msg1 = makeMessage({ to: recipientAddress, sentAt: now - 3000, amount: '1000' });
      const msg2 = makeMessage({ to: recipientAddress, sentAt: now - 2000, amount: '2000' });
      const msg3 = makeMessage({ to: recipientAddress, sentAt: now - 1000, amount: '3000' });
      await qStore.saveMessage(msg1);
      await qStore.saveMessage(msg2);
      await qStore.saveMessage(msg3);
      // Claim msg1 and mark as settled
      await qStore.claimMessage(msg1.id, recipientAddress);
      // Mark settled state so it appears with claimed=true
      qStore['assertDb']().prepare("UPDATE messages SET delivery_state = 'settled' WHERE id = ?").run(msg1.id);

      const authHeader = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-inbox',
        address: recipientAddress,
        privateKey: recipientSignKeypair.privateKey,
      });

      // Default: excludes claimed, returns all unclaimed
      const defaultRes = await rawJsonRequest(`${qUrl}/inbox`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });
      expect(defaultRes.status).toBe(200);
      const defaultBody = defaultRes.body as { messages: Array<{ id: string }> };
      expect(defaultBody.messages).toHaveLength(2);

      // With claimed=true: includes settled messages
      const claimedRes = await rawJsonRequest(`${qUrl}/inbox?claimed=true`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });
      expect(claimedRes.status).toBe(200);
      const claimedBody = claimedRes.body as { messages: Array<{ id: string }> };
      expect(claimedBody.messages).toHaveLength(3);

      // With limit=1: returns only 1 message (most recent)
      const limitRes = await rawJsonRequest(`${qUrl}/inbox?limit=1`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });
      expect(limitRes.status).toBe(200);
      const limitBody = limitRes.body as { messages: Array<{ id: string; amount: string }> };
      expect(limitBody.messages).toHaveLength(1);
      expect(limitBody.messages[0].id).toBe(msg3.id); // most recent

      // With before: pagination — only messages before msg3
      const beforeRes = await rawJsonRequest(`${qUrl}/inbox?before=${msg3.sentAt}`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': authHeader },
      });
      expect(beforeRes.status).toBe(200);
      const beforeBody = beforeRes.body as { messages: Array<{ id: string }> };
      expect(beforeBody.messages).toHaveLength(1); // only msg2 (msg1 is claimed)
      expect(beforeBody.messages[0].id).toBe(msg2.id);
    } finally {
      await new Promise<void>((r, j) => qServer.close(e => e ? j(e) : r()));
    }
  });
});

// ─── GET /inbox/:id (single claimed message fetch) ──────────────────────────

describe('GET /inbox/:id', () => {
  it('returns a settled message for the recipient', async () => {
    const gmStore = new SqliteMessageStore(':memory:');
    await gmStore.init();
    const gmService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const gmDb = new Database(':memory:');
    const gmSettings = new RuntimeSettingsStore(gmDb, runtimeSettingsFromConfig(serverConfig));
    const gmServer = createMailServer(serverConfig, gmStore, gmService, gmSettings);
    await new Promise<void>(r => gmServer.listen(0, '127.0.0.1', () => r()));
    const gmUrl = `http://127.0.0.1:${(gmServer.address() as AddressInfo).port}`;

    try {
      // Send and claim a message
      const secretHex = randomBytes(32).toString('hex');
      const hashedSecretHex = hashSecret(secretHex);
      const enc = await encryptMail(
        { v: 1, secret: secretHex, subject: 'fetch test', body: 'fetch me' },
        recipientEncryptPubkeyHex,
      );
      const senderAddress = pubkeyToStxAddress(senderPubkeyHex);
      const proof = JSON.stringify({
        hashedSecret: hashedSecretHex,
        forPrincipal: senderAddress,
        amount: '1000',
      });

      const sendRes = await rawJsonRequest(`${gmUrl}/messages/${recipientAddress}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-x402-payment': proof,
        },
        body: JSON.stringify({ from: senderAddress, encryptedPayload: enc }),
      });
      expect(sendRes.status).toBe(200);
      const msgId = (sendRes.body as { messageId: string }).messageId;

      // Claim it
      const claimAuth = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'claim-message',
        address: recipientAddress,
        messageId: msgId,
        privateKey: recipientSignKeypair.privateKey,
      });
      const claimRes = await rawJsonRequest(`${gmUrl}/inbox/${msgId}/claim`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-mailslot-auth': claimAuth,
        },
        body: JSON.stringify({ secret: secretHex }),
      });
      expect(claimRes.status).toBe(200);

      // Now fetch the settled message
      const getAuth = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-message',
        address: recipientAddress,
        messageId: msgId,
        privateKey: recipientSignKeypair.privateKey,
      });
      const getRes = await rawJsonRequest(`${gmUrl}/inbox/${msgId}`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': getAuth },
      });
      expect(getRes.status).toBe(200);
      const getBody = getRes.body as { message: { id: string; from: string; encryptedPayload: Record<string, unknown> } };
      expect(getBody.message.id).toBe(msgId);
      expect(getBody.message.from).toBe(senderAddress);
      expect(getBody.message.encryptedPayload).toBeDefined();
    } finally {
      await new Promise<void>((r, j) => gmServer.close(e => e ? j(e) : r()));
    }
  });

  it('returns 404 for unclaimed message', async () => {
    const gmStore = new SqliteMessageStore(':memory:');
    await gmStore.init();
    const gmService = new MockPaymentService();
    const { default: Database } = await import('better-sqlite3');
    const gmDb = new Database(':memory:');
    const gmSettings = new RuntimeSettingsStore(gmDb, runtimeSettingsFromConfig(serverConfig));
    const gmServer = createMailServer(serverConfig, gmStore, gmService, gmSettings);
    await new Promise<void>(r => gmServer.listen(0, '127.0.0.1', () => r()));
    const gmUrl = `http://127.0.0.1:${(gmServer.address() as AddressInfo).port}`;

    try {
      // Send a message but don't claim it
      const secretHex = randomBytes(32).toString('hex');
      const enc = await encryptMail(
        { v: 1, secret: secretHex, body: 'not claimed' },
        recipientEncryptPubkeyHex,
      );
      const senderAddress = pubkeyToStxAddress(senderPubkeyHex);
      const proof = JSON.stringify({
        hashedSecret: hashSecret(secretHex),
        forPrincipal: senderAddress,
        amount: '1000',
      });

      const sendRes = await rawJsonRequest(`${gmUrl}/messages/${recipientAddress}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-x402-payment': proof,
        },
        body: JSON.stringify({ from: senderAddress, encryptedPayload: enc }),
      });
      expect(sendRes.status).toBe(200);
      const msgId = (sendRes.body as { messageId: string }).messageId;

      // Try to fetch — should 404 because not settled
      const getAuth = buildAuthHeader({
        pubkey: recipientSignKeypair.compressedPubkeyHex,
        action: 'get-message',
        address: recipientAddress,
        messageId: msgId,
        privateKey: recipientSignKeypair.privateKey,
      });
      const getRes = await rawJsonRequest(`${gmUrl}/inbox/${msgId}`, {
        method: 'GET',
        headers: { 'x-mailslot-auth': getAuth },
      });
      expect(getRes.status).toBe(404);
      expect((getRes.body as { error: string }).error).toBe('not-found');
    } finally {
      await new Promise<void>((r, j) => gmServer.close(e => e ? j(e) : r()));
    }
  });

  it('returns 404 for nonexistent message', async () => {
    const getAuth = buildAuthHeader({
      pubkey: recipientSignKeypair.compressedPubkeyHex,
      action: 'get-message',
      address: recipientAddress,
      messageId: 'nonexistent-id',
      privateKey: recipientSignKeypair.privateKey,
    });
    const res = await rawJsonRequest(`${baseUrl}/inbox/nonexistent-id`, {
      method: 'GET',
      headers: { 'x-mailslot-auth': getAuth },
    });
    expect(res.status).toBe(404);
  });
});

// ─── GET /payment-info/:addr ─────────────────────────────────────────────────

describe('GET /payment-info/:addr', () => {
  it('returns 404 for unregistered recipient', async () => {
    const res = await rawJsonRequest(`${baseUrl}/payment-info/SP_UNREGISTERED_ADDRESS`, {
      method: 'GET',
    });
    expect(res.status).toBe(404);
    expect((res.body as { error: string }).error).toBe('recipient-not-found');
  });
});

// ─── Payment service error propagation ──────────────────────────────────────

describe('payment service error propagation', () => {
  it('propagates typed payment service errors with correct status codes', async () => {
    const errService = new MockPaymentService();
    // Override createTapWithBorrowedLiquidityParams to throw a typed error
    errService.createTapWithBorrowedLiquidityParams = async () => {
      const err = Object.assign(new Error('insufficient liquidity'), {
        statusCode: 409,
        reason: 'insufficient-server-balance',
      });
      throw err;
    };
    const errStore = new SqliteMessageStore(':memory:');
    await errStore.init();
    const { default: Database } = await import('better-sqlite3');
    const errDb = new Database(':memory:');
    const errSettings = new RuntimeSettingsStore(errDb, runtimeSettingsFromConfig(serverConfig));
    const errServer = createMailServer(serverConfig, errStore, errService, errSettings);
    await new Promise<void>(r => errServer.listen(0, '127.0.0.1', () => r()));
    const errUrl = `http://127.0.0.1:${(errServer.address() as AddressInfo).port}`;

    try {
      const res = await rawJsonRequest(`${errUrl}/tap/borrow-params`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          borrower: recipientAddress,
          tapAmount: '1000',
          tapNonce: '0',
          borrowAmount: '1000',
          myBalance: '1000',
          reservoirBalance: '1000',
          borrowNonce: '1',
          mySignature: '0x' + '11'.repeat(65),
        }),
      });
      expect(res.status).toBe(409);
      const body = res.body as { error: string; message: string };
      expect(body.error).toBe('insufficient-server-balance');
      expect(body.message).toBe('insufficient liquidity');
    } finally {
      await new Promise<void>((r, j) => errServer.close(e => e ? j(e) : r()));
    }
  });
});
