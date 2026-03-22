import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { verifyInboxAuth, verifyInboxSessionToken, issueInboxSessionToken, pubkeyToStxAddress } from './auth.js';
import type { MessageStore } from './store.js';
import type { Config } from './types.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Generate a secp256k1 keypair. Returns Node.js KeyObjects + compressed pubkey hex. */
function generateTestKeypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });

  // Extract compressed pubkey from SPKI DER (last 65 bytes = uncompressed point)
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const uncompressed = spkiDer.subarray(spkiDer.length - 65); // 04 || x || y
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);
  const prefix = y[31] % 2 === 0 ? 0x02 : 0x03;
  const compressedPubkeyHex = Buffer.concat([Buffer.from([prefix]), x]).toString('hex');

  return { privateKey, compressedPubkeyHex };
}

/** Sign a string with compact (r||s) IEEE P1363 encoding. */
function signMessage(message: string, privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']): string {
  const signer = createSign('SHA256');
  signer.update(message);
  return signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('hex');
}

/** Build a base64-encoded x-mailslot-auth header. */
function buildAuthHeader(opts: {
  pubkey: string;
  action: string;
  address: string;
  audience?: string;
  timestamp?: number;
  messageId?: string;
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
}): string {
  const payload = {
    action: opts.action,
    address: opts.address,
    timestamp: opts.timestamp ?? Date.now(),
    audience: opts.audience ?? 'SP123',
    ...(opts.messageId ? { messageId: opts.messageId } : {}),
  };
  const signature = signMessage(JSON.stringify(payload), opts.privateKey);
  return Buffer.from(JSON.stringify({ pubkey: opts.pubkey, payload, signature })).toString('base64');
}

const testConfig: Config = {
  host: '127.0.0.1',
  port: 8800,
  dbBackend: 'sqlite',
  dbFile: ':memory:',
  maxEncryptedBytes: 65536,
  authTimestampTtlMs: 300_000,
  authAudience: 'SP123',
  stackflowNodeUrl: '',
  serverStxAddress: 'SP123',
  serverPrivateKey: '',
  sfContractId: '',
  reservoirContractId: '',
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
  rebalanceThresholdPct: 150,
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

/** Minimal in-memory MessageStore stub. */
function makeMockStore(): MessageStore {
  return {
    init: async () => {},
    savePublicKey: async () => {},
    getPublicKey: async () => null,
    savePendingPaymentInfo: async () => {},
    consumePendingPaymentInfo: async () => null,
    saveMessage: async () => {},
    getInbox: async () => [],
    getMessage: async () => null,
    getMessageForSender: async () => null,
    claimMessage: async () => { throw new Error('not implemented'); },
    getClaimedMessage: async () => null,
    markPaymentSettled: async () => {},
    markMessagePreviewed: async () => null,
    cancelMessageBySender: async () => null,
    recordSettlement: async () => {},
    getSettlement: async () => null,
    activateDeferredMessage: async () => {},
    getDeferredMessagesForRecipient: async () => [],
    expireDeferredMessages: async () => 0,
    countPendingFromSender: async () => 0,
    countPendingToRecipient: async () => 0,
    countDeferredFromSender: async () => 0,
    countDeferredToRecipient: async () => 0,
    countDeferredGlobal: async () => 0,
    getStats: async () => ({ totalMailboxes: 0, totalMessages: 0, messagesClaimed: 0, messagesUnclaimed: 0, totalVolume: '0', totalFees: '0', uniqueSenders: 0, uniqueRecipients: 0 }),
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('verifyInboxAuth', () => {
  it('accepts a valid auth header', async () => {
    const { privateKey, compressedPubkeyHex } = generateTestKeypair();
    const address = pubkeyToStxAddress(compressedPubkeyHex);

    const header = buildAuthHeader({ pubkey: compressedPubkeyHex, action: 'get-inbox', address, privateKey });
    const result = await verifyInboxAuth(header, testConfig, makeMockStore());

    expect(result.pubkeyHex).toBe(compressedPubkeyHex);
    expect(result.payload.address).toBe(address);
    expect(result.payload.action).toBe('get-inbox');
  });

  it('rejects an expired timestamp', async () => {
    const { privateKey, compressedPubkeyHex } = generateTestKeypair();
    const address = pubkeyToStxAddress(compressedPubkeyHex);

    const header = buildAuthHeader({
      pubkey: compressedPubkeyHex,
      action: 'get-inbox',
      address,
      timestamp: Date.now() - 400_000,
      privateKey,
    });
    await expect(verifyInboxAuth(header, testConfig, makeMockStore())).rejects.toThrow('auth timestamp expired');
  });

  it('rejects a future timestamp', async () => {
    const { privateKey, compressedPubkeyHex } = generateTestKeypair();
    const address = pubkeyToStxAddress(compressedPubkeyHex);

    const header = buildAuthHeader({
      pubkey: compressedPubkeyHex,
      action: 'get-inbox',
      address,
      timestamp: Date.now() + 10_000,
      privateKey,
    });
    await expect(verifyInboxAuth(header, testConfig, makeMockStore())).rejects.toThrow('auth timestamp expired');
  });

  it('rejects wrong signature (signed with different key)', async () => {
    const { compressedPubkeyHex } = generateTestKeypair();
    const { privateKey: wrongPrivkey } = generateTestKeypair();
    const address = pubkeyToStxAddress(compressedPubkeyHex);

    const header = buildAuthHeader({ pubkey: compressedPubkeyHex, action: 'get-inbox', address, privateKey: wrongPrivkey });
    await expect(verifyInboxAuth(header, testConfig, makeMockStore())).rejects.toThrow('invalid signature');
  });

  it('rejects pubkey that does not match claimed address', async () => {
    const { privateKey, compressedPubkeyHex } = generateTestKeypair();
    const { compressedPubkeyHex: otherPubkey } = generateTestKeypair();
    const address = pubkeyToStxAddress(otherPubkey); // address of a different key

    const header = buildAuthHeader({ pubkey: compressedPubkeyHex, action: 'get-inbox', address, privateKey });
    await expect(verifyInboxAuth(header, testConfig, makeMockStore())).rejects.toThrow('pubkey does not match claimed address');
  });

  it('rejects invalid base64 encoding', async () => {
    await expect(
      verifyInboxAuth('not-valid-json!!!', testConfig, makeMockStore())
    ).rejects.toThrow('invalid auth header encoding');
  });

  it('rejects missing action field', async () => {
    const { privateKey, compressedPubkeyHex } = generateTestKeypair();
    const address = pubkeyToStxAddress(compressedPubkeyHex);
    const payload = { address, timestamp: Date.now() }; // no action
    const signature = signMessage(JSON.stringify(payload), privateKey);
    const header = Buffer.from(JSON.stringify({ pubkey: compressedPubkeyHex, payload, signature })).toString('base64');

    await expect(verifyInboxAuth(header, testConfig, makeMockStore())).rejects.toThrow('auth payload missing required fields');
  });

  it('rejects audience mismatch', async () => {
    const { privateKey, compressedPubkeyHex } = generateTestKeypair();
    const address = pubkeyToStxAddress(compressedPubkeyHex);
    const header = buildAuthHeader({
      pubkey: compressedPubkeyHex,
      action: 'get-inbox',
      address,
      audience: 'https://evil.example',
      privateKey,
    });
    await expect(verifyInboxAuth(header, testConfig, makeMockStore())).rejects.toThrow('auth audience mismatch');
  });
});

describe('pubkeyToStxAddress', () => {
  it('produces an SP-prefixed mainnet address', () => {
    const { compressedPubkeyHex } = generateTestKeypair();
    const addr = pubkeyToStxAddress(compressedPubkeyHex);
    expect(addr).toMatch(/^SP/);
  });

  it('produces an ST-prefixed testnet address', () => {
    const { compressedPubkeyHex } = generateTestKeypair();
    const addr = pubkeyToStxAddress(compressedPubkeyHex, true);
    expect(addr).toMatch(/^ST/);
  });

  it('is deterministic', () => {
    const { compressedPubkeyHex } = generateTestKeypair();
    expect(pubkeyToStxAddress(compressedPubkeyHex)).toBe(pubkeyToStxAddress(compressedPubkeyHex));
  });

  it('differs for different pubkeys', () => {
    const { compressedPubkeyHex: k1 } = generateTestKeypair();
    const { compressedPubkeyHex: k2 } = generateTestKeypair();
    expect(pubkeyToStxAddress(k1)).not.toBe(pubkeyToStxAddress(k2));
  });
});

describe('inbox session tokens', () => {
  it('issues and verifies a valid token', () => {
    const token = issueInboxSessionToken('SP123SESSION', testConfig);
    const payload = verifyInboxSessionToken(token.token, testConfig);
    expect(payload.address).toBe('SP123SESSION');
    expect(payload.exp).toBeGreaterThan(Date.now());
  });

  it('rejects tampered tokens', () => {
    const token = issueInboxSessionToken('SP123SESSION', testConfig);
    const [payload, _sig] = token.token.split('.');
    const tampered = `${payload}.AAAA`;
    expect(() => verifyInboxSessionToken(tampered, testConfig)).toThrow('invalid inbox session token');
  });

  it('rejects expired tokens', () => {
    const shortTtlConfig = { ...testConfig, inboxSessionTtlMs: -1 };
    const token = issueInboxSessionToken('SP123SESSION', shortTtlConfig);
    expect(() => verifyInboxSessionToken(token.token, shortTtlConfig)).toThrow('inbox session expired');
  });

  it('rejects malformed tokens without a separator', () => {
    expect(() => verifyInboxSessionToken('no-dot-separator', testConfig)).toThrow('invalid inbox session token');
  });

  it('token address is preserved through issue/verify cycle', () => {
    const addr = 'SP3HHD6N7SXNYF37GWT05DP51WVT8PRK0QYZQXW37';
    const token = issueInboxSessionToken(addr, testConfig);
    const payload = verifyInboxSessionToken(token.token, testConfig);
    expect(payload.address).toBe(addr);
  });
});
