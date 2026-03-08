import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createECDH, randomBytes } from 'node:crypto';
import { StackmailClient, StackmailError } from './client.js';
import { encryptMail, hashSecret } from '@stackmail/crypto';
import type { ClientConfig, PaymentInfo } from './types.js';

// ─── Test keypair ─────────────────────────────────────────────────────────────

const recipientEcdh = createECDH('secp256k1');
recipientEcdh.generateKeys();
const recipientPrivkeyHex = recipientEcdh.getPrivateKey('hex');
const recipientPubkeyHex = recipientEcdh.getPublicKey('hex', 'compressed');

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<ClientConfig> = {}): ClientConfig {
  return {
    address: 'SP1RECIPIENT',
    publicKey: recipientPubkeyHex,
    serverUrl: 'http://localhost:9999',
    privateKey: recipientPrivkeyHex,
    signer: async (msg) => 'a'.repeat(128), // dummy sig — not verified in client tests
    paymentProofBuilder: async ({ hashedSecretHex }) =>
      JSON.stringify({ hashedSecret: hashedSecretHex, forPrincipal: 'SP1SENDER', amount: '1000' }),
    ...overrides,
  };
}

function makePaymentInfo(overrides: Partial<PaymentInfo> = {}): PaymentInfo {
  return {
    recipientPublicKey: recipientPubkeyHex,
    amount: '1000',
    fee: '100',
    recipientAmount: '900',
    stackflowNodeUrl: 'http://localhost:8787',
    serverAddress: 'SP1SERVER',
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('StackmailClient.getInbox', () => {
  it('returns inbox entries from the server', async () => {
    const entries = [
      { id: 'msg-1', from: 'SP1ALICE', sentAt: Date.now(), amount: '1000', claimed: false },
    ];
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ messages: entries }), { status: 200 }),
    );
    vi.stubGlobal('fetch', mockFetch);

    const client = new StackmailClient(makeConfig());
    const result = await client.getInbox();
    expect(result).toEqual(entries);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/inbox'),
      expect.objectContaining({ headers: expect.objectContaining({ 'x-stackmail-auth': expect.any(String) }) }),
    );
  });

  it('throws StackmailError on non-2xx response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'auth-expired' }), { status: 401 }),
    ));

    const client = new StackmailClient(makeConfig());
    await expect(client.getInbox()).rejects.toBeInstanceOf(StackmailError);
    await expect(client.getInbox()).rejects.toThrow('401');
  });
});

describe('StackmailClient.send', () => {
  it('fetches payment info and posts a message', async () => {
    const paymentInfo = makePaymentInfo();
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(paymentInfo), { status: 200 })) // GET /payment-info
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, messageId: 'msg-123' }), { status: 200 })); // POST /messages

    vi.stubGlobal('fetch', mockFetch);

    const client = new StackmailClient(makeConfig());
    const result = await client.send({ to: 'SP1BOB', body: 'Hello Bob' });
    expect(result.messageId).toBe('msg-123');
    expect(mockFetch).toHaveBeenCalledTimes(2);

    // First call: GET /payment-info/SP1BOB
    expect(mockFetch.mock.calls[0][0]).toContain('/payment-info/SP1BOB');
    // Second call: POST /messages/SP1BOB
    expect(mockFetch.mock.calls[1][0]).toContain('/messages/SP1BOB');
    expect(mockFetch.mock.calls[1][1]?.method).toBe('POST');
  });

  it('throws StackmailError when recipient is not registered', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: 'recipient-not-found' }), { status: 404 }),
    ));

    const client = new StackmailClient(makeConfig());
    const err = await client.send({ to: 'SP1UNKNOWN', body: 'Hi' }).catch(e => e);
    expect(err).toBeInstanceOf(StackmailError);
    expect(err.statusCode).toBe(404);
    expect(err.reason).toBe('recipient-not-found');
  });
});

describe('StackmailClient.claim', () => {
  it('decrypts message and reveals secret to server', async () => {
    // Create a real encrypted message so decryption actually works
    const secretHex = randomBytes(32).toString('hex');
    const hashedSecretHex = hashSecret(secretHex);
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, subject: 'Test', body: 'Hello claim test' },
      recipientPubkeyHex,
    );

    const msgId = 'msg-claim-1';
    const mockFetch = vi.fn()
      // GET /inbox/:id/preview
      .mockResolvedValueOnce(new Response(JSON.stringify({
        messageId: msgId,
        from: 'SP1SENDER',
        sentAt: Date.now(),
        amount: '1000',
        encryptedPayload,
        hashedSecret: hashedSecretHex,
        pendingPayment: null,
      }), { status: 200 }))
      // POST /inbox/:id/claim
      .mockResolvedValueOnce(new Response(JSON.stringify({
        message: {
          id: msgId,
          from: 'SP1SENDER',
          to: 'SP1RECIPIENT',
          sentAt: Date.now(),
          amount: '1000',
          fee: '100',
          paymentId: 'pay-1',
          encryptedPayload,
        },
        pendingPayment: null,
      }), { status: 200 }));

    vi.stubGlobal('fetch', mockFetch);

    const client = new StackmailClient(makeConfig());
    const result = await client.claim(msgId);

    expect(result.id).toBe(msgId);
    expect(result.subject).toBe('Test');
    expect(result.body).toBe('Hello claim test');

    // The claim call should have sent the correct secret
    const claimCall = mockFetch.mock.calls[1];
    const claimBody = JSON.parse(claimCall[1].body as string) as { secret: string };
    expect(claimBody.secret).toBe(secretHex);
  });

  it('throws StackmailError if server rejects the claim', async () => {
    const secretHex = randomBytes(32).toString('hex');
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, body: 'test' },
      recipientPubkeyHex,
    );

    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        encryptedPayload,
        hashedSecret: hashSecret(secretHex),
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'already-claimed' }), { status: 409 }))
    );

    const client = new StackmailClient(makeConfig());
    const err = await client.claim('msg-already-done').catch(e => e);
    expect(err).toBeInstanceOf(StackmailError);
    expect(err.statusCode).toBe(409);
  });
});

describe('StackmailClient.poll', () => {
  it('claims all unclaimed messages and returns results', async () => {
    const secretHex = randomBytes(32).toString('hex');
    const encryptedPayload = encryptMail(
      { v: 1, secret: secretHex, body: 'Poll test message' },
      recipientPubkeyHex,
    );
    const msgId = 'msg-poll-1';

    const mockFetch = vi.fn()
      // GET /inbox
      .mockResolvedValueOnce(new Response(JSON.stringify({
        messages: [{ id: msgId, from: 'SP1BOB', sentAt: Date.now(), amount: '1000', claimed: false }],
      }), { status: 200 }))
      // GET /inbox/:id/preview
      .mockResolvedValueOnce(new Response(JSON.stringify({
        encryptedPayload,
        hashedSecret: hashSecret(secretHex),
      }), { status: 200 }))
      // POST /inbox/:id/claim
      .mockResolvedValueOnce(new Response(JSON.stringify({
        message: {
          id: msgId, from: 'SP1BOB', to: 'SP1RECIPIENT',
          sentAt: Date.now(), amount: '1000', fee: '100', paymentId: 'pay-1', encryptedPayload,
        },
        pendingPayment: null,
      }), { status: 200 }));

    vi.stubGlobal('fetch', mockFetch);

    const client = new StackmailClient(makeConfig());
    const result = await client.poll();

    expect(result.inbox).toHaveLength(1);
    expect(result.claimed).toHaveLength(1);
    expect(result.claimed[0].body).toBe('Poll test message');
    expect(result.errors).toHaveLength(0);
  });

  it('collects errors without throwing when a claim fails', async () => {
    vi.stubGlobal('fetch', vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        messages: [{ id: 'msg-broken', from: 'SP1X', sentAt: Date.now(), amount: '1000', claimed: false }],
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'not-found' }), { status: 404 }))
    );

    const client = new StackmailClient(makeConfig());
    const result = await client.poll();

    expect(result.claimed).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].messageId).toBe('msg-broken');
  });
});
