import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { SqliteMessageStore } from './store.js';
import type { StoredMessage } from './types.js';

function makeStore() {
  return new SqliteMessageStore(':memory:');
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
    encryptedPayload: { v: 1, epk: 'aa'.repeat(33), iv: 'bb'.repeat(12), data: 'cc'.repeat(48) },
    pendingPayment: null,
    claimed: false,
    paymentSettled: false,
    ...overrides,
  };
}

describe('SqliteMessageStore', () => {
  it('initializes without error', async () => {
    await expect(makeStore().init()).resolves.toBeUndefined();
  });

  describe('public keys', () => {
    it('returns null for unknown address', async () => {
      const store = makeStore();
      await store.init();
      expect(await store.getPublicKey('SP1UNKNOWN')).toBeNull();
    });

    it('saves and retrieves a pubkey', async () => {
      const store = makeStore();
      await store.init();
      await store.savePublicKey('SP1ADDR', '0102030405');
      expect(await store.getPublicKey('SP1ADDR')).toBe('0102030405');
    });

    it('overwrites pubkey on upsert', async () => {
      const store = makeStore();
      await store.init();
      await store.savePublicKey('SP1ADDR', 'old');
      await store.savePublicKey('SP1ADDR', 'new');
      expect(await store.getPublicKey('SP1ADDR')).toBe('new');
    });
  });

  describe('messages', () => {
    it('saves and retrieves a message', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.id).toBe(msg.id);
      expect(retrieved?.from).toBe(msg.from);
      expect(retrieved?.amount).toBe(msg.amount);
      expect(retrieved?.hashedSecret).toBe(msg.hashedSecret);
      expect(retrieved?.claimed).toBe(false);
    });

    it('returns null for wrong recipient', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      expect(await store.getMessage(msg.id, 'SP1WRONG')).toBeNull();
    });

    it('stores and retrieves encryptedPayload correctly', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage({
        encryptedPayload: { v: 1, epk: 'aabb'.repeat(8), iv: 'ccdd'.repeat(3), data: 'eeff'.repeat(24) },
      });
      await store.saveMessage(msg);
      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.encryptedPayload).toEqual(msg.encryptedPayload);
    });

    it('stores and retrieves pendingPayment', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage({
        pendingPayment: { stateProof: { nonce: 42, sig: 'abc' }, amount: '900', hashedSecret: 'xyz' },
      });
      await store.saveMessage(msg);
      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.pendingPayment).toEqual(msg.pendingPayment);
    });

    it('null pendingPayment round-trips', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage({ pendingPayment: null });
      await store.saveMessage(msg);
      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.pendingPayment).toBeNull();
    });

    it('getInbox returns messages for recipient only', async () => {
      const store = makeStore();
      await store.init();
      const msg1 = makeMessage({ to: 'SP1ALICE', sentAt: Date.now() - 2 });
      const msg2 = makeMessage({ to: 'SP1ALICE', sentAt: Date.now() - 1 });
      const msg3 = makeMessage({ to: 'SP1BOB' });
      await store.saveMessage(msg1);
      await store.saveMessage(msg2);
      await store.saveMessage(msg3);

      const inbox = await store.getInbox('SP1ALICE', { limit: 50 });
      expect(inbox).toHaveLength(2);
      expect(inbox.map(m => m.id)).toContain(msg1.id);
      expect(inbox.map(m => m.id)).toContain(msg2.id);
    });

    it('getInbox excludes claimed messages by default', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage({ to: 'SP1ALICE' });
      await store.saveMessage(msg);
      await store.claimMessage(msg.id, 'SP1ALICE');

      expect(await store.getInbox('SP1ALICE', {})).toHaveLength(0);
      expect(await store.getInbox('SP1ALICE', { includeClaimed: true })).toHaveLength(1);
    });

    it('getInbox respects limit', async () => {
      const store = makeStore();
      await store.init();
      for (let i = 0; i < 5; i++) await store.saveMessage(makeMessage({ to: 'SP1ALICE' }));
      const inbox = await store.getInbox('SP1ALICE', { limit: 3 });
      expect(inbox).toHaveLength(3);
    });

    it('claims a message and marks it claimed', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);

      const claimed = await store.claimMessage(msg.id, msg.to);
      expect(claimed.id).toBe(msg.id);
      expect(claimed.encryptedPayload).toEqual(msg.encryptedPayload);

      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.claimed).toBe(true);
    });

    it('throws when claiming a non-existent message', async () => {
      const store = makeStore();
      await store.init();
      await expect(store.claimMessage('does-not-exist', 'SP1ADDR')).rejects.toThrow('message-not-found');
    });

    it('throws when claiming an already-claimed message', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      await store.claimMessage(msg.id, msg.to);
      await expect(store.claimMessage(msg.id, msg.to)).rejects.toThrow('already-claimed');
    });

    it('getClaimedMessage returns null for unclaimed', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      expect(await store.getClaimedMessage(msg.id, msg.to)).toBeNull();
    });

    it('getClaimedMessage returns message after claim', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      await store.claimMessage(msg.id, msg.to);
      const claimed = await store.getClaimedMessage(msg.id, msg.to);
      expect(claimed?.id).toBe(msg.id);
    });

    it('markPaymentSettled completes without error', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      await expect(store.markPaymentSettled(msg.paymentId)).resolves.toBeUndefined();
    });
  });
});
