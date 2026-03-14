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
    encryptedPayload: {
      v: 1,
      epk: '02' + 'aa'.repeat(32),
      iv: 'bb'.repeat(12),
      data: 'cc'.repeat(48),
    },
    pendingPayment: { stateProof: { nonce: 1, sig: 'abc' }, amount: '900', hashedSecret: 'abc123hashedsecret' },
    deliveryState: 'ready',
    claimed: false,
    paymentSettled: false,
    ...overrides,
  };
}

describe('SqliteMessageStore', () => {
  it('initializes without error', async () => {
    await expect(makeStore().init()).resolves.toBeUndefined();
  });

  describe('public key registry', () => {
    it('saves and retrieves a registered recipient public key', async () => {
      const store = makeStore();
      await store.init();
      await store.savePublicKey('SP1RECIPIENT', '02' + '11'.repeat(32));
      await expect(store.getPublicKey('SP1RECIPIENT')).resolves.toBe('02' + '11'.repeat(32));
    });

    it('updates an existing recipient public key', async () => {
      const store = makeStore();
      await store.init();
      await store.savePublicKey('SP1RECIPIENT', '02' + '11'.repeat(32));
      await store.savePublicKey('SP1RECIPIENT', '03' + '22'.repeat(32));
      await expect(store.getPublicKey('SP1RECIPIENT')).resolves.toBe('03' + '22'.repeat(32));
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
        encryptedPayload: {
          v: 1,
          epk: '03' + 'aabb'.repeat(16),
          iv: 'ccdd'.repeat(6),
          data: 'eeff'.repeat(48),
        },
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
      const msg = makeMessage({ pendingPayment: null, deliveryState: 'deferred', deferredReason: 'no-recipient-tap' });
      await store.saveMessage(msg);
      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.pendingPayment).toBeNull();
      expect(retrieved?.deliveryState).toBe('deferred');
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

    it('marks a message previewed and excludes cancelled messages from inbox', async () => {
      const store = makeStore();
      await store.init();
      const previewed = makeMessage({ to: 'SP1ALICE' });
      const cancelled = makeMessage({ to: 'SP1ALICE' });
      await store.saveMessage(previewed);
      await store.saveMessage(cancelled);
      const previewedRow = await store.markMessagePreviewed(previewed.id, 'SP1ALICE', Date.now());
      expect(previewedRow?.deliveryState).toBe('previewed');
      const cancelledRow = await store.cancelMessageBySender(cancelled.id, cancelled.from, Date.now());
      expect(cancelledRow?.deliveryState).toBe('cancelled');
      const inbox = await store.getInbox('SP1ALICE', {});
      expect(inbox.map(m => m.id)).toContain(previewed.id);
      expect(inbox.map(m => m.id)).not.toContain(cancelled.id);
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

    it('records settlement artifacts', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage();
      await store.saveMessage(msg);
      await store.claimMessage(msg.id, msg.to);
      await store.recordSettlement({
        messageId: msg.id,
        paymentId: msg.paymentId,
        recipientAddr: msg.to,
        hashedSecret: msg.hashedSecret,
        secret: '11'.repeat(32),
        pendingPayment: msg.pendingPayment,
        settledAt: Date.now(),
      });
      const settlement = await store.getSettlement(msg.id);
      expect(settlement?.messageId).toBe(msg.id);
      expect(settlement?.paymentId).toBe(msg.paymentId);
      expect(settlement?.secret).toBe('11'.repeat(32));
    });

    it('activates deferred messages when pending payment becomes available', async () => {
      const store = makeStore();
      await store.init();
      const msg = makeMessage({
        pendingPayment: null,
        deliveryState: 'deferred',
        deferredReason: 'insufficient-recipient-liquidity',
        deferredUntil: Date.now() + 60_000,
      });
      await store.saveMessage(msg);
      expect((await store.getInbox(msg.to, {})).length).toBe(0);
      await store.activateDeferredMessage(msg.id, msg.to, {
        stateProof: { nonce: 2, sig: 'def' },
        amount: '900',
        hashedSecret: msg.hashedSecret,
      });
      const retrieved = await store.getMessage(msg.id, msg.to);
      expect(retrieved?.deliveryState).toBe('ready');
      expect(retrieved?.pendingPayment?.amount).toBe('900');
      expect((await store.getInbox(msg.to, {})).length).toBe(1);
    });

    it('counts pending messages per sender and per recipient', async () => {
      const store = makeStore();
      await store.init();
      const msg1 = makeMessage({ from: 'SP1SENDER1', to: 'SP1ALICE' });
      const msg2 = makeMessage({ from: 'SP1SENDER1', to: 'SP1ALICE' });
      const msg3 = makeMessage({ from: 'SP1SENDER2', to: 'SP1ALICE' });
      const msg4 = makeMessage({ from: 'SP1SENDER1', to: 'SP1BOB' });
      await store.saveMessage(msg1);
      await store.saveMessage(msg2);
      await store.saveMessage(msg3);
      await store.saveMessage(msg4);
      await store.claimMessage(msg2.id, 'SP1ALICE');

      expect(await store.countPendingFromSender('SP1SENDER1', 'SP1ALICE')).toBe(1);
      expect(await store.countPendingToRecipient('SP1ALICE')).toBe(2);
    });

    it('counts deferred messages separately', async () => {
      const store = makeStore();
      await store.init();
      await store.saveMessage(makeMessage({
        from: 'SP1SENDER1',
        to: 'SP1ALICE',
        pendingPayment: null,
        deliveryState: 'deferred',
        deferredReason: 'no-recipient-tap',
        deferredUntil: Date.now() + 60_000,
      }));
      await store.saveMessage(makeMessage({
        from: 'SP1SENDER1',
        to: 'SP1ALICE',
        pendingPayment: null,
        deliveryState: 'deferred',
        deferredReason: 'insufficient-recipient-liquidity',
        deferredUntil: Date.now() + 60_000,
      }));
      await store.saveMessage(makeMessage({
        from: 'SP1SENDER2',
        to: 'SP1BOB',
        pendingPayment: null,
        deliveryState: 'deferred',
        deferredReason: 'no-recipient-tap',
        deferredUntil: Date.now() + 60_000,
      }));
      expect(await store.countDeferredFromSender('SP1SENDER1', 'SP1ALICE')).toBe(2);
      expect(await store.countDeferredToRecipient('SP1ALICE')).toBe(2);
      expect(await store.countDeferredGlobal()).toBe(3);
    });
  });

});
