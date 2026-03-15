import type {
  StoredMessage,
  InboxEntry,
  MailMessage,
  InboxQuery,
  PendingPayment,
  EncryptedMail,
  SettlementRecord,
  DeferredReason,
} from './types.js';

// ─── Interface ───────────────────────────────────────────────────────────────

export interface MessageStore {
  init(): Promise<void>;

  // Recipient public key registry
  savePublicKey(addr: string, pubkeyHex: string): Promise<void>;
  getPublicKey(addr: string): Promise<string | null>;

  // Payment info lifecycle (single-use, expires)
  savePendingPaymentInfo(info: {
    paymentId: string;
    hashedSecret: string;
    secret: string;         // server holds R server-side until recipient claims
    recipientAddr: string;
    amount: string;
    fee: string;
    expiresAt: number;
  }): Promise<void>;
  consumePendingPaymentInfo(paymentId: string): Promise<{
    hashedSecret: string;
    secret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
  } | null>;

  // Messages
  saveMessage(msg: StoredMessage): Promise<void>;
  getInbox(addr: string, query: InboxQuery): Promise<InboxEntry[]>;
  getMessage(id: string, recipientAddr: string): Promise<StoredMessage | null>;
  getMessageForSender(id: string, senderAddr: string): Promise<StoredMessage | null>;
  claimMessage(id: string, recipientAddr: string): Promise<MailMessage>;
  getClaimedMessage(id: string, recipientAddr: string): Promise<MailMessage | null>;
  markPaymentSettled(paymentId: string): Promise<void>;
  markMessagePreviewed(id: string, recipientAddr: string, previewedAt: number): Promise<StoredMessage | null>;
  cancelMessageBySender(id: string, senderAddr: string, cancelledAt: number): Promise<StoredMessage | null>;
  recordSettlement(record: SettlementRecord): Promise<void>;
  getSettlement(messageId: string): Promise<SettlementRecord | null>;
  activateDeferredMessage(id: string, recipientAddr: string, pendingPayment: PendingPayment): Promise<void>;
  getDeferredMessagesForRecipient(addr: string, now: number, limit: number): Promise<StoredMessage[]>;
  expireDeferredMessages(now: number): Promise<number>;

  /** Count unclaimed messages from a given sender to a given recipient */
  countPendingFromSender(fromAddr: string, toAddr: string): Promise<number>;
  /** Count all unclaimed messages currently waiting for a recipient */
  countPendingToRecipient(toAddr: string): Promise<number>;
  /** Count deferred sender-paid messages from a given sender to a given recipient */
  countDeferredFromSender(fromAddr: string, toAddr: string): Promise<number>;
  /** Count deferred sender-paid messages currently queued for a recipient */
  countDeferredToRecipient(toAddr: string): Promise<number>;
  /** Count all deferred sender-paid messages on this server */
  countDeferredGlobal(): Promise<number>;

  /** Aggregate stats for admin dashboard */
  getStats(): Promise<{
    totalMailboxes: number;
    totalMessages: number;
    messagesClaimed: number;
    messagesUnclaimed: number;
    totalVolume: string;
    totalFees: string;
    uniqueSenders: number;
    uniqueRecipients: number;
  }>;
}

// ─── SQLite implementation ────────────────────────────────────────────────────

export class SqliteMessageStore implements MessageStore {
  private db: import('better-sqlite3').Database | null = null;
  private readonly dbFile: string;

  constructor(dbFile: string) {
    this.dbFile = dbFile;
  }

  async init(): Promise<void> {
    const { default: Database } = await import('better-sqlite3');
    this.db = new Database(this.dbFile);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');
    this.db.pragma('foreign_keys = ON');
    this.migrate();
  }

  private migrate(): void {
    const db = this.assertDb();
    db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      -- Single-use payment parameters generated for each send.
      -- Consumed (deleted) when the corresponding message is received.
      CREATE TABLE IF NOT EXISTS pending_payment_info (
        payment_id    TEXT PRIMARY KEY,
        hashed_secret TEXT NOT NULL,
        secret        TEXT NOT NULL,   -- R, held server-side
        recipient_addr TEXT NOT NULL,
        amount        TEXT NOT NULL,
        fee           TEXT NOT NULL,
        expires_at    INTEGER NOT NULL,
        created_at    INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
      );
      CREATE INDEX IF NOT EXISTS idx_ppi_expires ON pending_payment_info (expires_at);

      -- Messages: body never returned in listing; only after claim.
      CREATE TABLE IF NOT EXISTS messages (
        id                TEXT PRIMARY KEY,
        from_addr         TEXT NOT NULL,
        to_addr           TEXT NOT NULL,
        sent_at           INTEGER NOT NULL,
        amount            TEXT NOT NULL,
        fee               TEXT NOT NULL,
        payment_id        TEXT NOT NULL,
        hashed_secret     TEXT NOT NULL,
        -- ECIES-encrypted payload (JSON blob: EncryptedMail)
        encrypted_payload TEXT NOT NULL,
        -- Server's signed outgoing StackFlow state update (JSON blob: PendingPayment | null)
        pending_payment   TEXT,
        delivery_state    TEXT NOT NULL DEFAULT 'ready',
        deferred_reason   TEXT,
        deferred_until    INTEGER,
        previewed_at      INTEGER,
        cancelled_at      INTEGER,
        claimed           INTEGER NOT NULL DEFAULT 0,
        claimed_at        INTEGER,
        payment_settled   INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_msg_inbox ON messages (to_addr, sent_at DESC);
      CREATE INDEX IF NOT EXISTS idx_msg_payment ON messages (payment_id);

      CREATE TABLE IF NOT EXISTS public_keys (
        stx_address TEXT PRIMARY KEY,
        pubkey_hex  TEXT NOT NULL,
        updated_at  INTEGER NOT NULL DEFAULT (unixepoch('now') * 1000)
      );

      CREATE TABLE IF NOT EXISTS message_settlements (
        message_id       TEXT PRIMARY KEY,
        payment_id       TEXT NOT NULL,
        recipient_addr   TEXT NOT NULL,
        hashed_secret    TEXT NOT NULL,
        secret           TEXT NOT NULL,
        pending_payment  TEXT,
        settled_at       INTEGER NOT NULL
      );
    `);
    const cols = db.prepare(`PRAGMA table_info('messages')`).all() as Array<{ name: string }>;
    const colSet = new Set(cols.map(c => c.name));
    const ensureColumn = (name: string, typeSql: string): void => {
      if (!colSet.has(name)) db.exec(`ALTER TABLE messages ADD COLUMN ${name} ${typeSql};`);
    };
    ensureColumn('delivery_state', "TEXT NOT NULL DEFAULT 'ready'");
    ensureColumn('deferred_reason', 'TEXT');
    ensureColumn('deferred_until', 'INTEGER');
    ensureColumn('previewed_at', 'INTEGER');
    ensureColumn('cancelled_at', 'INTEGER');
    db.exec('CREATE INDEX IF NOT EXISTS idx_msg_deferred ON messages (to_addr, delivery_state, deferred_until, sent_at DESC);');
    db.prepare("INSERT OR IGNORE INTO meta VALUES ('version', '1')").run();
  }

  private assertDb(): import('better-sqlite3').Database {
    if (!this.db) throw new Error('Store not initialized — call init() first');
    return this.db;
  }

  async savePendingPaymentInfo(info: {
    paymentId: string;
    hashedSecret: string;
    secret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
    expiresAt: number;
  }): Promise<void> {
    this.assertDb().prepare(`
      INSERT INTO pending_payment_info
        (payment_id, hashed_secret, secret, recipient_addr, amount, fee, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(info.paymentId, info.hashedSecret, info.secret, info.recipientAddr, info.amount, info.fee, info.expiresAt);
  }

  async savePublicKey(addr: string, pubkeyHex: string): Promise<void> {
    this.assertDb().prepare(`
      INSERT INTO public_keys (stx_address, pubkey_hex, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(stx_address) DO UPDATE SET
        pubkey_hex = excluded.pubkey_hex,
        updated_at = excluded.updated_at
    `).run(addr, pubkeyHex, Date.now());
  }

  async getPublicKey(addr: string): Promise<string | null> {
    const row = this.assertDb()
      .prepare('SELECT pubkey_hex FROM public_keys WHERE stx_address = ?')
      .get(addr) as { pubkey_hex: string } | undefined;
    return row?.pubkey_hex ?? null;
  }

  async consumePendingPaymentInfo(paymentId: string): Promise<{
    hashedSecret: string;
    secret: string;
    recipientAddr: string;
    amount: string;
    fee: string;
  } | null> {
    const db = this.assertDb();
    const row = db.prepare(`
      SELECT hashed_secret, secret, recipient_addr, amount, fee, expires_at
      FROM pending_payment_info WHERE payment_id = ?
    `).get(paymentId) as Record<string, unknown> | undefined;

    if (!row) return null;
    if ((row.expires_at as number) < Date.now()) {
      db.prepare('DELETE FROM pending_payment_info WHERE payment_id = ?').run(paymentId);
      return null;
    }

    // Single-use: consume it
    db.prepare('DELETE FROM pending_payment_info WHERE payment_id = ?').run(paymentId);
    return {
      hashedSecret: row.hashed_secret as string,
      secret: row.secret as string,
      recipientAddr: row.recipient_addr as string,
      amount: row.amount as string,
      fee: row.fee as string,
    };
  }

  async saveMessage(msg: StoredMessage): Promise<void> {
    this.assertDb().prepare(`
      INSERT INTO messages
        (id, from_addr, to_addr, sent_at, amount, fee, payment_id, hashed_secret,
         encrypted_payload, pending_payment, delivery_state, deferred_reason, deferred_until, previewed_at, cancelled_at, claimed)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      msg.id,
      msg.from,
      msg.to,
      msg.sentAt,
      msg.amount,
      msg.fee,
      msg.paymentId,
      msg.hashedSecret,
      JSON.stringify(msg.encryptedPayload),
      msg.pendingPayment ? JSON.stringify(msg.pendingPayment) : null,
      msg.deliveryState ?? 'ready',
      msg.deferredReason ?? null,
      msg.deferredUntil ?? null,
      msg.previewedAt ?? null,
      msg.cancelledAt ?? null,
    );
  }

  async getInbox(addr: string, query: InboxQuery): Promise<InboxEntry[]> {
    const limit = Math.min(query.limit ?? 50, 100);
    const before = query.before ?? Date.now() + 1000;
    const stateClause = query.includeClaimed
      ? "AND delivery_state IN ('ready', 'previewed', 'settled')"
      : "AND delivery_state IN ('ready', 'previewed') AND claimed = 0";

    const rows = this.assertDb().prepare(`
      SELECT id, from_addr, sent_at, amount, claimed
      FROM messages
      WHERE to_addr = ? AND sent_at < ? ${stateClause}
      ORDER BY sent_at DESC
      LIMIT ?
    `).all(addr, before, limit) as Record<string, unknown>[];

    return rows.map(row => ({
      id: row.id as string,
      from: row.from_addr as string,
      sentAt: row.sent_at as number,
      amount: row.amount as string,
      claimed: Boolean(row.claimed),
    }));
  }

  async getMessage(id: string, recipientAddr: string): Promise<StoredMessage | null> {
    const row = this.assertDb()
      .prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ?')
      .get(id, recipientAddr) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToStored(row);
  }

  async getMessageForSender(id: string, senderAddr: string): Promise<StoredMessage | null> {
    const row = this.assertDb()
      .prepare('SELECT * FROM messages WHERE id = ? AND from_addr = ?')
      .get(id, senderAddr) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToStored(row);
  }

  async markMessagePreviewed(id: string, recipientAddr: string, previewedAt: number): Promise<StoredMessage | null> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ?')
      .get(id, recipientAddr) as Record<string, unknown> | undefined;
    if (!row) return null;
    const state = String(row.delivery_state ?? 'ready');
    if (state === 'ready') {
      db.prepare(`
        UPDATE messages
        SET delivery_state = 'previewed',
            previewed_at = COALESCE(previewed_at, ?)
        WHERE id = ? AND to_addr = ?
      `).run(previewedAt, id, recipientAddr);
      row.delivery_state = 'previewed';
      row.previewed_at = row.previewed_at ?? previewedAt;
    }
    return this.rowToStored(row);
  }

  async claimMessage(id: string, recipientAddr: string): Promise<MailMessage> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ?')
      .get(id, recipientAddr) as Record<string, unknown> | undefined;
    if (!row) throw new Error('message-not-found');
    if (row.claimed) throw new Error('already-claimed');
    if (row.delivery_state !== 'ready' && row.delivery_state !== 'previewed') throw new Error('message-not-claimable');

    db.prepare(`
      UPDATE messages
      SET claimed = 1,
          claimed_at = ?,
          payment_settled = 1,
          delivery_state = 'settled'
      WHERE id = ?
    `).run(Date.now(), id);
    return this.rowToMail(row);
  }

  async getClaimedMessage(id: string, recipientAddr: string): Promise<MailMessage | null> {
    const row = this.assertDb()
      .prepare("SELECT * FROM messages WHERE id = ? AND to_addr = ? AND delivery_state = 'settled'")
      .get(id, recipientAddr) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToMail(row);
  }

  async markPaymentSettled(paymentId: string): Promise<void> {
    this.assertDb()
      .prepare('UPDATE messages SET payment_settled = 1 WHERE payment_id = ?')
      .run(paymentId);
  }

  async cancelMessageBySender(id: string, senderAddr: string, cancelledAt: number): Promise<StoredMessage | null> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ? AND from_addr = ?')
      .get(id, senderAddr) as Record<string, unknown> | undefined;
    if (!row) return null;
    const state = String(row.delivery_state ?? 'ready');
    if (Boolean(row.claimed) || state === 'previewed' || state === 'settled' || state === 'cancelled') {
      return this.rowToStored(row);
    }
    db.prepare(`
      UPDATE messages
      SET delivery_state = 'cancelled',
          cancelled_at = ?,
          pending_payment = NULL
      WHERE id = ? AND from_addr = ?
    `).run(cancelledAt, id, senderAddr);
    row.delivery_state = 'cancelled';
    row.cancelled_at = cancelledAt;
    row.pending_payment = null;
    return this.rowToStored(row);
  }

  async recordSettlement(record: SettlementRecord): Promise<void> {
    this.assertDb().prepare(`
      INSERT INTO message_settlements
        (message_id, payment_id, recipient_addr, hashed_secret, secret, pending_payment, settled_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(message_id) DO UPDATE SET
        payment_id = excluded.payment_id,
        recipient_addr = excluded.recipient_addr,
        hashed_secret = excluded.hashed_secret,
        secret = excluded.secret,
        pending_payment = excluded.pending_payment,
        settled_at = excluded.settled_at
    `).run(
      record.messageId,
      record.paymentId,
      record.recipientAddr,
      record.hashedSecret,
      record.secret,
      record.pendingPayment ? JSON.stringify(record.pendingPayment) : null,
      record.settledAt,
    );
  }

  async getSettlement(messageId: string): Promise<SettlementRecord | null> {
    const row = this.assertDb()
      .prepare('SELECT * FROM message_settlements WHERE message_id = ?')
      .get(messageId) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      messageId: row.message_id as string,
      paymentId: row.payment_id as string,
      recipientAddr: row.recipient_addr as string,
      hashedSecret: row.hashed_secret as string,
      secret: row.secret as string,
      pendingPayment: row.pending_payment
        ? JSON.parse(row.pending_payment as string) as PendingPayment
        : null,
      settledAt: row.settled_at as number,
    };
  }

  async activateDeferredMessage(id: string, recipientAddr: string, pendingPayment: PendingPayment): Promise<void> {
    this.assertDb().prepare(`
      UPDATE messages
      SET pending_payment = ?,
          delivery_state = 'ready',
          deferred_reason = NULL,
          deferred_until = NULL
      WHERE id = ? AND to_addr = ? AND delivery_state = 'deferred'
    `).run(JSON.stringify(pendingPayment), id, recipientAddr);
  }

  async getDeferredMessagesForRecipient(addr: string, now: number, limit: number): Promise<StoredMessage[]> {
    const rows = this.assertDb().prepare(`
      SELECT *
      FROM messages
      WHERE to_addr = ?
        AND delivery_state = 'deferred'
        AND claimed = 0
        AND (deferred_until IS NULL OR deferred_until >= ?)
      ORDER BY sent_at ASC
      LIMIT ?
    `).all(addr, now, limit) as Record<string, unknown>[];
    return rows.map(row => this.rowToStored(row));
  }

  async expireDeferredMessages(now: number): Promise<number> {
    const result = this.assertDb().prepare(`
      DELETE FROM messages
      WHERE delivery_state = 'deferred'
        AND claimed = 0
        AND deferred_until IS NOT NULL
        AND deferred_until < ?
    `).run(now);
    return result.changes;
  }

  async countPendingFromSender(fromAddr: string, toAddr: string): Promise<number> {
    const row = this.assertDb()
      .prepare("SELECT COUNT(*) as cnt FROM messages WHERE from_addr = ? AND to_addr = ? AND claimed = 0 AND delivery_state IN ('ready', 'previewed')")
      .get(fromAddr, toAddr) as { cnt: number };
    return row?.cnt ?? 0;
  }

  async countPendingToRecipient(toAddr: string): Promise<number> {
    const row = this.assertDb()
      .prepare("SELECT COUNT(*) as cnt FROM messages WHERE to_addr = ? AND claimed = 0 AND delivery_state IN ('ready', 'previewed')")
      .get(toAddr) as { cnt: number };
    return row?.cnt ?? 0;
  }

  async countDeferredFromSender(fromAddr: string, toAddr: string): Promise<number> {
    const row = this.assertDb()
      .prepare("SELECT COUNT(*) as cnt FROM messages WHERE from_addr = ? AND to_addr = ? AND claimed = 0 AND delivery_state = 'deferred'")
      .get(fromAddr, toAddr) as { cnt: number };
    return row?.cnt ?? 0;
  }

  async countDeferredToRecipient(toAddr: string): Promise<number> {
    const row = this.assertDb()
      .prepare("SELECT COUNT(*) as cnt FROM messages WHERE to_addr = ? AND claimed = 0 AND delivery_state = 'deferred'")
      .get(toAddr) as { cnt: number };
    return row?.cnt ?? 0;
  }

  async countDeferredGlobal(): Promise<number> {
    const row = this.assertDb()
      .prepare("SELECT COUNT(*) as cnt FROM messages WHERE claimed = 0 AND delivery_state = 'deferred'")
      .get() as { cnt: number };
    return row?.cnt ?? 0;
  }

  async getStats(): Promise<{
    totalMailboxes: number;
    totalMessages: number;
    messagesClaimed: number;
    messagesUnclaimed: number;
    totalVolume: string;
    totalFees: string;
    uniqueSenders: number;
    uniqueRecipients: number;
  }> {
    const db = this.assertDb();
    const mailboxes = db.prepare("SELECT COUNT(*) as cnt FROM public_keys").get() as { cnt: number };
    const total = db.prepare("SELECT COUNT(*) as cnt FROM messages").get() as { cnt: number };
    const claimed = db.prepare("SELECT COUNT(*) as cnt FROM messages WHERE claimed = 1").get() as { cnt: number };
    const unclaimed = db.prepare("SELECT COUNT(*) as cnt FROM messages WHERE claimed = 0").get() as { cnt: number };
    const volume = db.prepare("SELECT COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total FROM messages").get() as { total: number };
    const fees = db.prepare("SELECT COALESCE(SUM(CAST(fee AS INTEGER)), 0) as total FROM messages").get() as { total: number };
    const senders = db.prepare("SELECT COUNT(DISTINCT from_addr) as cnt FROM messages").get() as { cnt: number };
    const recipients = db.prepare("SELECT COUNT(DISTINCT to_addr) as cnt FROM messages").get() as { cnt: number };
    return {
      totalMailboxes: mailboxes.cnt,
      totalMessages: total.cnt,
      messagesClaimed: claimed.cnt,
      messagesUnclaimed: unclaimed.cnt,
      totalVolume: volume.total.toString(),
      totalFees: fees.total.toString(),
      uniqueSenders: senders.cnt,
      uniqueRecipients: recipients.cnt,
    };
  }

  private rowToStored(row: Record<string, unknown>): StoredMessage {
    return {
      id: row.id as string,
      from: row.from_addr as string,
      to: row.to_addr as string,
      sentAt: row.sent_at as number,
      amount: row.amount as string,
      fee: row.fee as string,
      paymentId: row.payment_id as string,
      hashedSecret: row.hashed_secret as string,
      encryptedPayload: JSON.parse(row.encrypted_payload as string) as EncryptedMail,
      pendingPayment: row.pending_payment
        ? JSON.parse(row.pending_payment as string) as PendingPayment
        : null,
      deliveryState: (row.delivery_state as StoredMessage['deliveryState'] | undefined) ?? 'ready',
      deferredReason: (row.deferred_reason as DeferredReason | null | undefined) ?? undefined,
      deferredUntil: typeof row.deferred_until === 'number' ? row.deferred_until : undefined,
      previewedAt: typeof row.previewed_at === 'number' ? row.previewed_at : undefined,
      cancelledAt: typeof row.cancelled_at === 'number' ? row.cancelled_at : undefined,
      claimed: Boolean(row.claimed),
      claimedAt: row.claimed_at as number | undefined,
      paymentSettled: Boolean(row.payment_settled),
    };
  }

  private rowToMail(row: Record<string, unknown>): MailMessage {
    return {
      id: row.id as string,
      from: row.from_addr as string,
      to: row.to_addr as string,
      sentAt: row.sent_at as number,
      amount: row.amount as string,
      fee: row.fee as string,
      paymentId: row.payment_id as string,
      encryptedPayload: JSON.parse(row.encrypted_payload as string) as EncryptedMail,
    };
  }
}
