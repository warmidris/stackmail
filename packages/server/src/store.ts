import type {
  StoredMessage,
  InboxEntry,
  MailMessage,
  InboxQuery,
  PendingPayment,
  EncryptedMail,
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
  claimMessage(id: string, recipientAddr: string): Promise<MailMessage>;
  getClaimedMessage(id: string, recipientAddr: string): Promise<MailMessage | null>;
  markPaymentSettled(paymentId: string): Promise<void>;

  /** Count unclaimed messages from a given sender to a given recipient */
  countPendingFromSender(fromAddr: string, toAddr: string): Promise<number>;
  /** Count all unclaimed messages currently waiting for a recipient */
  countPendingToRecipient(toAddr: string): Promise<number>;
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
    `);
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
         encrypted_payload, pending_payment, claimed)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
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
    );
  }

  async getInbox(addr: string, query: InboxQuery): Promise<InboxEntry[]> {
    const limit = Math.min(query.limit ?? 50, 100);
    const before = query.before ?? Date.now() + 1000;
    const claimedClause = query.includeClaimed ? '' : 'AND claimed = 0';

    const rows = this.assertDb().prepare(`
      SELECT id, from_addr, sent_at, amount, claimed
      FROM messages
      WHERE to_addr = ? AND sent_at < ? ${claimedClause}
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

  async claimMessage(id: string, recipientAddr: string): Promise<MailMessage> {
    const db = this.assertDb();
    const row = db.prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ?')
      .get(id, recipientAddr) as Record<string, unknown> | undefined;
    if (!row) throw new Error('message-not-found');
    if (row.claimed) throw new Error('already-claimed');

    db.prepare('UPDATE messages SET claimed = 1, claimed_at = ? WHERE id = ?').run(Date.now(), id);
    return this.rowToMail(row);
  }

  async getClaimedMessage(id: string, recipientAddr: string): Promise<MailMessage | null> {
    const row = this.assertDb()
      .prepare('SELECT * FROM messages WHERE id = ? AND to_addr = ? AND claimed = 1')
      .get(id, recipientAddr) as Record<string, unknown> | undefined;
    if (!row) return null;
    return this.rowToMail(row);
  }

  async markPaymentSettled(paymentId: string): Promise<void> {
    this.assertDb()
      .prepare('UPDATE messages SET payment_settled = 1 WHERE payment_id = ?')
      .run(paymentId);
  }

  async countPendingFromSender(fromAddr: string, toAddr: string): Promise<number> {
    const row = this.assertDb()
      .prepare('SELECT COUNT(*) as cnt FROM messages WHERE from_addr = ? AND to_addr = ? AND claimed = 0')
      .get(fromAddr, toAddr) as { cnt: number };
    return row?.cnt ?? 0;
  }

  async countPendingToRecipient(toAddr: string): Promise<number> {
    const row = this.assertDb()
      .prepare('SELECT COUNT(*) as cnt FROM messages WHERE to_addr = ? AND claimed = 0')
      .get(toAddr) as { cnt: number };
    return row?.cnt ?? 0;
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
