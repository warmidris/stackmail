import type { EncryptedMail } from '@stackmail/crypto';

export type { EncryptedMail };

// ─── Wire types (over-the-network) ───────────────────────────────────────────

/**
 * Returned to sender before they compose a message.
 * Contains everything needed to encrypt the payload and build the payment proof.
 */
export interface PaymentInfo {
  paymentId: string;
  /** SHA-256 hash of R — sender embeds this in their StackFlow state update */
  hashedSecret: string;
  /** Recipient's compressed secp256k1 pubkey (33 bytes hex) — sender encrypts to this */
  recipientPublicKey: string;
  /** Total amount sender must pay, in token base units */
  amount: string;
  /** Server's cut */
  fee: string;
  /** What recipient receives (amount - fee) */
  recipientAmount: string;
  /** Server's StackFlow node URL, for the indirect x402 payment */
  stackflowNodeUrl: string;
  /** Server's STX address */
  serverAddress: string;
  /** Unix ms — this paymentId expires and cannot be reused after this */
  expiresAt: number;
}

/**
 * Pending outgoing StackFlow state update from server → recipient,
 * locked by the same hashedSecret. Sent to recipient when they poll,
 * so they can verify the payment before revealing R.
 */
export interface PendingPayment {
  /** Full StackFlow state proof, signed by server */
  stateProof: Record<string, unknown>;
  /** Amount offered to recipient */
  amount: string;
  hashedSecret: string;
}

/** Inbox listing entry — no body, no secret */
export interface InboxEntry {
  id: string;
  from: string;
  sentAt: number;
  /** Payment offered to recipient if they claim */
  amount: string;
  claimed: boolean;
}

/** Full message returned after claiming */
export interface MailMessage {
  id: string;
  from: string;
  to: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  /** Encrypted payload — recipient decrypts this to get subject, body, and secret */
  encryptedPayload: EncryptedMail;
}

// ─── DB / internal ───────────────────────────────────────────────────────────

export interface StoredMessage {
  id: string;
  from: string;
  to: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  hashedSecret: string;
  encryptedPayload: EncryptedMail;
  /** Server's signed outgoing state update to recipient, created at receipt time */
  pendingPayment: PendingPayment | null;
  claimed: boolean;
  claimedAt?: number;
  paymentSettled: boolean;
}

export interface InboxQuery {
  limit?: number;
  before?: number;
  includeClaimed?: boolean;
}

// ─── Config ──────────────────────────────────────────────────────────────────

export interface Config {
  host: string;
  port: number;
  dbBackend: 'sqlite' | 'postgres';
  dbFile: string;
  dbUrl?: string;
  maxEncryptedBytes: number;
  authTimestampTtlMs: number;
  stackflowNodeUrl: string;
  serverStxAddress: string;
  messagePriceSats: string;
  minFeeSats: string;
}

export function loadConfig(): Config {
  return {
    host: process.env.STACKMAIL_HOST ?? '127.0.0.1',
    port: parseInt(process.env.STACKMAIL_PORT ?? '8800', 10),
    dbBackend: (process.env.STACKMAIL_DB_BACKEND ?? 'sqlite') as 'sqlite' | 'postgres',
    dbFile: process.env.STACKMAIL_DB_FILE ?? './data/stackmail.db',
    dbUrl: process.env.STACKMAIL_DB_URL,
    // Max size of the encrypted payload blob in bytes (covers body + subject + secret overhead)
    maxEncryptedBytes: parseInt(process.env.STACKMAIL_MAX_ENCRYPTED_BYTES ?? '65536', 10),
    authTimestampTtlMs: parseInt(process.env.STACKMAIL_AUTH_TIMESTAMP_TTL_MS ?? '300000', 10),
    stackflowNodeUrl: process.env.STACKMAIL_STACKFLOW_NODE_URL ?? 'http://127.0.0.1:8787',
    serverStxAddress: process.env.STACKMAIL_SERVER_STX_ADDRESS ?? '',
    messagePriceSats: process.env.STACKMAIL_MESSAGE_PRICE_SATS ?? '1000',
    minFeeSats: process.env.STACKMAIL_MIN_FEE_SATS ?? '100',
  };
}
