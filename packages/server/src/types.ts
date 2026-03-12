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
  /** @deprecated kept for payment-info response compatibility */
  stackflowNodeUrl: string;
  /** Standard principal used to verify server signatures (derived from private key by default) */
  serverStxAddress: string;
  /** Hex private key used by the reservoir to sign outgoing state updates */
  serverPrivateKey: string;
  /** StackFlow contract ID this server operates (e.g. SP...stackflow-sbtc-0-6-0) */
  sfContractId: string;
  /** Reservoir contract principal (e.g. SP....sm-reservoir) for tap onboarding */
  reservoirContractId: string;
  /** Stacks chain ID: 1 = mainnet, 2147483648 = testnet/devnet */
  chainId: number;
  messagePriceSats: string;
  minFeeSats: string;
  /** Max unclaimed messages allowed from a single sender to a single recipient */
  maxPendingPerSender: number;
  /** Max total unclaimed messages allowed for a single recipient inbox */
  maxPendingPerRecipient: number;
  inboxSessionTtlMs: number;
}

export function loadConfig(): Config {
  const network = (process.env.STACKMAIL_STACKS_NETWORK ?? 'mainnet').toLowerCase();
  const chainId = network === 'mainnet' ? 1 : 2147483648;
  return {
    host: process.env.STACKMAIL_HOST ?? '0.0.0.0',
    port: parseInt(process.env.STACKMAIL_PORT ?? '8800', 10),
    dbBackend: (process.env.STACKMAIL_DB_BACKEND ?? 'sqlite') as 'sqlite' | 'postgres',
    dbFile: process.env.STACKMAIL_DB_FILE ?? './data/stackmail.db',
    dbUrl: process.env.STACKMAIL_DB_URL,
    maxEncryptedBytes: parseInt(process.env.STACKMAIL_MAX_ENCRYPTED_BYTES ?? '65536', 10),
    authTimestampTtlMs: parseInt(process.env.STACKMAIL_AUTH_TIMESTAMP_TTL_MS ?? '300000', 10),
    stackflowNodeUrl: process.env.STACKMAIL_STACKFLOW_NODE_URL ?? '',
    serverStxAddress: process.env.STACKMAIL_SERVER_STX_ADDRESS ?? '',
    serverPrivateKey: process.env.STACKMAIL_SERVER_PRIVATE_KEY ?? '',
    sfContractId: process.env.STACKMAIL_SF_CONTRACT_ID ?? '',
    reservoirContractId: process.env.STACKMAIL_RESERVOIR_CONTRACT_ID ?? '',
    chainId,
    messagePriceSats: process.env.STACKMAIL_MESSAGE_PRICE_SATS ?? '1000',
    minFeeSats: process.env.STACKMAIL_MIN_FEE_SATS ?? '100',
    maxPendingPerSender: parseInt(process.env.STACKMAIL_MAX_PENDING_PER_SENDER ?? '5', 10),
    maxPendingPerRecipient: parseInt(process.env.STACKMAIL_MAX_PENDING_PER_RECIPIENT ?? '20', 10),
    inboxSessionTtlMs: parseInt(process.env.STACKMAIL_INBOX_SESSION_TTL_MS ?? '300000', 10),
  };
}
