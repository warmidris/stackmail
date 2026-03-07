import type { EncryptedMail, MailPayload } from '@stackmail/crypto';
export type { EncryptedMail, MailPayload };

export interface InboxEntry {
  id: string;
  from: string;
  sentAt: number;
  amount: string;
  claimed: boolean;
}

/** Returned by the server after claiming — contains encrypted payload */
export interface MailMessage {
  id: string;
  from: string;
  to: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  encryptedPayload: EncryptedMail;
}

/** Decrypted message after calling client.claim() */
export interface DecryptedMessage {
  id: string;
  from: string;
  to: string;
  sentAt: number;
  amount: string;
  fee: string;
  paymentId: string;
  subject?: string;
  body: string;
}

/** Server's payment parameters for sending to an address */
export interface PaymentInfo {
  recipientPublicKey: string;   // 33-byte hex compressed secp256k1
  amount: string;
  fee: string;
  recipientAmount: string;
  stackflowNodeUrl: string;
  serverAddress: string;
}

/**
 * Server's signed outgoing payment state update (server → recipient, locked by H).
 * Recipient verifies this before revealing R.
 */
export interface PendingPayment {
  stateProof: Record<string, unknown>;
  amount: string;
  hashedSecret: string;
}

export interface SendOptions {
  /** Recipient STX address */
  to: string;
  subject?: string;
  body: string;
  /** Override the default server URL for this send */
  serverUrl?: string;
}

export interface PollResult {
  inbox: InboxEntry[];
  claimed: DecryptedMessage[];
  errors: Array<{ messageId: string; error: string }>;
}

export interface ClientConfig {
  /** Agent's STX address */
  address: string;
  /** Agent's compressed secp256k1 public key (33 bytes hex) */
  publicKey: string;
  /** Default stackmail server base URL */
  serverUrl: string;
  /**
   * Sign a message string with the agent's secp256k1 private key.
   * Must return a compact 64-byte ECDSA signature (r||s) as hex.
   */
  signer: (message: string) => Promise<string>;
  /**
   * Build an x402 payment proof for the StackFlow counterparty transfer endpoint.
   * Receives the hashedSecret (to embed in the state update) and payment parameters.
   * Returns a JSON string or base64url-encoded JSON of the transfer state proof.
   */
  paymentProofBuilder: (args: {
    hashedSecret: string;
    hashedSecretHex: string;
    paymentInfo: PaymentInfo;
  }) => Promise<string>;
  /**
   * Agent's secp256k1 private key (32 bytes hex) — used to decrypt messages.
   * Keep this in memory only; never log or persist.
   */
  privateKey: string;
}
