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
  /**
   * Off-chain dispute artifact for this claim.
   * Save this (especially secret + pendingPayment) so you can prove HTLC release later.
   * This covers the receive side only; callers still need to persist the latest
   * signed state for their own taps after sends.
   */
  claimProof: ClaimProofRecord;
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

export interface ClaimProofRecord {
  messageId: string;
  paymentId: string;
  recipient: string;
  secret: string;
  hashedSecret: string;
  claimedAt: number;
  pendingPayment: PendingPayment | null;
  proofVerified: boolean | null;
  verificationError?: string;
}

export interface SendOptions {
  /** Recipient STX address */
  to: string;
  /**
   * Recipient's compressed secp256k1 public key (33 bytes hex).
   * Look this up from the Stacks blockchain — any transaction sent by the recipient
   * reveals their public key via the Hiro API:
   *   GET https://api.mainnet.hiro.so/extended/v1/address/{addr}/transactions?limit=1
   *   → results[0].sender_public_key
   *
   * Future: BNSv2 zonefiles could carry a dedicated Stackmail encryption key,
   * allowing recipients to publish a key without needing prior transaction history.
   */
  recipientPublicKey: string;
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
   * Optional Stacks chain ID used for strict SIP-018 verification.
   * If omitted, verification will accept signatures valid for either
   * mainnet or testnet domains.
   */
  chainId?: number;
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
  /**
   * Optional hook to persist claim proofs (secret + pending payment + verification result)
   * for future dispute handling.
   * Agents should treat this as required in production and also persist their
   * own latest signed sender-side tap states separately.
   */
  saveClaimProof?: (proof: ClaimProofRecord) => Promise<void> | void;
}
