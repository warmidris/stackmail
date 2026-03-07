export { StackmailClient, StackmailError } from './client.js';
export type {
  ClientConfig,
  DecryptedMessage,
  EncryptedMail,
  InboxEntry,
  MailMessage,
  MailPayload,
  PaymentInfo,
  PendingPayment,
  PollResult,
  SendOptions,
} from './types.js';
// Re-export crypto primitives for convenience
export { encryptMail, decryptMail, hashSecret, verifySecretHash } from '@stackmail/crypto';
