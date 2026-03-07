# Stackmail Design

Micropayment-gated mailbox for AI agents, built on StackFlow payment channels.

Agents poll. No inbound ports required.

## Core Principles

- **No inbound listeners on agents.** Agents are pure HTTP clients — they poll periodically.
- **Sender generates the secret.** The HTLC preimage R is created by the sender, encrypted for the recipient. The server never learns R until the recipient chooses to reveal it.
- **End-to-end encrypted.** Subject + body + payment secret are encrypted together with the recipient's secp256k1 public key. The server stores only ciphertext.
- **Hub-and-spoke payments.** Both sender and recipient hold channels with the mailbox server. Server routes payment (sender → server → recipient), keeping a fee.
- **StackFlow channels settle on-chain only at open/close.** Every message is a single off-chain state update.
- **Pluggable storage.** SQLite for development, PostgreSQL for production.

## Encrypted Payload

Subject, body, and HTLC secret are encrypted together as a single `MailPayload`:

```typescript
interface MailPayload {
  v: 1;
  secret: string;    // 32-byte hex — HTLC preimage R; sha256(secret) == hashedSecret
  subject?: string;
  body: string;
}
```

Encryption uses ECIES over secp256k1 (recipient's STX public key):

```typescript
interface EncryptedMail {
  v: 1;
  epk: string;   // sender's ephemeral compressed pubkey (33 bytes hex)
  iv: string;    // AES-GCM nonce (12 bytes hex)
  data: string;  // AES-256-GCM(ciphertext || auth_tag) hex
}
```

Scheme: `ECDH(ephemeral_sk, recipient_pk)` → `HKDF-SHA256` → `AES-256-GCM`

No external dependencies — uses only Node.js built-in `crypto`.

## Payment Flow

```
Sender                          Server                        Recipient
  |                               |                              |
  | GET /payment-info/{to}        |                              |
  |------------------------------>|                              |
  |  { recipientPublicKey, amount, fee, stackflowNodeUrl }       |
  |<------------------------------|                              |
  |                               |                              |
  | generate R (32 random bytes)  |                              |
  | H = sha256(R)                 |                              |
  | enc = encrypt({secret:R, subject, body}, recipientPublicKey) |
  | proof = SF state update: "pay amount to server, locked by H" |
  |                               |                              |
  | POST /messages/{to}           |                              |
  |   x-x402-payment: proof       |                              |
  |   body: { from, encryptedPayload: enc }                      |
  |------------------------------>|                              |
  |                 verify proof via SF node                     |
  |                 create outgoing SF state:                    |
  |                   "pay (amount-fee) to recipient, locked H"  |
  |                 store message + pendingPayment               |
  |  { ok: true, messageId }      |                              |
  |<------------------------------|                              |
  |                               |                              |
  |                               |  GET /inbox (polls)          |
  |                               |<-----------------------------|
  |                               |  [{ id, from, sentAt, amount }]
  |                               |----------------------------->|
  |                               |                              |
  |                               |  GET /inbox/{id}/preview     |
  |                               |<-----------------------------|
  |                               |  { encryptedPayload,         |
  |                               |    pendingPayment, H }       |
  |                               |----------------------------->|
  |                               |              decrypt enc → R |
  |                               |              verify sha256(R)==H ✓
  |                               |              verify pendingPayment sig ✓
  |                               |                              |
  |                               |  POST /inbox/{id}/claim      |
  |                               |    { secret: R }             |
  |                               |<-----------------------------|
  |                               |  verify sha256(R)==H ✓       |
  |                               |  settle both SF channels     |
  |                               |  { message, pendingPayment } |
  |                               |----------------------------->|
```

## Why Sender Generates the Secret

- Server never knows R until the recipient chooses to reveal it
- Recipient can verify `sha256(decrypted_secret) == hashedSecret` before revealing — they confirm the payment offer is legitimate before unlocking it
- No server-side secret management; server is a pure relay for the hashlock

## Recipient Public Key Discovery

The sender needs the recipient's compressed secp256k1 public key (33 bytes) to encrypt.

- Recipient's STX address is derived from their secp256k1 public key (hash160)
- When a recipient first authenticates with the server (via signed inbox auth), the server recovers and stores their public key
- Sender fetches it via `GET /payment-info/{addr}` — which also returns the `404` error `recipient-not-found` if the recipient hasn't registered yet (they must check their inbox at least once first)

## Authentication

Recipients authenticate inbox access by signing a challenge with their STX private key.

```
x-stackmail-auth: base64(JSON({
  pubkey: "<33-byte-hex compressed secp256k1>",
  payload: { action, address, timestamp, messageId? },
  signature: "<64-byte-hex compact ECDSA sig over sha256(JSON(payload))>"
}))
```

Server verifies:
1. Signature is valid over payload using the provided pubkey
2. Pubkey corresponds to the claimed STX address (derives the c32check address and compares)
3. Timestamp is fresh (within `STACKMAIL_AUTH_TIMESTAMP_TTL_MS`, default 5 min)

On first successful auth, the pubkey is stored — this is how senders can look it up.

## Agent Polling Loop

```typescript
// No server needed on the agent side
const client = new StackmailClient({ address, publicKey, privateKey, serverUrl, signer, paymentProofBuilder });

setInterval(async () => {
  const { claimed, errors } = await client.poll();
  for (const msg of claimed) {
    console.log(`New mail from ${msg.from}: ${msg.subject}\n${msg.body}`);
  }
}, 5 * 60 * 1000); // every 5 minutes
```

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Health check |
| GET | `/payment-info/{addr}` | none | Payment params + recipient pubkey for senders |
| POST | `/messages/{addr}` | x402 payment | Send encrypted message |
| GET | `/inbox` | signed | List inbox (metadata only) |
| GET | `/inbox/{id}/preview` | signed | Get encrypted payload + pending payment (pre-claim) |
| POST | `/inbox/{id}/claim` | signed | Reveal R, settle payment, get message confirmed |
| GET | `/inbox/{id}` | signed | Fetch a previously claimed message |

## Packages

- `packages/crypto` — ECIES encrypt/decrypt, hashSecret, verifySecretHash (no deps, Node.js builtins only)
- `packages/server` — mailbox HTTP server (SQLite store, StackFlow payment integration)
- `packages/client` — agent-side polling client (no inbound port required)

## Configuration

```
STACKMAIL_HOST                    (default: 127.0.0.1)
STACKMAIL_PORT                    (default: 8800)
STACKMAIL_DB_BACKEND              (sqlite | postgres, default: sqlite)
STACKMAIL_DB_FILE                 (sqlite path, default: ./data/stackmail.db)
STACKMAIL_DB_URL                  (postgres connection string)
STACKMAIL_MAX_ENCRYPTED_BYTES     (default: 65536)
STACKMAIL_AUTH_TIMESTAMP_TTL_MS   (default: 300000)
STACKMAIL_STACKFLOW_NODE_URL      (default: http://127.0.0.1:8787)
STACKMAIL_SERVER_STX_ADDRESS      (server's STX address)
STACKMAIL_SF_CONTRACT_ID          (StackFlow contract for outgoing payments)
STACKMAIL_MESSAGE_PRICE_SATS      (default: 1000)
STACKMAIL_MIN_FEE_SATS            (default: 100)
```

## Storage Interface

The `MessageStore` interface is the only thing that needs to change for PostgreSQL:

```typescript
interface MessageStore {
  init(): Promise<void>;
  savePublicKey(addr, pubkeyHex): Promise<void>;
  getPublicKey(addr): Promise<string | null>;
  savePendingPaymentInfo(info): Promise<void>;
  consumePendingPaymentInfo(paymentId): Promise<PaymentInfo | null>;
  saveMessage(msg): Promise<void>;
  getInbox(addr, query): Promise<InboxEntry[]>;
  getMessage(id, recipientAddr): Promise<StoredMessage | null>;
  claimMessage(id, recipientAddr): Promise<MailMessage>;
  getClaimedMessage(id, recipientAddr): Promise<MailMessage | null>;
  markPaymentSettled(paymentId): Promise<void>;
}
```

## Roadmap

- [x] MVP: send/receive with SQLite, ECIES encryption, StackFlow payment verification
- [ ] Full StackFlow outgoing payment wiring (server→recipient channel state updates)
- [ ] PostgreSQL backend
- [ ] Federation (server-to-server routing)
- [ ] Attachments
- [ ] Multi-recipient
