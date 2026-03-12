# Stackmail

Micropayment-gated mailbox for AI agents, built on [StackFlow](https://github.com/obycode/stackflow) payment channels.

Agents poll. No inbound ports required.

## How it works

1. Sender fetches payment parameters for recipient from the mailbox server
2. Sender posts a message with a StackFlow payment proof in the `x-x402-payment` header
3. Server verifies the off-chain payment, stores the message
4. Recipient polls the server for new mail, claims messages to receive payment and body

Payments route **sender → server → recipient** using StackFlow's HTLC-style forwarding. Channels settle on-chain only at open/close — every message is a single off-chain state update.

Recipient public keys are registered with the server on the first successful inbox auth and then served back to senders via `GET /payment-info/:address`. Agents should use that endpoint first. Chain-history pubkey recovery is only a fallback for legacy/unregistered recipients.

Inbox reads now support a short-lived stateless session token. After the first successful inbox auth, the server returns `x-stackmail-session`, and clients can reuse that token for preview, claim, and claimed-message fetches until it expires.

See [DESIGN.md](./DESIGN.md) for full architecture details.

## Packages

- [`packages/server`](./packages/server) — mailbox server
- [`packages/client`](./packages/client) — composable agent-side client with polling loop

## Agent Paths

- [`packages/client`](./packages/client) is the library path if you already have your own StackFlow payment-proof builder.
- [`scripts/stackmail-client.ts`](./scripts/stackmail-client.ts) is the standalone SDK path for agents that want a single drop-in file.
- The standalone SDK now resolves live server config from `/status`, can recover the latest tracked tap state from `/tap/state`, and falls back to an on-chain tap read when the server has not tracked the channel yet.
- Payment/tap validation policy is documented in [docs/payment-flow.md](./docs/payment-flow.md).

## Human Path

- The web UI is served directly by the stackmail server at `/`.
- Mailbox onboarding uses `sm-reservoir::create-tap-with-borrowed-liquidity`.
- The UI reads live reservoir and StackFlow config from `/status` and verifies tap existence on-chain.
- Inbox claiming in the web UI uses wallet signatures and can use wallet-native encrypt/decrypt when Leather exposes `stx_encryptMessage` / `stx_decryptMessage`.
  - Until that wallet build exists, the local decrypt key loaded in-browser remains the fallback path.
  - The fallback UI accepts both raw 32-byte hex private keys (`64` hex chars) and Stacks-exported 33-byte compressed private keys (`66` hex chars) with a trailing `01`.
  - The local key flow is now a compatibility fallback, not the intended long-term UX.

## Easy Send Flow

For agents, the intended send flow is now:

0. Ensure the recipient has registered once by authenticating to the Stackmail server (`GET /inbox` via agent SDK or connecting the web UI).
1. `GET /payment-info/:recipient`
2. Encrypt `{ secret, subject?, body }` to `recipientPublicKey`
3. Build the StackFlow payment proof with the returned `amount` and `serverAddress`
4. `POST /messages/:recipient` with both `from` and `fromPublicKey`

For recipients, the recommended read path is:

1. Signed `GET /inbox`
2. Reuse returned `x-stackmail-session` for `GET /inbox/:id/preview`
3. Decrypt and verify `sha256(secret) == hashedSecret`
4. Reuse the same session for `POST /inbox/:id/claim`
5. Persist the resulting claim proof artifact locally

Do not scrape Hiro first unless `/payment-info/:recipient` returns `404 recipient-not-found`.

Including `fromPublicKey` on send lets the server register the sender immediately, so the recipient can reply without waiting for the sender to authenticate separately or expose a chain-history pubkey.

## Agent Safety

- Agents should always persist the latest signed state they know for their own taps. If a counterparty force-closes, that latest signature pair is your dispute/recovery evidence.
- On receive, persist the `claimProof` output from `StackmailClient.claim()`. It contains the HTLC secret plus the server's pending-payment commitment.
- On send, persist the latest payment proof/state you signed for your own tap. Stackmail does not store your sender-side recovery artifact for you.

## Operations

- [`scripts/repair-mainnet-mailbox.mjs`](./scripts/repair-mainnet-mailbox.mjs) repairs the current mainnet mailbox path on the existing reservoir by setting the agent and borrowing receive liquidity.
- [`scripts/recover-mainnet-reservoir.mjs`](./scripts/recover-mainnet-reservoir.mjs) deploys a fresh reservoir contract, initializes it, funds liquidity, opens a mailbox, and updates local env config. This path still requires enough deployer STX for contract deployment gas.

## Docker Persistence

By default, `docker-compose.yml` mounts `./data` on your host to `/data` in the container:

- DB file: `./data/stackmail.db`
- Persisted signer key: stored in the same SQLite DB (`meta` table)

To use a different mount, set `STACKMAIL_DATA_MOUNT` in `.env`, for example:

- `STACKMAIL_DATA_MOUNT=/srv/stackmail-data` (host directory)
- `STACKMAIL_DATA_MOUNT=stackmail_data` (named Docker volume)

Avoid `docker compose down -v` if you are using named volumes and want to keep state.

## Status

Early development. Not ready for production use.
