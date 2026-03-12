# Stackmail Payment Flow

## Goal

Define the rules Stackmail uses to accept sender payments, reserve recipient liquidity, and expose tap health in the UI.

This document distinguishes:

- current shipped behavior
- required invariants
- near-term improvements
- deferred-delivery work that is intentionally not fully implemented yet

## Terms

- Tap: a StackFlow pipe between a user and the reservoir.
- Send capacity: how much of the tap the user can currently spend toward the reservoir.
- Receive liquidity: how much of the tap the reservoir can currently forward to the user.
- Settled balance: confirmed on-chain balance in `get-pipe`.
- Pending balance: not-yet-matured deposit shown in `pending-1` or `pending-2`.
- Effective balance: `settled + pending` for the relevant side.

For Stackmail, the practical balance policy is:

- use effective balance for gating sends and receives
- show that this includes pending liquidity in the UI
- keep signatures and balance conservation valid against the full on-chain total

## Current Model

### Sender-side acceptance

To accept a message from sender `S` to recipient `R`, the server requires:

1. `S` has a tap with the reservoir.
2. The request includes a signed StackFlow transfer proof for the configured token and amount.
3. The proof is addressed to the reservoir side of the sender tap.
4. The proof signature recovers to `S`.
5. The proof nonce is newer than the last tracked state for that pipe.
6. The proof preserves the total balance of the tap.
7. The proof increases the reservoir-side balance by at least the configured message price.

If the server has no tracked row yet, it derives the starting entitlement balances from on-chain `get-pipe` using:

- `effective balance = confirmed balance + pending balance`

This matters for borrowed-liquidity taps, where receive liquidity often starts in `pending-2`.

### Recipient-side forwarding

Today, the server only accepts the message if it can also create a reservoir-signed outgoing pending payment for the recipient immediately.

That means:

1. `R` must already have a tracked tap with the reservoir.
2. The reservoir side of `R`'s tap must have at least `message price - fee` effective balance.
3. The server signs and stores a pending payment commitment for `R`.

If any of those fail, the send is rejected with `recipient-payment-unavailable`.

### Claim / reveal

When the recipient claims a message:

1. the client previews the message
2. decrypts the payload locally
3. checks that the decrypted secret hashes to the stored `hashedSecret`
4. verifies the server-signed pending payment proof
5. reveals the secret to the server

The current implementation marks the message payment as settled at claim time and keeps the latest signed state in the reservoir pipe row.

## Required Invariants

These must hold for every accepted sender proof:

1. The pipe exists on-chain or is already tracked locally.
2. The token matches the server-configured token for this Stackmail instance.
3. The actor is the sender and is part of the pipe.
4. The recipient side of the proof is the reservoir.
5. The proof signature is valid for the actor.
6. The nonce is strictly increasing.
7. The proof total equals the latest known total for the tap.
8. The reservoir-side balance increases by the charged amount.

These must hold for every created recipient pending payment:

1. The recipient has a tracked tap.
2. The recipient tap total is preserved.
3. The reservoir-side balance decreases by exactly `price - fee`.
4. The recipient-side balance increases by exactly `price - fee`.
5. The signed proof is persisted so the recipient can challenge later if needed.

## Balance Policy

### Why pending counts

Using only settled balances makes mailbox onboarding and recent top-ups look broken for several blocks. For Stackmail-sized value, that is not worth the UX cost.

### Policy

- Send capacity uses effective sender balance.
- Receive liquidity uses effective reservoir balance.
- UI should show both:
  - spendable / send capacity
  - incoming liquidity / receive liquidity
- If we later expose settled vs pending separately, the UI should make the distinction explicit instead of silently changing semantics.

## Abuse Limits

Current shipped limits:

- `maxPendingPerSender`: cap unclaimed messages from one sender to one recipient
- `maxPendingPerRecipient`: cap total unclaimed messages in a recipient inbox

These reduce obvious HTLC spam and inbox-filling abuse.

## Deferred Delivery

Desired future behavior:

- If the sender payment is valid but the recipient does not yet have a usable tap or enough receive liquidity, store the message and sender proof as deferred instead of rejecting immediately.
- Later, once the recipient opens or tops up the tap, the server can mint the recipient-side pending payment and make the message claimable.

This requires explicit queue state and additional limits. It should not be emulated by storing a message with `pendingPayment = null` and pretending it is ready.

### Required state for deferred delivery

- verified sender proof
- sender pipe snapshot used for acceptance
- encrypted payload
- hashed secret
- deferred reason:
  - no-recipient-tap
  - insufficient-recipient-liquidity
- expiration / garbage collection policy

### Required limits before shipping deferred delivery

- max deferred messages per sender
- max deferred messages per recipient
- max global deferred queue size
- expiration for unfulfillable deferred items
- rate limits on repeated retry/re-evaluation

Without those, deferred delivery creates an obvious DoS surface.

## UI Requirements

Status and compose surfaces should show:

- send capacity
- receive liquidity
- nonce

Recommended follow-up:

- split each side into:
  - effective
  - settled
  - pending

## Immediate Changes Implemented

- sender proof validation now enforces total-balance conservation even for already-tracked taps
- inbox load is capped per recipient in addition to per sender
- status UI surfaces both send capacity and receive liquidity

## Follow-up Work

1. Add first-class deferred delivery state instead of `recipient-payment-unavailable` hard-fail.
2. Track and expose settled vs pending balances separately in `/tap/state`.
3. Persist sender-side claim/release artifacts more explicitly for dispute workflows.
4. Add queue expiration and retry policy for deferred messages.
