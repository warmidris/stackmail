# Stackmail Payment Flow

## Goal

Define the rules Stackmail uses to accept sender payments, reserve recipient liquidity, and expose tap health in the UI.

This document distinguishes:

- current shipped behavior
- required invariants
- near-term improvements

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

Today, the server accepts the sender payment in both cases:

- if the recipient can be funded immediately, the message is `ready`
- if the recipient tap is missing or does not have enough receive liquidity, the message is stored as `deferred`

That means:

1. If `R` already has a usable tracked tap with enough effective receive liquidity, the server signs and stores a pending payment commitment for `R`.
2. If not, the server stores the verified sender proof plus encrypted payload as deferred work and retries activation on later recipient inbox loads.

### Claim / reveal

When the recipient claims a message:

1. the client previews the message
2. decrypts the payload locally
3. checks that the decrypted secret hashes to the stored `hashedSecret`
4. verifies the server-signed pending payment proof
5. reveals the secret to the server

The current implementation:

1. marks the message state as `settled`
2. stores a settlement artifact containing:
   - sender `paymentId`
   - `hashedSecret`
   - revealed `secret`
   - recipient pending payment proof
   - settlement timestamp
3. keeps the latest signed state in the reservoir pipe row

### Preview / cancel

Message delivery now distinguishes:

- `ready`: recipient payment exists, but it has not been previewed yet
- `previewed`: recipient has already fetched the pending payment proof
- `deferred`: sender payment accepted, recipient payment not yet activatable
- `settled`: secret revealed and claim completed
- `cancelled`: sender cancelled before preview

Sender cancel policy:

- sender may cancel while the message is still `deferred` or `ready`
- once the recipient has previewed the message and seen the pending payment proof, cancel is no longer allowed
- cancel appends compensating pending transfers on top of the latest sender and recipient pipe states
- sender receives a refund of `incomingAmount - fee`, so the server keeps the fee
- message state becomes `cancelled`, and the recipient-side commitment is economically reversed rather than deleted from the nonce chain

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

## Liquidity Management

Users need two distinct tap-management actions:

- `Add funds`
  - on-chain call: `sm-reservoir::add-funds`
  - effect: increases user-side tap balance
  - user-facing result: more send capacity

- `Borrow liquidity`
  - on-chain call: `sm-reservoir::borrow-liquidity`
  - effect: increases reservoir-side tap balance
  - user-facing result: more receive liquidity

Important product copy:

- send capacity is what the user can spend toward the reservoir
- receive liquidity is what the reservoir can forward to the user for incoming mail
- borrowing improves receive power, not spendable balance

Current UI policy:

- both actions are blocked while there are outstanding optimistic off-chain states
- both actions are blocked while there is an unmatured on-chain pending deposit
- after the on-chain tx confirms, the browser syncs the new tap state back to the server so local tracking stays usable

## Abuse Limits

Current shipped limits:

- `maxPendingPerSender`: cap unclaimed messages from one sender to one recipient
- `maxPendingPerRecipient`: cap total unclaimed messages in a recipient inbox
- `maxDeferredPerSender`: cap deferred messages from one sender to one recipient
- `maxDeferredPerRecipient`: cap deferred messages queued for one recipient
- `maxDeferredGlobal`: cap total deferred queue size
- `deferredMessageTtlMs`: expire deferred messages that remain unfulfillable too long

These reduce obvious HTLC spam and inbox-filling abuse.

## Deferred Delivery

Shipped behavior:

- If the sender payment is valid but the recipient does not yet have a usable tap or enough receive liquidity, the server stores the message and sender proof as `deferred`.
- Deferred messages are hidden from the inbox until the server can mint the recipient-side pending payment and promote them to `ready`.
- Inbox loads opportunistically retry deferred activation for that recipient.
- Expired deferred messages are garbage-collected before retries.

### Required state for deferred delivery

- verified sender proof
- sender pipe snapshot used for acceptance
- encrypted payload
- hashed secret
- deferred reason:
  - no-recipient-tap
  - insufficient-recipient-liquidity
- expiration / garbage collection policy

### Remaining follow-up for deferred delivery

- rate limits on repeated retry/re-evaluation
- background sweeper so activation does not depend on recipient inbox traffic
- richer sender-visible status APIs for queued messages

## Force Closures

Current operational assumption:

- the server stores the latest dispute-relevant off-chain state
- forced closures are not currently monitored automatically
- any close event must be detected and disputed manually
- the server now exposes `POST /hooks/dispute` so an external watcher can notify it when a close/dispute event is detected

What the server currently retains for manual dispute handling:

- latest pipe nonce
- latest pipe balances
- latest sender/reservoir signatures
- latest hashed secret on the pipe
- latest enforceable completed incoming transfer checkpoint, stored separately from optimistic pipe state
- revealed secrets for claimed messages
- recipient-side pending payment proofs accepted during claim

## Future Product Direction

Not part of the first deployment, but worth keeping in view:

- multiple reservoirs with different supported assets
- sender-paid asset and recipient-received asset may differ
- examples:
  - sender pays in sBTC, recipient receives in USDCx
  - sender pays in STX, recipient receives in sBTC

That likely implies:

- explicit pricing asset and payout asset metadata
- either per-reservoir FX logic or cross-reservoir settlement
- clearer fee accounting across asset boundaries

Current deployment assumption remains:

- one reservoir
- one supported token
- same asset on both sides of the payment

## Runtime Settings

Operational settings are now stored in DB-backed admin config:

- message price
- minimum fee
- queue/deferred caps
- deferred TTL

Current model:

- env vars provide startup defaults
- SQLite stores the live runtime values
- only the reservoir deployer can update them through the admin UI
- the reservoir can cap offered borrowed liquidity per tap

## Enforceable vs Optimistic State

The server now needs to distinguish two kinds of incoming sender state:

- `latest optimistic state`: the newest incoming payment proof the server has accepted for operational nonce/balance tracking
- `latest enforceable checkpoint`: the newest completed incoming transfer for which the HTLC secret is known and must be retained for dispute fallback

Why this matters:

- optimistic state can advance as soon as a new incoming sender proof is accepted
- but if later protocol steps never complete, the server may need to fall back to the latest completed incoming transfer when disputing a closure
- therefore the enforceable checkpoint must not be overwritten just because a newer optimistic payment was accepted

Current rule:

- accepting a sender payment updates optimistic pipe state
- successful claim stores the sender-side payment proof plus revealed secret as the latest enforceable incoming checkpoint for that pipe

Recommended future work:

- add a built-in polling watcher for StackFlow close/dispute events
- external callbacks such as Hiro Chainhook should be treated as wake-up hints, not the only source of truth
- track dispute submissions and watcher cursors in dedicated tables

## Recipient Signature After Claim

Current behavior:

- recipient verifies the reservoir-signed pending payment locally
- recipient reveals the HTLC secret to the server
- recipient does not sign the resulting reservoir -> recipient state transition back to the server

Implications:

- this is sufficient for the server to continue operating in the low-stakes model
- the server can still fall back to its last fully signed incoming state if a dispute is needed
- however, the server is then advancing local receive-side accounting without a stored recipient acknowledgement on the forwarded leg
- until the recipient signs a later state on that pipe, the forwarded receive-side balance should be treated as optimistic rather than fully enforceable

Recommended direction:

- keep the current behavior for now because it minimizes friction in the receive path
- treat the recipient signature as an optional but desirable hardening step
- preserve the last fully co-signed state separately from any newer optimistic server-tracked state
- if added later, request the recipient signature after claim/open and store it as the latest fully signed receive-side state for the pipe
- do not block message opening on that signature until the UX and retry semantics are solid

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

1. Add sender-visible queue status APIs for deferred messages.
2. Track and expose settled vs pending balances separately in `/tap/state`.
3. Add background retry / expiration processing for deferred messages.
4. Add explicit replay-safe sender payment indexing for settlement/dispute workflows.
5. Add force-close monitoring and dispute execution.
6. Decide whether post-claim recipient acknowledgements should be collected and persisted.
