# Stackmail Hosting Plan

## Runtime Shape

The current stackmail deployment only needs:

- the `@stackmail/server` HTTP process on port `8800`
- a persistent SQLite file or volume
- outbound HTTPS access to a Stacks API for read-only contract calls
- inbound HTTPS from humans and agents

The server now includes the reservoir signing logic directly. A separate StackFlow node is no longer required for the current mailbox flow.

## Recommended PoC Targets

### Option A: Fly.io

Good default when we want the fastest path to a public demo:

- one app
- one persistent volume mounted at `/data`
- automatic TLS
- simple `fly deploy`

Minimal shape:

```toml
app = "stackmail"

[build]
  dockerfile = "Dockerfile"

[[services]]
  internal_port = 8800
  protocol = "tcp"
  [[services.ports]]
    port = 80
    handlers = ["http"]
  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]

[[mounts]]
  source = "stackmail_data"
  destination = "/data"
```

### Option B: DigitalOcean Droplet

Good default when we want SSH access and simple local-disk persistence:

- Ubuntu 24.04
- Caddy or nginx in front of port `8800`
- SQLite stored on the droplet disk

Example Caddy file:

```caddy
stackmail.yourdomain.com {
    reverse_proxy 127.0.0.1:8800
}
```

## Environment Checklist

Required or strongly recommended server vars:

```bash
STACKMAIL_HOST=0.0.0.0
STACKMAIL_PORT=8800
STACKMAIL_DB_FILE=/data/stackmail.db
STACKMAIL_STACKS_NETWORK=mainnet
STACKMAIL_RESERVOIR_CONTRACT_ID=SP....sm-reservoir
STACKMAIL_SF_CONTRACT_ID=SP....sm-stackflow
STACKMAIL_MESSAGE_PRICE_SATS=1000
STACKMAIL_MIN_FEE_SATS=100
```

Optional identity vars:

```bash
STACKMAIL_SERVER_PRIVATE_KEY=<32-byte-hex>
STACKMAIL_SERVER_STX_ADDRESS=SP...
```

If the identity vars are omitted, the server generates a signer key once and persists it in the SQLite `meta` table. Do not rotate or discard that DB file unless you also plan to update the on-chain agent registration.

## Persistence Notes

- Keep `stackmail.db`, `stackmail.db-wal`, and `stackmail.db-shm` together.
- Do not use ephemeral storage for the production DB.
- Back up the DB before container or VM migrations because it contains the persisted signer key and tracked pipe state.

## Deployment Notes

- `npm install`
- `npm run build --workspaces`
- start `@stackmail/server`
- verify `GET /health`
- verify `GET /status`
- verify `/` serves the web UI

## Current Mainnet Reality

- A fresh reservoir deployment path exists in [`scripts/recover-mainnet-reservoir.mjs`](./scripts/recover-mainnet-reservoir.mjs).
- The currently repaired mainnet mailbox path uses the existing `sm-reservoir` contract plus the restored on-chain agent registration.
- Fresh contract deployment is still blocked until the deployer account has enough STX for deployment gas.
