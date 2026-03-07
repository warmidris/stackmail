# Stackmail PoC Hosting Plan

## Requirements

The stackmail server needs to run:
- The **stackmail server** (Node.js HTTP, port 8800)
- A **StackFlow node** (Node.js, port 8787) in counterparty + forwarding mode
- SQLite database (a volume or local disk)
- Outbound HTTPS to Stacks API (hiro.so or self-hosted)
- Inbound HTTPS from agents (sender/recipient)

No GPU, no high memory, low traffic for a PoC.

---

## Option A: DigitalOcean Droplet — Recommended

**Tier:** Basic Droplet, 1 vCPU / 1 GB RAM / 25 GB SSD

| Item | Cost |
|------|------|
| Droplet (1 vCPU / 1 GB / 25 GB) | $6/month |
| Reserved IP | $4/month (optional for PoC) |
| Managed SSL via Let's Encrypt (Caddy) | free |
| **Total** | **$6–10/month** |

**Why DO:** Simplest setup, predictable pricing, great docs, 1-click SSH. SQLite on local disk is fine for PoC.

**Stack:**
```
Caddy (reverse proxy + TLS)  → stackmail :8800
                             → stackflow-node :8787 (private only)
```

**Caddy config:**
```
stackmail.yourdomain.com {
    reverse_proxy localhost:8800
}
```

**Setup steps:**
1. Create Ubuntu 24.04 droplet ($6/month)
2. `apt install nodejs npm caddy`
3. Clone repo, `npm install && npm run build`
4. Write `.env` with `STACKMAIL_*` vars
5. Set up `systemd` units for both processes
6. Point DNS to droplet IP, Caddy handles TLS automatically

---

## Option B: AWS EC2 t4g.nano — Cheapest

**Tier:** t4g.nano (ARM, 2 vCPU burst / 512 MB RAM)

| Item | Cost |
|------|------|
| EC2 t4g.nano (On-Demand) | ~$3.07/month |
| EBS 8 GB gp3 | ~$0.64/month |
| Elastic IP | $3.65/month (if unattached) or free when attached |
| Data transfer out (< 1 GB/month) | ~$0.09 |
| **Total** | **~$4–7/month** |

**Caveat:** 512 MB is tight for two Node.js processes. Use t4g.micro (1 GB) at ~$6.10/month to be safe.

**Why AWS:** If Brice already has AWS infrastructure/billing. Otherwise more friction than DO for a PoC.

---

## Option C: Fly.io — Good for zero-maintenance

**Tier:** shared-cpu-1x, 256 MB RAM (or 512 MB)

| Item | Cost |
|------|------|
| shared-cpu-1x, 256 MB (free tier: 3 machines) | $0–2/month |
| Persistent volume 1 GB (SQLite) | $0.15/month |
| **Total** | **~$0–3/month** |

**Fly free tier** covers this easily for a PoC — 3 shared VMs free, volume is very cheap.

**Why Fly:** Zero TLS setup, built-in global anycast, `fly deploy` is one command. SQLite volume persistence is first-class. Good choice if we want to deploy fast.

**Fly setup:**
```toml
# fly.toml
app = "stackmail"
[build]
  dockerfile = "Dockerfile"
[[services]]
  internal_port = 8800
  protocol = "tcp"
  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]
[[mounts]]
  source = "stackmail_data"
  destination = "/data"
```

---

## Recommendation

| Scenario | Pick |
|----------|------|
| Fastest path to running | **Fly.io** (free, one command) |
| Most control / familiar VPS | **DigitalOcean $6/month** |
| Already in AWS ecosystem | **EC2 t4g.micro ~$6/month** |

**For a PoC: Fly.io.** Free, TLS automatic, SQLite volume included. Can migrate to DO or AWS later.

---

## Production Upgrade Path (when traffic justifies it)

| Component | PoC | Production |
|-----------|-----|------------|
| DB | SQLite on volume | PostgreSQL (DO Managed DB: $15/month, or RDS) |
| Instances | 1 | 2+ (add shared replay store for gateway) |
| StackFlow node | Co-located | Separate instance or managed |
| TLS | Caddy / Fly | Same, or AWS ACM + ALB |
| Monitoring | Logs | Grafana Cloud free tier |

Full production cost (DO): ~$30–50/month (Droplet + Managed PG + reserved IP).

---

## Environment Setup Checklist

```bash
# Required env vars for the stackmail server
STACKMAIL_HOST=0.0.0.0
STACKMAIL_PORT=8800
STACKMAIL_DB_FILE=/data/stackmail.db
STACKMAIL_STACKFLOW_NODE_URL=http://localhost:8787
STACKMAIL_SERVER_STX_ADDRESS=SP...
STACKMAIL_SF_CONTRACT_ID=SP....stackflow-sbtc-0-6-0
STACKMAIL_MESSAGE_PRICE_SATS=1000
STACKMAIL_MIN_FEE_SATS=100

# StackFlow node vars
STACKFLOW_NODE_PORT=8787
STACKFLOW_NODE_HOST=127.0.0.1          # private only
STACKFLOW_NODE_COUNTERPARTY_KEY=<hex>
STACKFLOW_NODE_FORWARDING_ENABLED=true
STACKFLOW_NODE_FORWARDING_MIN_FEE=100
STACKS_NETWORK=mainnet
STACKS_API_URL=https://api.hiro.so
```

A `docker-compose.yml` bundling both services would make this one-command deployable.
