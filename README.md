# 🔍 ICP Audit Log

**Immutable, verifiable audit trail on the Internet Computer — powered by Motoko**

A tamper-proof append-only audit log canister that records every tool call, agent action, and user interaction from Hermes Agent. Self-hosts its own dashboard. Data is hashed and stored on-chain with full verifiability.

## Features

- **Append-only immutable log** — entries can never be modified or deleted
- **On-chain hash chain** — every entry has a SHA-256 content hash for verifiability
- **Self-hosted dashboard** — HTML/CSS/JS dashboard served directly from the canister
- **Paginated API** — `/api/entries?page=N`, `/api/stats`
- **Batch upload** — `log_batch` for efficient bulk inserts
- **Query by agent/type** — `get_entries_by_agent`, `get_entries_by_type`
- **Hash chain verification** — `get_hash_chain` + `verify_entry`

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Blockchain** | Internet Computer (ICP) |
| **Backend** | Motoko (persistent actor) |
| **Dashboard** | Vanilla HTML/CSS/JS (served from canister) |
| **Bridge** | Python 3 — reads Hermes state.db, uploads via `dfx` |
| **Identity** | Plaintext `.pem` (nebulock-prod) |

## Architecture

```
┌─────────────────────────────────────┐
│  Hermes Agent (state.db)            │
│  ┌───────────────────────────────┐  │
│  │  messages table (SQLite)      │  │
│  │  tool calls, responses, etc.  │  │
│  └──────────────┬────────────────┘  │
└─────────────────┼───────────────────┘
                  │
          audit_bridge.py
          (reads new rows → dfx call log_batch)
                  │
                  ▼
┌─────────────────────────────────────┐
│  ICP Canister (s7oui-qqaaa-...)     │
│  ┌───────────────────────────────┐  │
│  │  AuditLog (persistent actor)  │  │
│  │  • entries: [LogEntry]        │  │
│  │  • log_action / log_batch     │  │
│  │  • get_all / get_recent       │  │
│  │  • http_request → dashboard   │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
                  │
                  ▼
      https://s7oui-qqaaa-aaaag-ayx2a-cai.raw.icp0.io/
      (self-hosted dashboard with pagination)
```

## Canister

- **ID:** `s7oui-qqaaa-aaaag-ayx2a-cai`
- **Network:** IC mainnet
- **Candid:** `src/audit_log_backend/main.mo`
- **Dashboard:** served via `http_request` on `/`, `/dashboard`, `/app`

### API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/api/entries?page=N` | GET | Paginated entries (200 per page) |
| `/api/stats` | GET | Total count, unique agents, unique types |
| `/`, `/dashboard`, `/app` | GET | Self-hosted HTML dashboard |

### Canister Methods

| Method | Type | Description |
|--------|------|-------------|
| `log_action(agent_id, action_type, hash, metadata)` | Update | Append single entry |
| `log_batch(vec { records })` | Update | Batch append |
| `get_entry(index)` | Query | Get single entry by index |
| `get_all_entries()` | Query | Get all entries |
| `get_recent_entries(limit)` | Query | Get N most recent |
| `get_entries_by_agent(id)` | Query | Filter by agent |
| `get_entries_by_type(type)` | Query | Filter by type |
| `get_total_count()` | Query | Total entries |
| `get_hash_chain()` | Query | All hashes for verification |
| `verify_entry(index, hash)` | Query | Verify a specific entry |

## Bridge Scripts

Located in `bridge/`:

| Script | Purpose |
|--------|---------|
| `audit_bridge.py` | Main bridge: reads Hermes state.db, uploads new entries every 5 min |
| `upload_400.py` | One-shot: upload last 400 entries from state.db |
| `bulk_upload.py` | Bulk upload from state.db |
| `api_server.py` | Simple HTTP server for dashboard.html |
| `run_bridge_mainnet.sh` | Production loop (`while true; python3 audit_bridge.py --once; sleep 300`) |
| `run_bridge_loop.sh` | Loop runner |

## Deploy

```bash
# Build
dfx build --network ic

# Deploy (upgrade, preserves data)
dfx deploy --network ic

# Reinstall (WIPES ALL DATA)
echo "yes" | dfx canister install --mode reinstall --network ic audit_log_backend
```

## Dashboard

The dashboard (`dashboard/dashboard.html`) is embedded directly in the Motoko canister as `DASHBOARD_HTML`. To update:

1. Edit `dashboard/dashboard.html`
2. Minify and embed into `main.mo` replacing the `DASHBOARD_HTML` variable
3. `dfx deploy --network ic`

## License

MIT
