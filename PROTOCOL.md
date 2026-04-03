# nous-token Protocol v2

## Overview

nous-token is an open-source AI usage tracking protocol. A transparent gateway proxies LLM API calls, extracts real token consumption from provider responses, and signs a **receipt** for every call. Users own their receipts and decide what to store on-chain.

The gateway guarantees data authenticity. It does not dictate storage format.

## How It Works

```
User → Plugin/CLI/SDK → Gateway → LLM Provider (any)
                           ↓            ↓
                    hash(API key)    extract .usage
                    X-Nous-User      auto-detect format
                           ↓
                     sign receipt (ECDSA) + store in D1 + update Merkle tree
                           ↓
                   User fetches receipts → decides what to store on-chain
```

### Provider Routing

Two ways to route through the gateway:

1. **Shortcut prefix**: `/{provider}/v1/...` for known providers (openai, anthropic, deepseek, gemini, groq, together, mistral, openrouter, fireworks, perplexity, cohere)
2. **Custom upstream**: Set `X-Nous-Upstream: https://api.example.com` header to proxy any OpenAI-compatible API

Usage extraction auto-detects response format (OpenAI, Anthropic, or Gemini style). No provider registration needed.

## The Receipt

Every API call through the gateway produces a signed receipt:

```json
{
  "p": "nous",
  "v": 1,
  "type": "receipt",
  "id": 42,
  "ts": "2026-04-02T12:00:00.000Z",
  "user": "a1b2c3d4...",
  "provider": "anthropic",
  "model": "claude-opus-4-6",
  "input": 5000,
  "output": 2000,
  "cache_read": 0,
  "cache_write": 0,
  "total": 7000,
  "leaf": "sha256...",
  "sig": "ecdsa_signature..."
}
```

**Verification**: `leaf` = SHA-256(`ts|user|provider|model|input|output|cache_read|cache_write|total`). `sig` = ECDSA-P256-SHA256 signature over `leaf`. Verify with the gateway's public key at `/api/pubkey`.

The gateway signs the leaf hash, not the JSON. This means:
- Anyone can independently recompute `leaf` from the fields and verify it matches
- The signature proves the gateway attested to this exact data
- No ambiguity from JSON serialization differences

## What the Gateway Guarantees

1. **Token counts are real** — extracted from the actual provider response, not estimated
2. **Receipts are signed** — ECDSA P-256 signature on each record's leaf hash
3. **History is append-only** — Merkle Mountain Range makes deletion/modification detectable
4. **Data is public** — anyone can pull all records and verify independently

## What the Gateway Does NOT Dictate

- What the user stores on-chain (individual receipts, summaries, or nothing)
- How the user calculates cost (different plans have different rates)
- What fields the user displays publicly
- When the user stores proof

## Wallet Identity

Users identify themselves with an Ethereum wallet address. The wallet is the permanent identity — API keys rotate, wallets don't.

### How it works

1. User runs `npx nous-token setup`, enters wallet address + API key
2. CLI computes `user_hash = SHA-256(api_key)[0:16]` locally, sends `{api_key, wallet}` to `/api/link`
3. Gateway computes the same hash, verifies it exists in records, links all records to the wallet
4. Future API calls include `?wallet=0x...` in the base URL (set by CLI) or `X-Nous-Wallet` header (set by plugin)
5. Gateway stores wallet with each new record and backfills old records for the same hash

### Binding rules

- **First bind wins**: Once a hash is linked to a wallet, it cannot be relinked to a different wallet. This prevents rebinding with expired or leaked API keys.
- **Multiple hashes per wallet**: A user can link multiple API keys (hashes) to the same wallet. The leaderboard aggregates all hashes under one wallet.
- **Wallet validation**: Must be a valid Ethereum address (`0x` + 40 hex chars). Invalid addresses are silently ignored.

### Leaderboard aggregation

The leaderboard uses `CASE WHEN wallet != '' THEN wallet ELSE user_hash END` as the identity key. Users with wallets are aggregated by wallet; users without wallets fall back to hash-based identity.

## Privacy by Structure

Not by promise — by code. Audit the source:

- **API Key**: Plugin computes SHA-256 hash locally, sends only the hash via `X-Nous-User` header. If no `X-Nous-User` is present (e.g., Claude Code via base URL), the gateway reads the API key from `Authorization` header **solely** to compute the same hash. The key is never stored, logged, or retained — it exists in Worker memory only for the duration of one SHA-256 call, then is discarded by GC. The `X-Nous-Upstream` header (if used) is stripped before forwarding.
- **Prompts**: `request.body` is piped directly to the provider. No `.text()`, `.json()`, or `.getReader()` is called on it.
- **Responses (streaming)**: Tee'd. One branch to user unchanged, other buffers last 4KB to extract `.usage` only.
- **Responses (non-streaming)**: Full body in Worker memory (V8 isolate, GC'd after request) to extract `.usage`. Never reads `.choices`, `.content`.
- **Storage**: D1 stores: timestamp, user_hash, provider, model, token counts, leaf_hash, receipt_sig. No prompts, no responses, no keys.

## Tamper Detection: Merkle Mountain Range

Each receipt's `leaf` hash is appended to a Merkle Mountain Range (MMR). The MMR root changes if any single record is modified.

### Verification Levels

| Level | How | Cost |
|---|---|---|
| **Single receipt** | Recompute `leaf` from fields, verify `sig` with pubkey | O(1) |
| **Full tree** | Pull all records, rebuild MMR, compare root | O(n) |
| **External anchor** | Compare root with published root (GitHub, on-chain) | O(1) |

### Sentinel

Anyone can run an independent verifier:

```
npx tsx sentinel.ts --watch
```

The sentinel verifies leaf hashes, receipt signatures, and Merkle root integrity. No API key needed.

## On-Chain Storage

Users choose how to store proof on BASE (or any EVM chain):

### Option 1: Individual Receipts

Fetch signed receipts via `/api/user/:hash/receipts`, store as calldata. Each receipt is independently verifiable.

### Option 2: Summary

Request a signed summary via `POST /api/sign`, store as calldata. The summary aggregates multiple receipts into a single signed attestation.

Both options use self-to-self transactions with data as calldata. No smart contract needed — the ECDSA signature is the proof.

## Trust Model

1. **Code is open-source** — anyone can audit
2. **Per-call signatures** — every receipt is signed by the gateway
3. **Merkle tree** — tampering with any record breaks the tree
4. **Sentinels** — independent verifiers monitor continuously
5. **On-chain anchoring** — published roots prevent history rewrites

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/{provider}/v1/...` | * | Proxy to LLM provider (append `?wallet=0x...` for identity) |
| `/api/leaderboard` | GET | Top users by tokens (`?days=30`, `?days=0` for all time) |
| `/api/leaderboard/model` | GET | Per-model user ranking (`?model=...&days=30`) |
| `/api/models` | GET | Usage breakdown by model (aggregated across providers) |
| `/api/stats` | GET | Global totals |
| `/api/wallet/{address}` | GET | Usage for a wallet (all linked hashes aggregated) |
| `/api/user/{hash}` | GET | Single user aggregated stats |
| `/api/user/{hash}/receipts` | GET | Signed receipts (paginated) |
| `/api/link` | POST | Link hash to wallet (`{api_key, wallet}`) — first bind wins |
| `/api/records` | GET | Raw records for sentinel verification |
| `/api/chain` | GET | Merkle root and MMR state |
| `/api/sign` | POST | Signed summary (optional aggregation) |
| `/api/pubkey` | GET | Gateway's ECDSA public key |

## Auditing the Gateway

Search the source to verify privacy claims:
- `authorization`, `x-api-key` → read only to compute user hash when `X-Nous-User` is absent; value is not stored or logged
- `request.body` → only as argument to `fetch()` (piped, not consumed)
- `.content`, `.choices`, `.message` → absent from data-reading code
- `headers.get()` → only for `x-nous-user`, `x-nous-upstream`, `x-nous-wallet`, and `content-type`
