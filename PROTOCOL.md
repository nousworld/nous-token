# nous-token Protocol v1

## Overview

nous-token is an open-source AI usage tracking system. An OpenClaw plugin routes LLM API calls through a transparent gateway that records real token consumption from provider responses. Users can optionally store gateway-signed usage proofs on-chain.

## How It Works

```
User (OpenClaw) → Plugin → Gateway → LLM Provider
                    ↓          ↓
              hash(API key)  extract .usage
              via X-Nous-User  from response
                               ↓
                          Store in D1 + update Merkle tree
                               ↓
                          Leaderboard website reads D1
                          Sentinels verify Merkle root
```

## Privacy by Structure

Not by promise — by code. Audit the source:

- **API Key**: Plugin computes SHA-256 hash locally, sends only the hash via X-Nous-User header. Gateway code never calls `request.headers.get("authorization")`.
- **Prompts**: `request.body` is piped directly to the provider via `fetch()`. No `.text()`, `.json()`, or `.getReader()` is called on it.
- **Responses (streaming)**: Stream is tee'd. One branch goes to user unchanged. The other buffers only the last 4KB to extract `.usage`. No code reads `.choices`, `.content`, `.message`.
- **Responses (non-streaming)**: Full response body exists in Worker memory (V8 isolate, GC'd after request) to extract `.usage`. Code only accesses `.usage`/`.usageMetadata` fields. Infrastructure trust assumption is Cloudflare — same as any cloud provider.
- **Storage**: D1 stores only: timestamp, user_hash, provider, model, token counts, leaf_hash, endpoint.

## Tamper Detection: Merkle Mountain Range

Each usage record gets a leaf hash: `SHA-256(timestamp|user_hash|provider|model|tokens...)`.

Leaves are organized into a Merkle Mountain Range (MMR) — an append-only binary Merkle tree. Peaks (roots of complete subtrees) are maintained incrementally. The Merkle root is derived from all peaks.

Modifying any single record changes its leaf hash, which propagates through the tree and changes the root.

### Verification

- **Full verification**: Pull all records via `/api/records`, recompute all leaf hashes, rebuild the MMR, compare root with `/api/chain`. This is what sentinels do.
- **Spot check**: Recompute a single record's leaf hash and compare with the stored `leaf_hash`. O(1).
- **External anchoring**: Publish the Merkle root periodically (GitHub, Twitter, on-chain). Attackers cannot rewrite history without invalidating published roots.

### Sentinel

Anyone can run an independent verifier:

```
npx tsx sentinel.ts --watch
```

The sentinel pulls all records, recomputes every leaf hash, rebuilds the MMR locally, and compares the root with the gateway's. No API key needed. All data is public.

## Trust Model

The gateway is operated centrally. Trust comes from:

1. **Code is open-source** — anyone can audit
2. **Merkle tree** — every record is hashed, tampering breaks the tree
3. **Sentinels** — independent verifiers continuously monitor integrity
4. **Gateway-signed proofs** — on-chain data is signed by the gateway's ECDSA key, verifiable by anyone

## On-Chain Proof Format

Users request a gateway-signed proof via `POST /api/sign`, then store it on BASE (or any EVM chain) as calldata in a self-to-self transaction.

```json
{
  "proof": {
    "p": "nous",
    "v": 1,
    "op": "proof",
    "user": "<user_hash>",
    "total_tokens": 2847500,
    "total_calls": 147,
    "models": [
      { "provider": "anthropic", "model": "claude-opus-4-6", "total_tokens": 1500000 },
      { "provider": "openai", "model": "gpt-4o", "total_tokens": 1347500 }
    ],
    "ts": 1743580800
  },
  "sig": "<ECDSA-P256-SHA256 signature hex>",
  "gateway": "https://gateway.noustoken.com"
}
```

Verification: fetch the gateway's public key from `/api/pubkey`, verify the signature against the proof JSON. If valid, this data was attested by the gateway — not fabricated by the user.

No smart contract needed. The signature provides cryptographic proof of origin.

## nous point

nous points are calculated from gateway data:

- Each recorded API call = nous points based on token count
- Viewable on the leaderboard website
- On-chain proof is optional — points exist in the gateway database regardless

### Halving Schedule

| Relay Count | nous points per relay |
|---|---|
| 1 — 1,000,000 | 100 |
| 1,000,001 — 2,000,000 | 50 |
| 2,000,001 — 3,000,000 | 25 |
| 3,000,001+ | continues halving |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/{provider}/v1/...` | * | Proxy to LLM provider |
| `/api/leaderboard` | GET | Top users by total tokens |
| `/api/models` | GET | Usage breakdown by model |
| `/api/stats` | GET | Global totals |
| `/api/user/{hash}` | GET | Single user stats |
| `/api/records` | GET | Export raw records for verification |
| `/api/chain` | GET | Current Merkle root and MMR state |
| `/api/sign` | POST | Gateway-signed usage proof |
| `/api/pubkey` | GET | Gateway's ECDSA public key |

## Auditing the Gateway

Search the gateway source code to verify privacy claims:
- `authorization`, `x-api-key` → never read, only forwarded in HTTP headers
- `request.body` → only appears as argument to `fetch()` (piped, not consumed)
- `.content`, `.choices`, `.message` → do not appear in any data-reading context
- `headers.get()` → only called for `x-nous-user` and `content-type`
