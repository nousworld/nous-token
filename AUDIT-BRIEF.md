# NOUS Token — Security Audit Brief

**Project**: nous-token (Token-20)
**Repository**: https://github.com/nousworld/nous-token
**Version**: 0.3.5
**License**: MIT
**Date**: 2026-04-05
**Contract Address**: Test deployment — final address TBD

---

## 1. Project Overview

nous-token is an open-source AI usage tracking protocol. A transparent gateway proxies LLM API calls, extracts real token consumption from provider responses, and signs a receipt for every call. Users own their receipts and can mint ERC-721 NFTs on Base as verifiable proof of AI compute consumption.

| Component | Purpose |
|-----------|---------|
| **Token20.sol** | ERC-721 smart contract on Base. Manages series, inscriptions (minting), fee collection, gateway-signed receipt verification, and Merkle-anchored proofs. |
| **Gateway (Cloudflare Worker)** | Transparent LLM proxy. Routes requests to 11+ providers, extracts `.usage` from responses, signs receipts (ECDSA P-256 + secp256k1), maintains Merkle Mountain Range for tamper detection, submits on-chain anchors via cron. |
| **Frontend (web/index.html)** | Single-page leaderboard and inscription UI hosted on Cloudflare Pages. Displays usage stats, series, proofs, and supports MetaMask wallet connection. |
| **CLI (cli/setup.ts)** | One-command setup tool. Detects installed AI tools (Claude Code, Cursor, Codex, Gemini CLI, Python SDKs), configures them to route through the gateway. |
| **OpenClaw Plugin (index.ts)** | Provider plugin for OpenClaw. Registers 11 built-in providers + custom providers, injects `X-Nous-User` hash header, routes through gateway. |
| **Sentinel (sentinel.ts)** | Independent verifier. Pulls all records, recomputes leaf hashes, rebuilds the MMR, verifies receipt signatures. Anyone can run it. |

---

## 2. Architecture

### 2.1 Data Flow

```
                          ┌──────────────────────────────────────────┐
                          │          LLM Providers                   │
                          │  (OpenAI, Anthropic, DeepSeek,           │
                          │   Gemini, Groq, Together, Mistral,       │
                          │   OpenRouter, Fireworks, Perplexity,     │
                          │   Cohere, + any custom HTTPS upstream)   │
                          └──────────────┬───────────────────────────┘
                                         │ response with .usage
                                         ▼
┌─────────┐   ┌──────────────┐   ┌──────────────────┐   ┌──────────┐
│  User   │──▶│ Plugin / CLI │──▶│    Gateway        │──▶│ Provider │
│ (human) │   │  / SDK       │   │ (CF Worker)       │   │ upstream │
└─────────┘   └──────────────┘   └────────┬──────────┘   └──────────┘
                                          │
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                   ┌──────────┐   ┌──────────┐   ┌──────────────┐
                   │  D1 DB   │   │  MMR     │   │ token-20     │
                   │ (usage   │   │ (tamper  │   │ receipt      │
                   │  records)│   │  detect) │   │ (secp256k1)  │
                   └──────────┘   └──────────┘   └──────┬───────┘
                                                        │
                                          ┌─────────────┘
                                          ▼
                                   ┌──────────────┐    ┌──────────────┐
                                   │  Cron (10m)  │───▶│  Token20.sol │
                                   │  Merkle tree │    │  on Base     │
                                   │  anchor tx   │    │  (ERC-721)   │
                                   └──────────────┘    └──────┬───────┘
                                                              │
                                                              ▼
                                                       ┌──────────────┐
                                                       │  User mints  │
                                                       │  NFT via     │
                                                       │  inscribe()  │
                                                       │  (USDC fee)  │
                                                       └──────────────┘
```

### 2.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│  User Domain                                         │
│  - Holds API keys (never leaves machine in clear)    │
│  - Plugin computes SHA-256(key) locally               │
│  - Holds wallet private key (MetaMask)               │
│  - Approves USDC to contract                         │
└──────────────────────┬──────────────────────────────┘
                       │ hash(API key), request body (piped)
                       ▼
┌─────────────────────────────────────────────────────┐
│  Gateway Domain (Cloudflare Worker)                  │
│  - Secrets: SIGNING_KEY, GATEWAY_PRIVATE_KEY,        │
│    ADMIN_SECRET                                      │
│  - Can read API key from Authorization header to     │
│    compute hash (then discards)                      │
│  - Signs receipts (P-256 + secp256k1)                │
│  - Submits anchor txs (gateway wallet on-chain)      │
└──────────────────────┬──────────────────────────────┘
                       │ receipt signature, merkle root
                       ▼
┌─────────────────────────────────────────────────────┐
│  Smart Contract Domain (Base L2)                     │
│  - Trusts registered gateways (owner-managed)        │
│  - Verifies ECDSA signatures via ecrecover           │
│  - Verifies Merkle proofs via OpenZeppelin           │
│  - Holds USDC (deploy fees, inscription fees)        │
└─────────────────────────────────────────────────────┘
```

---

## 3. Component Details

### 3.1 Smart Contract — Token20.sol

**File**: `contracts/src/Token20.sol`
**Solidity**: `^0.8.24`
**EVM**: Cancun
**Compiler**: Optimizer enabled, 200 runs, via-ir
**Dependencies**: OpenZeppelin Contracts (ERC721, Ownable, Pausable, Strings, Base64, ECDSA, MerkleProof, MessageHashUtils)

#### 3.1.1 Core Functions

| Function | Access | Description |
|----------|--------|-------------|
| `deploy()` | Public (whenNotPaused) | Create a new NFT series. Charges `deployFee` in USDC via `transferFrom`. |
| `deployWithAuth()` | Public (whenNotPaused) | Same as `deploy()` but uses EIP-3009 `transferWithAuthorization` for gasless USDC payment. |
| `inscribe()` | Public (whenNotPaused) | Mint an NFT. Verifies gateway signature, Merkle proof, receipt balance. Charges `inscriptionFee` in USDC. |
| `inscribeWithAuth()` | Public (whenNotPaused) | Same as `inscribe()` with EIP-3009 payment. |
| `anchor()` | Gateway only | Submit a Merkle root for a time period. Period must be aligned to `anchorInterval`, not in the future, not too old. |
| `verify()` | View | Verify a receipt's gateway signature and Merkle proof. Returns validity and remaining token balance. |
| `claimCreatorFee()` | Public | Creator claims accumulated inscription fee surplus. |
| `authorize()` / `authorizeBatch()` / `revokeAuth()` | Series creator | Manage whitelist for RESTRICTED-mode series. |
| `registerGateway()` / `revokeGateway()` | Owner | Manage trusted gateway addresses. |
| `invalidateAnchor()` | Owner | Remove a fraudulent or erroneous anchor. |
| `pause()` / `unpause()` | Owner | Emergency circuit breaker. Blocks deploy and inscribe; does NOT block anchor. |
| `setDeployFee()` | Owner | Update deploy fee. |
| `setMinInscriptionFee()` | Owner | Update minimum inscription fee (must be >= PROTOCOL_FEE). |
| `setAnchorInterval()` | Owner | Update anchor period alignment (must be > 0). |
| `setMaxAnchorAge()` | Owner | Update max anchor age in blocks (must be > 0). |
| `withdraw()` | Owner | Withdraw protocol revenue. Cannot withdraw pending creator fees. |
| `renounceOwnership()` | Disabled | Overridden to always revert. |
| `tokenURI()` | View | On-chain metadata as base64-encoded JSON (series name, model, tokens, block, gateway). |

#### 3.1.2 Fee Model

- **Deploy fee**: 5 USDC (configurable by owner). Paid by series creator.
- **Inscription fee**: Set by series creator, minimum 1 USDC.
- **Protocol fee**: Fixed 1 USDC per inscription (constant `PROTOCOL_FEE`).
- **Creator share**: `inscriptionFee - PROTOCOL_FEE`. Accumulated in `creatorBalance` mapping, claimable via `claimCreatorFee()`.
- **Withdrawal protection**: `withdraw()` subtracts `totalPendingCreatorFees` from available balance, preventing the owner from withdrawing creator funds.

#### 3.1.3 Permission Model

| Role | Capabilities |
|------|-------------|
| **Owner** | Register/revoke gateways, pause/unpause, set fees, set anchor params, invalidate anchors, withdraw protocol revenue |
| **Gateway** (registered address) | Submit anchors. Signature verified during inscribe via `ecrecover`. |
| **Series Creator** | Set inscription fee, manage authorized addresses for RESTRICTED series |
| **User** | Deploy series, inscribe NFTs, claim creator fees, verify receipts |

#### 3.1.4 State Variables and Mappings

| Variable | Type | Purpose |
|----------|------|---------|
| `usdc` | `IERC20WithAuth` (immutable) | USDC contract reference |
| `deployFee` | `uint256` | Cost to create a series (default: 5 USDC) |
| `minInscriptionFee` | `uint256` | Minimum inscription fee (default: 1 USDC) |
| `PROTOCOL_FEE` | `uint256` (constant) | Fixed protocol cut per inscription (1 USDC) |
| `anchorInterval` | `uint256` | Period alignment in blocks (default: 300, ~10 min on Base) |
| `maxAnchorAge` | `uint256` | Max blocks since period start for anchor submission (default: 43200, ~24h) |
| `_nextTokenId` | `uint256` | Auto-incrementing NFT token ID (starts at 1) |
| `_nextSeriesId` | `uint256` | Auto-incrementing series ID (starts at 1) |
| `series` | `mapping(uint256 => Series)` | Series configurations |
| `nameExists` | `mapping(bytes32 => bool)` | Prevents duplicate series names |
| `receiptUsed` | `mapping(bytes32 => uint256)` | Tokens consumed from each receipt (shared across series) |
| `inscriptions` | `mapping(uint256 => Inscription)` | NFT metadata per token ID |
| `gateways` | `mapping(address => bool)` | Registered gateway addresses |
| `authorized` | `mapping(uint256 => mapping(address => bool))` | RESTRICTED series whitelist |
| `creatorBalance` | `mapping(address => uint256)` | Claimable creator fees |
| `totalPendingCreatorFees` | `uint256` | Sum of all unclaimed creator fees |
| `anchors` | `mapping(uint256 => bytes32)` | Merkle roots by period start block |

#### 3.1.5 External Calls

- `usdc.transferFrom(from, to, amount)` — in `deploy()`, `inscribe()`
- `usdc.transferWithAuthorization(...)` — in `deployWithAuth()`, `inscribeWithAuth()`
- `usdc.transfer(to, amount)` — in `claimCreatorFee()`, `withdraw()`
- `usdc.balanceOf(address(this))` — in `withdraw()`

#### 3.1.6 Security Mechanisms

- **CEI Pattern**: State updates (`receiptUsed`, `_nextTokenId`, `s.minted`, `_mint`, `_splitFee`) all happen before `emit` in `_inscribe`. Fee split updates internal mappings only; the external USDC transfer happens only during `claimCreatorFee()` (separate tx).
- **Pausable**: `deploy`, `deployWithAuth`, `inscribe`, `inscribeWithAuth` are gated by `whenNotPaused`. Anchor is intentionally NOT paused to avoid blocking legitimate data.
- **renounceOwnership disabled**: Prevents accidental lockout.
- **Input validation**: `_isSafeString()` restricts series names and model IDs to `[a-zA-Z0-9-._/ ]`, preventing JSON injection in `tokenURI()`.
- **Receipt balance tracking**: `receiptUsed` mapping prevents double-spending of the same receipt across any series.
- **Anchor constraints**: Period alignment check, future period rejection, max age enforcement, duplicate anchor prevention.
- **Withdraw protection**: Owner cannot withdraw creator-pending USDC.
- **Batch limit**: `authorizeBatch` capped at 100 addresses per call.

### 3.2 Gateway — Cloudflare Worker

**Files**:

| File | Purpose |
|------|---------|
| `gateway/src/index.ts` | Main Worker entry point: request routing, proxy logic, API endpoints, CORS, authentication, cron handler |
| `gateway/src/db.ts` | D1 database operations: schema init, usage recording, MMR (Merkle Mountain Range) operations, token-20 receipt/anchor storage |
| `gateway/src/providers.ts` | Auto-detect usage format from provider responses (OpenAI, Anthropic, Gemini) |
| `gateway/src/stream.ts` | Tee streaming responses for usage extraction without modifying the stream |
| `gateway/src/token20.ts` | secp256k1 receipt signing, Merkle tree construction, anchor submission to Base via viem |
| `gateway/wrangler.toml` | Worker configuration: D1 binding, cron schedule |

#### 3.2.1 API Endpoints — Complete List

**Proxy Endpoints** (require API key or X-Nous-User):

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/{provider}/v1/...` | Any | API key in Authorization / X-Api-Key / X-Goog-Api-Key header | Proxy to known provider (openai, anthropic, deepseek, gemini, groq, together, mistral, openrouter, fireworks, perplexity, cohere). Wallet via path segment `/w/{addr}/` or headers. |
| `/v1/...` (with X-Nous-Upstream) | Any | API key + X-Nous-Upstream header | Proxy to custom upstream URL |

**Public Read-Only Endpoints** (no auth required):

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/` or `/health` | GET | None | Health check |
| `/api/leaderboard` | GET | None | Top users by tokens. Params: `days` (default 30, 0=all time), `limit` (max 500) |
| `/api/leaderboard/model` | GET | None | Per-model user ranking. Params: `model` (required), `days`, `limit` |
| `/api/models` | GET | None | Usage breakdown by model. Params: `days` |
| `/api/stats` | GET | None | Global totals (calls, tokens, users, models) |
| `/api/wallet/{address}` | GET | None | Usage for a wallet. Address validated: `/^0x[a-f0-9]{40}$/` |
| `/api/user/{hash}` | GET | None | Usage for a user hash. Hash validated: `/^[a-f0-9]+$/` |
| `/api/user/{hash}/receipts` | GET | None | Signed receipts (paginated). Params: `after`, `limit` (max 1000) |
| `/api/records` | GET | None | Raw records for sentinel verification. Params: `after`, `limit` (max 10000) |
| `/api/chain` | GET | None | Merkle root and MMR state |
| `/api/pubkey` | GET | None | Gateway's ECDSA P-256 public key (JWK, public components only) |
| `/api/t20/wallet/{address}` | GET | None | Token-20 receipts for a wallet (public fields only) |
| `/api/t20/anchors` | GET | None | Recent anchors (last 50) |

**Authenticated Endpoints**:

| Path | Method | Auth | Description |
|------|--------|------|-------------|
| `/api/sign` | POST | API key (Authorization header) | Sign a usage summary. User hash computed server-side from API key. Can only sign own usage. Optionally specify `receipt_ids` (max 100). |
| `/api/bind-wallet` | POST | API key (Authorization header) | Bind wallet with cryptographic signature proof. User signs `nous-token:bind:{wallet}` with their wallet. Verified via `viem.verifyMessage`. |
| `/api/t20/my-receipts` | GET | Wallet signature (X-Wallet-Address + X-Wallet-Signature) OR API key | Returns full receipt data including signature and Merkle proofs for anchored receipts. Web auth: user signs `token-20:my-receipts:{wallet}`. |
| `/api/t20/anchor` | POST | ADMIN_SECRET (Bearer token) | Manually trigger anchor submission. Separate from cron. |

**Cron Trigger**:

| Schedule | Description |
|----------|-------------|
| `*/10 * * * *` | Every 10 minutes: build Merkle tree for completed periods, submit anchor tx to Base, verify past anchors on-chain, retry failed anchors |

#### 3.2.2 Identity Authentication Flow

1. **Plugin flow**: Plugin computes `SHA-256(API_key).slice(0, 32 hex chars)` locally, sends as `X-Nous-User` header. Gateway does NOT read the API key.
2. **Direct base URL flow** (e.g., Claude Code via ANTHROPIC_BASE_URL): No plugin. Gateway reads API key from `Authorization` / `X-Api-Key` / `X-Goog-Api-Key` header, computes same SHA-256 hash. Key is never stored/logged.
3. **Mismatch protection**: If both `X-Nous-User` and an API key are present, the gateway computes the hash from the key and rejects if `X-Nous-User` does not match (HTTP 403).
4. **Authenticated API endpoints** (`/api/sign`, `/api/bind-wallet`): Always compute user hash from API key. Never trust `X-Nous-User` header alone.

#### 3.2.3 Wallet Binding Flow

1. User calls `POST /api/bind-wallet` with `{ wallet: "0x...", signature: "0x..." }`.
2. Gateway verifies: `verifyMessage({ address: wallet, message: "nous-token:bind:{wallet}", signature })`.
3. If valid and no prior binding: backfills all existing records for this user hash with the wallet.
4. If rebinding to a different wallet: old records keep old wallet, new records use new wallet.
5. Cache updated for subsequent requests.

#### 3.2.4 Receipt Signing

**P-256 (ECDSA) — Gateway usage receipts**:
- `SIGNING_KEY`: ECDSA P-256 private key in JWK format (Worker secret).
- Leaf hash = `SHA-256(timestamp|user_hash|provider|model|input|output|cache_read|cache_write|total)`.
- Signature = `ECDSA-P256-SHA256(leaf_hash)`.
- Public key available at `/api/pubkey`.

**secp256k1 — Token-20 on-chain receipts**:
- `GATEWAY_PRIVATE_KEY`: secp256k1 hex private key (Worker secret). Must be registered in the Token20 contract.
- Receipt = ABI-encoded `(address wallet, string model, uint256 tokens, uint256 blockNumber)`.
- Receipt hash = `keccak256(receipt)`.
- Signature = EIP-191 personal sign (`account.signMessage({ message: { raw: receiptHash } })`).
- Contract verifies via `ECDSA.recover(toEthSignedMessageHash(keccak256(receipt)), signature)`.

#### 3.2.5 Merkle Tree and Anchor Flow

**MMR (off-chain, D1)**:
- Every usage record produces a leaf hash appended to a Merkle Mountain Range.
- Optimistic locking (3 retries) handles concurrent writes.
- Root is `SHA-256(all peak hashes)` or single peak's hash.

**Token-20 Merkle Tree (on-chain anchor)**:
- Per anchor period (~10 min / 300 blocks), token-20 receipts are collected.
- Cron builds a balanced Merkle tree (padded to power-of-2, leaves sorted for OpenZeppelin `MerkleProof.verify` compatibility).
- Root submitted to contract via `Token20.anchor(periodStart, merkleRoot, receiptCount)`.
- Post-submission: cron verifies anchor on-chain by reading `anchors(periodStart)`. If zero (tx failed), deletes local record so next cron retries.

#### 3.2.6 SSRF Prevention

Custom upstream URLs (`X-Nous-Upstream`) are validated:
- Must use HTTPS protocol.
- Blocked hostnames/IPs: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, `[::1]`, full IPv6 loopback.
- Blocked ranges: `10.*`, `192.168.*`, `172.*`, `169.254.*` (link-local), `fc*`, `fd*` (IPv6 ULA), `fe80*` (link-local IPv6), `::ffff:127.*` (IPv4-mapped loopback).
- Blocked suffixes: `.local`, `.internal`.
- Blocked specific: `metadata.google.internal`, `100.100.100.200` (Alibaba Cloud metadata).

#### 3.2.7 CORS Configuration

- **Allowed origins**: `https://token.nousai.cc`, `https://nousai.cc`
- **Allowed methods**: `GET, POST, OPTIONS`
- **Allowed headers**: `Content-Type, Authorization, X-Api-Key, X-Goog-Api-Key, X-Nous-User, X-Nous-Upstream, X-Nous-Wallet, X-Wallet-Address, X-Wallet-Signature`
- **Max-Age**: 86400 (24h)
- **Vary**: Origin
- Non-matching origins fall back to `https://token.nousai.cc` (not wildcard).

#### 3.2.8 Secret Management

| Secret | Type | Purpose | Storage |
|--------|------|---------|---------|
| `SIGNING_KEY` | ECDSA P-256 JWK | Sign usage receipt leaf hashes | Wrangler secret |
| `GATEWAY_PRIVATE_KEY` | secp256k1 hex | Sign token-20 receipts, submit anchor txs | Wrangler secret |
| `ADMIN_SECRET` | String | Authenticate admin-only endpoints (`/api/t20/anchor`) | Wrangler secret |

### 3.3 Frontend — web/index.html

**File**: `web/index.html` (single-file SPA, no build step)

#### 3.3.1 Features

- Global stats dashboard (tokens, API calls, users, models)
- Leaderboard with period selector (30d / all time)
- Model usage breakdown
- Series listing (from contract)
- My Proofs view (wallet-gated)
- User/wallet lookup
- MetaMask wallet connection
- Inscribe modal (UI prepared, flow in development)
- Setup instructions

#### 3.3.2 Security Mechanisms

- **Content-Security-Policy**: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self' https://gateway.nousai.cc https://mainnet.base.org; img-src 'self' data:; frame-ancestors 'none'`
- **X-Frame-Options**: `DENY`
- **XSS prevention**: All dynamic content rendered via `esc()` function (creates text node, reads `innerHTML` — equivalent to DOM-based escaping). No `innerHTML` with unsanitized user input.
- **Wallet address validation**: `/^0x[a-f0-9]{40}$/i` regex before any use.
- **Anchor tx hash validation**: `/^0x[a-f0-9]{64}$/i` before rendering as link.
- **No external scripts**: All JS is inline (covered by CSP).
- **connect-src whitelist**: Only `gateway.nousai.cc` and `mainnet.base.org`.

### 3.4 CLI & Plugin

#### 3.4.1 CLI Setup (cli/setup.ts)

- Accepts wallet address as argument or interactive prompt.
- Validates wallet format: `/^0x[a-fA-F0-9]{40}$/`.
- Saves wallet to `~/.nous-token` (mode 0o600).
- Auto-detects installed tools: OpenClaw, Claude Code, Cursor, Codex, Gemini CLI, Python openai/anthropic SDKs.
- Configures base URLs to route through `https://gateway.nousai.cc/{provider}/w/{wallet}/v1`.
- Does NOT write to shell rc files automatically — outputs commands for user to run.

#### 3.4.2 OpenClaw Plugin (index.ts)

- Registers 11 built-in providers + custom providers from config.
- `wrapStreamFn`: Intercepts outgoing requests to inject `X-Nous-User` header.
- API key handling: Reads from `authorization` or `x-api-key` header, computes `SHA-256(key).slice(0, 32 hex chars)`, injects as `X-Nous-User`. The **first 16 bytes** (32 hex chars) of SHA-256 are used (truncated hash).
- Wallet address injected into base URL path segment.
- Custom providers: wallet sent via `X-Nous-Wallet` header (can't use path prefix).

---

## 4. Trust Boundaries

| Trust Relationship | What is Trusted | Risk if Breached |
|---|---|---|
| User trusts Gateway | Gateway proxies requests without reading prompt/completion content. Gateway signs receipts honestly. | Fabricated usage data, leaked API keys (structurally mitigated — key only used for hashing). |
| User trusts Contract | USDC approval to contract. Contract distributes fees correctly. | Loss of approved USDC. |
| Gateway trusts LLM Provider | Provider returns accurate `.usage` data in responses. | Inflated or deflated token counts. |
| Contract trusts registered Gateway | Gateway-signed receipts are verified via `ecrecover`. Only registered gateways can anchor. | Fraudulent receipts/anchors if gateway key compromised (mitigable via `revokeGateway` + `invalidateAnchor`). |
| Frontend trusts Gateway API | API responses rendered in UI. | UI poisoning (mitigated by `esc()` sanitization). |
| Everyone trusts Cloudflare | Worker isolate memory is private. D1 data integrity. | Full compromise of gateway state. Out of scope for contract audit. |

---

## 5. Known Attack Surfaces & Mitigations

### 5.1 Identity Spoofing via X-Nous-User

**Attack**: Attacker sends forged `X-Nous-User` header to claim another user's identity.
**Mitigation**: When an API key is present in the request, the gateway always computes the hash from the key and rejects if `X-Nous-User` mismatches (HTTP 403). For authenticated endpoints (`/api/sign`, `/api/bind-wallet`), `X-Nous-User` is never trusted — hash is always computed from the API key.

### 5.2 Wallet Binding without Ownership

**Attack**: Attacker binds someone else's wallet to their user hash.
**Mitigation**: `POST /api/bind-wallet` requires a cryptographic signature: user must sign `nous-token:bind:{wallet}` with the wallet's private key. Verified via `viem.verifyMessage`.

### 5.3 Receipt Signature Leakage

**Attack**: Attacker obtains a signed receipt and inscribes on behalf of another user.
**Mitigation**: Token-20 receipt signatures are only returned in authenticated endpoints (`/api/t20/my-receipts`) which require wallet signature proof or API key. Public endpoints (`/api/t20/wallet/{addr}`) do not expose signatures or encoded receipts.

### 5.4 SSRF via X-Nous-Upstream

**Attack**: Attacker sets `X-Nous-Upstream` to an internal service URL.
**Mitigation**: HTTPS-only enforcement + blocklist of internal IP ranges and hostnames (localhost, RFC 1918, link-local, cloud metadata endpoints). Header is stripped before forwarding.

### 5.5 Anchor Transaction Failure

**Attack**: Anchor tx submitted but not confirmed — receipts left in limbo.
**Mitigation**: Cron job verifies past anchors on-chain (reads `anchors(periodStart)` from contract). If zero, deletes local anchor record so next cron cycle retries. 5-minute grace period before verification.

### 5.6 Admin Endpoint Access

**Attack**: Unauthorized access to manual anchor trigger.
**Mitigation**: `POST /api/t20/anchor` requires `ADMIN_SECRET` as Bearer token, separate from all other auth mechanisms. Returns 401 on mismatch.

### 5.7 XSS in Frontend

**Attack**: Malicious data in user hashes, model names, or wallet addresses rendered as HTML.
**Mitigation**: All dynamic content rendered via `esc()` (DOM text node creation). CSP blocks external scripts. Wallet and tx hash formats validated by regex before rendering as links.

### 5.8 CORS Abuse

**Attack**: Malicious site makes cross-origin requests to gateway API.
**Mitigation**: CORS whitelist limited to `token.nousai.cc` and `nousai.cc`. Non-matching origins receive `token.nousai.cc` as allowed origin (browsers enforce this). Proxy endpoints require API key.

### 5.9 JSON Injection in tokenURI

**Attack**: Malicious model name or series name containing JSON special characters corrupts on-chain metadata.
**Mitigation**: `_isSafeString()` restricts all string inputs to `[a-zA-Z0-9-._/ ]`. No quotes, brackets, or control characters allowed.

### 5.10 Receipt Double-Spend Across Series

**Attack**: Use the same receipt to inscribe in multiple series, exceeding the receipt's token count.
**Mitigation**: `receiptUsed` mapping tracks total tokens consumed from each receipt hash globally (not per-series). Each inscribe deducts `mintThreshold` from the receipt's remaining balance.

### 5.11 Owner Draining Creator Funds

**Attack**: Contract owner calls `withdraw()` to drain USDC including pending creator fees.
**Mitigation**: `withdraw()` computes available balance as `usdc.balanceOf(address(this)) - totalPendingCreatorFees`. Reverts if requested amount exceeds protocol share.

### 5.12 Gateway Key Compromise

**Attack**: Attacker obtains `GATEWAY_PRIVATE_KEY`, can sign arbitrary receipts and submit anchors.
**Mitigation**: Owner can `revokeGateway(compromisedAddress)` and `invalidateAnchor(periodStart)`. Anchors are immutable once verified, but owner can invalidate and re-anchor.

### 5.13 Stale Anchor Submission

**Attack**: Gateway submits anchor for very old period containing manipulated data.
**Mitigation**: `maxAnchorAge` (default 43200 blocks, ~24h) limits how far back an anchor can reach. Contract rejects anchors older than this.

---

## 6. Deployment

| Component | Platform | Configuration |
|-----------|----------|---------------|
| **Token20.sol** | Base mainnet (EVM) | Deployed via Foundry (`forge script Deploy.s.sol`). Constructor takes USDC address. Post-deploy: `registerGateway(gatewayAddress)`. |
| **Gateway** | Cloudflare Workers | Deployed via `wrangler deploy`. Secrets set via `wrangler secret put`. D1 database binding `nous-token-usage`. Cron trigger every 10 minutes. |
| **Frontend** | Cloudflare Pages | Static single file (`web/index.html`). Domain: `token.nousai.cc`. |
| **CLI/Plugin** | npm | Published as `nous-token` package. Users install via `npx nous-token setup`. |

**Environment Variables / Secrets**:

| Name | Where | Type |
|------|-------|------|
| `SIGNING_KEY` | Worker secret | ECDSA P-256 JWK (JSON string) |
| `GATEWAY_PRIVATE_KEY` | Worker secret | secp256k1 private key (hex string) |
| `ADMIN_SECRET` | Worker secret | Admin authentication token |
| `USDC_ADDRESS` | Deploy script env | USDC contract address (Base mainnet: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) |
| `GATEWAY_ADDRESS` | Deploy script env | Gateway EOA address to register |

---

## 7. Test Coverage

**Framework**: Foundry (forge)
**Test File**: `contracts/test/Token20.t.sol`
**Results**: 60 tests, 60 passed, 0 failed, 0 skipped

| Category | Tests | Scenarios Covered |
|----------|-------|-------------------|
| Deploy Series | 7 | Happy path, duplicate name, fee too low, empty name, long name, unsafe characters, deployWithAuth, deployWithAuth wrong value |
| Inscribe | 10 | Happy path, multiple from same receipt (receipt balance exhaustion), model mismatch, wildcard model, restricted mode (authorized + unauthorized), invalid gateway signature, empty model, inscribeWithAuth, inscribeWithAuth wrong value |
| Multi-leaf Merkle | 1 | Two-leaf tree with proof verification for both leaves |
| Receipt Balance | 1 | Cross-series receipt consumption tracking |
| Revenue Split | 5 | Protocol + creator split, min fee (no creator share), nothing to claim revert, only-creator-can-claim, multiple creators isolated |
| Anchor | 5 | Happy path, non-gateway revert, duplicate revert, not-aligned revert, too-old revert |
| Anchor Admin | 4 | invalidateAnchor, non-owner revert, not-anchored revert, setMaxAnchorAge |
| Gateway Management | 1 | Revoke gateway, re-register new gateway, old signatures rejected |
| Pause | 4 | Blocks deploy, blocks inscribe, does not block anchor, unpause resumes |
| Verify | 1 | Valid receipt verification with remaining balance |
| Token URI | 1 | On-chain metadata base64 encoding |
| Admin Parameters | 5 | setDeployFee, setMinInscriptionFee, setMinInscriptionFee below protocol revert, setAnchorInterval, setAnchorIntervalZero revert |
| Authorization Events | 2 | authorize emits event, revokeAuth emits event |
| Batch Authorization | 1 | Batch limit (101 reverts) |
| Boundary | 2 | maxSupply=1, threshold=tokens (exact fit) |
| Withdraw | 3 | Happy path, non-owner revert, exceeds balance revert, protects creator balance |
| Ownership | 1 | renounceOwnership reverts |
| JSON Injection | 2 | Unsafe name revert, unsafe model revert |
| Nonexistent Series | 1 | Inscribe to nonexistent series reverts |

---

## 8. Files Inventory

| File | Purpose |
|------|---------|
| `contracts/src/Token20.sol` | ERC-721 smart contract — series, inscriptions, anchors, fee management |
| `contracts/test/Token20.t.sol` | 60 Foundry tests covering all contract functions |
| `contracts/script/Deploy.s.sol` | Deployment script (USDC address + gateway registration) |
| `contracts/script/E2ETest.s.sol` | End-to-end test script (anchor + inscribe on live chain) |
| `contracts/foundry.toml` | Foundry config (solc 0.8.24, optimizer, remappings) |
| `contracts/README.md` | Contract documentation |
| `gateway/src/index.ts` | Worker entry point: proxy, API routes, auth, cron, CORS |
| `gateway/src/db.ts` | D1 schema, usage recording, MMR, token-20 receipt/anchor storage |
| `gateway/src/providers.ts` | Usage format auto-detection (OpenAI/Anthropic/Gemini) |
| `gateway/src/stream.ts` | Streaming response tee for usage extraction |
| `gateway/src/token20.ts` | secp256k1 signing, Merkle tree, anchor submission via viem |
| `gateway/wrangler.toml` | Worker config (D1 binding, cron schedule) |
| `web/index.html` | Frontend SPA — leaderboard, series, proofs, MetaMask |
| `index.ts` | OpenClaw plugin — provider registration, X-Nous-User injection |
| `cli/setup.ts` | CLI setup — tool detection, base URL configuration |
| `sentinel.ts` | Independent Merkle tree verifier — leaf hashes, MMR rebuild, signature verification |
| `openclaw.plugin.json` | Plugin manifest (11 providers, config schema) |
| `package.json` | npm package config (v0.3.5) |
| `PROTOCOL.md` | Full protocol specification |
| `README.md` | Project overview and quick start |
| `.gitignore` | Excludes node_modules, .wrangler, contracts build artifacts |

---

## 9. Out of Scope

The following are explicitly out of scope for this audit:

- **Cloudflare infrastructure security**: Worker isolate memory isolation, D1 durability, secret storage implementation, DDoS protection.
- **LLM provider security**: Provider API correctness, provider response integrity, provider rate limiting.
- **USDC contract security**: Circle's USDC implementation on Base, EIP-3009 transferWithAuthorization.
- **OpenZeppelin library security**: ERC721, Ownable, Pausable, ECDSA, MerkleProof implementations (audited separately by OZ).
- **Base L2 security**: Sequencer integrity, bridge security, L1 settlement.
- **viem library security**: Client-side signing, RPC communication.
- **Browser/MetaMask security**: Wallet key management, transaction signing UI.
- **npm supply chain**: Dependencies of the CLI/plugin package.
- **DNS/TLS**: Domain security for `nousai.cc`, `gateway.nousai.cc`, `token.nousai.cc`.
