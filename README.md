# nous-token

You spend hundreds of dollars a month on AI. Do you know exactly where it goes?

nous-token is an open-source protocol that tracks every AI token you consume — across every provider, every tool, every model — and gives you a cryptographically signed receipt for each call. Not estimated. Not self-reported. Extracted from the actual provider response and signed.

**Live leaderboard**: [token.nousai.cc](https://token.nousai.cc)

## Why This Exists

Every other usage tracker asks you to trust them. We don't.

- **Helicone, LangSmith, OpenMeter** — they see your prompts, store your data, and you trust their numbers. If they miscount, you'd never know.
- **nous-token** — your prompts are never read. Every record is ECDSA-signed. A Merkle tree makes tampering detectable. Anyone can run an independent verifier. The code is open. The math is the proof.

This is not an observability platform. This is a **receipt system** — the difference between a bank statement you trust because the bank says so, and a signed check you can verify yourself.

## Quick Start

```bash
npx nous-token setup
```

One question: your **wallet address** (0x...). That's your permanent identity — API keys rotate, wallets don't.

The CLI auto-detects your AI tools (Claude Code, Cursor, Python SDKs, etc.) and routes them through the gateway. Works with both API keys and subscription plans (Claude Max, ChatGPT Plus, etc.).

## How It Works

```
You → AI Tool → Gateway → LLM Provider
                  ↓
            extract .usage from response
            sign receipt (ECDSA)
            record in Merkle tree
                  ↓
            token.nousai.cc / on-chain (Base)
```

The gateway is a transparent proxy. It forwards your request untouched, reads only the `.usage` field from the response, signs a receipt, and records it. Your prompts and completions are never read or stored.

## Don't Trust Us. Verify.

Anyone can run a sentinel — an independent verifier that pulls all records, recomputes every hash, rebuilds the Merkle tree, and checks every signature. No API key needed.

```bash
npx tsx sentinel.ts          # one-shot verify
npx tsx sentinel.ts --watch  # continuous monitoring
```

If a single record has been tampered with, the sentinel catches it. This is the entire trust model:

1. **Code is open-source** — audit everything
2. **Per-call ECDSA signatures** — every receipt is signed by the gateway
3. **Merkle Mountain Range** — tampering with any record breaks the tree
4. **Sentinels** — independent verifiers anyone can run
5. **On-chain anchoring** — Merkle roots anchored to Base every 10 minutes

## Supported Providers

Works with any OpenAI-compatible API out of the box:

| Provider | Route |
|----------|-------|
| OpenAI | `/openai/v1/...` |
| Anthropic | `/anthropic/...` |
| DeepSeek | `/deepseek/v1/...` |
| Google Gemini | `/gemini/...` |
| Groq | `/groq/v1/...` |
| Together | `/together/v1/...` |
| Mistral | `/mistral/v1/...` |
| OpenRouter | `/openrouter/api/v1/...` |
| Fireworks | `/fireworks/v1/...` |
| Perplexity | `/perplexity/v1/...` |
| Cohere | `/cohere/v1/...` |
| **Any custom** | Set `X-Nous-Upstream` header |

## Privacy by Structure

Not by promise — by code. [Audit the source](gateway/src/index.ts).

| Data | What happens |
|------|-------------|
| Auth Token | Hashed (SHA-256) for identity. Never stored. |
| Prompts | `request.body` piped directly to provider. Never read. |
| Responses (streaming) | Tee'd. Only last 4KB buffered to extract `.usage`. |
| Responses (non-streaming) | In V8 isolate memory. Only `.usage` accessed. GC'd after request. |
| Storage | D1 stores: timestamp, user_hash, wallet, provider, model, token counts. Nothing else. |

## Wallet Identity

Your wallet address is your permanent identity across all API keys, all machines, all plans.

- All usage across any API key or OAuth token links to your wallet
- Switch keys, switch machines, switch plans — your history follows you
- First bind is permanent per auth token (prevents rebind with leaked keys)

## API

Gateway: `https://gateway.nousai.cc`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/{provider}/v1/...` | * | Proxy to LLM provider |
| `/api/leaderboard` | GET | Top users by tokens |
| `/api/leaderboard/model` | GET | Per-model user ranking |
| `/api/models` | GET | Usage breakdown by model |
| `/api/stats` | GET | Global totals |
| `/api/wallet/{address}` | GET | Usage for a wallet |
| `/api/user/{hash}/receipts` | GET | Signed receipts |
| `/api/records` | GET | Raw records for sentinel verification |
| `/api/chain` | GET | Merkle root and MMR state |
| `/api/pubkey` | GET | Gateway's ECDSA public key |

## Architecture

```
nous-token/
├── gateway/          Cloudflare Worker — proxy + usage extraction + signing
│   └── src/
│       ├── index.ts      API routes + proxy logic
│       ├── db.ts         D1 storage + Merkle Mountain Range
│       ├── providers.ts  Usage format auto-detection (OpenAI/Anthropic/Gemini)
│       ├── stream.ts     Streaming response usage extraction
│       └── token20.ts    On-chain anchoring + receipt signing (secp256k1)
├── contracts/        Foundry — ERC-721 on Base
│   └── src/
│       └── Token20.sol   Series, inscriptions, fee collection, Merkle proofs
├── web/              Cloudflare Pages — leaderboard + inscription UI
├── cli/              One-command setup tool
│   └── setup.ts
├── index.ts          OpenClaw plugin (provider integration)
├── sentinel.ts       Independent Merkle tree verifier
└── PROTOCOL.md       Full protocol specification
```

## License

MIT
