# nous-token

Open-source AI usage tracker. Every token, verified.

One command to track all your AI spending across every provider. Your data is signed, verifiable, and yours.

**Live leaderboard**: [token.nousai.cc](https://token.nousai.cc)

## Quick Start

```bash
npx nous-token setup
```

The CLI asks one thing: your **wallet address** (0x...) — your permanent identity.

Then it auto-detects your AI tools (Claude Code, Cursor, Python SDKs, etc.) and routes them through the gateway. Works with both API keys and subscription plans (Claude Max, etc.).

## How It Works

```
You → AI Tool → Gateway → LLM Provider
                  ↓
            extract .usage from response
            sign receipt (ECDSA)
            record in Merkle tree
                  ↓
            token.nousai.cc
```

The gateway is a transparent proxy. It forwards your request untouched, reads only the `.usage` field from the response, signs a receipt, and records it. Your prompts and completions are never read or stored.

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

## Wallet Identity

Your wallet address is your permanent identity. API keys expire and rotate — your wallet doesn't.

- Run `npx nous-token setup` with your wallet address
- All usage across any API key or OAuth token links to your wallet
- Switch keys, switch machines, switch plans — your history follows you
- First bind is permanent per auth token (prevents rebind with leaked keys)
- Works with API keys and subscription plans (Claude Max, ChatGPT Plus, etc.)

## Privacy by Structure

Not by promise — by code. [Audit the source](gateway/src/index.ts).

| Data | What happens |
|------|-------------|
| Auth Token | Hashed (SHA-256) for identity. Never stored. Works with API keys and OAuth tokens. |
| Prompts | `request.body` piped directly to provider. Never read. |
| Responses (streaming) | Tee'd. Only last 4KB buffered to extract `.usage`. |
| Responses (non-streaming) | In V8 isolate memory. Only `.usage` accessed. GC'd after request. |
| Storage | D1 stores: timestamp, user_hash, wallet, provider, model, token counts. Nothing else. |

## Verification

Every API call produces a signed receipt. Anyone can verify independently.

### Run a sentinel

```bash
npx tsx sentinel.ts          # one-shot verify
npx tsx sentinel.ts --watch  # continuous monitoring
```

The sentinel pulls all records, recomputes leaf hashes, rebuilds the Merkle tree, and verifies receipt signatures. No API key needed.

### Trust model

1. **Code is open-source** — audit everything
2. **Per-call ECDSA signatures** — every receipt is signed
3. **Merkle Mountain Range** — tampering breaks the tree
4. **Sentinels** — independent verifiers anyone can run
5. **On-chain anchoring** — store receipts on BASE or any EVM chain

## API

Gateway: `https://gateway.nousai.cc`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/{provider}/v1/...` | * | Proxy to LLM provider |
| `/api/leaderboard` | GET | Top users by tokens (`?days=30`, `?days=0` for all time) |
| `/api/leaderboard/model` | GET | Per-model user ranking (`?model=...`) |
| `/api/models` | GET | Usage breakdown by model |
| `/api/stats` | GET | Global totals |
| `/api/wallet/{address}` | GET | Usage for a wallet (all linked hashes) |
| `/api/user/{hash}` | GET | Single user stats |
| `/api/user/{hash}/receipts` | GET | Signed receipts (paginated) |
| `/api/records` | GET | Raw records for sentinel verification |
| `/api/chain` | GET | Merkle root and MMR state |
| `/api/sign` | POST | Signed summary for on-chain storage |
| `/api/pubkey` | GET | Gateway's ECDSA public key |

## Architecture

```
nous-token/
├── gateway/          Cloudflare Worker — proxy + usage extraction + signing
│   └── src/
│       ├── index.ts      API routes + proxy logic
│       ├── db.ts         D1 storage + Merkle Mountain Range
│       ├── providers.ts  Usage format auto-detection (OpenAI/Anthropic/Gemini)
│       └── stream.ts     Streaming response usage extraction
├── web/              Cloudflare Pages — leaderboard frontend
│   └── index.html
├── cli/              CLI setup tool
│   └── setup.ts
├── index.ts          OpenClaw plugin
├── sentinel.ts       Independent Merkle tree verifier
└── PROTOCOL.md       Full protocol specification
```

## License

MIT
