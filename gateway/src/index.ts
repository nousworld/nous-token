// nous-token gateway — transparent LLM API proxy that records real usage
//
// PRIVACY BY STRUCTURE (not by promise):
//
// 1. API Key: When X-Nous-User header is present (plugin flow), gateway never
//    reads the API key. When X-Nous-User is absent (direct base URL flow, e.g.
//    Claude Code), gateway reads the key ONLY to compute SHA-256 hash for user
//    identity — the key is never stored, logged, or retained beyond the hash
//    computation. The hash matches what the plugin would have computed locally.
//
// 2. Request body (prompts): NEVER READ. request.body is piped directly to the
//    provider via fetch(). No .text(), .json(), or reader.read() is called.
//
// 3. Response body (completions):
//    - Streaming: tee'd. One branch to user unchanged, other buffers last 4KB
//      to extract .usage. Content chunks pass through without inspection.
//    - Non-streaming: full response body is read into Worker memory as
//      arrayBuffer to extract .usage. The FULL response (including content)
//      exists in Worker memory for the duration of the request. However:
//      code only accesses .usage/.usageMetadata fields, never .choices/.content.
//      Worker memory is V8-isolate-scoped (one isolate per request) and GC'd
//      after the request completes. No other request or external party can read
//      it. The infrastructure trust assumption is Cloudflare itself — same as
//      any cloud provider.
//
// 4. Storage: D1 only stores: timestamp, user_hash, provider, model, token
//    counts, endpoint path. No prompts, no responses, no API keys.
//
// AUDIT: Search this codebase for "authorization", "x-api-key", "content",
// "choices", "message", "prompt" — none appear in any data-reading context.

import { PROVIDER_SHORTCUTS, extractUsage, type UsageData } from "./providers";
import { teeStreamForUsage } from "./stream";
import {
  initDB, recordUsage, getMerkleState,
  storeT20Receipt, getUnanchoredReceipts, storeT20Anchor,
  isAnchorPeriodDone, getReceiptProofData,
  getUnverifiedAnchors, markAnchorVerified, deleteFailedAnchor,
  walletCache,
  type Env
} from "./db";
import {
  createSignedReceipt, buildMerkleTree, submitAnchor,
  getCurrentBlock, getAnchorPeriod, formatReceiptHeader,
  checkAnchorOnChain, submitInscribeWithPermit, getInscribeNonce,
  type SignedReceipt
} from "./token20";
import { verifyMessage } from "viem";
import type { Hex, Address } from "viem";

let dbReady = false;
let cachedSigningKey: CryptoKey | null = null;

// ── SIWE helpers (EIP-4361) ──

const SIWE_DOMAIN = "token.nousai.cc";
const SIWE_URI = "https://token.nousai.cc";
const SIWE_CHAIN_ID = "8453"; // Base
const SIWE_VERSION = "1";
const SIWE_NONCE_TTL = 300; // 5 minutes

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function parseSiweMessage(msg: string): {
  domain: string; address: string; statement: string;
  uri: string; version: string; chainId: string;
  nonce: string; issuedAt: string;
} | null {
  const re = /^(.+?) wants you to sign in with your Ethereum account:\n(0x[a-fA-F0-9]{40})\n\n(.*?)\n\nURI: (.+?)\nVersion: (\d+)\nChain ID: (\d+)\nNonce: ([a-f0-9]+)\nIssued At: (.+)$/s;
  const m = msg.match(re);
  if (!m) return null;
  return {
    domain: m[1], address: m[2], statement: m[3],
    uri: m[4], version: m[5], chainId: m[6],
    nonce: m[7], issuedAt: m[8],
  };
}

async function getSigningKey(env: Env): Promise<CryptoKey | null> {
  if (cachedSigningKey) return cachedSigningKey;
  if (!env.SIGNING_KEY) return null;
  try {
    cachedSigningKey = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(env.SIGNING_KEY),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    return cachedSigningKey;
  } catch {
    return null;
  }
}

export default {
  // Cron trigger: anchor Merkle roots every 10 minutes
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    if (!dbReady) {
      await initDB(env.DB);
      dbReady = true;
    }
    const result = await handleAnchor(env);
    if (result.anchored.length > 0) {
      console.log(`Anchored periods: ${result.anchored.join(", ")}`);
    }
    if (result.errors.length > 0) {
      console.error(`Anchor errors: ${result.errors.join("; ")}`);
    }
  },

  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(request) });
    }

    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      return json({ ok: true, service: "nous-token-gateway", version: "0.1.0" });
    }

    // Leaderboard API (public, read-only)
    if (url.pathname.startsWith("/api/")) {
      if (!dbReady) {
        await initDB(env.DB);
        dbReady = true;
      }
      // Token-20 endpoints + wallet auth
      if (url.pathname.startsWith("/api/t20/") || url.pathname.startsWith("/api/auth/")) {
        const t20Response = await handleT20API(request, url, env);
        if (t20Response) return t20Response;
      }
      return handleAPI(request, url, env);
    }

    // ── Proxy Logic ──

    // Wallet identity: from header, query param, or path segment (/provider/w/0x.../)
    // Path segment is needed because ANTHROPIC_BASE_URL can't have query params (SDK breaks them)
    let walletFromPath = "";
    const walletHeader = (request.headers.get("x-nous-wallet") || "").toLowerCase();
    const walletQuery = (url.searchParams.get("wallet") || "").toLowerCase();
    // Path wallet extracted during routing below

    // User identity: always compute from API key when available.
    // X-Nous-User is accepted ONLY when no API key is present (e.g. plugin stripped it).
    // When both exist, they must match — prevents identity spoofing.
    const authRaw = request.headers.get("authorization")
      || request.headers.get("x-api-key")
      || request.headers.get("x-goog-api-key")  // Gemini
      || "";
    const rawKey = authRaw.replace(/^Bearer\s+/i, "");
    const claimedHash = request.headers.get("x-nous-user");

    let userHash: string;
    if (rawKey) {
      userHash = await sha256Short(rawKey);
      if (claimedHash && claimedHash !== userHash) {
        return json({ error: "X-Nous-User does not match API key" }, 403);
      }
    } else if (claimedHash && /^[a-f0-9]{32}$/.test(claimedHash)) {
      userHash = claimedHash;
    } else {
      return json({ error: "Missing API key or X-Nous-User header." }, 401);
    }

    // Resolve upstream: shortcut prefix (e.g. /openai/v1/...) or X-Nous-Upstream header
    const parts = url.pathname.split("/");
    const firstSegment = parts[1]?.toLowerCase() || "";
    const shortcutUpstream = PROVIDER_SHORTCUTS[firstSegment];
    const customUpstream = request.headers.get("x-nous-upstream");

    let upstreamBase: string;
    let providerName: string;
    let apiPath: string;

    if (shortcutUpstream) {
      // Known shortcut: /openai/v1/chat/completions → api.openai.com/v1/chat/completions
      upstreamBase = shortcutUpstream;
      providerName = firstSegment;
      // Check for wallet in path: /provider/w/0x.../rest/of/path
      let restParts = parts.slice(2);
      if (restParts[0] === "w" && restParts[1] && /^0x[a-f0-9]{40}$/i.test(restParts[1])) {
        walletFromPath = restParts[1].toLowerCase();
        restParts = restParts.slice(2);
      }
      apiPath = "/" + restParts.join("/");
    } else if (customUpstream) {
      // Custom upstream via header: validated URL (HTTPS only, no internal IPs)
      try {
        const parsed = new URL(customUpstream);
        if (parsed.protocol !== "https:") {
          return json({ error: "X-Nous-Upstream must use HTTPS" }, 400);
        }
        // Block internal/private ranges (IPv4, IPv6, link-local, metadata)
        const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase(); // strip IPv6 brackets
        if (isBlockedHost(host)) {
          return json({ error: "X-Nous-Upstream cannot target internal addresses" }, 400);
        }
        upstreamBase = parsed.origin;
        providerName = parsed.hostname.split(".")[1] || parsed.hostname.split(".")[0] || "custom";
        // Full path from the request (no prefix stripping)
        apiPath = url.pathname;
      } catch {
        return json({ error: "Invalid X-Nous-Upstream URL" }, 400);
      }
    } else {
      const shortcuts = Object.keys(PROVIDER_SHORTCUTS).join(", /");
      return json(
        { error: `Unknown route. Use: /${shortcuts}, or set X-Nous-Upstream header for custom providers.` },
        400
      );
    }

    // Strip nous-specific query params before forwarding
    const upstreamParams = new URLSearchParams(url.search);
    upstreamParams.delete("wallet");
    const upstreamQuery = upstreamParams.toString();
    const upstreamUrl = upstreamBase + apiPath + (upstreamQuery ? "?" + upstreamQuery : "");

    const upstreamHeaders = new Headers(request.headers);
    upstreamHeaders.delete("host");
    upstreamHeaders.delete("x-nous-user");
    upstreamHeaders.delete("x-nous-upstream");
    upstreamHeaders.delete("x-nous-wallet");

    let upstreamResponse: Response;
    try {
      upstreamResponse = await fetch(upstreamUrl, {
        method: request.method,
        headers: upstreamHeaders,
        body: request.body,
      });
    } catch (err) {
      return json({ error: "Failed to reach provider" }, 502);
    }

    const responseHeaders = new Headers(upstreamResponse.headers);
    for (const [k, v] of Object.entries(corsHeaders(request))) {
      responseHeaders.set(k, v);
    }
    // Resolve wallet from header, query, or path (in priority order)
    const walletRaw = walletHeader || walletQuery || walletFromPath;
    const validWallet = /^0x[a-f0-9]{40}$/.test(walletRaw) ? walletRaw : "";

    // Tell the user their hash — so they can find themselves on the leaderboard
    responseHeaders.set("x-nous-user-hash", userHash);

    if (!dbReady) {
      await initDB(env.DB);
      dbReady = true;
    }

    const contentType = upstreamResponse.headers.get("content-type") || "";
    const isStreaming = contentType.includes("text/event-stream");
    const endpoint = apiPath.replace(/^\//, "");

    const signingKey = await getSigningKey(env);

    if (isStreaming && upstreamResponse.body) {
      const [clientStream, usagePromise] = teeStreamForUsage(upstreamResponse);

      ctx.waitUntil(
        usagePromise.then(async (usage) => {
          if (usage) {
            const receipt = await recordUsage(env.DB, userHash, providerName, usage, endpoint, signingKey ?? undefined, validWallet);
            // Generate token-20 receipt if wallet is present and gateway key configured
            if (validWallet && env.GATEWAY_PRIVATE_KEY && receipt) {
              await generateT20Receipt(env, validWallet, usage, receipt.id);
            }
          }
        })
      );

      return new Response(clientStream, {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    } else {
      const bodyBytes = await upstreamResponse.arrayBuffer();

      // Record usage and generate T20 receipt in background to avoid blocking response.
      // Receipt is stored in DB and retrievable via /api/t20/my-receipts.
      ctx.waitUntil(
        (async () => {
          try {
            const text = new TextDecoder().decode(bodyBytes);
            const parsed = JSON.parse(text) as Record<string, unknown>;
            const usage = extractUsage(parsed);
            if (usage && usage.totalTokens > 0) {
              const receipt = await recordUsage(env.DB, userHash, providerName, usage, endpoint, signingKey ?? undefined, validWallet);
              if (validWallet && env.GATEWAY_PRIVATE_KEY && receipt) {
                await generateT20Receipt(env, validWallet, usage, receipt.id);
              }
            }
          } catch {
            // Non-JSON response or no usage data — expected for non-chat endpoints
          }
        })()
      );

      return new Response(bodyBytes, {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    }
  },
};

// ── Leaderboard API (read-only) ──

async function handleAPI(request: Request, url: URL, env: Env): Promise<Response> {
  if (!dbReady) {
    await initDB(env.DB);
    dbReady = true;
  }

  // GET /api/leaderboard — top users by total tokens
  if (url.pathname === "/api/leaderboard") {
    const days = safeInt(url.searchParams.get("days"), 30);
    const limit = Math.min(safeInt(url.searchParams.get("limit"), 100), 500);
    const idExpr = `CASE WHEN wallet != '' THEN wallet ELSE user_hash END`;

    const rows = days > 0
      ? await env.DB.prepare(
          `SELECT ${idExpr} as identity, MAX(wallet) as wallet, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count
           FROM usage_records WHERE timestamp > ? GROUP BY ${idExpr} ORDER BY total_tokens DESC LIMIT ?`
        ).bind(new Date(Date.now() - days * 86400000).toISOString(), limit).all()
      : await env.DB.prepare(
          `SELECT ${idExpr} as identity, MAX(wallet) as wallet, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count
           FROM usage_records GROUP BY ${idExpr} ORDER BY total_tokens DESC LIMIT ?`
        ).bind(limit).all();

    return json({ ok: true, data: rows.results, period_days: days });
  }

  // GET /api/models — usage breakdown by model (aggregated across providers)
  if (url.pathname === "/api/models") {
    const days = safeInt(url.searchParams.get("days"), 30);

    const rows = days > 0
      ? await env.DB.prepare(
          `SELECT model, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count, COUNT(DISTINCT CASE WHEN wallet != '' THEN wallet ELSE user_hash END) as unique_users
           FROM usage_records WHERE timestamp > ? GROUP BY model ORDER BY total_tokens DESC`
        ).bind(new Date(Date.now() - days * 86400000).toISOString()).all()
      : await env.DB.prepare(
          `SELECT model, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count, COUNT(DISTINCT CASE WHEN wallet != '' THEN wallet ELSE user_hash END) as unique_users
           FROM usage_records GROUP BY model ORDER BY total_tokens DESC`
        ).all();

    return json({ ok: true, data: rows.results, period_days: days });
  }

  // GET /api/leaderboard/model — top users for a specific model (across all providers)
  if (url.pathname === "/api/leaderboard/model") {
    const model = url.searchParams.get("model") || "";
    const days = safeInt(url.searchParams.get("days"), 30);
    const limit = Math.min(safeInt(url.searchParams.get("limit"), 100), 500);
    const idExpr = `CASE WHEN wallet != '' THEN wallet ELSE user_hash END`;

    if (!model) return json({ error: "model parameter required" }, 400);

    const rows = days > 0
      ? await env.DB.prepare(
          `SELECT ${idExpr} as identity, MAX(wallet) as wallet, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count
           FROM usage_records WHERE model = ? AND timestamp > ? GROUP BY ${idExpr} ORDER BY total_tokens DESC LIMIT ?`
        ).bind(model, new Date(Date.now() - days * 86400000).toISOString(), limit).all()
      : await env.DB.prepare(
          `SELECT ${idExpr} as identity, MAX(wallet) as wallet, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count
           FROM usage_records WHERE model = ? GROUP BY ${idExpr} ORDER BY total_tokens DESC LIMIT ?`
        ).bind(model, limit).all();

    return json({ ok: true, data: rows.results, model, period_days: days });
  }

  // GET /api/stats — global totals
  if (url.pathname === "/api/stats") {
    const rows = await env.DB.prepare(
      `SELECT COUNT(*) as total_calls,
              SUM(total_tokens) as total_tokens,
              COUNT(DISTINCT CASE WHEN wallet != '' THEN wallet ELSE user_hash END) as total_users,
              COUNT(DISTINCT model) as total_models
       FROM usage_records`
    ).all();

    return json({ ok: true, data: rows.results[0] });
  }

  // GET /api/wallet/:address — usage for a wallet (aggregated across all linked hashes)
  const walletMatch = url.pathname.match(/^\/api\/wallet\/(0x[a-f0-9]{40})$/);
  if (walletMatch) {
    const addr = walletMatch[1];
    const rows = await env.DB.prepare(
      `SELECT model,
              SUM(total_tokens) as total_tokens,
              SUM(input_tokens) as input_tokens,
              SUM(output_tokens) as output_tokens,
              SUM(cost) as total_cost,
              COUNT(*) as call_count
       FROM usage_records
       WHERE wallet = ?
       GROUP BY model
       ORDER BY total_tokens DESC`
    ).bind(addr).all();

    return json({ ok: true, data: rows.results, wallet: addr });
  }

  // GET /api/user/:hash — single user stats
  const userMatch = url.pathname.match(/^\/api\/user\/([a-f0-9]+)$/);
  if (userMatch) {
    const hash = userMatch[1];
    const rows = await env.DB.prepare(
      `SELECT provider, model,
              SUM(total_tokens) as total_tokens,
              SUM(input_tokens) as input_tokens,
              SUM(output_tokens) as output_tokens,
              SUM(cost) as total_cost,
              COUNT(*) as call_count
       FROM usage_records
       WHERE user_hash = ?
       GROUP BY provider, model
       ORDER BY total_tokens DESC`
    ).bind(hash).all();

    return json({ ok: true, data: rows.results, user_hash: hash });
  }

  // GET /api/user/:hash/receipts — signed receipts for a user
  // Each receipt is independently verifiable with the gateway's public key.
  const receiptsMatch = url.pathname.match(/^\/api\/user\/([a-f0-9]+)\/receipts$/);
  if (receiptsMatch) {
    const hash = receiptsMatch[1];
    const afterId = safeInt(url.searchParams.get("after"), 0);
    const limit = Math.min(safeInt(url.searchParams.get("limit"), 100), 1000);

    const rows = await env.DB.prepare(
      `SELECT id, timestamp, provider, model,
              input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
              total_tokens, leaf_hash, receipt_sig
       FROM usage_records
       WHERE user_hash = ? AND id > ?
       ORDER BY id ASC
       LIMIT ?`
    ).bind(hash, afterId, limit).all();

    return json({
      ok: true,
      data: (rows.results as Array<Record<string, unknown>>).map((r) => ({
        p: "nous",
        v: 1,
        type: "receipt",
        id: r.id,
        ts: r.timestamp,
        user: hash,
        provider: r.provider,
        model: r.model,
        input: r.input_tokens,
        output: r.output_tokens,
        cache_read: r.cache_read_tokens,
        cache_write: r.cache_write_tokens,
        total: r.total_tokens,
        leaf: r.leaf_hash,
        sig: r.receipt_sig,
      })),
      has_more: rows.results.length === limit,
    });
  }

  // GET /api/records — export raw records for verification
  // Sentinels pull this to independently recompute leaf hashes and rebuild the MMR.
  if (url.pathname === "/api/records") {
    const afterId = safeInt(url.searchParams.get("after"), 0);
    const limit = Math.min(safeInt(url.searchParams.get("limit"), 1000), 10000);

    const rows = await env.DB.prepare(
      `SELECT id, timestamp, user_hash, provider, model,
              input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
              total_tokens, leaf_hash, receipt_sig
       FROM usage_records
       WHERE id > ?
       ORDER BY id ASC
       LIMIT ?`
    ).bind(afterId, limit).all();

    return json({ ok: true, data: rows.results, has_more: rows.results.length === limit });
  }

  // GET /api/chain — Merkle root and MMR state for tamper verification
  // Sentinels compare their locally computed root with this.
  if (url.pathname === "/api/chain") {
    const state = await getMerkleState(env.DB);

    return json({
      ok: true,
      data: {
        merkle_root: state.merkle_root || "empty",
        leaf_count: state.leaf_count,
        peak_count: state.peaks.length,
      },
    });
  }

  // POST /api/sign — gateway signs a user's usage summary for on-chain proof
  // Requires API key — hash is computed server-side, not trusted from header.
  if (url.pathname === "/api/sign" && request.method === "POST") {
    if (!env.SIGNING_KEY) {
      return json({ error: "Signing not configured" }, 501);
    }

    const callerHash = await authenticateCaller(request);
    if (!callerHash) {
      return json({ error: "API key required (Authorization header)" }, 401);
    }

    try {
      const body = await request.json() as { user_hash?: string; receipt_ids?: number[] };
      const userHash = body.user_hash || callerHash;
      if (userHash !== callerHash) {
        return json({ error: "Can only sign your own usage" }, 403);
      }
      if (!/^[a-f0-9]{32}$/.test(userHash)) {
        return json({ error: "Invalid user_hash" }, 400);
      }

      // If receipt_ids provided, summarize only those receipts
      // Otherwise, summarize all receipts for this user
      let rows;
      if (body.receipt_ids && body.receipt_ids.length > 0) {
        if (!Array.isArray(body.receipt_ids)
          || body.receipt_ids.length > 100
          || !body.receipt_ids.every((id: unknown) => typeof id === "number" && Number.isInteger(id))) {
          return json({ error: "receipt_ids must be an array of up to 100 integers" }, 400);
        }
        const placeholders = body.receipt_ids.map(() => "?").join(",");
        rows = await env.DB.prepare(
          `SELECT provider, model,
                  SUM(input_tokens) as input_tokens,
                  SUM(output_tokens) as output_tokens,
                  SUM(total_tokens) as total_tokens,
                  COUNT(*) as call_count,
                  MIN(id) as first_id,
                  MAX(id) as last_id
           FROM usage_records
           WHERE user_hash = ? AND id IN (${placeholders})
           GROUP BY provider, model
           ORDER BY total_tokens DESC`
        ).bind(userHash, ...body.receipt_ids).all();
      } else {
        rows = await env.DB.prepare(
          `SELECT provider, model,
                  SUM(input_tokens) as input_tokens,
                  SUM(output_tokens) as output_tokens,
                  SUM(total_tokens) as total_tokens,
                  COUNT(*) as call_count,
                  MIN(id) as first_id,
                  MAX(id) as last_id
           FROM usage_records
           WHERE user_hash = ?
           GROUP BY provider, model
           ORDER BY total_tokens DESC`
        ).bind(userHash).all();
      }

      if (!rows.results || rows.results.length === 0) {
        return json({ error: "No data for this user" }, 404);
      }

      let totalTokens = 0, totalCalls = 0;
      for (const r of rows.results as Array<Record<string, number>>) {
        totalTokens += r.total_tokens || 0;
        totalCalls += r.call_count || 0;
      }

      const proof = {
        p: "nous",
        v: 1,
        type: "summary",
        user: userHash,
        total_tokens: totalTokens,
        total_calls: totalCalls,
        models: (rows.results as Array<Record<string, unknown>>).map((r) => ({
          provider: r.provider,
          model: r.model,
          tokens: r.total_tokens,
          calls: r.call_count,
        })),
        ts: Math.floor(Date.now() / 1000),
      };

      const proofString = JSON.stringify(proof);

      const signingKey = await getSigningKey(env);
      if (!signingKey) {
        return json({ error: "Signing key unavailable" }, 500);
      }

      const sigBuffer = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        signingKey,
        new TextEncoder().encode(proofString)
      );

      const signature = Array.from(new Uint8Array(sigBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      return json({ ok: true, proof, signature });
    } catch (err) {
      return json({ error: "Signing failed" }, 500);
    }
  }

  // GET /api/pubkey — gateway's public key for verifying signed proofs
  if (url.pathname === "/api/pubkey") {
    if (!env.SIGNING_KEY) {
      return json({ error: "Signing not configured" }, 501);
    }
    try {
      const jwk = JSON.parse(env.SIGNING_KEY);
      // Return only the public components (strip d, the private key)
      const pubkey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
      return json({ ok: true, algorithm: "ECDSA-P256-SHA256", pubkey });
    } catch {
      return json({ error: "Key error" }, 500);
    }
  }

  // POST /api/bind-wallet — cryptographic wallet binding with signature verification
  // User signs "nous-token:bind:{wallet}" with their wallet, proving ownership.
  if (url.pathname === "/api/bind-wallet" && request.method === "POST") {
    const callerHash = await authenticateCaller(request);
    if (!callerHash) {
      return json({ error: "API key required (Authorization header)" }, 401);
    }

    try {
      const body = await request.json() as { wallet?: string; signature?: string; timestamp?: number };
      const wallet = (body.wallet || "").toLowerCase();
      const signature = body.signature || "";

      if (!wallet || !/^0x[a-f0-9]{40}$/.test(wallet)) {
        return json({ error: "Invalid wallet address" }, 400);
      }
      if (!signature) {
        return json({ error: "Signature required" }, 400);
      }

      // Verify the wallet owner signed the binding message with timestamp
      // Message format: "nous-token:bind:{wallet}:{timestamp}"
      // Timestamp must be within 5 minutes to prevent replay attacks
      const bindTs = body.timestamp;
      const now = Math.floor(Date.now() / 1000);
      if (!bindTs || typeof bindTs !== "number" || Math.abs(now - bindTs) > 300) {
        return json({ error: "Timestamp required and must be within 5 minutes" }, 400);
      }

      const message = `nous-token:bind:${wallet}:${bindTs}`;
      const valid = await verifyMessage({
        address: wallet as Address,
        message,
        signature: signature as Hex,
      });
      if (!valid) {
        return json({ error: "Invalid signature — wallet ownership not proven" }, 403);
      }

      // Check current binding
      const existing = await env.DB.prepare(
        `SELECT wallet FROM usage_records WHERE user_hash = ? AND wallet != '' ORDER BY id DESC LIMIT 1`
      ).bind(callerHash).first<{ wallet: string }>();

      const oldWallet = existing?.wallet || "";

      if (oldWallet === wallet) {
        return json({ ok: true, message: "Already bound", wallet });
      }

      // Backfill only records with no wallet (first bind),
      // or leave old records on old wallet (rebind — new records go to new wallet)
      if (!oldWallet) {
        await env.DB.prepare(
          `UPDATE usage_records SET wallet = ? WHERE user_hash = ? AND wallet = ''`
        ).bind(wallet, callerHash).run();
      }

      // Update cache so new records use new wallet
      walletCache.set(callerHash, wallet);

      const msg = oldWallet ? `Rebound from ${oldWallet.slice(0,6)}...${oldWallet.slice(-4)}` : "Wallet bound";
      return json({ ok: true, message: msg, wallet, previous: oldWallet || undefined });
    } catch (err) {
      return json({ error: "Bind failed" }, 500);
    }
  }

  return json({ error: "Not found" }, 404);
}

// ── Token-20 ──

async function generateT20Receipt(
  env: Env,
  wallet: string,
  usage: UsageData,
  usageRecordId: number
): Promise<SignedReceipt | null> {
  if (!env.GATEWAY_PRIVATE_KEY) return null;
  try {
    const blockNumber = await getCurrentBlock();
    const anchorPeriod = getAnchorPeriod(blockNumber);
    const pk = (env.GATEWAY_PRIVATE_KEY.startsWith("0x")
      ? env.GATEWAY_PRIVATE_KEY
      : "0x" + env.GATEWAY_PRIVATE_KEY) as Hex;

    // Normalize model name: strip "provider/" prefix to match DB storage and on-chain series modelId
    const normalizedModel = usage.model.includes("/") ? usage.model.split("/").pop()! : usage.model;

    const signed = await createSignedReceipt(
      pk,
      wallet as Address,
      normalizedModel,
      usage.totalTokens,
      blockNumber
    );

    await storeT20Receipt(
      env.DB,
      usageRecordId,
      wallet,
      usage.model,
      usage.totalTokens,
      blockNumber,
      signed.receiptEncoded,
      signed.receiptHash,
      signed.signature,
      anchorPeriod
    );

    return signed;
  } catch (err) {
    console.error("token-20 receipt error:", err);
    return null;
  }
}

/**
 * Anchor handler: build Merkle tree for completed periods and submit to chain.
 * Called by cron trigger every 10 minutes.
 */
async function handleAnchor(env: Env): Promise<{ anchored: number[]; errors: string[] }> {
  if (!env.GATEWAY_PRIVATE_KEY) return { anchored: [], errors: ["No GATEWAY_PRIVATE_KEY"] };

  const pk = (env.GATEWAY_PRIVATE_KEY.startsWith("0x")
    ? env.GATEWAY_PRIVATE_KEY
    : "0x" + env.GATEWAY_PRIVATE_KEY) as Hex;

  const currentBlock = await getCurrentBlock();
  const currentPeriod = getAnchorPeriod(currentBlock);

  // Find all periods with receipts that haven't been anchored yet
  const rows = await env.DB.prepare(
    `SELECT DISTINCT anchor_period FROM t20_receipts
     WHERE anchor_period < ?
     AND anchor_period NOT IN (SELECT period_start FROM t20_anchors)
     ORDER BY anchor_period ASC`
  ).bind(currentPeriod).all();

  const anchored: number[] = [];
  const errors: string[] = [];

  for (const row of rows.results as Array<{ anchor_period: number }>) {
    const period = row.anchor_period;
    try {
      const receipts = await getUnanchoredReceipts(env.DB, period);
      if (receipts.length === 0) continue;

      const hashes = receipts.map(r => r.receipt_hash as Hex);
      const { root } = buildMerkleTree(hashes);

      const txHash = await submitAnchor(pk, period, root, receipts.length);
      await storeT20Anchor(env.DB, period, root, receipts.length, txHash);

      anchored.push(period);
    } catch (err) {
      errors.push(`Period ${period}: ${String(err)}`);
    }
  }

  // Verify past anchors: check on-chain state for unverified records older than 5 minutes
  const unverified = await getUnverifiedAnchors(env.DB);
  for (const a of unverified) {
    try {
      const onChainRoot = await checkAnchorOnChain(a.period_start);
      const zeroRoot = "0x" + "0".repeat(64);
      if (onChainRoot === zeroRoot) {
        // Not on chain — tx failed, delete so next cron retries
        await deleteFailedAnchor(env.DB, a.period_start);
        errors.push(`Period ${a.period_start}: tx ${a.tx_hash} not on chain, will retry`);
      } else {
        await markAnchorVerified(env.DB, a.period_start);
      }
    } catch {
      // RPC error — skip, try next cron cycle
    }
  }

  return { anchored, errors };
}

// ── Token-20 API endpoints ──

async function handleT20API(request: Request, url: URL, env: Env): Promise<Response | null> {
  // GET /api/t20/my-receipts — authenticated, returns full receipt data including signature
  // Two auth methods:
  //   1. Web: X-Wallet-Signature header (SIWE — user signs message with wallet)
  //   2. CLI/SDK: X-Nous-User header (API key hash)
  if (url.pathname === "/api/t20/my-receipts") {
    let wallet = "";

    // Auth method 1: Wallet signature (web)
    const walletAddr = (request.headers.get("x-wallet-address") || "").toLowerCase();
    const walletSig = request.headers.get("x-wallet-signature") || "";
    const walletTs = request.headers.get("x-wallet-timestamp") || "";
    if (walletAddr && walletSig && /^0x[a-f0-9]{40}$/.test(walletAddr)) {
      // Verify signature: user signed "token-20:my-receipts:{wallet}:{timestamp}"
      // Timestamp must be within 5 minutes to prevent replay attacks
      try {
        const ts = parseInt(walletTs, 10);
        const now = Math.floor(Date.now() / 1000);
        if (!isNaN(ts) && Math.abs(now - ts) <= 300) {
          const { verifyMessage } = await import("viem");
          const valid = await verifyMessage({
            address: walletAddr as Address,
            message: `token-20:my-receipts:${walletAddr}:${ts}`,
            signature: walletSig as Hex,
          });
          if (valid) wallet = walletAddr;
        }
      } catch { /* invalid sig */ }
    }

    // Auth method 2: API key (CLI/SDK) — compute hash from key, don't trust X-Nous-User alone
    if (!wallet) {
      const authRaw = request.headers.get("authorization")
        || request.headers.get("x-api-key")
        || request.headers.get("x-goog-api-key")
        || "";
      const rawKey = authRaw.replace(/^Bearer\s+/i, "");
      if (rawKey) {
        const userHash = await sha256Short(rawKey);
        const walletRow = await env.DB.prepare(
          `SELECT wallet FROM usage_records WHERE user_hash = ? AND wallet != '' ORDER BY id DESC LIMIT 1`
        ).bind(userHash).first<{ wallet: string }>();
        if (walletRow) wallet = walletRow.wallet;
      }
    }

    // Auth method 3: JWT session token (from /api/auth/wallet)
    if (!wallet) {
      const authHeader = request.headers.get("authorization") || "";
      const bearer = authHeader.replace(/^Bearer\s+/i, "").trim();
      if (bearer && bearer.includes(".")) {
        const signingKey = await getSigningKey(env);
        if (signingKey) {
          wallet = await verifyWalletJWT(env, bearer);
        }
      }
    }

    if (!wallet) {
      return json({ error: "Authentication required. Provide JWT (Authorization: Bearer), wallet signature, or API key." }, 401);
    }

    const rows = await env.DB.prepare(
      `SELECT r.*, a.merkle_root, a.tx_hash as anchor_tx
       FROM t20_receipts r
       LEFT JOIN t20_anchors a ON r.anchor_period = a.period_start
       WHERE r.wallet = ?
       ORDER BY r.id DESC
       LIMIT 100`
    ).bind(wallet).all();

    // Build Merkle proofs for anchored receipts
    const results = [];
    for (const row of rows.results as Array<Record<string, unknown>>) {
      const item: Record<string, unknown> = { ...row };
      if (row.anchor_tx && row.receipt_hash) {
        const proofData = await getReceiptProofData(env.DB, row.receipt_hash as string);
        if (proofData) {
          const hashes = proofData.allHashes.map(h => h as Hex);
          const { proofs } = buildMerkleTree(hashes);
          item.merkle_proof = proofs.get(row.receipt_hash as Hex) || [];
          item.period_start = proofData.anchorPeriod;
        }
      }
      results.push(item);
    }

    return json({ ok: true, wallet, data: results });
  }

  // GET /api/siwe/nonce — generate a one-time nonce for SIWE signing
  if (url.pathname === "/api/siwe/nonce" && request.method === "GET") {
    const nonce = generateNonce();
    const now = Math.floor(Date.now() / 1000);
    // Store nonce, clean expired ones opportunistically
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO siwe_nonces (nonce, created_at) VALUES (?, ?)`).bind(nonce, now),
      env.DB.prepare(`DELETE FROM siwe_nonces WHERE created_at < ?`).bind(now - SIWE_NONCE_TTL),
    ]);
    return json({ ok: true, nonce });
  }

  // POST /api/auth/wallet — SIWE signature → JWT session token (24 hours)
  if (url.pathname === "/api/auth/wallet" && request.method === "POST") {
    const signingKey = await getSigningKey(env);
    if (!signingKey) {
      return json({ error: "Signing not configured" }, 501);
    }

    try {
      const body = await request.json() as { wallet?: string; signature?: string; message?: string };
      const wallet = (body.wallet || "").toLowerCase();
      const signature = body.signature || "";
      const message = body.message || "";

      if (!wallet || !/^0x[a-f0-9]{40}$/.test(wallet)) {
        return json({ error: "Invalid wallet address" }, 400);
      }
      if (!signature || !message) {
        return json({ error: "signature and message required" }, 400);
      }

      // Parse and validate SIWE message
      const siwe = parseSiweMessage(message);
      if (!siwe) {
        return json({ error: "Invalid SIWE message format" }, 400);
      }
      if (siwe.domain !== SIWE_DOMAIN) {
        return json({ error: "Domain mismatch" }, 403);
      }
      if (siwe.address.toLowerCase() !== wallet) {
        return json({ error: "Address mismatch" }, 403);
      }
      if (siwe.chainId !== SIWE_CHAIN_ID) {
        return json({ error: "Chain ID mismatch" }, 403);
      }
      if (siwe.uri !== SIWE_URI) {
        return json({ error: "URI mismatch" }, 403);
      }
      if (siwe.version !== SIWE_VERSION) {
        return json({ error: "Version mismatch" }, 403);
      }

      // Verify issuedAt is within 5 minutes
      const issuedAt = new Date(siwe.issuedAt).getTime();
      if (isNaN(issuedAt) || Math.abs(Date.now() - issuedAt) > SIWE_NONCE_TTL * 1000) {
        return json({ error: "Message expired" }, 400);
      }

      // Verify nonce exists and consume it (one-time use)
      const nonceRow = await env.DB.prepare(
        `DELETE FROM siwe_nonces WHERE nonce = ? AND created_at > ? RETURNING nonce`
      ).bind(siwe.nonce, Math.floor(Date.now() / 1000) - SIWE_NONCE_TTL).first<{ nonce: string }>();
      if (!nonceRow) {
        return json({ error: "Invalid or expired nonce" }, 403);
      }

      // Verify wallet signature
      const valid = await verifyMessage({
        address: wallet as Address,
        message,
        signature: signature as Hex,
      });
      if (!valid) {
        return json({ error: "Invalid signature" }, 403);
      }

      // Issue JWT — 24 hour expiry
      const now = Math.floor(Date.now() / 1000);
      const jwt = await createWalletJWT(env, wallet, now + 86400);
      return json({ ok: true, token: jwt, wallet, expires_in: 86400 });
    } catch {
      return json({ error: "Auth failed" }, 500);
    }
  }

  // GET /api/t20/wallet/:address — receipts summary for a wallet (public, no sensitive fields)
  const walletMatch = url.pathname.match(/^\/api\/t20\/wallet\/(0x[a-f0-9]{40})$/);
  if (walletMatch) {
    const addr = walletMatch[1];
    const rows = await env.DB.prepare(
      `SELECT r.id, r.model, r.tokens, r.block_number, r.anchor_period, r.created_at,
              a.tx_hash as anchor_tx
       FROM t20_receipts r
       LEFT JOIN t20_anchors a ON r.anchor_period = a.period_start
       WHERE r.wallet = ?
       ORDER BY r.id DESC
       LIMIT 100`
    ).bind(addr).all();

    return json({ ok: true, data: rows.results });
  }

  // GET /api/t20/anchors — recent anchors
  if (url.pathname === "/api/t20/anchors") {
    const rows = await env.DB.prepare(
      `SELECT * FROM t20_anchors ORDER BY period_start DESC LIMIT 50`
    ).all();
    return json({ ok: true, data: rows.results });
  }

  // POST /api/t20/inscribe — relayer endpoint for agents
  // Agent provides: seriesId + permit signature (USDC) + EIP-712 inscribe auth signature.
  // Gateway looks up receipt + proof, submits inscribeWithPermit. USDC goes wallet→treasury/creator.
  if (url.pathname === "/api/t20/inscribe" && request.method === "POST") {
    if (!env.GATEWAY_PRIVATE_KEY) {
      return json({ error: "Not configured" }, 501);
    }

    // Authenticate: JWT or API key
    let wallet = "";

    const authHeaderVal = request.headers.get("authorization") || "";
    const bearerVal = authHeaderVal.replace(/^Bearer\s+/i, "").trim();
    if (bearerVal && bearerVal.includes(".")) {
      const signingKey = await getSigningKey(env);
      wallet = await verifyWalletJWT(env, bearerVal);
    }

    if (!wallet) {
      const callerHash = await authenticateCaller(request);
      if (callerHash) {
        const walletRow = await env.DB.prepare(
          `SELECT wallet FROM usage_records WHERE user_hash = ? AND wallet != '' ORDER BY id DESC LIMIT 1`
        ).bind(callerHash).first<{ wallet: string }>();
        if (walletRow) wallet = walletRow.wallet;
      }
    }

    if (!wallet) {
      return json({ error: "Authentication required (JWT or API key with bound wallet)" }, 401);
    }

    try {
      const body = await request.json() as {
        series_id?: number;
        // EIP-2612 permit (USDC approval for exact fee)
        permit_deadline?: number;
        permit_v?: number;
        permit_r?: string;
        permit_s?: string;
        // EIP-712 inscribe auth
        auth_v?: number;
        auth_r?: string;
        auth_s?: string;
      };

      if (!body.series_id || typeof body.series_id !== "number") {
        return json({ error: "series_id required" }, 400);
      }
      if (!body.permit_v || !body.permit_r || !body.permit_s || !body.permit_deadline) {
        return json({ error: "permit signature required (permit_deadline, permit_v, permit_r, permit_s)" }, 400);
      }
      if (!body.auth_v || !body.auth_r || !body.auth_s) {
        return json({ error: "inscribe auth signature required (auth_v, auth_r, auth_s)" }, 400);
      }

      // Find best anchored receipt
      const receiptRow = await env.DB.prepare(
        `SELECT r.*, a.merkle_root, a.period_start
         FROM t20_receipts r
         JOIN t20_anchors a ON r.anchor_period = a.period_start AND a.verified = 1
         WHERE r.wallet = ?
         ORDER BY r.tokens DESC
         LIMIT 1`
      ).bind(wallet).first<Record<string, unknown>>();

      if (!receiptRow) {
        return json({ error: "No anchored receipt found for this wallet" }, 404);
      }

      const proofData = await getReceiptProofData(env.DB, receiptRow.receipt_hash as string);
      if (!proofData) {
        return json({ error: "Cannot build merkle proof" }, 500);
      }

      const hashes = proofData.allHashes.map(h => h as Hex);
      const { proofs } = buildMerkleTree(hashes);
      const merkleProof = proofs.get(receiptRow.receipt_hash as Hex) || [];

      const pk = (env.GATEWAY_PRIVATE_KEY.startsWith("0x")
        ? env.GATEWAY_PRIVATE_KEY
        : "0x" + env.GATEWAY_PRIVATE_KEY) as Hex;

      const txHash = await submitInscribeWithPermit(
        pk,
        body.series_id,
        receiptRow.receipt_encoded as Hex,
        receiptRow.signature as Hex,
        merkleProof,
        proofData.anchorPeriod,
        BigInt(body.permit_deadline),
        body.permit_v,
        body.permit_r as Hex,
        body.permit_s as Hex,
        body.auth_v,
        body.auth_r as Hex,
        body.auth_s as Hex
      );

      return json({
        ok: true,
        tx_hash: txHash,
        wallet,
        series_id: body.series_id,
        receipt_tokens: receiptRow.tokens,
        period_start: proofData.anchorPeriod,
      });
    } catch (err) {
      return json({ error: `Inscribe failed: ${String(err)}` }, 500);
    }
  }

  // GET /api/t20/nonce/:wallet — get current inscribe nonce for wallet auth signing
  const nonceMatch = url.pathname.match(/^\/api\/t20\/nonce\/(0x[a-f0-9]{40})$/);
  if (nonceMatch) {
    try {
      const nonce = await getInscribeNonce(nonceMatch[1] as Address);
      return json({ ok: true, wallet: nonceMatch[1], nonce });
    } catch (err) {
      return json({ error: `Failed to read nonce: ${String(err)}` }, 500);
    }
  }

  // POST /api/t20/anchor — manually trigger anchor (admin only)
  if (url.pathname === "/api/t20/anchor" && request.method === "POST") {
    if (!env.GATEWAY_PRIVATE_KEY) {
      return json({ error: "Not configured" }, 501);
    }
    const adminSecret = (env as Record<string, unknown>).ADMIN_SECRET as string | undefined;
    if (!adminSecret) {
      return json({ error: "ADMIN_SECRET not configured" }, 501);
    }
    const authHeader = request.headers.get("authorization") || "";
    const bearerToken = authHeader.replace(/^Bearer\s+/i, "");
    if (!bearerToken || !timingSafeEqual(bearerToken, adminSecret)) {
      return json({ error: "Unauthorized" }, 401);
    }
    const result = await handleAnchor(env);
    return json({ ok: true, ...result });
  }

  return null;
}

// ── Helpers ──

const ALLOWED_ORIGINS = ["https://token.nousai.cc", "https://nousai.cc"];

function corsHeaders(request?: Request): Record<string, string> {
  const origin = request?.headers.get("origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key, X-Goog-Api-Key, X-Nous-User, X-Nous-Upstream, X-Nous-Wallet, X-Wallet-Address, X-Wallet-Signature, X-Wallet-Timestamp",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function safeInt(val: string | null, fallback: number): number {
  const n = parseInt(val || String(fallback));
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

// Authenticate API caller: compute user_hash from API key.
// Returns null if no API key present — never trusts X-Nous-User alone for API endpoints.
async function authenticateCaller(request: Request): Promise<string | null> {
  const authRaw = request.headers.get("authorization")
    || request.headers.get("x-api-key")
    || request.headers.get("x-goog-api-key")
    || "";
  const rawKey = authRaw.replace(/^Bearer\s+/i, "");
  if (!rawKey) return null;
  return sha256Short(rawKey);
}

// SSRF protection: block internal/private/metadata addresses
// Covers RFC 1918, link-local, loopback, IPv4-mapped IPv6, cloud metadata
function isBlockedHost(host: string): boolean {
  // Loopback
  if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0"
    || host === "::1" || host === "[::1]"
    || host === "0000:0000:0000:0000:0000:0000:0000:0001") return true;

  // RFC 1918 IPv4
  if (host.startsWith("10.")) return true;
  if (host.startsWith("192.168.")) return true;
  // 172.16.0.0/12 = 172.16.x.x through 172.31.x.x (NOT all 172.x.x.x)
  if (host.startsWith("172.")) {
    const second = parseInt(host.split(".")[1], 10);
    if (second >= 16 && second <= 31) return true;
  }

  // Link-local
  if (host.startsWith("169.254.")) return true;

  // IPv6 private/link-local
  if (host.startsWith("fc") || host.startsWith("fd")) return true;  // ULA
  if (host.startsWith("fe80")) return true;  // link-local

  // IPv4-mapped IPv6 — catches ::ffff:10.x, ::ffff:127.x, ::ffff:192.168.x, ::ffff:172.16-31.x
  const v4mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4mapped) return isBlockedHost(v4mapped[1]);
  // Also catch full-form IPv4-mapped: 0:0:0:0:0:ffff:XXYY:ZZWW (hex octets)
  const v4mappedFull = host.match(/^(?:0+:){5}ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (v4mappedFull) {
    const hi = parseInt(v4mappedFull[1], 16);
    const lo = parseInt(v4mappedFull[2], 16);
    const ip = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
    return isBlockedHost(ip);
  }

  // DNS suffixes
  if (host.endsWith(".local") || host.endsWith(".internal")) return true;

  // Cloud metadata endpoints
  if (host === "metadata.google.internal") return true;
  if (host === "100.100.100.200") return true;  // Alibaba Cloud

  return false;
}

// Constant-time string comparison to prevent timing attacks
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

// ── JWT Helpers (compact, HMAC-based) ──
// Uses independent JWT_SECRET — fully decoupled from SIGNING_KEY (receipt signatures).

let cachedHmacKey: CryptoKey | null = null;

async function getHmacKey(env: Env): Promise<CryptoKey | null> {
  if (cachedHmacKey) return cachedHmacKey;
  const jwtSecret = (env as Record<string, unknown>).JWT_SECRET as string | undefined;
  if (!jwtSecret) return null;
  const seed = new TextEncoder().encode(jwtSecret);
  const hashBuf = await crypto.subtle.digest("SHA-256", seed);
  cachedHmacKey = await crypto.subtle.importKey(
    "raw", hashBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
  return cachedHmacKey;
}

async function createWalletJWT(env: Env, wallet: string, exp: number): Promise<string> {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" })).replace(/=+$/, "");
  const payload = btoa(JSON.stringify({ sub: wallet, exp })).replace(/=+$/, "");
  const data = `${header}.${payload}`;
  const hmacKey = await getHmacKey(env);
  if (!hmacKey) throw new Error("JWT_SECRET not configured");
  const sigBuf = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(data));
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${data}.${sig}`;
}

async function verifyWalletJWT(env: Env, token: string): Promise<string> {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return "";

    const data = `${parts[0]}.${parts[1]}`;
    const sig = Uint8Array.from(atob(parts[2].replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));

    const hmacKey = await getHmacKey(env);
    if (!hmacKey) return "";
    const valid = await crypto.subtle.verify("HMAC", hmacKey, sig, new TextEncoder().encode(data));
    if (!valid) return "";

    const payload = JSON.parse(atob(parts[1] + "=".repeat((4 - parts[1].length % 4) % 4)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return ""; // expired
    return (payload.sub || "").toLowerCase();
  } catch {
    return "";
  }
}

// SHA-256, first 16 bytes as 32-char hex (matches plugin's hash)
async function sha256Short(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
