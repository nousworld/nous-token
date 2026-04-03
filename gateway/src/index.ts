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
import { initDB, recordUsage, getMerkleState, type Env } from "./db";

let dbReady = false;
let cachedSigningKey: CryptoKey | null = null;

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
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/health") {
      return json({ ok: true, service: "nous-token-gateway", version: "0.1.0" });
    }

    // Leaderboard API (public, read-only)
    if (url.pathname.startsWith("/api/")) {
      return handleAPI(request, url, env);
    }

    // ── Proxy Logic ──

    // User identity: prefer X-Nous-User header (plugin pre-computes hash).
    // Fallback: compute hash from API key in Authorization header.
    // This supports tools like Claude Code that can set base URL but not custom headers.
    // The API key is ONLY used for hashing — never stored, logged, or forwarded differently.
    let userHash = request.headers.get("x-nous-user");
    if (!userHash || !/^[a-f0-9]{32}$/.test(userHash)) {
      // Try to compute from API key
      const authHeader = request.headers.get("authorization")
        || request.headers.get("x-api-key")
        || request.headers.get("x-goog-api-key")  // Gemini
        || "";
      const rawKey = authHeader.replace(/^Bearer\s+/i, "");
      if (!rawKey) {
        return json({ error: "Missing X-Nous-User header and no API key found. Install the nous-token plugin or set ANTHROPIC_BASE_URL." }, 401);
      }
      userHash = await sha256Short(rawKey);
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
      apiPath = "/" + parts.slice(2).join("/");
    } else if (customUpstream) {
      // Custom upstream via header: any URL
      try {
        const parsed = new URL(customUpstream);
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
      return json({ error: "Failed to reach provider: " + String(err) }, 502);
    }

    const responseHeaders = new Headers(upstreamResponse.headers);
    for (const [k, v] of Object.entries(corsHeaders())) {
      responseHeaders.set(k, v);
    }
    // Wallet identity: from header (plugin) or query param (base URL tools like Claude Code)
    const walletRaw = (request.headers.get("x-nous-wallet") || url.searchParams.get("wallet") || "").toLowerCase();
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
        usagePromise.then((usage) => {
          if (usage) {
            return recordUsage(env.DB, userHash, providerName, usage, endpoint, signingKey ?? undefined, validWallet);
          }
        })
      );

      return new Response(clientStream, {
        status: upstreamResponse.status,
        headers: responseHeaders,
      });
    } else {
      const bodyBytes = await upstreamResponse.arrayBuffer();

      ctx.waitUntil(
        (async () => {
          try {
            const text = new TextDecoder().decode(bodyBytes);
            const parsed = JSON.parse(text) as Record<string, unknown>;
            const usage = extractUsage(parsed);
            if (usage && usage.totalTokens > 0) {
              await recordUsage(env.DB, userHash, providerName, usage, endpoint, signingKey ?? undefined, validWallet);
            }
          } catch {
            // Not JSON or no usage — fine
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
    const days = parseInt(url.searchParams.get("days") || "30");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 500);
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

  // GET /api/leaderboard/cost — top API users by real cost (only users with provider-reported cost)
  if (url.pathname === "/api/leaderboard/cost") {
    const days = parseInt(url.searchParams.get("days") || "30");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 500);
    const idExpr = `CASE WHEN wallet != '' THEN wallet ELSE user_hash END`;

    const rows = days > 0
      ? await env.DB.prepare(
          `SELECT ${idExpr} as identity, MAX(wallet) as wallet, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count
           FROM usage_records WHERE timestamp > ? AND cost > 0 GROUP BY ${idExpr} HAVING SUM(cost) > 0 ORDER BY SUM(cost) DESC LIMIT ?`
        ).bind(new Date(Date.now() - days * 86400000).toISOString(), limit).all()
      : await env.DB.prepare(
          `SELECT ${idExpr} as identity, MAX(wallet) as wallet, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count
           FROM usage_records WHERE cost > 0 GROUP BY ${idExpr} HAVING SUM(cost) > 0 ORDER BY SUM(cost) DESC LIMIT ?`
        ).bind(limit).all();

    return json({ ok: true, data: rows.results, period_days: days });
  }

  // GET /api/models — usage breakdown by model (aggregated across providers)
  if (url.pathname === "/api/models") {
    const days = parseInt(url.searchParams.get("days") || "30");

    const rows = days > 0
      ? await env.DB.prepare(
          `SELECT model, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count, COUNT(DISTINCT user_hash) as unique_users
           FROM usage_records WHERE timestamp > ? GROUP BY model ORDER BY total_tokens DESC`
        ).bind(new Date(Date.now() - days * 86400000).toISOString()).all()
      : await env.DB.prepare(
          `SELECT model, SUM(total_tokens) as total_tokens, SUM(input_tokens) as input_tokens, SUM(output_tokens) as output_tokens, SUM(cost) as total_cost, COUNT(*) as call_count, COUNT(DISTINCT user_hash) as unique_users
           FROM usage_records GROUP BY model ORDER BY total_tokens DESC`
        ).all();

    return json({ ok: true, data: rows.results, period_days: days });
  }

  // GET /api/leaderboard/model — top users for a specific model (across all providers)
  if (url.pathname === "/api/leaderboard/model") {
    const model = url.searchParams.get("model") || "";
    const days = parseInt(url.searchParams.get("days") || "30");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 500);
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
              COUNT(DISTINCT user_hash) as total_users,
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
    const afterId = parseInt(url.searchParams.get("after") || "0");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 1000);

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
    const afterId = parseInt(url.searchParams.get("after") || "0");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "1000"), 10000);

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
  // Optional convenience: aggregates receipts into a signed summary.
  // Individual receipts (via /api/user/:hash/receipts) are already signed per-call.
  if (url.pathname === "/api/sign" && request.method === "POST") {
    if (!env.SIGNING_KEY) {
      return json({ error: "Signing not configured" }, 501);
    }

    try {
      const body = await request.json() as { user_hash?: string; receipt_ids?: number[] };
      const userHash = body.user_hash;
      if (!userHash || !/^[a-f0-9]{32}$/.test(userHash)) {
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
      return json({ error: "Signing failed: " + String(err) }, 500);
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

  // POST /api/claim — CLI generates a 6-digit claim code
  // AUTHENTICATION: must include API key in Authorization header.
  // Gateway computes hash from the key to prove ownership — you can only
  // generate a claim code for your own hash. The key is not stored.
  if (url.pathname === "/api/claim" && request.method === "POST") {
    // Authenticate: compute hash from API key (same logic as proxy path)
    const authHeader = request.headers.get("authorization")
      || request.headers.get("x-api-key")
      || request.headers.get("x-goog-api-key")
      || "";
    const rawKey = authHeader.replace(/^Bearer\s+/i, "");
    if (!rawKey) {
      return json({ error: "Authorization header required. Send your API key to prove ownership." }, 401);
    }
    const hash = await sha256Short(rawKey);

    // Check that this user_hash actually exists in the database
    const exists = await env.DB.prepare(
      `SELECT 1 FROM usage_records WHERE user_hash = ? LIMIT 1`
    ).bind(hash).first();
    if (!exists) {
      return json({ error: "No usage records for this hash. Use the gateway first." }, 404);
    }

    // Generate 6-digit code
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    // Clean up expired codes, then insert new one
    await env.DB.prepare(`DELETE FROM claim_codes WHERE expires_at < ?`).bind(new Date().toISOString()).run();
    await env.DB.prepare(
      `INSERT OR REPLACE INTO claim_codes (code, user_hash, expires_at) VALUES (?, ?, ?)`
    ).bind(code, hash, expiresAt).run();

    return json({ ok: true, user_hash: hash, code, expires_in: 300 });
  }

  // POST /api/claim/verify — website verifies a claim code
  // Returns the user_hash if the code is valid and not expired.
  if (url.pathname === "/api/claim/verify" && request.method === "POST") {
    try {
      const body = await request.json() as { code?: string };
      const code = body.code?.trim();
      if (!code || !/^\d{6}$/.test(code)) {
        return json({ error: "Invalid code format" }, 400);
      }

      const row = await env.DB.prepare(
        `SELECT user_hash, expires_at FROM claim_codes WHERE code = ?`
      ).bind(code).first<{ user_hash: string; expires_at: string }>();

      if (!row) {
        return json({ error: "Invalid code" }, 404);
      }

      if (new Date(row.expires_at) < new Date()) {
        await env.DB.prepare(`DELETE FROM claim_codes WHERE code = ?`).bind(code).run();
        return json({ error: "Code expired" }, 410);
      }

      // Code is valid — delete it (one-time use) and return the hash
      await env.DB.prepare(`DELETE FROM claim_codes WHERE code = ?`).bind(code).run();

      return json({ ok: true, user_hash: row.user_hash });
    } catch {
      return json({ error: "Invalid request" }, 400);
    }
  }

  // POST /api/link — link a user_hash to a wallet address
  // Sends API key to prove ownership, gateway computes hash and binds wallet.
  if (url.pathname === "/api/link" && request.method === "POST") {
    try {
      const body = await request.json() as { api_key?: string; wallet?: string };
      const apiKey = body.api_key?.trim();
      const wallet = body.wallet?.trim().toLowerCase();

      if (!apiKey) return json({ error: "api_key required" }, 400);
      if (!wallet || !/^0x[a-f0-9]{40}$/.test(wallet)) return json({ error: "Invalid wallet address" }, 400);

      const hash = await sha256Short(apiKey.replace(/^Bearer\s+/i, ""));

      // Check this hash exists
      const exists = await env.DB.prepare(
        `SELECT 1 FROM usage_records WHERE user_hash = ? LIMIT 1`
      ).bind(hash).first();
      if (!exists) {
        return json({ error: "No usage records for this API key. Use the gateway first." }, 404);
      }

      // Link all records to wallet
      await env.DB.prepare(
        `UPDATE usage_records SET wallet = ? WHERE user_hash = ?`
      ).bind(wallet, hash).run();

      return json({ ok: true, user_hash: hash, wallet });
    } catch {
      return json({ error: "Invalid request" }, 400);
    }
  }

  return json({ error: "Not found" }, 404);
}

// ── Helpers ──

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Max-Age": "86400",
  };
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

// SHA-256, first 16 bytes as 32-char hex (matches plugin's hash)
async function sha256Short(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
