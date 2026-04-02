// nous-token gateway — transparent LLM API proxy that records real usage
//
// PRIVACY BY STRUCTURE (not by promise):
//
// 1. API Key: NEVER READ by gateway code. Plugin computes SHA-256 hash locally
//    and sends it via X-Nous-User header. Gateway only reads X-Nous-User.
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

import { PROVIDERS, type UsageData } from "./providers";
import { teeStreamForUsage } from "./stream";
import { initDB, recordUsage, getMerkleState, type Env } from "./db";

let dbReady = false;

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

    const parts = url.pathname.split("/");
    const providerKey = parts[1]?.toLowerCase();
    const provider = providerKey ? PROVIDERS[providerKey] : undefined;

    if (!provider) {
      return json(
        { error: "Unknown provider. Use: /" + Object.keys(PROVIDERS).join(", /") },
        400
      );
    }

    const userHash = request.headers.get("x-nous-user");
    if (!userHash || !/^[a-f0-9]{32}$/.test(userHash)) {
      return json({ error: "Missing or invalid X-Nous-User header. Install the nous-token plugin." }, 401);
    }

    const upstreamPath = "/" + parts.slice(2).join("/") + url.search;
    const upstreamUrl = provider.upstream + upstreamPath;

    const upstreamHeaders = new Headers(request.headers);
    upstreamHeaders.delete("host");
    upstreamHeaders.delete("x-nous-user");

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

    if (!dbReady) {
      await initDB(env.DB);
      dbReady = true;
    }

    const contentType = upstreamResponse.headers.get("content-type") || "";
    const isStreaming = contentType.includes("text/event-stream");
    const endpoint = parts.slice(2).join("/");

    if (isStreaming && upstreamResponse.body) {
      const [clientStream, usagePromise] = teeStreamForUsage(upstreamResponse, provider);

      ctx.waitUntil(
        usagePromise.then((usage) => {
          if (usage) {
            return recordUsage(env.DB, userHash, provider.name, usage, endpoint);
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
            const usage = provider.extractUsage(parsed);
            if (usage && usage.totalTokens > 0) {
              await recordUsage(env.DB, userHash, provider.name, usage, endpoint);
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
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const rows = await env.DB.prepare(
      `SELECT user_hash,
              SUM(total_tokens) as total_tokens,
              SUM(input_tokens) as input_tokens,
              SUM(output_tokens) as output_tokens,
              COUNT(*) as call_count
       FROM usage_records
       WHERE timestamp > ?
       GROUP BY user_hash
       ORDER BY total_tokens DESC
       LIMIT ?`
    ).bind(since, limit).all();

    return json({ ok: true, data: rows.results, period_days: days });
  }

  // GET /api/models — usage breakdown by model
  if (url.pathname === "/api/models") {
    const days = parseInt(url.searchParams.get("days") || "30");
    const since = new Date(Date.now() - days * 86400000).toISOString();

    const rows = await env.DB.prepare(
      `SELECT provider, model,
              SUM(total_tokens) as total_tokens,
              SUM(input_tokens) as input_tokens,
              SUM(output_tokens) as output_tokens,
              COUNT(*) as call_count,
              COUNT(DISTINCT user_hash) as unique_users
       FROM usage_records
       WHERE timestamp > ?
       GROUP BY provider, model
       ORDER BY total_tokens DESC`
    ).bind(since).all();

    return json({ ok: true, data: rows.results, period_days: days });
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

  // GET /api/user/:hash — single user stats
  const userMatch = url.pathname.match(/^\/api\/user\/([a-f0-9]+)$/);
  if (userMatch) {
    const hash = userMatch[1];
    const rows = await env.DB.prepare(
      `SELECT provider, model,
              SUM(total_tokens) as total_tokens,
              SUM(input_tokens) as input_tokens,
              SUM(output_tokens) as output_tokens,
              COUNT(*) as call_count
       FROM usage_records
       WHERE user_hash = ?
       GROUP BY provider, model
       ORDER BY total_tokens DESC`
    ).bind(hash).all();

    return json({ ok: true, data: rows.results, user_hash: hash });
  }

  // GET /api/records — export raw records for verification
  // Sentinels pull this to independently recompute leaf hashes and rebuild the MMR.
  if (url.pathname === "/api/records") {
    const afterId = parseInt(url.searchParams.get("after") || "0");
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "1000"), 10000);

    const rows = await env.DB.prepare(
      `SELECT id, timestamp, user_hash, provider, model,
              input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
              total_tokens, leaf_hash
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
  // The signature proves this data came from the gateway, not fabricated by the user.
  // Verify with the gateway's public key (published at /api/pubkey).
  if (url.pathname === "/api/sign" && request.method === "POST") {
    if (!env.SIGNING_KEY) {
      return json({ error: "Signing not configured" }, 501);
    }

    try {
      const body = await request.json() as { user_hash?: string };
      const userHash = body.user_hash;
      if (!userHash || !/^[a-f0-9]{32}$/.test(userHash)) {
        return json({ error: "Invalid user_hash" }, 400);
      }

      // Fetch this user's aggregated stats
      const rows = await env.DB.prepare(
        `SELECT provider, model,
                SUM(input_tokens) as input_tokens,
                SUM(output_tokens) as output_tokens,
                SUM(total_tokens) as total_tokens,
                COUNT(*) as call_count
         FROM usage_records
         WHERE user_hash = ?
         GROUP BY provider, model
         ORDER BY total_tokens DESC`
      ).bind(userHash).all();

      if (!rows.results || rows.results.length === 0) {
        return json({ error: "No data for this user" }, 404);
      }

      let totalTokens = 0, totalCalls = 0;
      for (const r of rows.results as Array<Record<string, number>>) {
        totalTokens += r.total_tokens || 0;
        totalCalls += r.call_count || 0;
      }

      // Build the proof payload (this is what goes on-chain)
      const proof = {
        p: "nous",
        v: 1,
        op: "proof",
        user: userHash,
        total_tokens: totalTokens,
        total_calls: totalCalls,
        models: (rows.results as Array<Record<string, unknown>>).map((r) => ({
          provider: r.provider,
          model: r.model,
          total_tokens: r.total_tokens,
        })),
        ts: Math.floor(Date.now() / 1000),
      };

      const proofString = JSON.stringify(proof);

      // Sign with ECDSA P-256
      const privateKey = await crypto.subtle.importKey(
        "jwk",
        JSON.parse(env.SIGNING_KEY),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      );

      const sigBuffer = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
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
