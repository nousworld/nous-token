#!/usr/bin/env npx tsx
//
// nous-token sentinel — independent Merkle tree verifier
//
// Pulls records from the gateway, recomputes leaf hashes, rebuilds the
// Merkle Mountain Range locally, and compares the root with the gateway's.
//
// Usage:
//   npx tsx sentinel.ts                          # one-shot verify
//   npx tsx sentinel.ts --watch                  # verify every 5 minutes
//   npx tsx sentinel.ts --gateway https://...    # verify a different gateway
//
// Anyone can run this. No API key needed. All data is public.

const DEFAULT_GATEWAY = "https://gateway.noustoken.com";
const POLL_INTERVAL_MS = 5 * 60 * 1000;

interface Record {
  id: number;
  timestamp: string;
  user_hash: string;
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  total_tokens: number;
  leaf_hash: string;
  receipt_sig?: string;
}

interface ChainState {
  merkle_root: string;
  leaf_count: number;
  peak_count: number;
}

interface Peak {
  height: number;
  hash: string;
}

// ── Crypto ──

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── MMR ──

function computeLeafHash(r: Record): Promise<string> {
  return sha256([
    r.timestamp,
    r.user_hash,
    r.provider,
    r.model,
    r.input_tokens,
    r.output_tokens,
    r.cache_read_tokens,
    r.cache_write_tokens,
    r.total_tokens,
  ].join("|"));
}

async function appendToMMR(peaks: Peak[], leafHash: string): Promise<Peak[]> {
  let current: Peak = { height: 0, hash: leafHash };

  while (peaks.length > 0 && peaks[peaks.length - 1].height === current.height) {
    const left = peaks.pop()!;
    const mergedHash = await sha256(left.hash + "|" + current.hash);
    current = { height: current.height + 1, hash: mergedHash };
  }

  peaks.push(current);
  return peaks;
}

async function computeRoot(peaks: Peak[]): Promise<string> {
  if (peaks.length === 0) return "empty";
  if (peaks.length === 1) return peaks[0].hash;
  return sha256(peaks.map((p) => p.hash).join("|"));
}

// ── HTTP ──

async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

// ── Receipt Signature Verification ──

async function getGatewayPubkey(gateway: string): Promise<CryptoKey | null> {
  try {
    const res = await fetchJSON<{ ok: boolean; algorithm: string; pubkey: JsonWebKey }>(
      `${gateway}/api/pubkey`
    );
    if (!res.ok || !res.pubkey) return null;
    return crypto.subtle.importKey(
      "jwk",
      res.pubkey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch {
    return null;
  }
}

async function verifyReceiptSig(pubkey: CryptoKey, leafHash: string, sig: string): Promise<boolean> {
  const sigBytes = new Uint8Array(sig.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pubkey,
    sigBytes,
    new TextEncoder().encode(leafHash)
  );
}

// ── Verification ──

async function verify(gateway: string): Promise<boolean> {
  // 1. Get Merkle state from gateway
  const chainRes = await fetchJSON<{ ok: boolean; data: ChainState }>(
    `${gateway}/api/chain`
  );
  const state = chainRes.data;

  if (state.leaf_count === 0) {
    console.log("[sentinel] Tree is empty (no records yet). OK.");
    return true;
  }

  console.log(`[sentinel] Gateway reports: ${state.leaf_count} records, ${state.peak_count} peaks`);
  console.log(`[sentinel] Merkle root: ${state.merkle_root}`);

  // 2. Fetch gateway public key for receipt signature verification
  const pubkey = await getGatewayPubkey(gateway);
  if (pubkey) {
    console.log(`[sentinel] Gateway public key loaded — will verify receipt signatures`);
  } else {
    console.log(`[sentinel] No public key available — skipping receipt signature verification`);
  }

  // 3. Pull all records and rebuild MMR
  let afterId = 0;
  let verified = 0;
  let sigVerified = 0;
  let sigMissing = 0;
  let peaks: Peak[] = [];

  while (true) {
    const recordsRes = await fetchJSON<{ ok: boolean; data: Record[]; has_more: boolean }>(
      `${gateway}/api/records?after=${afterId}&limit=10000`
    );

    if (recordsRes.data.length === 0) break;

    for (const r of recordsRes.data) {
      // Recompute leaf hash from record fields
      const computed = await computeLeafHash(r);
      if (computed !== r.leaf_hash) {
        console.error(`[sentinel] LEAF HASH MISMATCH at record #${r.id}`);
        console.error(`  Computed: ${computed}`);
        console.error(`  Stored:   ${r.leaf_hash}`);
        return false;
      }

      // Verify receipt signature if available
      if (pubkey && r.receipt_sig) {
        const sigValid = await verifyReceiptSig(pubkey, r.leaf_hash, r.receipt_sig);
        if (!sigValid) {
          console.error(`[sentinel] RECEIPT SIGNATURE INVALID at record #${r.id}`);
          return false;
        }
        sigVerified++;
      } else if (!r.receipt_sig) {
        sigMissing++;
      }

      // Append to local MMR
      peaks = await appendToMMR(peaks, computed);

      afterId = r.id;
      verified++;
    }

    console.log(`[sentinel] Verified ${verified} leaf hashes...`);

    if (!recordsRes.has_more) break;
  }

  // 3. Compare roots
  if (verified !== state.leaf_count) {
    console.error(`[sentinel] RECORD COUNT MISMATCH`);
    console.error(`  Gateway claims: ${state.leaf_count}`);
    console.error(`  Records found:  ${verified}`);
    return false;
  }

  const computedRoot = await computeRoot(peaks);
  if (computedRoot !== state.merkle_root) {
    console.error(`[sentinel] MERKLE ROOT MISMATCH`);
    console.error(`  Computed: ${computedRoot}`);
    console.error(`  Gateway:  ${state.merkle_root}`);
    return false;
  }

  console.log(`[sentinel] ALL ${verified} RECORDS VERIFIED. Merkle tree intact.`);
  console.log(`[sentinel] Root: ${computedRoot}`);
  console.log(`[sentinel] Peaks: ${peaks.length} (heights: ${peaks.map((p) => p.height).join(", ")})`);
  if (sigVerified > 0) {
    console.log(`[sentinel] Receipt signatures verified: ${sigVerified}/${verified}` +
      (sigMissing > 0 ? ` (${sigMissing} unsigned — pre-receipt records)` : ""));
  }
  return true;
}

// ── Main ──

const args = process.argv.slice(2);
const watch = args.includes("--watch");
const gatewayIdx = args.indexOf("--gateway");
const gateway = (gatewayIdx >= 0 ? args[gatewayIdx + 1] : DEFAULT_GATEWAY).replace(/\/$/, "");

console.log(`[sentinel] Gateway: ${gateway}`);
console.log(`[sentinel] Mode: ${watch ? "watch (every 5m)" : "one-shot"}`);
console.log("");

async function run() {
  try {
    const ok = await verify(gateway);
    if (!ok) {
      console.error("\n[sentinel] TAMPERING DETECTED. Data integrity compromised.");
      if (!watch) process.exit(1);
    }
  } catch (err) {
    console.error(`[sentinel] Error: ${err}`);
    if (!watch) process.exit(1);
  }
}

await run();

if (watch) {
  setInterval(run, POLL_INTERVAL_MS);
}
