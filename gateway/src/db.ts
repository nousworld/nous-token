// D1 database operations for usage records
//
// TAMPER DETECTION: Merkle Mountain Range (MMR)
//
// Each record has a leaf_hash = SHA-256(record fields).
// Leaves are organized into a Merkle Mountain Range — an append-only
// binary tree structure where "peaks" are roots of complete subtrees.
//
// Root = SHA-256(all peaks concatenated).
// Modifying any single record changes its leaf hash, which propagates
// up through the tree and changes the root.
//
// Verification:
//   Full: pull all records, recompute all leaf hashes, rebuild MMR, compare root.
//   Single: get the Merkle proof (O(log n) sibling hashes), verify path to root.

import type { UsageData } from "./providers";

// Isolate-level cache: hash → wallet. Avoids a SELECT on every request.
// Cleared when Cloudflare recycles the isolate (minutes to hours). Cache miss = one DB read.
export const walletCache = new Map<string, string>();

export interface Env {
  DB: D1Database;
  SIGNING_KEY?: string;
  GATEWAY_PRIVATE_KEY?: string;  // secp256k1 hex for token-20 Ethereum signing
}

export interface Receipt {
  id: number;
  leafHash: string;
  signature: string;
}

interface Peak {
  height: number;
  hash: string;
}

export async function initDB(db: D1Database): Promise<void> {
  // Use batch() for reliability on D1 remote — exec() with multiple statements can be flaky
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS usage_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      user_hash TEXT NOT NULL,
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      input_tokens INTEGER NOT NULL,
      output_tokens INTEGER NOT NULL,
      cache_read_tokens INTEGER NOT NULL DEFAULT 0,
      cache_write_tokens INTEGER NOT NULL DEFAULT 0,
      total_tokens INTEGER NOT NULL,
      endpoint TEXT NOT NULL,
      leaf_hash TEXT NOT NULL DEFAULT '',
      receipt_sig TEXT NOT NULL DEFAULT '',
      cost REAL NOT NULL DEFAULT 0
    )`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_records(user_hash)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_usage_time ON usage_records(timestamp)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_records(model)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS merkle_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      peaks TEXT NOT NULL DEFAULT '[]',
      merkle_root TEXT NOT NULL DEFAULT '',
      leaf_count INTEGER NOT NULL DEFAULT 0
    )`),
    db.prepare(`INSERT OR IGNORE INTO merkle_state (id, peaks, merkle_root, leaf_count) VALUES (1, '[]', '', 0)`),
  ]);
  // Migrations for existing databases
  try { await db.exec(`ALTER TABLE usage_records ADD COLUMN cost REAL NOT NULL DEFAULT 0`); } catch { /* exists */ }
  try { await db.exec(`ALTER TABLE usage_records ADD COLUMN wallet TEXT NOT NULL DEFAULT ''`); } catch { /* exists */ }
  try { await db.exec(`CREATE INDEX IF NOT EXISTS idx_usage_wallet ON usage_records(wallet)`); } catch { /* exists */ }

  // token-20 receipt storage
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS t20_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usage_record_id INTEGER NOT NULL,
      wallet TEXT NOT NULL,
      model TEXT NOT NULL,
      tokens INTEGER NOT NULL,
      block_number INTEGER NOT NULL,
      receipt_encoded TEXT NOT NULL,
      receipt_hash TEXT NOT NULL,
      signature TEXT NOT NULL,
      anchor_period INTEGER NOT NULL,
      created_at TEXT NOT NULL
    )`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_t20_wallet ON t20_receipts(wallet)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_t20_period ON t20_receipts(anchor_period)`),
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_t20_hash ON t20_receipts(receipt_hash)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS t20_anchors (
      period_start INTEGER PRIMARY KEY,
      merkle_root TEXT NOT NULL,
      receipt_count INTEGER NOT NULL,
      tx_hash TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      verified INTEGER NOT NULL DEFAULT 0
    )`),
  ]);
  // Migrations for t20_anchors
  try { await db.exec(`ALTER TABLE t20_anchors ADD COLUMN verified INTEGER NOT NULL DEFAULT 0`); } catch { /* exists */ }
}

export async function recordUsage(
  db: D1Database,
  userHash: string,
  provider: string,
  usage: UsageData,
  endpoint: string,
  signingKey?: CryptoKey,
  wallet?: string
): Promise<Receipt | null> {
  const timestamp = new Date().toISOString();

  // Normalize model name: strip "provider/" prefix (e.g. "anthropic/claude-3-5-haiku" → "claude-3-5-haiku")
  const model = usage.model.includes("/") ? usage.model.split("/").pop()! : usage.model;

  // Leaf hash: SHA-256 of record fields (independent, not chained)
  const leafHash = await sha256([
    timestamp,
    userHash,
    provider,
    model,
    usage.inputTokens,
    usage.outputTokens,
    usage.cacheReadTokens,
    usage.cacheWriteTokens,
    usage.totalTokens,
  ].join("|"));

  // Sign the leaf hash — this is the receipt signature
  let receiptSig = "";
  if (signingKey) {
    const sigBuffer = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      signingKey,
      new TextEncoder().encode(leafHash)
    );
    receiptSig = Array.from(new Uint8Array(sigBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Resolve wallet: look up verified binding only.
  // Wallet binding requires cryptographic proof via POST /api/bind-wallet.
  // Request-level wallet params are used for routing only, not for binding.
  let resolvedWallet = "";
  const cached = walletCache.get(userHash);

  if (cached !== undefined) {
    resolvedWallet = cached;
  } else {
    const existing = await db.prepare(
      `SELECT wallet FROM usage_records WHERE user_hash = ? AND wallet != '' ORDER BY id DESC LIMIT 1`
    ).bind(userHash).first<{ wallet: string }>();
    resolvedWallet = existing?.wallet || "";
    walletCache.set(userHash, resolvedWallet);
  }

  // Insert record with the resolved wallet
  const result = await db
    .prepare(
      `INSERT INTO usage_records (timestamp, user_hash, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, total_tokens, endpoint, leaf_hash, receipt_sig, cost, wallet)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      timestamp,
      userHash,
      provider,
      model,
      usage.inputTokens,
      usage.outputTokens,
      usage.cacheReadTokens,
      usage.cacheWriteTokens,
      usage.totalTokens,
      endpoint,
      leafHash,
      receiptSig,
      usage.cost,
      resolvedWallet
    )
    .run();

  // Update MMR
  await appendToMMR(db, leafHash);

  return {
    id: result.meta.last_row_id as number,
    leafHash,
    signature: receiptSig,
  };
}

// ── MMR Operations ──

async function appendToMMR(db: D1Database, leafHash: string): Promise<void> {
  // Optimistic locking: retry if another concurrent request updated peaks first.
  // UPDATE ... WHERE leaf_count = expected will affect 0 rows if someone else wrote.
  for (let attempt = 0; attempt < 3; attempt++) {
    const state = await db
      .prepare(`SELECT peaks, leaf_count FROM merkle_state WHERE id = 1`)
      .first<{ peaks: string; leaf_count: number }>();

    let peaks: Peak[] = state ? JSON.parse(state.peaks) : [];
    const expectedCount = state?.leaf_count || 0;
    const newCount = expectedCount + 1;

    // New leaf is a peak of height 0
    let current: Peak = { height: 0, hash: leafHash };

    // Merge with existing peaks of same height (right-to-left)
    while (peaks.length > 0 && peaks[peaks.length - 1].height === current.height) {
      const left = peaks.pop()!;
      const mergedHash = await sha256(left.hash + "|" + current.hash);
      current = { height: current.height + 1, hash: mergedHash };
    }

    peaks.push(current);

    // Root = single peak's hash, or SHA-256 of all peaks concatenated
    const root = peaks.length === 1
      ? peaks[0].hash
      : await sha256(peaks.map((p) => p.hash).join("|"));

    // Optimistic lock: only update if leaf_count hasn't changed since we read it
    const result = await db
      .prepare(
        `UPDATE merkle_state SET peaks = ?, merkle_root = ?, leaf_count = ? WHERE id = 1 AND leaf_count = ?`
      )
      .bind(JSON.stringify(peaks), root, newCount, expectedCount)
      .run();

    if (result.meta.changes > 0) return; // success
    // else: concurrent write detected, retry with fresh state
  }
  // After 3 retries, the leaf is in usage_records but MMR may be stale.
  // Next successful append will re-read leaf_count and continue from there.
  // Log so we can monitor frequency — if this fires often, we need a queue.
  console.error(`[MMR] optimistic lock failed after 3 retries for leaf ${leafHash.slice(0, 16)}`);
}

/** Get current Merkle root and stats */
export async function getMerkleState(db: D1Database): Promise<{
  merkle_root: string;
  leaf_count: number;
  peaks: Peak[];
}> {
  const state = await db
    .prepare(`SELECT peaks, merkle_root, leaf_count FROM merkle_state WHERE id = 1`)
    .first<{ peaks: string; merkle_root: string; leaf_count: number }>();

  if (!state || state.leaf_count === 0) {
    return { merkle_root: "", leaf_count: 0, peaks: [] };
  }

  return {
    merkle_root: state.merkle_root,
    leaf_count: state.leaf_count,
    peaks: JSON.parse(state.peaks),
  };
}

// ── Token-20 Receipt Storage ──

export async function storeT20Receipt(
  db: D1Database,
  usageRecordId: number,
  wallet: string,
  model: string,
  tokens: number,
  blockNumber: number,
  receiptEncoded: string,
  receiptHash: string,
  signature: string,
  anchorPeriod: number
): Promise<void> {
  await db.prepare(
    `INSERT INTO t20_receipts (usage_record_id, wallet, model, tokens, block_number, receipt_encoded, receipt_hash, signature, anchor_period, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    usageRecordId, wallet, model, tokens, blockNumber,
    receiptEncoded, receiptHash, signature, anchorPeriod,
    new Date().toISOString()
  ).run();
}

export async function getUnanchoredReceipts(
  db: D1Database,
  anchorPeriod: number
): Promise<Array<{ receipt_hash: string; id: number }>> {
  const rows = await db.prepare(
    `SELECT id, receipt_hash FROM t20_receipts WHERE anchor_period = ? ORDER BY id ASC`
  ).bind(anchorPeriod).all();
  return rows.results as Array<{ receipt_hash: string; id: number }>;
}

export async function storeT20Anchor(
  db: D1Database,
  periodStart: number,
  merkleRoot: string,
  receiptCount: number,
  txHash: string
): Promise<void> {
  await db.prepare(
    `INSERT OR REPLACE INTO t20_anchors (period_start, merkle_root, receipt_count, tx_hash, created_at)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(periodStart, merkleRoot, receiptCount, txHash, new Date().toISOString()).run();
}

export async function isAnchorPeriodDone(db: D1Database, periodStart: number): Promise<boolean> {
  const row = await db.prepare(
    `SELECT 1 FROM t20_anchors WHERE period_start = ?`
  ).bind(periodStart).first();
  return !!row;
}

export async function getUnverifiedAnchors(
  db: D1Database,
  graceMinutes = 5
): Promise<Array<{ period_start: number; tx_hash: string }>> {
  const rows = await db.prepare(
    `SELECT period_start, tx_hash FROM t20_anchors
     WHERE verified = 0
     AND created_at < datetime('now', '-' || ? || ' minutes')
     ORDER BY period_start ASC
     LIMIT 20`
  ).bind(graceMinutes).all();
  return rows.results as Array<{ period_start: number; tx_hash: string }>;
}

export async function markAnchorVerified(db: D1Database, periodStart: number): Promise<void> {
  await db.prepare(
    `UPDATE t20_anchors SET verified = 1 WHERE period_start = ?`
  ).bind(periodStart).run();
}

export async function deleteFailedAnchor(db: D1Database, periodStart: number): Promise<void> {
  await db.prepare(
    `DELETE FROM t20_anchors WHERE period_start = ?`
  ).bind(periodStart).run();
}

export async function getReceiptProofData(
  db: D1Database,
  receiptHash: string
): Promise<{ anchorPeriod: number; allHashes: string[] } | null> {
  const receipt = await db.prepare(
    `SELECT anchor_period FROM t20_receipts WHERE receipt_hash = ?`
  ).bind(receiptHash).first<{ anchor_period: number }>();
  if (!receipt) return null;

  const rows = await db.prepare(
    `SELECT receipt_hash FROM t20_receipts WHERE anchor_period = ? ORDER BY id ASC`
  ).bind(receipt.anchor_period).all();

  return {
    anchorPeriod: receipt.anchor_period,
    allHashes: (rows.results as Array<{ receipt_hash: string }>).map(r => r.receipt_hash),
  };
}

// ── Crypto ──

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
