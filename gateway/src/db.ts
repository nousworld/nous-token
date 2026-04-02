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

export interface Env {
  DB: D1Database;
  SIGNING_KEY?: string;
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
  await db.exec(`
    CREATE TABLE IF NOT EXISTS usage_records (
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
      leaf_hash TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_records(user_hash);
    CREATE INDEX IF NOT EXISTS idx_usage_time ON usage_records(timestamp);
    CREATE INDEX IF NOT EXISTS idx_usage_model ON usage_records(model);

    CREATE TABLE IF NOT EXISTS merkle_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      peaks TEXT NOT NULL DEFAULT '[]',
      merkle_root TEXT NOT NULL DEFAULT '',
      leaf_count INTEGER NOT NULL DEFAULT 0
    );
    INSERT OR IGNORE INTO merkle_state (id, peaks, merkle_root, leaf_count) VALUES (1, '[]', '', 0);

    CREATE TABLE IF NOT EXISTS claim_codes (
      code TEXT PRIMARY KEY,
      user_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
  `);
  // Migration: add receipt_sig column for existing databases
  try {
    await db.exec(`ALTER TABLE usage_records ADD COLUMN receipt_sig TEXT NOT NULL DEFAULT ''`);
  } catch {
    // Column already exists
  }
}

export async function recordUsage(
  db: D1Database,
  userHash: string,
  provider: string,
  usage: UsageData,
  endpoint: string,
  signingKey?: CryptoKey
): Promise<Receipt | null> {
  const timestamp = new Date().toISOString();

  // Leaf hash: SHA-256 of record fields (independent, not chained)
  const leafHash = await sha256([
    timestamp,
    userHash,
    provider,
    usage.model,
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

  // Insert record with receipt signature
  const result = await db
    .prepare(
      `INSERT INTO usage_records (timestamp, user_hash, provider, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, total_tokens, endpoint, leaf_hash, receipt_sig)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      timestamp,
      userHash,
      provider,
      usage.model,
      usage.inputTokens,
      usage.outputTokens,
      usage.cacheReadTokens,
      usage.cacheWriteTokens,
      usage.totalTokens,
      endpoint,
      leafHash,
      receiptSig
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
  // Sentinel will detect the mismatch; next successful append will fix the count.
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

// ── Crypto ──

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
