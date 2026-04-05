// token-20 on-chain integration
//
// Handles:
// 1. secp256k1 receipt signing (for ecrecover on-chain)
// 2. Merkle tree construction per anchor period
// 3. Periodic anchor submission to Base
// 4. Inscribe flow (x402 or direct)

import {
  createWalletClient,
  createPublicClient,
  http,
  keccak256,
  encodePacked,
  encodeAbiParameters,
  parseAbiParameters,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

// ─── Constants ───

const TOKEN20_ADDRESS = "0x95EB768E1A423F5C06Ffd12C93633296563A021c" as Address;
const BASE_RPC = "https://mainnet.base.org";
const ANCHOR_INTERVAL = 300; // ~10 min on Base (2s blocks)

// ─── Types ───

export interface Token20Receipt {
  wallet: Address;
  model: string;
  tokens: number;
  blockNumber: number;
}

export interface SignedReceipt {
  receipt: Token20Receipt;
  receiptEncoded: Hex;
  receiptHash: Hex;
  signature: Hex;
}

// ─── Receipt Signing ───

/**
 * Create and sign a token-20 receipt.
 * The signature is verifiable on-chain via ecrecover.
 */
export async function createSignedReceipt(
  privateKey: Hex,
  wallet: Address,
  model: string,
  tokens: number,
  blockNumber: number
): Promise<SignedReceipt> {
  const receipt: Token20Receipt = { wallet, model, tokens, blockNumber };

  // ABI-encode the receipt (must match contract's abi.decode)
  const receiptEncoded = encodeAbiParameters(
    parseAbiParameters("address wallet, string model, uint256 tokens, uint256 blockNumber"),
    [wallet, model, BigInt(tokens), BigInt(blockNumber)]
  );

  const receiptHash = keccak256(receiptEncoded);

  // Sign with Ethereum personal sign (produces EIP-191 signature)
  // Contract uses: receiptHash.toEthSignedMessageHash().recover(signature)
  const account = privateKeyToAccount(privateKey);
  const signature = await account.signMessage({
    message: { raw: receiptHash as Hex },
  });

  return { receipt, receiptEncoded, receiptHash, signature };
}

// ─── Merkle Tree ───

/**
 * Build a Merkle tree from receipt hashes.
 * Returns the root and proof for each leaf.
 */
export function buildMerkleTree(leafHashes: Hex[]): {
  root: Hex;
  proofs: Map<Hex, Hex[]>;
} {
  if (leafHashes.length === 0) {
    return { root: "0x" as Hex, proofs: new Map() };
  }

  if (leafHashes.length === 1) {
    return { root: leafHashes[0], proofs: new Map([[leafHashes[0], []]]) };
  }

  // Pad to power of 2
  const leaves = [...leafHashes];
  while (leaves.length & (leaves.length - 1)) {
    leaves.push(leaves[leaves.length - 1]); // duplicate last
  }

  // Build tree bottom-up
  const layers: Hex[][] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next: Hex[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = current[i + 1];
      // Sort to match OpenZeppelin's MerkleProof.verify
      const [a, b] = left < right ? [left, right] : [right, left];
      next.push(keccak256(encodePacked(["bytes32", "bytes32"], [a as Hex, b as Hex])));
    }
    layers.push(next);
    current = next;
  }

  const root = layers[layers.length - 1][0];

  // Generate proofs
  const proofs = new Map<Hex, Hex[]>();
  for (let leafIdx = 0; leafIdx < leafHashes.length; leafIdx++) {
    const proof: Hex[] = [];
    let idx = leafIdx;
    for (let layer = 0; layer < layers.length - 1; layer++) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      proof.push(layers[layer][siblingIdx]);
      idx = Math.floor(idx / 2);
    }
    proofs.set(leafHashes[leafIdx], proof);
  }

  return { root, proofs };
}

// ─── Anchor ───

const TOKEN20_ABI = [
  {
    name: "anchor",
    type: "function",
    inputs: [
      { name: "periodStart", type: "uint256" },
      { name: "merkleRoot", type: "bytes32" },
      { name: "receiptCount", type: "uint256" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

/**
 * Submit a Merkle root anchor to the Token20 contract.
 */
export async function submitAnchor(
  privateKey: Hex,
  periodStart: number,
  merkleRoot: Hex,
  receiptCount: number
): Promise<Hex> {
  const account = privateKeyToAccount(privateKey);

  const client = createWalletClient({
    account,
    chain: base,
    transport: http(BASE_RPC),
  });

  const hash = await client.writeContract({
    address: TOKEN20_ADDRESS,
    abi: TOKEN20_ABI,
    functionName: "anchor",
    args: [BigInt(periodStart), merkleRoot as Hex, BigInt(receiptCount)],
  });

  return hash;
}

/**
 * Get the current Base block number.
 */
export async function getCurrentBlock(): Promise<number> {
  const client = createPublicClient({
    chain: base,
    transport: http(BASE_RPC),
  });
  const block = await client.getBlockNumber();
  return Number(block);
}

/**
 * Calculate the anchor period for a given block number.
 */
export function getAnchorPeriod(blockNumber: number): number {
  return Math.floor(blockNumber / ANCHOR_INTERVAL) * ANCHOR_INTERVAL;
}

/**
 * Check if an anchor exists on-chain. Returns the merkle root (bytes32).
 * Zero bytes32 = not anchored. Throws on RPC error.
 */
export async function checkAnchorOnChain(periodStart: number): Promise<Hex> {
  const client = createPublicClient({
    chain: base,
    transport: http(BASE_RPC),
  });
  const result = await client.readContract({
    address: TOKEN20_ADDRESS,
    abi: [{ name: "anchors", type: "function", inputs: [{ name: "", type: "uint256" }], outputs: [{ name: "", type: "bytes32" }], stateMutability: "view" }] as const,
    functionName: "anchors",
    args: [BigInt(periodStart)],
  });
  return result as Hex;
}

// ─── Receipt Header ───

/**
 * Format a signed receipt for the X-Token20-Receipt response header.
 * JSON format so SDK can parse and verify.
 */
export function formatReceiptHeader(signed: SignedReceipt): string {
  return JSON.stringify({
    p: "token-20",
    wallet: signed.receipt.wallet,
    model: signed.receipt.model,
    tokens: signed.receipt.tokens,
    block: signed.receipt.blockNumber,
    receipt: signed.receiptEncoded,
    sig: signed.signature,
  });
}
