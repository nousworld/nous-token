#!/usr/bin/env node
// Auto-update CSP script hash before deployment.
// Run: node web/update-csp.mjs

import { readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";

const file = new URL("index.html", import.meta.url).pathname;
let html = readFileSync(file, "utf-8");

const match = html.match(/<script>([\s\S]*?)<\/script>/);
if (!match) {
  console.error("No <script> block found");
  process.exit(1);
}

const hash = createHash("sha256").update(match[1]).digest("base64");
const newHash = `sha256-${hash}`;

const cspMatch = html.match(/script-src 'self' '(sha256-[A-Za-z0-9+/=]+)'/);
if (!cspMatch) {
  console.error("No CSP sha256 found in HTML");
  process.exit(1);
}

if (cspMatch[1] === newHash) {
  console.log(`CSP hash already current: ${newHash}`);
  process.exit(0);
}

html = html.replace(cspMatch[1], newHash);
writeFileSync(file, html);
console.log(`CSP hash updated: ${cspMatch[1]} → ${newHash}`);
