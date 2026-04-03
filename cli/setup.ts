#!/usr/bin/env npx tsx
//
// nous-token setup — one command to configure all AI tools
//
// Usage: npx nous-token setup
//
// Scans for installed AI tools, configures them to route through
// the nous-token gateway for usage tracking.

import { existsSync, readFileSync, writeFileSync, mkdirSync, appendFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { execSync } from "child_process";
import { createHash } from "crypto";

const GATEWAY = "https://gateway.nousai.cc";
const HOME = homedir();
const NOUS_CONFIG = join(HOME, ".nous-token");

function loadWallet(): string {
  try { return readFileSync(NOUS_CONFIG, "utf-8").trim(); } catch { return ""; }
}

function saveWallet(wallet: string): void {
  writeFileSync(NOUS_CONFIG, wallet);
}

function gatewayUrl(path: string, wallet: string): string {
  return wallet ? `${GATEWAY}${path}?wallet=${wallet}` : `${GATEWAY}${path}`;
}

interface Tool {
  name: string;
  detect: () => boolean;
  configure: (wallet: string) => ConfigResult;
}

interface ConfigResult {
  success: boolean;
  message: string;
}

// ── Tool detectors and configurators ──

const tools: Tool[] = [
  // OpenClaw
  {
    name: "OpenClaw",
    detect: () => {
      try { execSync("which openclaw", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: (_wallet: string) => {
      try {
        execSync("openclaw plugins install nous-token", { stdio: "inherit" });
        return { success: true, message: "installed nous-token plugin" };
      } catch {
        return { success: false, message: "plugin install failed" };
      }
    },
  },

  // Claude Code
  {
    name: "Claude Code",
    detect: () => {
      const claudeDir = join(HOME, ".claude");
      if (existsSync(claudeDir)) return true;
      try { execSync("which claude", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: (wallet: string) => {
      return setShellEnv("ANTHROPIC_BASE_URL", gatewayUrl("/anthropic", wallet), "Claude Code");
    },
  },

  // Cursor
  {
    name: "Cursor",
    detect: () => {
      const paths = [
        join(HOME, ".cursor"),
        join(HOME, "Library", "Application Support", "Cursor"),
        join(HOME, ".config", "Cursor"),
      ];
      return paths.some(p => existsSync(p));
    },
    configure: (wallet: string) => {
      const settingsPaths = [
        join(HOME, "Library", "Application Support", "Cursor", "User", "settings.json"),
        join(HOME, ".config", "Cursor", "User", "settings.json"),
      ];
      for (const sp of settingsPaths) {
        if (existsSync(sp)) {
          try {
            const content = JSON.parse(readFileSync(sp, "utf-8"));
            if (content["openai.baseUrl"]?.includes("nousai")) {
              return { success: true, message: "already configured" };
            }
            content["openai.baseUrl"] = gatewayUrl("/openai/v1", wallet);
            writeFileSync(sp, JSON.stringify(content, null, 2));
            return { success: true, message: `set baseUrl in Cursor settings` };
          } catch {
            return { success: false, message: "failed to update Cursor settings" };
          }
        }
      }
      return { success: false, message: "Cursor settings file not found" };
    },
  },

  // Codex CLI
  {
    name: "Codex",
    detect: () => {
      return existsSync(join(HOME, ".codex")) ||
        (() => { try { execSync("which codex", { stdio: "ignore" }); return true; } catch { return false; } })();
    },
    configure: (wallet: string) => {
      return setShellEnv("OPENAI_BASE_URL", gatewayUrl("/openai/v1", wallet), "Codex");
    },
  },

  // Gemini CLI
  {
    name: "Gemini CLI",
    detect: () => {
      return existsSync(join(HOME, ".gemini")) ||
        (() => { try { execSync("which gemini", { stdio: "ignore" }); return true; } catch { return false; } })();
    },
    configure: (wallet: string) => {
      return setShellEnv("GOOGLE_GEMINI_BASE_URL", gatewayUrl("/gemini", wallet), "Gemini CLI");
    },
  },

  // Python openai SDK
  {
    name: "Python (openai)",
    detect: () => {
      try { execSync("python3 -c 'import openai'", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: (wallet: string) => {
      return setShellEnv("OPENAI_BASE_URL", gatewayUrl("/openai/v1", wallet), "Python openai SDK");
    },
  },

  // Python anthropic SDK
  {
    name: "Python (anthropic)",
    detect: () => {
      try { execSync("python3 -c 'import anthropic'", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: (wallet: string) => {
      return setShellEnv("ANTHROPIC_BASE_URL", gatewayUrl("/anthropic", wallet), "Python anthropic SDK");
    },
  },
];

// ── Shell env helper ──

function setShellEnv(key: string, value: string, toolName: string): ConfigResult {
  const shell = process.env.SHELL || "/bin/bash";
  const rcFile = shell.includes("zsh") ? join(HOME, ".zshrc") : join(HOME, ".bashrc");

  if (existsSync(rcFile)) {
    const content = readFileSync(rcFile, "utf-8");
    // Check if already configured with the exact same value
    if (content.includes(`${key}="${value}"`)) {
      return { success: true, message: "already configured" };
    }
    // Remove old nous-token setting if exists, then write new one
    const lines = content.split("\n").filter(l => !(l.includes(`${key}=`) && l.includes("nousai")));
    lines.push(`export ${key}="${value}"  # nous-token gateway`);
    writeFileSync(rcFile, lines.join("\n"));
  } else {
    writeFileSync(rcFile, `export ${key}="${value}"  # nous-token gateway\n`);
  }

  // Also set in current process
  process.env[key] = value;

  const rcName = rcFile.includes("zsh") ? "~/.zshrc" : "~/.bashrc";
  return { success: true, message: `set ${key} in ${rcName}` };
}

// ── Find first available API key ──

function findFirstApiKey(): string | null {
  const keys = [
    process.env.OPENAI_API_KEY,
    process.env.ANTHROPIC_API_KEY,
    process.env.DEEPSEEK_API_KEY,
    process.env.GEMINI_API_KEY,
    process.env.GROQ_API_KEY,
  ];
  for (const key of keys) {
    if (key) return key.replace(/^Bearer\s+/i, "");
  }
  return null;
}

function computeUserHash(): string | null {
  const key = findFirstApiKey();
  if (!key) return null;
  return createHash("sha256").update(key).digest("hex").slice(0, 32);
}

// ── Prompt helper ──

async function ask(prompt: string): Promise<string> {
  process.stdout.write(prompt);
  return new Promise<string>((resolve) => {
    process.stdin.setEncoding("utf-8");
    process.stdin.once("data", (chunk) => resolve(chunk.toString().trim()));
    process.stdin.resume();
  });
}

// ── Main ──

console.log("");
console.log("  \x1b[1mnous-token setup\x1b[0m\n");

// Step 1: Wallet address
let wallet = loadWallet();
const walletArg = process.argv.find(a => /^0x[a-fA-F0-9]{40}$/.test(a));
if (walletArg) {
  wallet = walletArg.toLowerCase();
} else if (!wallet) {
  const input = await ask("  Wallet address (0x...): ");
  if (/^0x[a-fA-F0-9]{40}$/.test(input)) {
    wallet = input.toLowerCase();
  } else if (input) {
    console.log("  \x1b[33mInvalid address format.\x1b[0m\n");
    process.exit(1);
  }
}

if (wallet) {
  saveWallet(wallet);
  console.log(`  \x1b[36mWallet: ${wallet}\x1b[0m\n`);
} else {
  console.log("  \x1b[90mNo wallet. Run again with: npx nous-token setup 0x...\x1b[0m\n");
  process.exit(0);
}

// Step 2: API key — read from env or ask
let apiKey = findFirstApiKey();
if (!apiKey) {
  const input = await ask("  API key (sk-...): ");
  if (input) {
    apiKey = input.replace(/^Bearer\s+/i, "");
  }
}

// Step 3: Link hash → wallet via gateway
if (apiKey) {
  const hash = createHash("sha256").update(apiKey).digest("hex").slice(0, 32);
  console.log(`  \x1b[90mUser hash: ${hash}\x1b[0m`);
  try {
    const res = await fetch(`${GATEWAY}/api/link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: apiKey, wallet }),
    });
    const data = await res.json() as { ok?: boolean; error?: string };
    if (data.ok) {
      console.log(`  \x1b[32m✓ Linked to wallet\x1b[0m\n`);
    } else {
      console.log(`  \x1b[90m${data.error || "No existing records to link — they'll link automatically on first use."}\x1b[0m\n`);
    }
  } catch {
    console.log("  \x1b[90mCouldn't reach gateway — linking will happen on first use.\x1b[0m\n");
  }
} else {
  console.log("  \x1b[90mNo API key found. Wallet will link on first use through the gateway.\x1b[0m\n");
}

// Step 4: Configure tools
console.log("  Scanning for AI tools...\n");

let configured = 0;

for (const tool of tools) {
  if (tool.detect()) {
    const result = tool.configure(wallet);
    if (result.success) {
      console.log(`  \x1b[32m✓\x1b[0m ${tool.name.padEnd(20)} → ${result.message}`);
      configured++;
    } else {
      console.log(`  \x1b[31m✗\x1b[0m ${tool.name.padEnd(20)} → ${result.message}`);
    }
  } else {
    console.log(`  \x1b[90m-\x1b[0m \x1b[90m${tool.name.padEnd(20)} → not found\x1b[0m`);
  }
}

console.log("");

if (configured > 0) {
  console.log(`  \x1b[32m${configured} tool(s) configured.\x1b[0m`);
  console.log(`  See your usage at \x1b[4mhttps://token.nousai.cc\x1b[0m`);
  console.log(`  Run \x1b[1msource ~/.zshrc\x1b[0m to apply changes in this terminal.`);
} else {
  console.log("  No AI tools found. Install Claude Code, Cursor, or any OpenAI-compatible tool.");
}

console.log("");
