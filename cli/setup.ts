#!/usr/bin/env npx tsx
//
// nous-token setup — one command to configure all AI tools
//
// Usage: npx nous-token setup
//
// Scans for installed AI tools, configures them to route through
// the nous-token gateway for usage tracking.

import { existsSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { execSync } from "child_process";

const GATEWAY = "https://gateway.nousai.cc";
const HOME = homedir();
const NOUS_CONFIG = join(HOME, ".nous-token");

function loadWallet(): string {
  try { return readFileSync(NOUS_CONFIG, "utf-8").trim(); } catch { return ""; }
}

function saveWallet(wallet: string): void {
  writeFileSync(NOUS_CONFIG, wallet);
}

function gatewayUrl(provider: string, apiPath: string, wallet: string): string {
  return wallet ? `${GATEWAY}/${provider}/w/${wallet}${apiPath}` : `${GATEWAY}/${provider}${apiPath}`;
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
      return setShellEnv("ANTHROPIC_BASE_URL", gatewayUrl("anthropic", "", wallet), "Claude Code");
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
            content["openai.baseUrl"] = gatewayUrl("openai", "/v1", wallet);
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
      return setShellEnv("OPENAI_BASE_URL", gatewayUrl("openai", "/v1", wallet), "Codex");
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
      return setShellEnv("GOOGLE_GEMINI_BASE_URL", gatewayUrl("gemini", "", wallet), "Gemini CLI");
    },
  },

  // Python openai SDK
  {
    name: "Python (openai)",
    detect: () => {
      try { execSync("python3 -c 'import openai'", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: (wallet: string) => {
      return setShellEnv("OPENAI_BASE_URL", gatewayUrl("openai", "/v1", wallet), "Python openai SDK");
    },
  },

  // Python anthropic SDK
  {
    name: "Python (anthropic)",
    detect: () => {
      try { execSync("python3 -c 'import anthropic'", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: (wallet: string) => {
      return setShellEnv("ANTHROPIC_BASE_URL", gatewayUrl("anthropic", "", wallet), "Python anthropic SDK");
    },
  },
];

// ── Shell env helper ──

// Collect env vars to set — don't write to shell rc file
const envCommands: string[] = [];

function setShellEnv(key: string, value: string, toolName: string): ConfigResult {
  envCommands.push(`export ${key}="${value}"`);
  return { success: true, message: `${key}` };
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
} else if (wallet) {
  // Existing wallet — ask user to confirm or change
  const input = await ask(`  Wallet [${wallet.slice(0, 6)}...${wallet.slice(-4)}] (press Enter to keep, or paste new): `);
  if (input && /^0x[a-fA-F0-9]{40}$/.test(input)) {
    wallet = input.toLowerCase();
  } else if (input) {
    console.log("  \x1b[33mInvalid address format. Keeping current wallet.\x1b[0m");
  }
} else {
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

// Step 2: Configure tools
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
  console.log(`  \x1b[32m${configured} tool(s) detected.\x1b[0m\n`);
  console.log("  \x1b[1mThis terminal only:\x1b[0m");
  console.log(`  \x1b[36m${envCommands.join(" && ")}\x1b[0m\n`);
  console.log("  \x1b[1mAll terminals (permanent):\x1b[0m");
  const shell = process.env.SHELL || "/bin/bash";
  const rcFile = shell.includes("zsh") ? "~/.zshrc" : "~/.bashrc";
  console.log(`  \x1b[36mecho '${envCommands.join("\\n")}' >> ${rcFile} && source ${rcFile}\x1b[0m\n`);
  console.log(`  See your usage at \x1b[4mhttps://token.nousai.cc\x1b[0m`);
} else {
  console.log("  No AI tools found. Install Claude Code, Cursor, or any OpenAI-compatible tool.");
}

console.log("");
process.exit(0);
