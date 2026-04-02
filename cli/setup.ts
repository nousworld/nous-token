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

interface Tool {
  name: string;
  detect: () => boolean;
  configure: () => ConfigResult;
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
    configure: () => {
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
    configure: () => {
      // Claude Code reads ANTHROPIC_BASE_URL from shell environment (process.env),
      // not from ~/.claude/.env. Write to .zshrc/.bashrc like other tools.
      return setShellEnv("ANTHROPIC_BASE_URL", `${GATEWAY}/anthropic`, "Claude Code");
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
    configure: () => {
      // Cursor uses VS Code-style settings
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
            content["openai.baseUrl"] = `${GATEWAY}/openai/v1`;
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
    configure: () => {
      return setShellEnv("OPENAI_BASE_URL", `${GATEWAY}/openai/v1`, "Codex");
    },
  },

  // Gemini CLI
  {
    name: "Gemini CLI",
    detect: () => {
      return existsSync(join(HOME, ".gemini")) ||
        (() => { try { execSync("which gemini", { stdio: "ignore" }); return true; } catch { return false; } })();
    },
    configure: () => {
      // Gemini CLI uses GOOGLE_GEMINI_BASE_URL (not GEMINI_BASE_URL)
      // Must use API key auth, not OAuth (OAuth bypasses proxy)
      return setShellEnv("GOOGLE_GEMINI_BASE_URL", `${GATEWAY}/gemini`, "Gemini CLI");
    },
  },

  // Python openai SDK
  {
    name: "Python (openai)",
    detect: () => {
      try { execSync("python3 -c 'import openai'", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: () => {
      return setShellEnv("OPENAI_BASE_URL", `${GATEWAY}/openai/v1`, "Python openai SDK");
    },
  },

  // Python anthropic SDK
  {
    name: "Python (anthropic)",
    detect: () => {
      try { execSync("python3 -c 'import anthropic'", { stdio: "ignore" }); return true; } catch { return false; }
    },
    configure: () => {
      return setShellEnv("ANTHROPIC_BASE_URL", `${GATEWAY}/anthropic`, "Python anthropic SDK");
    },
  },
];

// ── Shell env helper ──

function setShellEnv(key: string, value: string, toolName: string): ConfigResult {
  const shell = process.env.SHELL || "/bin/bash";
  const rcFile = shell.includes("zsh") ? join(HOME, ".zshrc") : join(HOME, ".bashrc");

  if (existsSync(rcFile)) {
    const content = readFileSync(rcFile, "utf-8");
    if (content.includes(`${key}=`) && content.includes("nousai")) {
      return { success: true, message: "already configured" };
    }
    // Remove old setting if exists
    const lines = content.split("\n").filter(l => !l.includes(`${key}=`) || !l.includes("nousai"));
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

// ── Main ──

const command = process.argv[2] || "setup";

if (command === "claim") {
  // ── Claim: prove you own a hash on the leaderboard ──
  // Sends API key in Authorization header — gateway computes hash from it.
  // This proves you actually hold the key, not just know the hash.
  const apiKey = findFirstApiKey();
  if (!apiKey) {
    console.log("\n  No API key found in environment. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or similar.\n");
    process.exit(1);
  }

  const hash = createHash("sha256").update(apiKey.replace(/^Bearer\s+/i, "")).digest("hex").slice(0, 32);

  console.log("");
  console.log(`  \x1b[1mnous-token claim\x1b[0m`);
  console.log(`  Your user hash: \x1b[36m${hash}\x1b[0m`);
  console.log("  Requesting claim code...\n");

  try {
    const res = await fetch(`${GATEWAY}/api/claim`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
      },
    });
    const data = await res.json() as { ok?: boolean; code?: string; user_hash?: string; error?: string };
    if (!data.ok || !data.code) {
      console.log(`  \x1b[31mFailed:\x1b[0m ${data.error || "unknown error"}`);
      console.log("  Make sure you've used the gateway at least once.\n");
      process.exit(1);
    }
    console.log(`  \x1b[32mYour claim code: \x1b[1m${data.code}\x1b[0m`);
    console.log("");
    console.log("  Enter this code on the leaderboard website within 5 minutes.");
    console.log(`  \x1b[4mhttps://token.nousai.cc\x1b[0m → Claim tab → Enter code`);
    console.log("");
  } catch (err) {
    console.log(`  \x1b[31mFailed to reach gateway:\x1b[0m ${err}`);
    console.log("");
    process.exit(1);
  }
} else {
  // ── Setup: configure AI tools ──
  console.log("");
  console.log("  \x1b[1mnous-token setup\x1b[0m");
  console.log("  Scanning for AI tools...\n");

  let configured = 0;

  for (const tool of tools) {
    if (tool.detect()) {
      const result = tool.configure();
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

    const hash = computeUserHash();
    if (hash) {
      console.log(`  Your user hash: \x1b[36m${hash}\x1b[0m`);
    }

    console.log("");
    console.log(`  See your usage at \x1b[4mhttps://token.nousai.cc\x1b[0m`);
    console.log(`  To claim your identity on the leaderboard: \x1b[1mnpx nous-token claim\x1b[0m`);
    console.log(`  Run \x1b[1msource ~/.zshrc\x1b[0m to apply env changes in this terminal.`);
  } else {
    console.log("  No AI tools found. Install OpenClaw, Claude Code, Cursor, or any OpenAI-compatible tool.");
  }

  console.log("");
}
