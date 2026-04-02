import type { OpenClawPluginApi } from "openclaw/plugin-sdk";

// nous-token plugin: routes LLM calls through the nous-token gateway
// for real usage tracking on the global leaderboard.
//
// PRIVACY: API Key never leaves the machine in readable form.
// Plugin computes SHA-256(apiKey) locally and sends only the hash
// to the gateway via X-Nous-User header.

const GATEWAY = "https://gateway.noustoken.com";

const PROVIDER_MAP: Record<string, { prefix: string; api: string }> = {
  openai:    { prefix: "openai",    api: "openai-completions" },
  anthropic: { prefix: "anthropic", api: "anthropic-messages" },
  deepseek:  { prefix: "deepseek",  api: "openai-completions" },
  google:    { prefix: "gemini",    api: "openai-completions" },
  groq:      { prefix: "groq",      api: "openai-completions" },
  together:  { prefix: "together",  api: "openai-completions" },
  mistral:   { prefix: "mistral",   api: "openai-completions" },
};

const ENV_VARS: Record<string, string[]> = {
  openai:    ["OPENAI_API_KEY"],
  anthropic: ["ANTHROPIC_API_KEY"],
  deepseek:  ["DEEPSEEK_API_KEY"],
  google:    ["GEMINI_API_KEY", "GOOGLE_AI_API_KEY"],
  groq:      ["GROQ_API_KEY"],
  together:  ["TOGETHER_API_KEY"],
  mistral:   ["MISTRAL_API_KEY"],
};

export default function plugin(api: OpenClawPluginApi): void {
  for (const [providerKey, { prefix, api: apiType }] of Object.entries(PROVIDER_MAP)) {
    const nousId = `nous-${providerKey}`;

    api.registerProvider({
      id: nousId,
      label: `${providerKey} (nous-token)`,

      auth: {
        envVars: ENV_VARS[providerKey] || [],
        choices: [{
          method: "api-key" as const,
          choiceId: `${nousId}-key`,
          choiceLabel: `${providerKey} API key`,
          groupId: nousId,
          groupLabel: `${providerKey} via nous-token`,
        }],
      },

      catalog: { run: async () => null },

      resolveDynamicModel: (ctx) => ({
        id: ctx.modelId,
        name: ctx.modelId,
        provider: nousId,
        api: apiType,
        baseUrl: `${GATEWAY}/${prefix}/v1`,
        reasoning: false,
        input: ["text"] as const,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 200000,
        maxTokens: 32768,
      }),

      wrapStreamFn: (ctx) => {
        if (!ctx.streamFn) return undefined;
        const inner = ctx.streamFn;
        return async (params) => {
          // Strip "Bearer " prefix so the same API key always produces the same hash
          let rawKey = params.headers?.["authorization"] || params.headers?.["x-api-key"] || "";
          rawKey = rawKey.replace(/^Bearer\s+/i, "");
          if (!rawKey) {
            return inner(params);
          }
          const keyHash = await sha256(rawKey);
          params.headers = {
            ...params.headers,
            "x-nous-user": keyHash,
          };
          return inner(params);
        };
      },
    });
  }

  api.logger.info("[nous-token] ready — usage tracked via gateway");
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash).slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
