// Provider configuration — maps route prefix to upstream API base URL
//
// NOTE: No auth header names here. The gateway does NOT read API keys.
// User identity comes from X-Nous-User header (hash computed by plugin locally).

export interface ProviderConfig {
  name: string;
  upstream: string;
  extractUsage: (body: Record<string, unknown>) => UsageData | null;
}

export interface UsageData {
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  totalTokens: number;
}

// OpenAI-compatible usage extraction (works for OpenAI, DeepSeek, Groq, Together, etc.)
function extractOpenAIUsage(body: Record<string, unknown>): UsageData | null {
  const usage = body.usage as Record<string, unknown> | undefined;
  if (!usage) return null;
  const model = (body.model as string) || "unknown";
  const prompt = (usage.prompt_tokens as number) || 0;
  const completion = (usage.completion_tokens as number) || 0;
  const total = (usage.total_tokens as number) || prompt + completion;

  // OpenAI extended fields
  const details = usage.prompt_tokens_details as Record<string, unknown> | undefined;
  const cacheRead = (details?.cached_tokens as number) || 0;

  return {
    model,
    inputTokens: prompt,
    outputTokens: completion,
    cacheReadTokens: cacheRead,
    cacheWriteTokens: 0,
    totalTokens: total,
  };
}

// Anthropic usage extraction
function extractAnthropicUsage(body: Record<string, unknown>): UsageData | null {
  const usage = body.usage as Record<string, unknown> | undefined;
  if (!usage) return null;
  const model = (body.model as string) || "unknown";
  return {
    model,
    inputTokens: (usage.input_tokens as number) || 0,
    outputTokens: (usage.output_tokens as number) || 0,
    cacheReadTokens: (usage.cache_read_input_tokens as number) || 0,
    cacheWriteTokens: (usage.cache_creation_input_tokens as number) || 0,
    totalTokens: ((usage.input_tokens as number) || 0) + ((usage.output_tokens as number) || 0),
  };
}

// Google Gemini usage extraction
// NOTE: Google changes field names across API versions. If extraction fails,
// we still return a record with model name and zero tokens rather than null,
// so the call is counted even if token details are lost.
function extractGeminiUsage(body: Record<string, unknown>): UsageData | null {
  // Try usageMetadata (current) and usage (potential future name)
  const meta = (body.usageMetadata ?? body.usage) as Record<string, unknown> | undefined;
  const model = (body.modelVersion as string) || (body.model as string) || "unknown";
  if (!meta) {
    // No usage data at all — but if body has a model, record a zero-token entry
    if (body.candidates || body.modelVersion) {
      return { model, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, totalTokens: 0 };
    }
    return null;
  }
  // Try multiple known field names for each metric
  const input = (meta.promptTokenCount as number) || (meta.input_tokens as number) || 0;
  const output = (meta.candidatesTokenCount as number) || (meta.output_tokens as number) || 0;
  const cached = (meta.cachedContentTokenCount as number) || (meta.cache_read_tokens as number) || 0;
  return {
    model,
    inputTokens: input,
    outputTokens: output,
    cacheReadTokens: cached,
    cacheWriteTokens: 0,
    totalTokens: (meta.totalTokenCount as number) || (meta.total_tokens as number) || input + output,
  };
}

export const PROVIDERS: Record<string, ProviderConfig> = {
  openai: {
    name: "openai",
    upstream: "https://api.openai.com",
    extractUsage: extractOpenAIUsage,
  },
  anthropic: {
    name: "anthropic",
    upstream: "https://api.anthropic.com",
    extractUsage: extractAnthropicUsage,
  },
  deepseek: {
    name: "deepseek",
    upstream: "https://api.deepseek.com",
    extractUsage: extractOpenAIUsage,
  },
  gemini: {
    name: "gemini",
    upstream: "https://generativelanguage.googleapis.com",
    extractUsage: extractGeminiUsage,
  },
  groq: {
    name: "groq",
    upstream: "https://api.groq.com",
    extractUsage: extractOpenAIUsage,
  },
  together: {
    name: "together",
    upstream: "https://api.together.xyz",
    extractUsage: extractOpenAIUsage,
  },
  mistral: {
    name: "mistral",
    upstream: "https://api.mistral.ai",
    extractUsage: extractOpenAIUsage,
  },
};
