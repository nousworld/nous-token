// Usage extraction — auto-detects format from provider response
//
// Three formats exist in the wild:
//   1. OpenAI-compatible: body.usage.prompt_tokens / completion_tokens
//   2. Anthropic: body.usage.input_tokens / output_tokens
//   3. Gemini: body.usageMetadata.promptTokenCount / candidatesTokenCount
//
// Most providers (OpenAI, DeepSeek, Groq, Together, Mistral, Fireworks,
// Perplexity, OpenRouter, etc.) use format 1. Auto-detection means we
// don't need to know about providers in advance.

export interface UsageData {
  model: string;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  totalTokens: number;
}

/**
 * Auto-detect usage format and extract token counts.
 * Tries all three known formats. Returns null if no usage found.
 */
export function extractUsage(body: Record<string, unknown>): UsageData | null {
  // Try OpenAI-compatible format (most common)
  const openai = tryOpenAI(body);
  if (openai) return openai;

  // Try Anthropic format
  const anthropic = tryAnthropic(body);
  if (anthropic) return anthropic;

  // Try Gemini format
  const gemini = tryGemini(body);
  if (gemini) return gemini;

  return null;
}

function tryOpenAI(body: Record<string, unknown>): UsageData | null {
  const usage = body.usage as Record<string, unknown> | undefined;
  if (!usage || !("prompt_tokens" in usage || "completion_tokens" in usage)) return null;
  const model = (body.model as string) || "unknown";
  const prompt = (usage.prompt_tokens as number) || 0;
  const completion = (usage.completion_tokens as number) || 0;
  const total = (usage.total_tokens as number) || prompt + completion;
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

function tryAnthropic(body: Record<string, unknown>): UsageData | null {
  const usage = body.usage as Record<string, unknown> | undefined;
  if (!usage || !("input_tokens" in usage)) return null;
  // Disambiguate from OpenAI: Anthropic has input_tokens, OpenAI has prompt_tokens
  if ("prompt_tokens" in usage) return null; // it's OpenAI format
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

function tryGemini(body: Record<string, unknown>): UsageData | null {
  const meta = (body.usageMetadata ?? body.usage) as Record<string, unknown> | undefined;
  if (!meta || !("promptTokenCount" in meta || "candidatesTokenCount" in meta)) return null;
  const model = (body.modelVersion as string) || (body.model as string) || "unknown";
  const input = (meta.promptTokenCount as number) || (meta.input_tokens as number) || 0;
  const output = (meta.candidatesTokenCount as number) || (meta.output_tokens as number) || 0;
  const cached = (meta.cachedContentTokenCount as number) || 0;
  return {
    model,
    inputTokens: input,
    outputTokens: output,
    cacheReadTokens: cached,
    cacheWriteTokens: 0,
    totalTokens: (meta.totalTokenCount as number) || input + output,
  };
}

// ── Common provider shortcuts ──
// Users can also pass any upstream URL via X-Nous-Upstream header.

export const PROVIDER_SHORTCUTS: Record<string, string> = {
  openai:      "https://api.openai.com",
  anthropic:   "https://api.anthropic.com",
  deepseek:    "https://api.deepseek.com",
  gemini:      "https://generativelanguage.googleapis.com",
  groq:        "https://api.groq.com",
  together:    "https://api.together.xyz",
  mistral:     "https://api.mistral.ai",
  openrouter:  "https://openrouter.ai",
  fireworks:   "https://api.fireworks.ai",
  perplexity:  "https://api.perplexity.ai",
  cohere:      "https://api.cohere.com",
};
