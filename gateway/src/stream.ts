// Extract usage from SSE streaming responses
// LLM providers send usage data in the final SSE chunk
//
// Anthropic splits data across events:
//   message_start  → model + input usage (input_tokens, cache_read/write)
//   message_delta  → output usage (output_tokens)
// We capture both and merge them at the end.
//
// OpenAI-compatible providers put usage in the final chunk.
// Auto-detection handles both.

import { extractUsage, type UsageData } from "./providers";

/** Partial usage captured from early stream events (Anthropic message_start) */
interface EarlyUsage {
  model: string;
  inputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

/**
 * Tee a streaming response: pass all chunks through to the client unchanged,
 * while extracting usage data from the stream events.
 *
 * Returns [readableStream for client, promise that resolves to UsageData or null]
 */
export function teeStreamForUsage(
  response: Response
): [ReadableStream<Uint8Array>, Promise<UsageData | null>] {
  const reader = response.body!.getReader();
  const decoder = new TextDecoder();
  let tail = ""; // buffer last chunk lines for usage extraction
  let early: EarlyUsage | null = null; // captured from message_start
  let sseBuffer = ""; // accumulate partial SSE lines across chunks

  let resolveUsage: (v: UsageData | null) => void;
  const usagePromise = new Promise<UsageData | null>((r) => {
    resolveUsage = r;
  });

  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) {
        controller.close();
        const usage = extractUsageFromSSE(tail, early);
        resolveUsage(usage);
        return;
      }
      // Pass through unchanged
      controller.enqueue(value);

      const text = decoder.decode(value, { stream: true });

      // Scan for Anthropic message_start event (carries model + input usage)
      // Only buffer until we find it, then stop accumulating to save memory.
      if (!early) {
        sseBuffer += text;
        early = extractEarlyUsage(sseBuffer);
        if (early) sseBuffer = ""; // found it, free the buffer
      }

      // Buffer tail for final usage extraction (keep last 4KB)
      tail = (tail + text).slice(-4096);
    },
    cancel() {
      reader.cancel();
      resolveUsage(null);
    },
  });

  return [stream, usagePromise];
}

/**
 * Extract model and input usage from Anthropic's message_start event.
 */
function extractEarlyUsage(buffer: string): EarlyUsage | null {
  const lines = buffer.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("data: ") || trimmed === "data: [DONE]") continue;
    try {
      const json = JSON.parse(trimmed.slice(6)) as Record<string, unknown>;
      if (json.type === "message_start") {
        const msg = json.message as Record<string, unknown> | undefined;
        if (!msg) continue;
        const model = (msg.model as string) || "unknown";
        const usage = msg.usage as Record<string, unknown> | undefined;
        return {
          model,
          inputTokens: (usage?.input_tokens as number) || 0,
          cacheReadTokens: (usage?.cache_read_input_tokens as number) || 0,
          cacheWriteTokens: (usage?.cache_creation_input_tokens as number) || 0,
        };
      }
    } catch {
      // not valid JSON yet (partial line), skip
    }
  }
  return null;
}

/**
 * Parse SSE tail to find the last data chunk containing usage info.
 * Auto-detects format: tries Anthropic message_delta first, then generic extractUsage.
 */
function extractUsageFromSSE(
  tail: string,
  early: EarlyUsage | null
): UsageData | null {
  const lines = tail.split("\n");
  // Walk backwards to find the last JSON with usage
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line.startsWith("data: ") || line === "data: [DONE]") continue;
    try {
      const json = JSON.parse(line.slice(6)) as Record<string, unknown>;

      // Anthropic streams: message_delta carries output_tokens
      if (json.type === "message_delta") {
        const u = json.usage as Record<string, unknown> | undefined;
        if (u) {
          const outputTokens = (u.output_tokens as number) || 0;
          const inputTokens = early?.inputTokens || 0;
          const cacheRead = early?.cacheReadTokens || 0;
          const cacheWrite = early?.cacheWriteTokens || 0;
          return {
            model: early?.model || "unknown",
            inputTokens,
            outputTokens,
            cacheReadTokens: cacheRead,
            cacheWriteTokens: cacheWrite,
            totalTokens: inputTokens + outputTokens,
          };
        }
      }

      // OpenAI-compatible and others: auto-detect from the chunk
      const usage = extractUsage(json);
      if (usage && usage.totalTokens > 0) return usage;
    } catch {
      // not valid JSON, skip
    }
  }
  return null;
}
