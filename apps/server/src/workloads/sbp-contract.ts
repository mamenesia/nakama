import { isIP } from "node:net";
import { z } from "zod";

export const SBP_PATH = "/v1/workloads/sbp-search/runs";
export const SBP_PROFILE = "property-local-discovery";
export const SBP_ORG = "seek-best-property";
export const SBP_DEADLINE_MS = 55_000;
export const SBP_RESPONSE_BYTES = 32_768;

// Output links only, never fetched locally. Conservatively exclude literal IPs
// and non-public naming forms; the consumer must also apply its URL policy.
export function isSbpPublicUrl(value: string): boolean {
  try {
    const url = new URL(value);
    const host = url.hostname.replace(/\.$/, "").toLowerCase();
    return (
      url.protocol === "https:" &&
      !(url.username || url.password || url.port || url.hash) &&
      host.includes(".") &&
      !isIP(host) &&
      !host.includes(":") &&
      !/(^|\.)(localhost|local|internal|test|invalid|example|onion)$/.test(
        host
      ) &&
      !/[\s\u0000-\u001f\u007f]/.test(value)
    );
  } catch {
    return false;
  }
}

export const sbpUrlSchema = z.string().min(1).max(2048).refine(isSbpPublicUrl);
export const sbpRequestSchema = z.strictObject({
  query: z
    .string()
    .trim()
    .min(1)
    .refine(
      (value) => Array.from(value).length <= 1000 && value.isWellFormed()
    ),
});
export const sbpPreviewSchema = z.strictObject({
  description: z.string().max(1600),
  title: z.string().min(1).max(240),
  url: sbpUrlSchema,
});
export const sbpEvidenceSchema = z.strictObject({
  observed_urls: z.array(sbpUrlSchema).max(5),
  provider: z.enum(["exa", "firecrawl"]),
  tool: z.literal("web_search"),
});
export const sbpResultSchema = z
  .strictObject({
    evidence: z.tuple([sbpEvidenceSchema]),
    results: z.array(sbpPreviewSchema).max(4),
  })
  .refine(({ results, evidence }) => {
    const urls = evidence[0].observed_urls;
    return (
      new Set(urls).size === urls.length &&
      new Set(results.map((r) => r.url)).size === results.length &&
      results.every((r) => urls.includes(r.url))
    );
  });
const envelope = {
  profile_id: z.literal(SBP_PROFILE),
  request_id: z.uuid(),
  version: z.literal(1),
};
export const sbpSuccessSchema = sbpResultSchema.safeExtend({
  ...envelope,
  status: z.literal("ok"),
});
export const SBP_ERRORS = {
  busy: 429,
  cancelled: 499,
  deadline: 504,
  invalid_request: 400,
  search_failed: 502,
  unauthorized: 401,
  unavailable: 503,
} as const;
export type SbpErrorCode = keyof typeof SBP_ERRORS;
export const sbpErrorSchema = z.strictObject({
  ...envelope,
  error: z.strictObject({
    code: z.enum(Object.keys(SBP_ERRORS) as [SbpErrorCode, ...SbpErrorCode[]]),
  }),
  status: z.literal("error"),
});
export type SbpResult = z.infer<typeof sbpResultSchema>;

export class SbpError extends Error {
  constructor(readonly code: SbpErrorCode) {
    super(code);
  }
}

/** Bounds decoded transfer size, including chunked bodies; cancels on every exit. */
export async function readSbpBody(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  signal: AbortSignal
): Promise<string> {
  signal.throwIfAborted();
  if (!body) {
    throw new Error("missing_body");
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  const abort = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", abort, { once: true });
  try {
    for (;;) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) {
        return new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(chunks, size)
        );
      }
      size += value.byteLength;
      if (size > maxBytes) {
        throw new Error("body_limit");
      }
      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", abort);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
