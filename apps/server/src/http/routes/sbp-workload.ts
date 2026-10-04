import { randomUUID } from "node:crypto";
import { log } from "@nakama/core";
import {
  authenticateSbp,
  loadSbpKeys,
  type SbpKeys,
} from "../../workloads/sbp-auth";
import {
  readSbpBody,
  SBP_DEADLINE_MS,
  SBP_ERRORS,
  SBP_PATH,
  SBP_PROFILE,
  SBP_RESPONSE_BYTES,
  SbpError,
  type SbpErrorCode,
  type SbpResult,
  sbpRequestSchema,
  sbpSuccessSchema,
} from "../../workloads/sbp-contract";
import type { HonoApp } from "../types";

export interface SbpAudit {
  code: SbpErrorCode | "ok";
  durationMs: number;
  keyId?: string;
  requestId: string;
}
export interface SbpRouteOptions {
  audit?: (fields: SbpAudit) => void;
  deadlineMs?: number;
  loadKeys?: () => SbpKeys;
  /** Test clock only; production limits cannot be changed by caller/config. */
  now?: () => number;
  run: (query: string, signal: AbortSignal) => Promise<SbpResult>;
}

/** Register before shared middleware: no browser auth, request-ID or error logs. */
export function registerSbpWorkloadRoute(
  app: HonoApp,
  options: SbpRouteOptions
) {
  let active = 0;
  let windowStart = 0;
  let attempts = 0;
  let authenticated = 0;
  const now = options.now ?? Date.now;
  const audit =
    options.audit ?? ((fields) => log("info", "sbp.workload", { ...fields }));

  app.post(SBP_PATH, async (c) => {
    const started = now();
    const requestId = randomUUID();
    const envelope = {
      version: 1,
      profile_id: SBP_PROFILE,
      request_id: requestId,
    };
    const headers = {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "X-Request-Id": requestId,
    };
    let code: SbpErrorCode | "ok" = "search_failed";
    let keyId: string | undefined;
    let admitted = false;
    const controller = new AbortController();
    const cancel = () => controller.abort(new SbpError("cancelled"));
    const request = c.req.raw;
    request.signal.addEventListener("abort", cancel, { once: true });
    if (request.signal.aborted) {
      cancel();
    }
    const timer = setTimeout(
      () => controller.abort(new SbpError("deadline")),
      options.deadlineMs ?? SBP_DEADLINE_MS
    );
    try {
      if (started - windowStart >= 60_000) {
        windowStart = started;
        attempts = 0;
        authenticated = 0;
      }
      attempts += 1;
      if (attempts > 120) {
        throw new SbpError("busy");
      }
      keyId = authenticateSbp(
        request.headers.get("authorization"),
        (options.loadKeys ?? loadSbpKeys)()
      );
      authenticated += 1;
      if (authenticated > 20 || active >= 2) {
        throw new SbpError("busy");
      }
      active += 1;
      admitted = true;
      controller.signal.throwIfAborted();
      if (
        new URL(request.url).search ||
        ["cookie", "x-org-id", "x-nakama-app-user-id"].some((h) =>
          request.headers.has(h)
        ) ||
        !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
          request.headers.get("content-type") ?? ""
        ) ||
        request.headers.has("content-encoding")
      ) {
        throw new SbpError("invalid_request");
      }
      let query: string;
      try {
        const body = await readSbpBody(request.body, 8192, controller.signal);
        query = sbpRequestSchema.parse(JSON.parse(body)).query;
      } catch {
        throw new SbpError("invalid_request");
      }
      const result = await options.run(query, controller.signal);
      controller.signal.throwIfAborted();
      const response = JSON.stringify(
        sbpSuccessSchema.parse({ ...result, ...envelope, status: "ok" })
      );
      if (Buffer.byteLength(response) > SBP_RESPONSE_BYTES) {
        throw new SbpError("search_failed");
      }
      code = "ok";
      return new Response(response, { status: 200, headers });
    } catch (error) {
      const reason: unknown = controller.signal.aborted
        ? controller.signal.reason
        : error;
      code = reason instanceof SbpError ? reason.code : "search_failed";
      return Response.json(
        { ...envelope, status: "error", error: { code } },
        {
          status: SBP_ERRORS[code],
          headers: {
            ...headers,
            ...(code === "busy" ? { "Retry-After": "60" } : {}),
          },
        }
      );
    } finally {
      clearTimeout(timer);
      request.signal.removeEventListener("abort", cancel);
      controller.abort();
      if (!request.bodyUsed) {
        await request.body?.cancel().catch(() => {});
      }
      if (admitted) {
        active -= 1;
      }
      // Logging must never change a result or leak the underlying failure.
      try {
        audit({
          requestId,
          ...(keyId ? { keyId } : {}),
          code,
          durationMs: now() - started,
        });
      } catch {}
    }
  });
}
