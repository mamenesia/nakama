/** Disposable loopback-only integration fixture. Never imported by the server. */
import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { OpenAPIHono } from "@hono/zod-openapi";
import { registerSbpWorkloadRoute } from "../http/routes/sbp-workload";
import type { HonoApp } from "../http/types";
import { SBP_PROFILE } from "./sbp-contract";
import {
  createSbpRun,
  SBP_MODEL,
  SBP_ORG_ID,
  SBP_PROVIDER_ID,
} from "./sbp-run";

const tokenFile = process.env.SBP_FIXTURE_TOKEN_FILE;
if (!tokenFile) {
  throw new Error("SBP_FIXTURE_TOKEN_FILE is required (new disposable file)");
}
const secret = randomBytes(32).toString("base64url");
writeFileSync(tokenFile, `sbp1.fixture.${secret}`, { flag: "wx", mode: 0o600 });
const app: HonoApp = new OpenAPIHono();
let activeTransports = 0;
let abortedTransports = 0;
let completedRuns = 0;
const run = createSbpRun({
  database: {
    getProfileExecutionScope: async () => ({
      composioCount: 0,
      id: SBP_PROFILE,
      isSuper: false,
      mcpCount: 0,
      model: `${SBP_PROVIDER_ID}::${SBP_MODEL}`,
      orgId: SBP_ORG_ID,
      skillCount: 0,
      tools: ["web_search", "web_fetch"].map((name) => ({
        handlerType: "builtin",
        name,
        orgId: SBP_ORG_ID,
      })),
    }),
  },
  fetch: async (url, init) => {
    const body = JSON.parse(String(init.body));
    if (url === "https://openrouter.ai/api/v1/chat/completions") {
      return Response.json({
        choices: [
          { finish_reason: "stop", message: { content: '{"indices":[1,0]}' } },
        ],
      });
    }
    if (url !== "https://api.exa.ai/search") {
      throw new Error("unapproved fixture egress");
    }
    const query = String(body.query);
    if (query === "fixture:failure") {
      return Response.json(
        { error: "synthetic upstream failure" },
        { status: 500 }
      );
    }
    if (query === "fixture:malformed") {
      return Response.json({ missing: "results" });
    }
    if (query === "fixture:empty") {
      return Response.json({ results: [] });
    }
    if (query === "fixture:slow") {
      activeTransports++;
      try {
        await new Promise<void>((_resolve, reject) => {
          const aborted = () => {
            abortedTransports++;
            reject(init.signal?.reason);
          };
          if (init.signal?.aborted) {
            aborted();
          } else {
            init.signal?.addEventListener("abort", aborted, { once: true });
          }
        });
      } finally {
        activeTransports--;
      }
    }
    return Response.json({
      results: [
        {
          text: "Public preview A",
          title: "Synthetic property A",
          url: "https://example.com/property-a",
        },
        {
          text: "Public preview B",
          title: "Synthetic lifestyle B",
          url: "https://example.com/lifestyle-b",
        },
      ],
    });
  },
  getUserConfig: () => ({
    defaultProviderId: null,
    providers: [
      {
        apiKey: "synthetic-not-a-credential",
        createdAt: "fixture",
        id: SBP_PROVIDER_ID,
        label: "Synthetic",
        openRouterRouting: {
          dataCollection: "deny",
          requireParameters: true,
          zdr: true,
        },
        type: "openrouter",
      },
    ],
  }),
  loadSearch: async () => ({
    apiKey: "synthetic-not-a-credential",
    endpoint: "https://api.exa.ai/search",
    provider: "exa",
  }),
});
registerSbpWorkloadRoute(app, {
  audit: () => {
    completedRuns++;
  },
  loadKeys: () => ({
    current: {
      id: "fixture",
      sha256: createHash("sha256").update(secret).digest("hex"),
    },
    next: null,
    revoked: [],
    version: 1,
  }),
  run,
});
// Diagnostic counters only; this endpoint does not exist in production.
app.get("/fixture-state", (c) =>
  c.json({ abortedTransports, activeTransports, completedRuns })
);
const cert = process.env.SBP_FIXTURE_CERT_FILE;
const key = process.env.SBP_FIXTURE_KEY_FILE;
if (Boolean(cert) !== Boolean(key)) {
  throw new Error("Both TLS fixture files are required");
}
const server = Bun.serve({
  fetch: (request) => app.fetch(request),
  hostname: "127.0.0.1",
  idleTimeout: 120,
  port: Number(process.env.SBP_FIXTURE_PORT ?? 4431),
  ...(cert && key ? { tls: { cert: Bun.file(cert), key: Bun.file(key) } } : {}),
});
process.stdout.write(
  `Synthetic fixture listening on loopback port ${server.port}; token written to private fixture file.\n`
);
