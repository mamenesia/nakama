import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OpenAPIHono } from "@hono/zod-openapi";
import type { ProviderInstance, UserConfig } from "@nakama/core";
import {
  createSqliteDatabase,
  type StoredProfileRecord,
  type StoredToolRecord,
} from "@nakama/db";
import {
  registerSbpWorkloadRoute,
  type SbpAudit,
  type SbpRouteOptions,
} from "../http/routes/sbp-workload";
import { createMinimalHonoApp } from "../http/test-app-helpers";
import type { HonoApp } from "../http/types";
import {
  authenticateSbp,
  loadSbpKeys,
  type SbpKeys,
  sbpKeysSchema,
} from "./sbp-auth";
import {
  readSbpBody,
  SBP_PATH,
  SBP_PROFILE,
  SbpError,
  type SbpResult,
  sbpErrorSchema,
  sbpSuccessSchema,
} from "./sbp-contract";
import {
  createSbpRun,
  SBP_MODEL,
  SBP_ORG_ID,
  SBP_PROVIDER_ID,
  type SbpRunOptions,
} from "./sbp-run";

function credential(id: string) {
  const secret = randomBytes(32).toString("base64url");
  return {
    key: { id, sha256: createHash("sha256").update(secret).digest("hex") },
    token: `Bearer sbp1.${id}.${secret}`,
  };
}
const current = credential("current_A-1");
const next = credential("next_B-2");
function keys(): SbpKeys {
  return { current: current.key, next: next.key, revoked: [], version: 1 };
}
const empty: SbpResult = {
  evidence: [{ observed_urls: [], provider: "exa", tool: "web_search" }],
  results: [],
};
function route(overrides: Partial<SbpRouteOptions> = {}) {
  const app: HonoApp = new OpenAPIHono();
  const audits: SbpAudit[] = [];
  registerSbpWorkloadRoute(app, {
    audit: (a) => audits.push(a),
    loadKeys: keys,
    run: async () => empty,
    ...overrides,
  });
  return { app, audits };
}
function request(
  body: unknown = { query: "homes near transit" },
  extra: RequestInit = {}
) {
  return new Request(`http://localhost${SBP_PATH}`, {
    body: typeof body === "string" ? body : JSON.stringify(body),
    headers: {
      authorization: current.token,
      "content-type": "application/json",
    },
    method: "POST",
    ...extra,
  });
}
async function expectError(
  response: Response,
  status: number,
  code: SbpError["code"]
) {
  expect(response.status).toBe(status);
  const result = sbpErrorSchema.parse(await response.json());
  expect(result.error.code).toBe(code);
  expect(response.headers.get("cache-control")).toBe("no-store");
}

describe("SBP authentication", () => {
  test("current/next rotation, removal and explicit revocation", () => {
    expect(authenticateSbp(current.token, keys())).toBe(current.key.id);
    expect(authenticateSbp(next.token, keys())).toBe(next.key.id);
    expect(() =>
      authenticateSbp(current.token, { ...keys(), revoked: [current.key.id] })
    ).toThrow("unauthorized");
    const promoted = { ...keys(), current: next.key, next: null };
    expect(() => authenticateSbp(current.token, promoted)).toThrow(
      "unauthorized"
    );
    expect(authenticateSbp(next.token, promoted)).toBe(next.key.id);
    for (const token of [
      null,
      "Bearer operator",
      current.token.replace("current_A-1", "unknown"),
      `${current.token}x`,
      credential(current.key.id).token,
    ]) {
      expect(() => authenticateSbp(token, keys())).toThrow("unauthorized");
    }
    expect(
      sbpKeysSchema.safeParse({ ...keys(), next: current.key }).success
    ).toBe(false);
  });

  test("hot file rotation, malformed, oversize, symlink and writable file fail closed", () => {
    const dir = mkdtempSync(join(tmpdir(), "sbp-keys-"));
    const path = join(dir, "keys.json");
    const previous = process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE;
    process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE = path;
    try {
      writeFileSync(path, JSON.stringify(keys()), { mode: 0o600 });
      expect(authenticateSbp(current.token, loadSbpKeys())).toBe(
        current.key.id
      );
      writeFileSync(
        join(dir, "next.json"),
        JSON.stringify({ ...keys(), revoked: [current.key.id] }),
        { mode: 0o600 }
      );
      renameSync(join(dir, "next.json"), path);
      expect(() => authenticateSbp(current.token, loadSbpKeys())).toThrow(
        "unauthorized"
      );
      chmodSync(path, 0o666);
      expect(() => loadSbpKeys()).toThrow("unavailable");
      chmodSync(path, 0o600);
      writeFileSync(path, "x".repeat(16_385));
      expect(() => loadSbpKeys()).toThrow("unavailable");
      writeFileSync(path, "{}");
      expect(() => loadSbpKeys()).toThrow("unavailable");
      symlinkSync(path, join(dir, "link"));
      process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE = join(dir, "link");
      expect(() => loadSbpKeys()).toThrow("unavailable");
    } finally {
      if (previous === undefined) {
        delete process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE;
      } else {
        process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE = previous;
      }
      rmSync(dir, { force: true, recursive: true });
    }
  });
});

describe("SBP route", () => {
  test("valid run/retry, generated ID, no raw audit content", async () => {
    const queries: string[] = [];
    const { app, audits } = route({
      run: async (query) => {
        queries.push(query);
        return empty;
      },
    });
    const ids: string[] = [];
    for (const query of [
      "  first private question  ",
      "different second question",
    ]) {
      const response = await app.fetch(request({ query }));
      expect(response.status).toBe(200);
      const value = sbpSuccessSchema.parse(await response.json());
      expect(value.evidence).toEqual(empty.evidence);
      expect(value.results).toEqual([]);
      ids.push(value.request_id);
    }
    expect(ids[0]).not.toBe(ids[1]);
    expect(queries).toEqual([
      "first private question",
      "different second question",
    ]);
    expect(audits.map((a) => a.code)).toEqual(["ok", "ok"]);
    expect(Object.keys(audits[0]).sort()).toEqual([
      "code",
      "durationMs",
      "keyId",
      "requestId",
    ]);
    expect(JSON.stringify(audits)).not.toContain("question");
    expect(JSON.stringify(audits)).not.toContain(current.token);
  });

  test.each([
    "{",
    "[]",
    "null",
    {},
    { query: " " },
    { query: 7 },
    { query: "x".repeat(1001) },
    "x".repeat(8193),
    ...[
      "profile",
      "org_id",
      "tools",
      "model",
      "files",
      "settings",
      "skills",
      "session_id",
      "history",
    ].map((field) => ({ query: "okay", [field]: "forbidden" })),
  ])("rejects malformed and arbitrary scope: %j", async (body) => {
    const { app } = route({
      run: async () => {
        throw new Error("should not execute");
      },
    });
    await expectError(await app.fetch(request(body)), 400, "invalid_request");
  });

  test("1000 query boundary accepted; scope/cookie/query/encoding rejected", async () => {
    const { app } = route();
    expect((await app.fetch(request({ query: "x".repeat(1000) }))).status).toBe(
      200
    );
    for (const name of [
      "cookie",
      "x-org-id",
      "x-nakama-app-user-id",
      "content-encoding",
    ]) {
      const r = request();
      r.headers.set(name, "forbidden");
      await expectError(await app.fetch(r), 400, "invalid_request");
    }
    const r = request();
    await expectError(
      await app.fetch(new Request(`${r.url}?profile=other`, r)),
      400,
      "invalid_request"
    );
  });

  test("invalid auth precedes body/config execution; failures sanitized", async () => {
    const { app, audits } = route({
      run: async () => {
        throw new Error("secret private query sql password");
      },
    });
    const r = request("malformed");
    r.headers.set("authorization", "Bearer operator-secret");
    await expectError(await app.fetch(r), 401, "unauthorized");
    const failed = await app.fetch(request());
    await expectError(failed, 502, "search_failed");
    expect(JSON.stringify(audits)).not.toMatch(/secret|private|password|sql/);
    expect(
      (
        await route({
          loadKeys: () => {
            throw new SbpError("unavailable");
          },
        }).app.fetch(request())
      ).status
    ).toBe(503);
  });

  test("missing/forged evidence and total UTF8 output overflow fail closed", async () => {
    for (const result of [
      { evidence: [], results: [] },
      {
        evidence: empty.evidence,
        results: [
          { description: "d", title: "t", url: "https://example.com/forged" },
        ],
      },
      {
        evidence: [
          {
            observed_urls: Array.from(
              { length: 4 },
              (_, i) => `https://example.com/${i}${"x".repeat(1990)}`
            ),
            provider: "exa",
            tool: "web_search",
          },
        ],
        results: Array.from({ length: 4 }, (_, i) => ({
          description: "漢".repeat(1600),
          title: "漢".repeat(240),
          url: `https://example.com/${i}${"x".repeat(1990)}`,
        })),
      },
    ]) {
      const { app } = route({ run: async () => result as SbpResult });
      await expectError(await app.fetch(request()), 502, "search_failed");
    }
  });

  test("bounded global authenticated and anonymous rates independent of spoofed IP", async () => {
    let time = 100_000;
    const { app } = route({ now: () => time });
    for (let i = 0; i < 20; i++) {
      expect((await app.fetch(request())).status).toBe(200);
    }
    await expectError(await app.fetch(request()), 429, "busy");
    time += 60_000;
    expect((await app.fetch(request())).status).toBe(200);
    const anonymous = route().app;
    for (let i = 0; i < 120; i++) {
      const r = request();
      r.headers.delete("authorization");
      r.headers.set("x-forwarded-for", `1.2.3.${i}`);
      expect((await anonymous.fetch(r)).status).toBe(401);
    }
    await expectError(await anonymous.fetch(request()), 429, "busy");
  });

  test("concurrency2, abort and timeout settle before releasing slots", async () => {
    let running = 0;
    const started = Promise.withResolvers<void>();
    const { app } = route({
      deadlineMs: 80,
      run: async (_query, signal) => {
        running++;
        if (running === 2) {
          started.resolve();
        }
        try {
          await new Promise<void>((_resolve, reject) =>
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            })
          );
        } finally {
          running--;
        }
        return empty;
      },
    });
    const first = new AbortController();
    const a = app.fetch(request({ query: "A" }, { signal: first.signal }));
    const b = app.fetch(request({ query: "B" }));
    await started.promise;
    await expectError(await app.fetch(request()), 429, "busy");
    first.abort();
    await expectError(await a, 499, "cancelled");
    expect(running).toBe(1);
    await expectError(await b, 504, "deadline");
    expect(running).toBe(0);
    await expectError(await app.fetch(request()), 504, "deadline");
    expect(running).toBe(0);
  });

  test("real TCP client disconnect cancels running workload and permits next run", async () => {
    const started = Promise.withResolvers<void>();
    const stopped = Promise.withResolvers<void>();
    let calls = 0;
    const { app } = route({
      run: async (_query, signal) => {
        if (++calls > 1) {
          return empty;
        }
        started.resolve();
        try {
          await new Promise<void>((_resolve, reject) =>
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            })
          );
        } finally {
          stopped.resolve();
        }
        return empty;
      },
    });
    const server = Bun.serve({
      fetch: (r) => app.fetch(r),
      hostname: "127.0.0.1",
      port: 0,
    });
    try {
      const controller = new AbortController();
      const pending = fetch(
        new Request(`http://127.0.0.1:${server.port}${SBP_PATH}`, request()),
        { signal: controller.signal }
      ).catch(() => null);
      await started.promise;
      controller.abort();
      await pending;
      await Promise.race([
        stopped.promise,
        Bun.sleep(1500).then(() => {
          throw new Error("disconnect did not propagate");
        }),
      ]);
      const response = await fetch(
        new Request(`http://127.0.0.1:${server.port}${SBP_PATH}`, request())
      );
      expect(response.status).toBe(200);
    } finally {
      await server.stop(true);
    }
  });

  test("full app workload owns oversize errors before generic body/auth middleware", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sbp-app-"));
    const path = join(dir, "keys.json");
    const previous = process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE;
    writeFileSync(path, JSON.stringify(keys()), { mode: 0o600 });
    process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE = path;
    try {
      const { app } = createMinimalHonoApp();
      const oversized = request("x".repeat(11 * 1024 * 1024));
      oversized.headers.set("x-request-id", "private-caller-content");
      const response = await app.fetch(oversized);
      expect(response.headers.get("x-request-id")).not.toBe(
        "private-caller-content"
      );
      await expectError(response, 400, "invalid_request");
      const operator = request();
      operator.headers.set("authorization", "Bearer operator");
      await expectError(await app.fetch(operator), 401, "unauthorized");
    } finally {
      if (previous === undefined) {
        delete process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE;
      } else {
        process.env.NAKAMA_SBP_WORKLOAD_KEYS_FILE = previous;
      }
      rmSync(dir, { force: true, recursive: true });
    }
  });

  test("workload bearer never authenticates ordinary APIs in full app", async () => {
    const { app } = createMinimalHonoApp();
    for (const path of [
      "/v1/profiles",
      "/v1/sessions",
      "/v1/tools",
      "/v1/skills",
      "/v1/org-memory",
      "/v1/settings",
    ]) {
      expect(
        (await app.request(path, { headers: { authorization: current.token } }))
          .status
      ).toBe(401);
    }
  });
});

function runtimeFixture() {
  const profile: StoredProfileRecord = {
    createdAt: "now",
    id: SBP_PROFILE,
    isSuper: false,
    model: `${SBP_PROVIDER_ID}::${SBP_MODEL}`,
    name: "fixed",
    orgId: SBP_ORG_ID,
    systemPrompt: "PRIVATE_PROFILE_PROMPT",
    updatedAt: "now",
  };
  const tools: StoredToolRecord[] = ["web_search", "web_fetch"].map((name) => ({
    createdAt: "now",
    description: "",
    handlerConfig: {},
    handlerType: "builtin",
    id: name,
    name,
    orgId: SBP_ORG_ID,
    updatedAt: "now",
  }));
  const provider: ProviderInstance = {
    apiKey: "synthetic-model-key",
    createdAt: "now",
    id: SBP_PROVIDER_ID,
    label: "fixed",
    openRouterRouting: {
      dataCollection: "deny",
      requireParameters: true,
      zdr: true,
    },
    type: "openrouter",
  };
  const config: UserConfig = { defaultProviderId: null, providers: [provider] };
  const calls: {
    url: string;
    body: Record<string, unknown>;
    signal: AbortSignal | null | undefined;
  }[] = [];
  let searchResponse: unknown = {
    results: [
      {
        text: "Alpha public snippet",
        title: "First",
        url: "https://example.com/a",
      },
      {
        text: "Beta public snippet",
        title: "Second",
        url: "https://example.com/b",
      },
      {
        text: "Gamma public snippet",
        title: "Third",
        url: "https://example.com/c",
      },
    ],
  };
  let modelResponse: unknown = {
    choices: [
      { finish_reason: "stop", message: { content: '{"indices":[2,0]}' } },
    ],
  };
  const options: SbpRunOptions = {
    database: {
      getProfileExecutionScope: async (id, orgId) => {
        expect([id, orgId]).toEqual([SBP_PROFILE, SBP_ORG_ID]);
        return {
          ...profile,
          composioCount: 0,
          mcpCount: 0,
          orgId: profile.orgId!,
          skillCount: 0,
          tools: tools.map((t) => ({
            handlerType: t.handlerType,
            name: t.name,
            orgId: t.orgId ?? null,
          })),
        };
      },
    },
    fetch: (async (url, init) => {
      calls.push({
        body: JSON.parse(String(init?.body)),
        signal: init?.signal,
        url: String(url),
      });
      expect(init?.redirect).toBe("error");
      return Response.json(
        String(url).includes("exa.ai") ? searchResponse : modelResponse
      );
    }) as typeof fetch,
    getUserConfig: () => config,
    loadSearch: async () => ({
      apiKey: "synthetic-search-key",
      endpoint: "https://api.exa.ai/search",
      provider: "exa",
    }),
  };
  return {
    calls,
    model: (value: unknown) => {
      modelResponse = value;
    },
    options,
    profile,
    provider,
    search: (value: unknown) => {
      searchResponse = value;
    },
    tools,
  };
}

describe("SBP execution boundary", () => {
  test("metadata-only real SQLite read and repeated runs leave all storage unchanged", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sbp-storage-"));
    const path = join(dir, "test.sqlite");
    const database = await createSqliteDatabase(`file:${path}`);
    const f = runtimeFixture();
    try {
      await database.adapter.upsertOrganization({
        createdAt: "now",
        id: SBP_ORG_ID,
        name: "synthetic",
        slug: "seek-best-property",
        updatedAt: "now",
      });
      await database.adapter.upsertProfile(f.profile);
      for (const tool of f.tools) {
        await database.adapter.upsertTool(tool);
        await database.adapter.assignToolToProfile(SBP_PROFILE, tool.id);
      }
      const raw = new Database(path, { readonly: true });
      try {
        const before = createHash("sha256")
          .update(raw.serialize())
          .digest("hex");
        const scope = await database.adapter.getProfileExecutionScope(
          SBP_PROFILE,
          SBP_ORG_ID
        );
        expect(Object.keys(scope!).sort()).toEqual([
          "composioCount",
          "id",
          "isSuper",
          "mcpCount",
          "model",
          "orgId",
          "skillCount",
          "tools",
        ]);
        expect(JSON.stringify(scope)).not.toContain("PRIVATE_PROFILE_PROMPT");
        expect(
          await database.adapter.getProfileExecutionScope(SBP_PROFILE, "other")
        ).toBeNull();
        f.options.database = database.adapter;
        const run = createSbpRun(f.options);
        await run("first", new AbortController().signal);
        await run("second", new AbortController().signal);
        f.model({ error: "synthetic-error" });
        await expect(
          run("failure", new AbortController().signal)
        ).rejects.toThrow();
        expect(createHash("sha256").update(raw.serialize()).digest("hex")).toBe(
          before
        );
        expect(raw.query("PRAGMA integrity_check").get()).toEqual({
          integrity_check: "ok",
        });
      } finally {
        raw.close();
      }
    } finally {
      database.release();
      rmSync(dir, { force: true, recursive: true });
    }
  });

  test("Unicode scalar query limits align with Python, invalid surrogate rejected", async () => {
    const { app } = route();
    expect(
      (await app.fetch(request({ query: "😀".repeat(1000) }))).status
    ).toBe(200);
    await expectError(
      await app.fetch(request({ query: "😀".repeat(1001) })),
      400,
      "invalid_request"
    );
    await expectError(
      await app.fetch(request({ query: "\ud800" })),
      400,
      "invalid_request"
    );
  });

  test("actual search evidence, asymmetric ranking, exact ZDR request, no history or SQL", async () => {
    const f = runtimeFixture();
    const run = createSbpRun(f.options);
    const signal = new AbortController().signal;
    const result = await run("first-private-query", signal);
    expect(result.results.map((r) => r.title)).toEqual(["Third", "First"]);
    expect(result.results.map((r) => r.description)).toEqual([
      "Gamma public snippet",
      "Alpha public snippet",
    ]);
    expect(result.evidence).toEqual([
      {
        observed_urls: [
          "https://example.com/a",
          "https://example.com/b",
          "https://example.com/c",
        ],
        provider: "exa",
        tool: "web_search",
      },
    ]);
    expect(f.calls[0].body).toEqual({
      contents: { text: { maxCharacters: 1600 } },
      numResults: 5,
      query: "first-private-query",
    });
    expect(f.calls[1].body.provider).toEqual({
      data_collection: "deny",
      require_parameters: true,
      zdr: true,
    });
    expect(f.calls[1].body.max_tokens).toBe(512);
    expect(f.calls[1].body.tools).toBeUndefined();
    expect(f.calls[1].body.model).toBe("openai/gpt-6-luna");
    expect(f.calls.every((c) => c.signal === signal)).toBe(true);
    expect(JSON.stringify(f.calls)).not.toContain("PRIVATE_PROFILE_PROMPT");
    await run("second-private-query", signal);
    expect(JSON.stringify(f.calls.slice(2))).not.toContain(
      "first-private-query"
    );
    expect(f.calls.length).toBe(4);
  });

  test("empty actual search skips inference; malformed evidence is not empty success", async () => {
    const f = runtimeFixture();
    f.search({ results: [] });
    expect(
      await createSbpRun(f.options)("query", new AbortController().signal)
    ).toEqual(empty);
    expect(f.calls.length).toBe(1);
    for (const payload of [
      {},
      { error: "secret" },
      { results: null },
      { results: [{ title: "missing url" }] },
    ]) {
      f.search(payload);
      await expect(
        createSbpRun(f.options)("query", new AbortController().signal)
      ).rejects.toThrow();
    }
  });

  test.each([
    "http://example.com/x",
    "https://127.0.0.1/x",
    "https://[::1]/",
    "https://user:pass@example.com/",
    "https://host.internal/x",
    "file:///etc/passwd",
    "https://example.com:8443/x",
  ])("unsafe search links excluded: %s", async (url) => {
    const f = runtimeFixture();
    f.search({ results: [{ title: "unsafe", url }] });
    expect(
      await createSbpRun(f.options)("query", new AbortController().signal)
    ).toEqual(empty);
    expect(f.calls.length).toBe(1);
  });

  test.each([
    "{}",
    '{"indices":[9]}',
    '{"indices":[0,0]}',
    '{"indices":[1.2]}',
    '{"indices":[0],"url":"https://forged.com"}',
    "not json",
  ])("model cannot forge evidence/ranking: %s", async (content) => {
    const f = runtimeFixture();
    f.model({ choices: [{ finish_reason: "stop", message: { content } }] });
    await expect(
      createSbpRun(f.options)("query", new AbortController().signal)
    ).rejects.toThrow();
    expect(f.calls.length).toBe(2);
  });

  test("scope/provider/model/tool/privacy drift fails before any egress", async () => {
    const changes: ((f: ReturnType<typeof runtimeFixture>) => void)[] = [
      (f) => {
        f.profile.isSuper = true;
      },
      (f) => {
        f.profile.orgId = "other";
      },
      (f) => {
        f.profile.model = `${SBP_PROVIDER_ID}::other-model`;
      },
      (f) => {
        f.provider.type = "openai";
      },
      (f) => {
        f.provider.openRouterRouting = undefined;
      },
      (f) => {
        f.provider.openRouterRouting!.zdr = false;
      },
      (f) => {
        f.provider.openRouterRouting!.dataCollection = "allow";
      },
      (f) => {
        f.provider.openRouterRouting!.requireParameters = false;
      },
      (f) => {
        f.tools[0].handlerType = "javascript";
      },
      (f) => {
        f.tools[0].name = "sql";
      },
      (f) => {
        f.tools.push({ ...f.tools[0], name: "read_file" });
      },
      (f) => {
        const original = f.options.database.getProfileExecutionScope;
        f.options.database.getProfileExecutionScope = async (id, orgId) => ({
          ...(await original(id, orgId))!,
          skillCount: 1,
        });
      },
      (f) => {
        const original = f.options.database.getProfileExecutionScope;
        f.options.database.getProfileExecutionScope = async (id, orgId) => ({
          ...(await original(id, orgId))!,
          mcpCount: 1,
        });
      },
      (f) => {
        const original = f.options.database.getProfileExecutionScope;
        f.options.database.getProfileExecutionScope = async (id, orgId) => ({
          ...(await original(id, orgId))!,
          composioCount: 1,
        });
      },
      (f) => {
        f.options.loadSearch = async () => ({
          apiKey: "synthetic",
          endpoint: "https://evil.com/search",
          provider: "exa",
        });
      },
    ];
    for (const change of changes) {
      const f = runtimeFixture();
      change(f);
      await expect(
        createSbpRun(f.options)("query", new AbortController().signal)
      ).rejects.toThrow("unavailable");
      expect(f.calls).toEqual([]);
    }
  });

  test("provider error/oversize/redirect fail without retries or exposing payloads", async () => {
    for (const response of [
      new Response("provider-secret", { status: 500 }),
      new Response("redirect", { status: 302 }),
      new Response("x".repeat(262_145), {
        headers: { "content-type": "application/json" },
      }),
    ]) {
      const f = runtimeFixture();
      let calls = 0;
      f.options.fetch = async () => {
        calls++;
        return response;
      };
      const { app } = route({ run: createSbpRun(f.options) });
      await expectError(await app.fetch(request()), 502, "search_failed");
      expect(calls).toBe(1);
    }
  });

  test("real provider HTTP body closes on workload deadline", async () => {
    const disconnected = Promise.withResolvers<void>();
    const upstream = Bun.serve({
      fetch(r) {
        r.signal.addEventListener("abort", () => disconnected.resolve(), {
          once: true,
        });
        return new Response(
          new ReadableStream({
            cancel() {
              disconnected.resolve();
            },
            start(c) {
              c.enqueue(new TextEncoder().encode('{"results":['));
            },
          }),
          { headers: { "content-type": "application/json" } }
        );
      },
      hostname: "127.0.0.1",
      port: 0,
    });
    try {
      const f = runtimeFixture();
      f.options.fetch = (_url, init) =>
        fetch(`http://127.0.0.1:${upstream.port}`, init);
      const { app } = route({ deadlineMs: 100, run: createSbpRun(f.options) });
      await expectError(await app.fetch(request()), 504, "deadline");
      await Promise.race([
        disconnected.promise,
        Bun.sleep(1000).then(() => {
          throw new Error("upstream socket remained open");
        }),
      ]);
    } finally {
      await upstream.stop(true);
    }
  });

  test("early auth failure cancels an unread body", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
    });
    const { app } = route();
    const r = request(undefined, {
      body,
      headers: { authorization: "Bearer wrong" },
    });
    await expectError(await app.fetch(r), 401, "unauthorized");
    expect(cancelled).toBe(true);
  });

  test("chunked input bounds and stalled body cancellation release reader", async () => {
    let cancelled = false;
    const huge = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
      start(c) {
        c.enqueue(new Uint8Array(8193));
      },
    });
    await expect(
      readSbpBody(huge, 8192, new AbortController().signal)
    ).rejects.toThrow();
    expect(cancelled).toBe(true);
    expect(huge.locked).toBe(false);
    const controller = new AbortController();
    const stalled = new ReadableStream<Uint8Array>();
    const reading = readSbpBody(stalled, 8192, controller.signal);
    controller.abort();
    await expect(reading).rejects.toThrow();
    expect(stalled.locked).toBe(false);
  });
});
