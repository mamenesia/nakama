# SBP workload extension (v1)

SBP-maintained extension of upstream `ahmadrosid/nakama` tag `v0.4.38`,
commit `ce5ae048ac92c16639d5a368e128befdc07a079d`. Dedicated instance only.
This is not a restoration of removed organization keys or app-user access.

## Threat model and decisions

Untrusted parties: anonymous Internet clients, visitors supplying queries, a
compromised workload caller, search results, and model output. Trusted parties:
the instance operator, fixed SBP profile configuration, approved search provider,
and OpenRouter's enforcement of ZDR. Protect ordinary/retired user data, private
files, SQL access, credentials, availability, and evidence integrity.

* Separate authentication before ordinary auth/org middleware. A workload key
  never creates a user, operator, session, or organization auth context.
* Fixed organization `org_0c8def70162d4136a6aaa1f94847090e` (`seek-best-property`),
  profile `property-local-discovery`. Check metadata only with one read-only
  SQL statement: org, model, non-super status, exact builtin search/fetch
  assignments, and zero skills/MCP/Composio assignments. No prompt or skill
  content is read. No schema change or stored-data mutation is introduced.
* Do not use AgentService execution or Cognito: those read soul, user context,
  org memory and add tools even when chat persistence is disabled.
* Execute one fixed search followed by at most one model ranking call. No
  agent-controlled tools, arbitrary URL fetches, model-written previews,
  filesystem context, SQL, history, usage writes, skills, or sessions. Ranking
  returns indices into observed search hits. `web_fetch` remains an approved
  profile assignment but is not needed or executed by v1.
* Require the resolved profile provider to be OpenRouter with `zdr: true`,
  `dataCollection: deny`, `requireParameters: true`. Send these on every inference
  call. No provider fallback or retries. Search retention is separate from ZDR.
* Public search titles/snippets can contain public PII; user queries can contain
  private PII and reach both providers. This extension is not a PII redactor.
  SBP retains its SQL `sbp_sql_agent`/`ai_public` and input privacy boundaries.
* Evidence contains only provider/tool identity and public observed URLs, never
  raw provider payloads, query, prompts, keys or exception text. Model output
  cannot manufacture a URL or change a preview. Previews remain unverified.
* Fixed body/output/provider-transfer limits, runtime, concurrency and rate
  budgets. Abort all fetches on disconnect/deadline; release admission only
  after execution settles. No detached background execution or retained state.
* Authentication hashes uniformly random 32-byte secrets (not passwords), uses
  constant-time digest comparisons, current/next slots and explicit revocation.
  Keys live outside SQLite; there are no migrations or writes to ordinary data.
  Hot-read an operator-owned bounded JSON file, atomically replace to rotate.
* Audit only generated request UUID, accepted configured key ID, result code and
  elapsed time. Do not use caller-controlled request IDs or log request bodies,
  URLs, headers, provider responses or errors.

Rejected alternatives: general org keys, operator/local/browser tokens, shared
sessions, Cognito with normal loaders, arbitrary stored/custom JS tools, full
agent loops, hosted direct-OpenAI search, model-asserted evidence, and DB schema
changes. They enlarge privileges, persistence, cost or retention risk.

Residual risks: process/host compromise bypasses in-process isolation; operators
can alter the fixed profile/provider settings; search vendors retain queries
under their own terms; ZDR is a provider guarantee, not a local redaction tool.
Global fixed-window limits assume one API process/replica, can be exhausted for
denial of service, and reset on restart. Enforce TLS, upstream request/header
limits and service-scoped egress restrictions. Do not run multiple replicas
without an external admission/rate boundary. Cancellation stops local network
work, not necessarily processing already accepted by external providers.

## HTTP contract

`POST /v1/workloads/sbp-search/runs`, `Content-Type: application/json`.
No URL query string, cookies, org/app-user scope headers or extra JSON keys.
Body: `{ "query": "property or lifestyle search" }`. Trimmed query 1–1000
Unicode scalar values (matching Python character counts), no lone surrogates;
body at most 8192 bytes. See exported Zod schemas in
`apps/server/src/workloads/sbp-contract.ts` for executable wire definitions.

Authentication: `Authorization: Bearer sbp1.<kid>.<secret>` where kid is 1–32
ASCII letters/digits/underscore/hyphen and secret is the canonical unpadded
base64url encoding of 32 random bytes (43 characters). SBP stores the entire
credential in its new `NAKAMA_WORKLOAD_TOKEN`; no legacy fallback. Never put it
in URLs. Browser/operator tokens do not authenticate here.

Success HTTP 200:

```json
{
  "version": 1,
  "profile_id": "property-local-discovery",
  "request_id": "server-generated UUID",
  "status": "ok",
  "results": [{"url":"https://example.com/listing","title":"Public title","description":"Public snippet"}],
  "evidence": [{"tool":"web_search","provider":"exa","observed_urls":["https://example.com/listing"]}]
}
```

At most four results, each URL an exact member of `observed_urls` (at most five
unique URLs). Evidence is exactly one successful search record. Wire provider
enum is `exa` or `firecrawl`; this dedicated deployment permits **Exa only**.
HTTPS only, no credentials/fragment/non-default port/literal IP/private naming
forms. URLs must pass SBP's independent public-URL policy as well. URLs max2048,
titles max240, descriptions max1600 UTF-16 units; total response max32768 UTF-8
bytes. No image field in v1. Empty real search (or no safe/relevant hits) is
HTTP 200 with empty results, not missing evidence. Malformed search/model data
fails closed. Search response transfer max256 KiB, model response max32 KiB;
one model call, max512 output tokens, no hosted tools or fallback.

Errors share version/profile/request_id and have `status: "error"`,
`error: { "code": "..." }`, with no results/evidence or exception messages:

| HTTP | code | Meaning |
| --- | --- | --- |
| 400 | invalid_request | Malformed, oversized, extra scope or unsupported body |
| 401 | unauthorized | Missing/invalid/revoked workload credential |
| 429 | busy | Rate/admission limit (`Retry-After: 60`) |
| 499 | cancelled | Disconnected request, if delivery is still possible |
| 502 | search_failed | Provider, model or evidence validation failed |
| 503 | unavailable | Disabled/malformed configuration or scope/routing drift |
| 504 | deadline | 55-second server deadline (SBP call timeout 60 seconds) |

Responses use `Cache-Control: no-store`. No retries, request deduplication,
status endpoint or session deletion. Caller cancellation closes the request;
the same signal cancels in-flight reads and fetches. Max two admitted requests
(including body reads); 120 attempts/minute globally, 20 authenticated
attempts/minute globally across both keys. Limits include unsuccessful runs.

## Operator configuration and delivery

Set `NAKAMA_SBP_WORKLOAD_KEYS_FILE` to an absolute path outside the data workspace,
readable by runtime UID 1000, not writable by that UID. No variable means disabled.
File JSON (hashes are SHA-256 of the UTF-8 43-character secret, lowercase hex):

```text
{ "version": 1,
  "current": { "id": "key-id", "sha256": "64 lowercase hexadecimal characters" },
  "next": null,
  "revoked": [] }
```

`current`/`next` may each be null; both non-null IDs must differ; `revoked` lists
up to 64 IDs and wins over either slot. Atomic file replacement takes effect on
the next request (already running work is bounded by 55 seconds; drain/restart
only this service for emergency in-flight revocation). Maximum file 16 KiB.
Generate secrets offline in the approved secret manager; store only hashes here.
To rotate: install next, change SBP's token, then revoke/remove previous current
and promote next. On revocation never reuse that key ID or secret.

Existing server configuration is read-only: fixed organization/profile, builtin
tool assignments, `[web_search]` provider/api_key/endpoint, and the profile's
OpenRouter provider/model/routing. Expected stored model is exactly
`2d2ae555-7969-4b5c-b0e7-e6edebdf3d04::openai/gpt-6-luna`; Exa endpoint must be
`https://api.exa.ai/search`. Model requests go only to
`https://openrouter.ai/api/v1/chat/completions`. Changing those constants requires
a reviewed extension rebuild; caller/config drift fails closed. No new
database migrations, settings writes or production variables beyond the key-file
path. An enabled key-file mount must be a directory read-only bind mount, not
a single-file bind mount, so atomic file replacement becomes visible inside the
container. The loader rejects symlinks, special files and group/world-writable
files. Operator must additionally enforce parent-directory and owner permissions.

Deployment is gated on independent base/hash review, focused and combined tests,
security review, built-container smoke, actual synthetic provider evidence and
real network cancellation. This orb must not deploy, publish or use production
credentials. Build and updater/rollback procedures are finalized with test
evidence in the handoff; no production success is implied by offline tests.

## Disposable cross-repository fixture

`apps/server/src/workloads/sbp-fixture.ts` runs the real auth/route/runtime with
synthetic, injected provider transports and admission metadata. It cannot make
external provider calls and is never imported by the production entrypoint.
Use Bun 1.4.2 (the Dockerfile runtime) and `bun install --frozen-lockfile --ignore-scripts`.
Generate a private disposable TLS certificate and key; do not commit or transfer
them. From the repository root:

```sh
FIXTURE_DIR=$(mktemp -d)
chmod 700 "$FIXTURE_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$FIXTURE_DIR/key.pem" -out "$FIXTURE_DIR/cert.pem"
SBP_FIXTURE_TOKEN_FILE="$FIXTURE_DIR/token" \
SBP_FIXTURE_CERT_FILE="$FIXTURE_DIR/cert.pem" \
SBP_FIXTURE_KEY_FILE="$FIXTURE_DIR/key.pem" \
SBP_FIXTURE_PORT=4431 bun apps/server/src/workloads/sbp-fixture.ts
```

The final command stays in the foreground. In an orb run it with `amp orb service
start` instead. The fixture binds loopback only. Load the token from its mode0600
file in the test process, set the SBP origin to the local HTTPS fixture, and
trust only the temporary certificate in the test client (`httpx` SSL context).
Do not add a production HTTP/TLS-verification bypass. The fixture refuses to
overwrite a token file; restart with a new file after process interruption.
Stop the service and delete the whole disposable directory after testing.

Queries: ordinary text returns two actual synthetic search hits ranked [1,0];
`fixture:empty` returns empty success; `fixture:failure` and `fixture:malformed`
return502; `fixture:slow` waits until disconnect/55s deadline. Loopback-only
`GET /fixture-state` gives active/aborted transport and completed-run counters.
Two slow calls plus a third prove429; cancel both and require active=0, then
run a fresh successful request. A 55-second slow request must yield504 and
active=0. These diagnostics do **not** exist on the production app.

## Image, pin, rollout and narrow rollback

Only the integration owner may accept/publish the reviewed feature branch;
only the source runner performs authorized production operations. No main
merge, upstream PR, `v*` tag, or existing `latest` workflow. Publishing workflow
ownership is separate and not part of this bundle. A Docker-only source build
is supported; the host does not need Bun/Node:

```sh
BASE=ce5ae048ac92c16639d5a368e128befdc07a079d
HEAD=$(git rev-parse HEAD)
git merge-base --is-ancestor "$BASE" "$HEAD"
test -z "$(git status --porcelain)"
TAG="sbp-workload-0.4.38-$(git rev-parse --short=12 HEAD)"
docker buildx build --platform linux/amd64 --load \
  --label "org.opencontainers.image.source=https://github.com/mamenesia/nakama" \
  --label "org.opencontainers.image.revision=$HEAD" \
  --label "org.opencontainers.image.version=$TAG" \
  --label "com.sbp.nakama.upstream-revision=$BASE" \
  -t "ghcr.io/mamenesia/nakama:$TAG" .
```

Use the existing Dockerfile without new build secrets. The local verification
build used `--build-arg OMNI_VERSION=` to omit optional Omni; workload execution
never invokes Omni. Record this argument in provenance and use the same argument
for the reviewed production image if that is the accepted artifact. With an
authorized registry publisher, replace `--load` with `--push --provenance=mode=max
--sbom=true`. Publish exactly the one custom tag. Record manifest-list and
linux/amd64 manifest digests, attestations, revision/source/version labels and
SBOM. Never mistake inherited Bun-base image labels for source provenance.
Package version stays upstream0.4.38; custom OCI version/tag identifies the
extension. Registry publication/attestation availability is not verified here.

Before production stop, the source runner must:

1. Verify transferred hashes/base ancestry, independently inspect the diff,
   pass combined SBP/fixture tests and security review, and execute a private
   synthetic live Exa/OpenRouter ZDR search without logging keys/query content.
2. Publish through the separately reviewed publisher, pull the **digest** on
   the deployment host, inspect labels/platform, run container smoke and prove
   ordinary API tokens and workload tokens remain disjoint.
3. Record exact existing dedicated service image digest, configuration and
   updater timer state. Observed rollback image was
   `ghcr.io/ahmadrosid/nakama:0.4.38`, digest
   `sha256:549648a4efa79143c78b81dd602a65d09624b4788abb3a869b1a2ac03a55f990`;
   recapture and verify before rollout, do not assume a mutable tag is unchanged.
4. Suspend **only** the dedicated Nakama updater timer/exclude that service.
   Do not alter host-wide updaters. Verify no update job is running before pin.
5. The backup service is currently failed (413); no verified current0.4.38
   backup exists. Stop only the dedicated service, create a fresh **private
   stopped-volume backup** of `orison-nakama-data`, verify archive/hash and a
   disposable restore/integrity drill, then proceed. Never transfer this backup
   into an Amp bundle or use the old0.4.37 archive as an automatic downgrade.
6. Add the read-only external key directory mount/path, configure SBP's new
   credential privately, and pin only this service to the reviewed custom digest
   retaining `/nakama/data` and its existing volume. Start and verify health,
   real synthetic search/evidence, wrong-key rejection, deadline/cancellation,
   no ordinary history rows and no sensitive audit/log content. No broad key
   rotation or database rewrite is required.

Rollback: stop only the dedicated service; restore the recaptured official
0.4.38 digest and pre-rollout service configuration using **the same volume**.
Remove the workload key-path env/read-only mount; revert SBP adapter activation
to its pre-rollout configuration (legacy integration may remain unavailable—do
not represent rollback as restoring the retired key API). No down migration,
volume restore, or data deletion. Start official0.4.38, verify image/digest,
`/healthz`, `/readyz`, ordinary browser/API access, SQLite integrity and sample
synthetic saved data, absence of the workload endpoint, and no unexplained
storage changes. Restore only the dedicated updater's previous enabled/waiting
state after removing the custom pin; verify its service remains inactive until
its next scheduled run. Retain the private backup under existing policy; this
extension does not redesign the failed backup service.
