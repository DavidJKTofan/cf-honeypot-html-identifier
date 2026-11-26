# AGENTS.md

This is context for coding agents and contributors working on **cf-honeypot-html-identifier**. The [README](README.md) has the product view; [ROADMAP.md](ROADMAP.md) has what's next.

## What this is

A Cloudflare Worker (TypeScript) that:
1. Seals a per-request fingerprint into a 91-character AES-GCM token and hides it in HTML with HTMLRewriter.
2. Discovers clones through a beacon script, foreign Referers and Brand Protection.
3. Investigates approved leads with a Workflow that writes evidence to R2, including a Cloudflare abuse report draft when the copy is on Cloudflare.
4. Asks a human through a pluggable notifier (Discord bot with buttons today; Slack and Telegram can use the same interface).
5. Enforces (decoy or WAF block) **only after explicit human approval**, and never against Cloudflare IP ranges.

The project is educational and defensive. Keep that framing in code, comments and docs.

## Commands

| Task | Command |
|---|---|
| Install | `npm install` (approve the `workerd`/`esbuild` install scripts if npm asks) |
| Types (after any `wrangler.jsonc` change) | `npm run types` (`wrangler types --strict-vars=false`) |
| Type check | `npm run typecheck` |
| Tests (local workerd, no network) | `npm test` |
| Local dev | `npm run dev` (needs `.dev.vars`; Analytics SQL is remote-only) |
| Deploy | `npm run deploy` (remote migrations, then `wrangler deploy`). First time: `npx wrangler deploy --secrets-file .dev.vars`, then `npm run db:migrate:remote`, then [enable D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/#enable-read-replication) |
| D1 migrations | `npm run db:migrate:local`, `npm run db:migrate:remote` |
| Admin CLI | `npm run hp -- <command>` (endpoints: `src/admin/openapi.yaml`; with Access, needs the service token in `.env`) |

## File map

Every folder has a README with setup, usage and references. Start at [`src/README.md`](src/README.md).

| Folder | Responsibility |
|---|---|
| `src/index.ts` | Router; `fetch` handler; exports both Workflow classes |
| `src/core/` | `config.ts` (typed `vars`, parsed per request), `util.ts` (crypto, bounded reads, logs) |
| `src/identity/` | `fingerprint.ts` (trusted signals), `token.ts` (seal/open, `TOKEN_KEYS` key ring), `carriers.ts` (inject/scan), `zerowidth.ts` |
| `src/honeypot/` | `trap.ts` (pending flag, decoy, tarpit, robots, hotlinks), `beacon.ts` (script and receiver → pending lead) |
| `src/storage/` | `d1.ts` (all SQL), `analytics.ts` (WAE writes, Analytics SQL reads) |
| `src/approvals/` | `actions.ts` (**the only human-approved actions**, shared by every channel), `cases.ts`, `enforce.ts` (Cloudflare-IP protection, WAF sync), `leads.ts` |
| `src/notify/` | `Notifier` interface and factory; `discord/` (REST client, messages, notifiers, Ed25519 verify, interactions endpoint) |
| `src/admin/` | `router.ts` (auth and dispatch), `access.ts` (Access JWT verification), `openapi.yaml` (**the API contract**), `routes/*` (decode, leads, cases, flags, ops), `decode.ts` |
| `src/integrations/cloudflare/` | `api.ts` (Lists, Intel, URL Scanner, Brand Protection, Abuse Reports), `ip-ranges.ts`, `abuse.ts` |
| `src/workflows/` | `investigate.ts`, `maintenance.ts`, `report.ts`, `evidence.ts` (pure helpers: live-mirror detection, ingestion wait, decision targets), `types.ts` |
| `migrations/` | `0001_init.sql`, `0002_notifications_abuse.sql`, `0003_approval_guards.sql` (one open case per host, purge index), `0004_lead_tokens.sql` (beacon token, scraper IP and re-open time on leads) |
| `public/` | Fictional demo site (Static Assets, `run_worker_first: true`; `.assetsignore` keeps READMEs out) |
| `scripts/hp.mjs` | Admin CLI |
| `DEMO.md`, `demo/` | Customer demo script; demo kit (`scrape.sh`, a clone Worker with a `/live/*` proxy, `screenshots/`). `demo/clone/site/` is gitignored (scraped tokens) |
| `test/` | `@cloudflare/vitest-plugin` tests (token, carriers, Cloudflare, Discord, routes, approvals concurrency, abuse bounds, evidence, leads, hotlinks, WAF, and end-to-end `InvestigateWorkflow` runs) |

Dependencies point inward: `admin`, `notify`, `workflows` → `approvals` → `storage`, `integrations` → `identity`, `core`.

## Public-repo hygiene

- **No account-specific identifiers in the repo.** `wrangler.jsonc` has no `account_id` (use `CLOUDFLARE_ACCOUNT_ID` in a gitignored `.env`) and no `database_id` (automatic provisioning reuses the deployed binding).
- **Runtime IDs are Worker secrets:** `ACCOUNT_ID`, `WAF_LIST_ID`, `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `DISCORD_APPLICATION_ID`, `DISCORD_PUBLIC_KEY`, `DISCORD_CHANNEL_ID`, `DISCORD_APPROVER_IDS`, `DISCORD_APPROVER_ROLE_IDS`, plus the real credentials. They're typed as optional in `src/env.d.ts`, with placeholders in `.dev.vars.example`, and uploaded with `wrangler deploy --secrets-file .dev.vars` (which uploads **everything** in that file).
- **CLI-only credentials go in `.env`**, never `.dev.vars`: the Access service token (`HP_ACCESS_CLIENT_ID`, `HP_ACCESS_CLIENT_SECRET`) must not become a Worker secret.
- **A name can't be both a var and a secret.** Never add these back to `vars`.
- **Before committing,** grep for account, zone, list and Discord IDs, real tokens (91-character strings sealed with the production key), and image metadata (strip XMP/EXIF from PNGs). Screenshots follow the redaction rules in `demo/screenshots/README.md`. The history was squashed before the repo went public, so no older commit holds these IDs.

## Invariants (do not break)

- **Approval gate.** Automated paths only ever create `pending` flags or leads. Only `src/approvals/actions.ts` may set `active`, start an investigation, send a decision or submit an abuse report. It is called from the admin API, from notifier callbacks (Discord buttons), and from the Workflow's decision event.
- **Camouflage, not secrecy.** Carriers must look like ordinary page furniture (a CSRF-style meta tag, a RUM script, a hidden link). A token's validity comes from the AES-GCM key, never from the scheme being secret, so don't add obfuscation that breaks pages or accessibility.
- **The trap is disallowed for every crawler.** The Worker must serve `/robots.txt` on every tokenized host, and `addTrapDisallow` must add the rule to every `User-agent` group (RFC 9309: a crawler with its own group ignores `*`). Never put `TRAP_PATH` in a sitemap.
- **Approvals are atomic.** Every human action claims its row with a conditional `UPDATE … WHERE status = …` and checks `meta.changes` before doing anything else (lead `pending → approved`, case `awaiting_decision → applying`, `abuse_report IS NULL → submitting`, lead `token IS NULL →` first beacon token). A partial unique index allows one open case per host. The Workflow's own status writes are conditional too (`setCaseStatusIf`): expiry only from `awaiting_decision`, and if a late click already claimed the case, a second `waitForEvent` picks up its buffered event and applies it; close only from `applying` (or `awaiting_decision`). Never replace a claim with read-then-write.
- **Cloudflare IP ranges are protected.** Never flag, decoy or WAF-list an address from <https://api.cloudflare.com/client/v4/ips> (`enforce.ts` throws `ProtectedIpError`). The live list is unioned with the bundled snapshot, so a partial answer can never drop a range. Abuse from Cloudflare (Workers: `CF-Worker` header) is handled with an abuse report.
- **Verified bots are never enforced on.** The token's `verifiedBot` bit comes from `request.cf.botManagement.verifiedBot` or `request.cf.verifiedBotCategory` (Workers can't read `cf.client.bot`). The trap skips verified bots, `decisionTargets()` skips them (`skippedVerifiedBotIps`), and `index.ts` never decoys or 403s one. Without Bot Management the Worker can't see either signal (which is why the README lists Bot Management as **required**), so the WAF block rule must add `not cf.client.bot`. Details: `src/approvals/README.md#verified-bots`.
- **No runaway Workflows.** Keep one open case per host, `concurrency.limit` 5, notifications once per lead, plus at most one beacon corroboration and a re-scrape re-open per 24 h (`NOTIFY_LIMITER`), and a daily flag digest instead of per-flag messages.
- **Admin auth.** With `ACCESS_TEAM_DOMAIN` + `ACCESS_AUD` set, only a verified Cloudflare Access JWT authenticates `ADMIN_PREFIX` (bearer ignored; actor = Access identity). Without them, the bearer token. Unauthenticated → plain `404`. Only `ADMIN_PREFIX` sits behind Access; the beacon, trap and Discord endpoint stay public. Setup: `src/admin/README.md#cloudflare-access`.
- **The OpenAPI spec is the admin contract.** Add or change a route → update `src/admin/openapi.yaml` (and the endpoint table in [README, Admin API and CLI](README.md#admin-api-and-cli)); `test/openapi.test.ts` fails if a documented operation isn't routed.
- **Notifier callbacks must verify signatures** (Discord: Ed25519 with ±5 min skew), check an **approver allowlist**, ACK within the platform deadline, and render untrusted values as inline code with mentions disabled.
- **Tokens stay 91 characters, and old tokens keep decoding.** Every token version seals to `SEALED_LENGTH` (68) bytes; carriers, `scanHtml`, the beacon's regex and the zero-width carrier depend on it (`test/token.test.ts` checks). Version 1 tokens decode with `TOKEN_KEY`, then `TOKEN_KEY_PREVIOUS`; version 2 with the `TOKEN_KEYS` entry its header names. The highest ring ID seals. A malformed ring entry is logged and skipped, never fatal, and never logged with key material. Retired-key tokens are logged as `token_retired_key`.
- **Abuse reports are drafted, never auto-submitted.** Drafts contain no personal data and never pre-fill `agree` or `signature` (`buildSubmission` adds them at submission); submission needs `ABUSE_REPORTS="submit"`, `ABUSE_REPORTER_JSON` and a human click. **Beacon-only evidence never gets a draft**: a draft claims the captured page contains our identifier, and a beacon report can be forged.
- **Beacon-reported tokens are unconfirmed evidence.** When the capture holds no token, the Workflow may use the lead's beacon token (`source: "beacon"`, `beaconOnly`), and the report, Discord message and `report.json` must say "unconfirmed". Never present it as proof the page contains the token.
- **Hotlinks are subresource loads only** (`Sec-Fetch-Dest` ≠ `document`/`iframe`). A link click from another site is normal traffic, not a clone signal.
- **Never shadow a site's own fields.** If `<meta name=META_NAME>` already exists (for example a real Rails or Laravel CSRF token), the identifier goes to `<meta name="request-id">`. If a form already has a `FORM_FIELD` control (Spring Security and Express csurf use `_csrf`), the `form` carrier uses `request_id`.
- **No per-request DB writes.** Per-request data goes into the token and WAE. D1 writes must stay deduplicated and rate-limited.
- **Trusted IP only.** Use `CF-Connecting-IP`. Never read `X-Forwarded-For` or `True-Client-IP` from the client.
- **Clone-visitor privacy (beacon and hotlinks).** Beacon requests and hotlinked asset loads come from a clone's *visitor*. Never store anything that identifies them: IP, JA3/JA4, User-Agent, city, ASN and AS organization, RTT, detection IDs, `CF-Worker`, Accept-Language, or their Ray ID (it pivots to logs that hold the IP). Both paths go through `scrubVisitorSignals()`. What a lead stores (`leads.token`, `leads.token_ip`) is the *scraper's* token and the IP inside it, never the beacon sender's.
- **The capture must not identify itself.** `fetchPage` sends ordinary browser headers with `CAPTURE_USER_AGENT` (default: a desktop Chrome UA). Never reintroduce a self-identifying UA: clones cloak by UA. (`CF-Worker` and Cloudflare's ASN can't be hidden from a Worker fetch; see ROADMAP B4.)
- **The scanner decodes before it matches.** `scanHtml` entity-decodes (`decodeCharRefs`) and trims attribute values: lol-html returns them raw, while browsers and the beacon decode them.
- **A downgraded block leaves the WAF list.** When an approval turns an active block into a decoy (manual flag or case decision), its list item is removed (`downgradedBlockIp`), or the edge keeps blocking the IP. Reconcile is the daily backstop, and removes orphans only when its D1 read of active blocks wasn't capped.
- **Bounded public writes.** Beacon leads are limited per clone host and per token (`BEACON_LIMITER`, charged only after the token opens; invalid reports use their own `beacon-invalid:<host>` key) and globally (`LEAD_LIMITER`); trap flags per IP (`TRAP_LIMITER`) and globally (`TRAP_GLOBAL_LIMITER`). Keep a global bound on every public path that writes to D1.
- **Quota-consuming calls** (Intel, URL Scanner) run only after approval *and* a valid token.
- **No tracker headers.** Never emit `X-Tracker-*` or similar headers. Rewritten HTML gets `Cache-Control: private, no-cache` and no `ETag`.
- **Evidence capture never fails on size or token count.** `fetchPage` keeps the first 2 MiB and sets `truncated`; the SHA-256 covers exactly the captured bytes. A case keeps at most `MAX_CASE_TOKENS` valid tokens (earliest plus newest; `omittedTokens` counts the rest), because a step result is capped at 1 MiB. Every candidate is still decoded: never cap candidates in document order, or junk values could hide the real token.
- **Workers best practices:**
  - no module-level mutable state; HTMLRewriter handler state is created per call
  - no floating promises (`await`, `return`, or `ctx.waitUntil`)
  - streaming bodies, with size caps when reading
  - Web Crypto for randomness; constant-time secret compares
  - structured JSON logs
  - no `passThroughOnException`; reads fail open explicitly in the `fetch` catch

## Data sources

**Sealed in the token** (`src/identity/token.ts` layout; [format and rotation](src/identity/README.md#key-rotation)):

| Field | Source |
|---|---|
| Version, key ID | Version 2 only: a 2-byte header (version `2`, `TOKEN_KEYS` ID 0–255), readable without a key (masked with the IV) and authenticated. Version 1 (`TOKEN_KEY`, no ring) has no key ID |
| IP | `CF-Connecting-IP` header |
| Ray ID | `cf-ray` header (first 16 hex characters) |
| ASN, country, colo | `request.cf.asn`, `request.cf.country`, `request.cf.colo` |
| Bot score, verified bot, JS detection | `request.cf.botManagement.{score, verifiedBot, jsDetection.passed}` (Enterprise Bot Management only, otherwise null) |
| issuedAt | Worker clock (unix seconds) |

Every version seals to 68 bytes (91 base64url characters). Version 2 packs country and colo into 4 bytes to make room for the header.

**Written to Workers Analytics Engine**, dataset `honeypot_events`:

| Column | Meaning |
|---|---|
| `index1` | Ray ID (page, decoy, trap events) or foreign host (hotlink, beacon events) |
| `blob1` | event type: page, decoy, trap, hotlink, beacon, beacon_invalid |
| `blob2`–`blob4` | host, path, ip |
| `blob5`–`blob7` | User-Agent, JA4, JA3 |
| `blob8`–`blob11` | asOrganization, country, colo, city |
| `blob12`–`blob15` | httpProtocol, tlsVersion, referer, accept-language |
| `blob16`–`blob18` | detectionIds, verifiedBotCategory, rayId |
| `blob19`–`blob20` | foreign host; note, or the `CF-Worker` zone for page, decoy and trap events (the token Ray for `beacon` events) |
| `double1`–`double4` | botScore (−1 = n/a), asn, issuedAt, clientTcpRtt (−1 = n/a) |

- The JA4, JA3 and detection-ID values come from `request.cf.botManagement.*`.
- Query from the Worker with `env.ANALYTICS_SQL.query()` against `events.analyticsEngine.honeypot_events`. Don't add an `accountTag` predicate; the binding scopes the query itself. Always include a lower `timestamp` bound.
- Externally, use `POST /accounts/{id}/analytics_engine/sql` (`FROM honeypot_events`) or `/accounts/{id}/analytics/sql` (`events.analyticsEngine.honeypot_events` plus `accountTag`), with an `Account Analytics Read` token.

## Storage choices

| Need | Product | Why |
|---|---|---|
| Per-request attribution | The token itself | Zero storage, never expires, tamper-evident |
| Per-request detail (User-Agent, JA4, path) | Workers Analytics Engine | Non-blocking writes, cheap at high volume, 3-month retention. Each Ray ID is its own index, so rows aren't sampled away |
| Flags, leads, cases | D1 (read replication must be enabled per database; it's off by default) | Small relational tables. One indexed read per HTML request through a nearby replica |
| Evidence (snapshots, screenshots, reports) | R2 | Object storage with no egress fees |
| Multi-step investigation with human wait | Workflows | Durable steps with retries; `waitForEvent` for up to 365 days |
| Public endpoint write bounds | Rate Limiting binding (`BEACON_LIMITER`, `LEAD_LIMITER`, `TRAP_LIMITER`, `TRAP_GLOBAL_LIMITER`, `NOTIFY_LIMITER`) | Per-location counters with no storage |
| Edge blocking of approved IPs | WAF IP List and a custom rule | Enforced before the Worker runs, so blocked requests cost no Worker CPU |

## External APIs (`CF_API_TOKEN`, optional)

| Need | Endpoint | Permission |
|---|---|---|
| WAF List items | `/accounts/{id}/rules/lists/{list_id}/items` (POST, GET with `search` or `cursor`/`per_page` ≤ 500, DELETE) | Account Filter Lists Edit |
| WAF List bulk operation | `/accounts/{id}/rules/lists/bulk_operations/{operation_id}` (`pending`, `running`, `completed`, `failed`) | Account Filter Lists Edit |
| Threat Intel | `/accounts/{id}/intel/{domain,whois,ip}` | Intel Read |
| URL Scanner | `/accounts/{id}/urlscanner/v2/{scan,result/{id},screenshots/{id}.png}` | URL Scanner Edit |
| Brand Protection | `/accounts/{id}/brand-protection/{queries,matches,logos,logo-matches}` | Intel Read |
| Abuse Reports (submit) | `POST /accounts/{id}/abuse-reports/{report_param}` (`report_param` = the report type, same as `act`) | Trust and Safety Write (plus the account entitlement) |
| Cloudflare IP ranges | `GET https://api.cloudflare.com/client/v4/ips` (public; edge-cached 24 h; snapshot fallback) | none |
| DNS-over-HTTPS | `https://cloudflare-dns.com/dns-query?name=…&type=A` (`accept: application/dns-json`) | none |
| Discord | `POST /channels/{id}/messages` (`Bot` token), `PATCH /webhooks/{app}/{token}/messages/@original` | bot token (`DISCORD_BOT_TOKEN`) |

Intel and Brand Protection share the monthly Intel quota (2,500 calls on Enterprise).

## Gotchas found while building

- **WAF managed rules may block raw pasted HTML** (full of `<script>` markup) in admin JSON bodies. Send `html_b64` instead.
- **Analytics Engine ingestion lags** by up to about a minute. Maintenance aggregation can miss very recent hotlinks; the next run picks them up. A live reverse proxy mints its token during the investigator's own capture, so the Workflow sleeps 90 s before enrichment when a token is under 2 minutes old (`needsIngestionWait`).
- **HTMLRewriter returns attribute values raw** (`&#100;` stays `&#100;`), unlike a browser. Decode before matching (`decodeCharRefs`), or a one-character entity hides a token from the investigator but not from the beacon.
- **HTMLRewriter calls `onEndTag` only for a literal end tag.** HTML lets pages omit `</head>` (minifiers do), and lol-html builds no tree, so an implied end tag never fires. Anything inserted at `</head>` needs a fallback (`injectCarriers` uses `<body>`, then the document end).
- **Workflow tests: `mockStepResult(step, null)` still runs the real step.** Mock a void step with any non-null value to skip it (`test/investigate.test.ts`).
- **Zone WAF rules see admin and beacon traffic.** An attack-score rule challenged `POST /__hp/decode` even with `html_b64` (`cf-mitigated: challenge`; the CLI reports it). A "pretend browser" rule matches every beacon (`sendBeacon` from a clone visitor's browser): keep such rules at *Log*, or exclude `BEACON_PATH`.
- **The deployed Worker can drift from `main`.** The live test found the demo three commits behind, with a migration unapplied. Check `npx wrangler deployments list` and `npx wrangler d1 migrations list DB --remote` before testing live.
- **Analytics SQL has no local implementation.** Tests set `remoteBindings: false`, and enrichment errors are caught; a noisy "needs to be run remotely" log in tests is expected.
- **`secrets.required` limits local secrets.** Only the listed secrets load from `.dev.vars`, so the optional `CF_API_TOKEN` must be set remotely with `wrangler secret put`.
- **The custom domain bypasses nothing.** `workers_dev: false` and `preview_urls: false` mean the zone's WAF and Bot Management always run first.
- **Brand Protection is noisy.** One fuzzy string query can have hundreds of matches. Intake only takes matches first seen in the last 2 days, capped at 25 per run.
- **URL Scanner v2 returns bare JSON.** Its own `result` field is the report URL, so `cfapi.ts` must not unwrap it as a `{ success, result }` envelope (`bare: true`).
- **Threat Intel omits WHOIS for subdomains.** The Workflow retries on parent domains (at most 3 lookups). `*.workers.dev` hosts return no WHOIS record at all.
- **Integration steps are best-effort.** URL Scanner and Intel failures are written into the report as `skipped: …` instead of failing the case.
- **Discord can't send buttons through plain channel webhooks**, so interactive approvals need the bot plus the Interactions Endpoint. `discord-webhook` mode is notify-only.
- **Discord probes the interactions endpoint with invalid signatures.** The endpoint must answer `401` or Discord removes the URL. If a zone rule challenges Discord's requests, endpoint setup fails; add a narrow skip rule for that path (see `src/notify/discord/README.md`).
- **The Cloudflare IP range fetch has no network in tests.** It times out after 1.5 s and falls back to the bundled snapshot.
- **Lists API writes are asynchronous.** A new item write sent while an earlier one is still processing gets `429` ([docs](https://developers.cloudflare.com/waf/tools/lists/lists-api/#rate-limiting-for-lists-api-requests)). Batch all IPs into one write, retry `429`, and poll the bulk operation (`CfApi.waitForListOperation`).
- **Rate Limiting binding `period` is 10 or 60 seconds**, and counters are per Cloudflare location ([docs](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)). `namespace_id` is an account-unique integer string.
- **D1 read replication is opt-in** per database. Automatic provisioning doesn't enable it; see [README, Test and deploy](README.md#test-and-deploy).
- **Agent worktrees live under `.claude/worktrees/`.** `vitest.config.ts` only collects `test/**/*.test.ts`, and `.gitignore` excludes that folder. A `node_modules` symlink in a worktree isn't matched by `node_modules/`, so leave it out of patches.
- **Benign foreign hosts render your pages too:** Google Translate (`*.translate.goog`), the Wayback Machine (`archive.org`), archive.today (`archive.ph`) and Google cache. These are built-in ignores.
- **Cloudflare's JavaScript Detections snippet leaks the Ray ID in clear text** (`window.__CF$cv$params={r:'<ray>',t:…}`) into every page on a zone with Bot Management, so it travels into copies too. It changes per request, which makes a diff of two fetches reveal more than our token. It is also an unauthenticated secondary identifier (ROADMAP B15). `Cache-Control: no-transform` from the origin stops the injection.

## Cloudflare documentation

- Workers: [Best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/) · [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/) · [Request / `request.cf`](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties) · [Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/) · [Static Assets `run_worker_first`](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/) · [Secrets](https://developers.cloudflare.com/workers/configuration/secrets/) · [Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) · [Storage options](https://developers.cloudflare.com/workers/platform/storage-options/) · [Custom domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/) · [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/) · [Vitest integration](https://developers.cloudflare.com/workers/testing/vitest-integration/)
- Bots and security: [Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/) · [Bot Management subscription](https://developers.cloudflare.com/bots/plans/bm-subscription/) · [JA3/JA4 fingerprints](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/) · [AI Crawl Control with WAF](https://developers.cloudflare.com/ai-crawl-control/configuration/ai-crawl-control-with-waf/) · [Rate limiting best practices](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/) · [WAF Lists](https://developers.cloudflare.com/waf/tools/lists/) · [Lists API](https://developers.cloudflare.com/waf/tools/lists/lists-api/)
- Data: [Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/) ([limits](https://developers.cloudflare.com/analytics/analytics-engine/limits/), [sampling](https://developers.cloudflare.com/analytics/analytics-engine/sampling/), [pricing](https://developers.cloudflare.com/analytics/analytics-engine/pricing/)) · [Analytics SQL Workers binding](https://developers.cloudflare.com/analytics/sql-api/workers-binding/) · [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) · [D1 limits](https://developers.cloudflare.com/d1/platform/limits/) · [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/) · [R2](https://developers.cloudflare.com/r2/)
- Orchestration: [Workflows](https://developers.cloudflare.com/workflows/) · [Events and `waitForEvent`](https://developers.cloudflare.com/workflows/build/events-and-parameters/) · [Scheduled Workflows](https://developers.cloudflare.com/workflows/build/trigger-workflows/)
- Discord: [Bots overview](https://docs.discord.com/developers/bots/overview) · [Receiving and responding to interactions](https://docs.discord.com/developers/interactions/receiving-and-responding) · [Message components](https://docs.discord.com/developers/components/reference) · [Rate limits](https://docs.discord.com/developers/topics/rate-limits)
- Abuse: [Report abuse](https://developers.cloudflare.com/fundamentals/reference/report-abuse/) · [Submit a report](https://developers.cloudflare.com/fundamentals/reference/report-abuse/submit-report/) · [Abuse Reports API](https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/) · [Cloudflare IP ranges](https://www.cloudflare.com/ips/)
- Security Center: [Brand Protection](https://developers.cloudflare.com/security-center/brand-protection/) · [Threat Intel APIs](https://developers.cloudflare.com/security-center/intel-apis/) ([limits](https://developers.cloudflare.com/security-center/intel-apis/limits/)) · [URL Scanner](https://developers.cloudflare.com/radar/investigate/url-scanner/)
