# Roadmap

This file has these parts:
- **[What's next](#whats-next-2026-11-27)**: the priority order, in one list
- **[Third review (2026-11-27)](#third-review-2026-11-27)**: three bugs fixed, and six open findings with a fix for each
- **[Enterprise readiness review (2026-11-27)](#enterprise-readiness-review-2026-11-27)**: whether this scales to high-traffic Enterprise sites (token key rotation included), and what has to be built first
- **[Second code review (2026-11-25)](#second-code-review-2026-11-25)**: bugs found in a second full review, all fixed, plus the open items from the first review that were closed with them (and the [follow-up of 2026-11-26](#follow-up-2026-11-26))
- **[Code review findings (2026-11-24)](#code-review-findings-2026-11-24)**: every finding from the full code review, what was fixed, and a concrete fix for what is still open, so a later session can pick it up
- **[Live test findings and scraper bypasses (2026-11-25)](#live-test-findings-and-scraper-bypasses-2026-11-25)**: what a live end-to-end test against the demo found, how a scraper would bypass the identifier, what was fixed, and designs for the rest
- a **[production-readiness review](#production-readiness-review)**: what to check carefully before running this at scale
- **[ideas for future development](#ideas)**, roughly in priority order

Nothing under "Ideas" is built yet.

## What's next (2026-11-27)

1. ✅ **C1–C3**, fixed in this review: an origin's `no-store` is kept, HEAD and 304 responses mint no token, and the expired-flag purge keeps up with a large crawl.
2. **Scale blockers for large sites:** [E3](#e3-take-d1-off-the-hot-path) (no D1 read per request) and [E6](#e6-trap-flags-from-analytics-engine-not-d1) (no D1 write per trap hit).
3. **Key volume:** [E1](#e1-volume-free-sealing-token-version-3) (token version 3 with per-day subkeys) and [E2](#e2-staged-key-promotion) (staged key promotion).
4. **Cost and operations:** [E5](#e5-invoke-the-worker-for-html-only) (Worker on HTML only) and [E4](#e4-split-the-edge-worker-from-the-control-plane) (separate edge and control Workers).
5. **Open findings C4–C9** below.
6. **Earlier open items:** [B11](#live-test-findings-and-scraper-bypasses-2026-11-25) IPv6 `/64` flags, B4 Browser Run capture, B5 a second discovery channel, risk-scored enforcement, the audit log, and an `env.staging` (L13).

## Third review (2026-11-27)

A third review read the request path, the token, maintenance, investigation and enforcement again. It checked them against the [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), the [D1 limits](https://developers.cloudflare.com/d1/platform/limits/), the [Workflows limits](https://developers.cloudflare.com/workflows/reference/limits/), [concurrency limits](https://developers.cloudflare.com/workflows/build/concurrency-limits/) and [schedules](https://developers.cloudflare.com/workflows/build/trigger-workflows/) (all three as configured), and the [Secrets Store](https://developers.cloudflare.com/secrets-store/manage-secrets/) and [Workers](https://developers.cloudflare.com/workers/platform/limits/) limits. Each fix has a test that fails without it.

| ID | Sev | Finding | Fix | Status |
|---|---|---|---|---|
| C1 | M | `injectCarriers` replaced every `Cache-Control` with `private, no-cache`. An account or banking page sent with `no-store` became storable in the browser's disk cache | `privateHtmlHeaders()` keeps an origin's `no-store` (`private, no-store`); everything else gets `private, no-cache`, with no `ETag` | ✅ |
| C2 | L | HEAD, 204 and 304 HTML responses sealed a token nobody sees and wrote a `page` row to Analytics Engine. Uptime monitors send HEAD all day | They get the same private headers as the GET, with no token and no event | ✅ |
| C3 | M | Maintenance read at most 1,000 expired flags of any status per daily run. A distributed trap crawl can add 30 pending flags a minute per location (`TRAP_GLOBAL_LIMITER`), so the backlog and the table grew without bound (D1's 10 GB limit, `COUNT(*)` scans in the digest) | Only active IP blocks (which have a list item) go through the WAF removal. Every other expired row is deleted in steps of 1,000 rows (`deleteStaleExpiredFlags`), up to 100,000 per run | ✅ |
| C4 | M | Expired-block removal looks up each IP with its own `findListItem` call: up to 1,000 calls in a row per run, against the [API rate limit](https://developers.cloudflare.com/fundamentals/api/reference/limits/) | Read the list once with `listItemsPage` (as reconcile does) and match IPs locally | ⬜ |
| C5 | L | Reconcile reads at most 10 pages (5,000 items). Enterprise accounts hold up to 500,000 list items, so in a shared list, orphans on later pages are never removed | A dedicated list for this Worker (documented), or a cursor carried across runs | ⬜ |
| C6 | L | With [Pseudo IPv4](https://developers.cloudflare.com/network/pseudo-ipv4/) set to *Overwrite Headers*, `CF-Connecting-IP` holds a Class E address (`240.0.0.0/4`) and the real one is in `CF-Connecting-IPv6`. If the Worker sees the overwritten value (to verify on a test zone), tokens, flags and list items name the pseudo address and never match `ip.src` | Use `CF-Connecting-IPv6` only when `CF-Connecting-IP` is in `240.0.0.0/4`, with a test | ⬜ |
| C7 | L | A rotation takes effect at once: the new highest ID seals immediately. During a [gradual deployment](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/), or with several Workers sharing a ring, a version that still holds the old ring can't open the new tokens, and the beacon drops them as invalid | [E2](#e2-staged-key-promotion). Until then: rotate only at 100% deployment (the runbook says so) | ⬜ |
| C8 | L | If `TOKEN_KEYS_STORE.get()` fails and `TOKEN_KEYS` is stale, pages are sealed with an older ID, and decode can't open the newer tokens during the outage | Documented: leave `TOKEN_KEYS` unset when you use the store, or keep both in sync | ⬜ (docs ✅) |
| C9 | L | The sealing key loads only after the origin response arrives: the ring JSON is parsed, every entry decoded, one key imported, plus a Secrets Store `get()`. That puts it on the time to first byte of every page | Start `loadSealingKey` in parallel with the upstream fetch, and measure `get()` latency (E10) | ⬜ |

Doc corrections made with this review:
- The README said static assets "skip all of it". The honeypot logic is skipped, but on a `/*` route the Worker is still invoked (and billed) for every asset: see [E5](#e5-invoke-the-worker-for-html-only).
- "Deterministic per-visitor tokens" (Ideas) *reduce* the random-IV volume limit (fewer distinct messages per key); they don't remove it.

## Enterprise readiness review (2026-11-27)

**Short answer.** The design works for Enterprise customers (it needs [Bot Management](https://developers.cloudflare.com/bots/plans/bm-subscription/) anyway), and it runs today for sites up to about **10–50 million tokenized HTML responses a day**: enable [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/), protect the admin API with Access, and rotate the key ring monthly. It is **not ready for the largest sites** (about 100 million HTML responses a day and up, or many zones). Four things block them, in this order:
1. **A D1 read on every HTML request.** Each D1 instance runs one query at a time, so a 1 ms query allows at most 1,000 queries a second, and read replication adds one replica per region (about six). Past that, D1 answers "overloaded". The lookup fails open, so decoys silently stop and POSTs slow down. Fix: [E3](#e3-take-d1-off-the-hot-path).
2. **Trap writes that grow with the attacker's IP count.** The global trap limit is per location, so a crawl from residential proxies in every region can still write about 30 rows a minute in each of 300+ locations. Fix: [E6](#e6-trap-flags-from-analytics-engine-not-d1) (and C3, done).
3. **Key volume.** At a billion pages a day, one key lasts four days. Rotation is manual, there are only 256 key IDs, and a Worker secret holds 95. Fix: [E1](#e1-volume-free-sealing-token-version-3) and [E2](#e2-staged-key-promotion).
4. **The Worker runs on every asset request**, which bills requests that never need it. Fix: [E5](#e5-invoke-the-worker-for-html-only).

### Key volume by traffic

AES-GCM with random 96-bit IVs should seal at most 2³² (about 4.3 billion) tokens per key ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), section 8.3). Count every token sealed with a key: pages for people and bots, decoys and trap hits, and every Worker or environment that shares the key. Give each environment and each Worker its own keys.

| HTML responses a day | One key lasts | Rotate | 256 key IDs last | A Worker secret (about 95 IDs) lasts |
|---|---|---|---|---|
| 1 million | 11.8 years | yearly, as hygiene | centuries | centuries |
| 10 million | 1.2 years | quarterly | more than 60 years | 24 years |
| 100 million | 43 days | monthly (only 1.4× margin; every two weeks above about 70 million) | 21 years | 8 years |
| 1 billion | 4.3 days | every 2 days | about 1.4 years | about 6 months |

At 100 million a day, version 2 works with a monthly rotation done by hand. At a billion, it doesn't: someone would have to rotate every two days, every rotation through a Worker secret is a new deployment, and the IDs run out. Scheduled rotation through the Secrets Store API is no answer either. The Worker would need write credentials for its own keys, and Cloudflare can't show a secret again, so the operator's backup of the ring would be out of date after every automatic rotation. E1 removes the problem instead.

### E1. Volume-free sealing (token version 3)

Derive a subkey per UTC day from each ring key, so a ring key never seals more than one day of tokens directly:

```
subkey = HKDF-SHA256(ikm = ring key, salt = "cf-honeypot-html-identifier/v3", info = day as uint16)
```

Layout, still 68 bytes (91 characters), so carriers, `scanHtml`, the beacon's pattern and the zero-width carrier don't change:

| Bytes | Field |
|---|---|
| 0–1 | version (`3`) and ring key ID, XORed with IV bytes 0–1 (as in version 2) |
| 2–13 | IV (12 random bytes) |
| 14–15 | day number (days since 2026-01-01 UTC, uint16: 179 years), XORed with IV bytes 2–3 |
| 16–51 | ciphertext of the 36-byte payload |
| 52–67 | GCM tag |

The payload is 36 bytes: seconds of the day (17 bits) and bot score (7 bits) in 3 bytes; IP (16); ASN (4); country and colo (30 bits) plus `verifiedBot` and `jsDetection` in 4 bytes; a flags byte (Bot Management present, 7 spare bits); Ray ID (8). The additional data is a version 3 label (`cf-honeypot-html-identifier/v3`) plus the unmasked header (version, key ID, day), so none of it can be altered.

- **Ceiling:** 2³² tokens a day per ring key (about 50,000 a second, sustained). Beyond that, give each Worker or zone its own ring key.
- **Rotation:** ring IDs change only as hygiene (yearly) or after a leak, so 256 IDs last centuries, the backup stays simple, and no automation is needed. This replaces the "Key rotation automation" idea; the retired-key alert stays useful.
- **Cost:** one HKDF derivation per seal and per open ([Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/) supports HKDF), cached for the request or step.
- **Trade-off:** anyone who knows the scheme can read the day a token was issued, just as they can read the key ID. That is camouflage, not secrecy.
- **Rollout:** opt-in with a `TOKEN_VERSION` var at first. Versions 1 and 2 keep decoding. Tests: the 68-byte length, the day boundary, cross-decoding of versions 1–3, and the fallback when a token only looks like a version 3 header.

### E2. Staged key promotion

Let a key be distributed before it seals. Accept `{"seal": 3, "keys": {"3": "…", "2": "…"}}` alongside today's plain format (where the highest ID seals). Roll the new key out to every version and Worker, then promote it. Add a grace window to the `token_retired_key` check, so tokens issued within a few minutes of a promotion aren't reported. Needed for [gradual deployments](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/), for E4, and to close C7.

### E3. Take D1 off the hot path

This turns M7 from an optimization into a blocker; see the D1 [throughput guidance](https://developers.cloudflare.com/d1/platform/limits/).
- **Design:** decoy IPs go into a second [WAF IP list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/), maintained like the block list (one bulk write per decision, reconcile). A [request header transform rule](https://developers.cloudflare.com/rules/transform/request-header-modification/) first removes any client-sent `x-hp-decoy` header, then sets it when `ip.src in $honeypot_decoy`. The Worker then needs no storage read at all. Check that your plan allows lists in that rule phase (they are not allowed in response header rules).
- **JA4 decoys** are rare: put them in a rule expression through the Rulesets API, or keep the D1 lookup for requests that carry a JA4 flagged in the last minute.
- **Fallback design:** a per-location [Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/) bit for "no active decoy flags" (30–60 s TTL), so most requests skip D1.

### E4. Split the edge Worker from the control plane

A lean **edge Worker** on the site route seals, injects and checks decoys, with low log sampling and [gradual deployments](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/). A **control Worker** takes the more specific routes (`ADMIN_PREFIX`, the beacon, the Discord endpoint) and runs the Workflows, with full logging. Why: [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/) caps an account at 5 billion logs a day and then samples 1%. Head sampling on a high-traffic Worker would also drop rare events such as `token_retired_key` and trap hits. The split also separates CPU limits, deploy cadence and blast radius. It needs E2, because both Workers must share keys.

### E5. Invoke the Worker for HTML only

On a `/*` route, every image, script and stylesheet invokes (and bills) the Worker, even though the honeypot logic skips it. Add [routes with no Worker](https://developers.cloudflare.com/workers/configuration/routing/routes/) for asset path prefixes (route patterns can't match extensions, so this needs asset paths such as `/static/*`). Hotlink detection then moves to maintenance: query [GraphQL Analytics](https://developers.cloudflare.com/analytics/graphql-api/) `httpRequestsAdaptiveGroups` grouped by `clientRefererHost` for asset requests, instead of a Worker event per asset.

### E6. Trap flags from Analytics Engine, not D1

Every trap hit already writes a `trap` event to Analytics Engine. Drop the D1 write from the public path. Instead, an hourly maintenance step promotes the top trap IPs from Analytics Engine (most hits, most paths, lowest bot score) to pending flags. Approvals arrive as a daily digest anyway, so nothing is lost, and the last public D1 write that grows with the attacker's IP count goes away.

### E7. Several zones and hosts

- `CANONICAL_HOSTS` with suffix matching (`.example.com`), and per-host configuration (carriers, trap path, meta name). This is the "Multi-site" idea under Ideas.
- An account-level [WAF custom ruleset](https://developers.cloudflare.com/waf/account/custom-rulesets/) for the block rule, so every zone enforces the list.

### E8. Data residency and retention

- Workflows can now be pinned to a [jurisdiction](https://developers.cloudflare.com/workflows/reference/data-location/) (`eu`, `us`, `fedramp`; fixed when the Workflow is created). D1 and R2 have jurisdictions too, and Workers Logs follow the account's [Customer Metadata Boundary](https://developers.cloudflare.com/data-localization/metadata-boundary/).
- Confirm where Analytics Engine stores data. If it can't be localized, store less per page (data minimization under Ideas).
- Set `default_retention` on both Workflows (now a [Wrangler setting](https://developers.cloudflare.com/workers/wrangler/configuration/#workflows)), and add [R2 lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) with [bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/) for evidence that must be kept.

### E9. Enterprise operations

These are under Ideas already; for Enterprise they come first: an `env.staging` (L13), Terraform for the lists, rules, Access and Secrets Store, an audit log exported through [Logpush](https://developers.cloudflare.com/logs/logpush/) to the customer's SIEM, an Access-protected approval UI, Slack or Teams adapters, and a two-person rule for blocks and abuse reports.

### E10. Load test, service levels and a cost model

- Measure HTMLRewriter CPU on 1–2 MB pages, the added p99 time to first byte, D1 latency and Secrets Store `get()` latency. Publish the numbers in the README.
- A cost model from current pricing pages, for example: [Workers](https://developers.cloudflare.com/workers/platform/pricing/) requests cost $0.30 per million over the included amount, and [Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/pricing/) data points $0.25 per million (not billed yet). Enterprise contracts differ.
- The levers are selective tokenization, data minimization (both under Ideas) and E5.

## Second code review (2026-11-25)

A second full review of `src/` against the [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), the [Workflows limits](https://developers.cloudflare.com/workflows/reference/limits/) and [events](https://developers.cloudflare.com/workflows/build/events-and-parameters/), the [Analytics SQL binding](https://developers.cloudflare.com/analytics/sql-api/workers-binding/) and [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/). Each fix has a test that fails without it (`test/investigate.test.ts` is new and drives `InvestigateWorkflow` end to end, which starts on L14).

| ID | Sev | Finding | Fix | Status |
|---|---|---|---|---|
| N1 | M | A capture's valid tokens were unbounded. A step result is capped at 1 MiB (about 3,000 tokens), so a clone stuffed with genuine tokens (one page load each) made every investigation of it fail, and one decision could create thousands of flags | `capCaseTokens`: at most `MAX_CASE_TOKENS` (50) per case, the earliest fetches plus the 5 newest (a live proxy's own fetch); `omittedTokens` in the report. Candidates are still all decoded, so junk values can't hide the real token | ✅ |
| N2 | L-M | A lead approval's override URL could name another host, and the Workflow then used that lead's beacon token as "unconfirmed" evidence against it | The override must stay on the lead's host; the beacon fallback also checks `lead.host === host` | ✅ |
| N3 | L | `ttlDays` between 0 and 1 floored to 0: the flag expired at once (a block sat in the WAF list until maintenance) | `ttlFrom` and `parseDecision` round up to at least 1 day | ✅ |
| N4 | L | The meta token was lost on pages with `<head>` but no `</head>` (valid, common when minified): lol-html never fires `onEndTag` for an implied end tag, and the fallbacks thought the tag was placed | Separate "head seen" and "tag placed" state; `<body>`, then the document end, insert it once | ✅ |
| N5 | L | `206` partial HTML responses were rewritten, corrupting the byte range | `206` passes through untouched | ✅ |
| N6 | L | An errored investigation left its lead `approved`, with no buttons and no way to approve it again | The lead goes back to `pending` (if still linked to the case) and is posted again as "Investigation failed" | ✅ |
| N7 | L | A corroboration was lost for good when `NOTIFY_LIMITER` was exhausted: the token claim is spent first | Not rate-limited (the claim already allows one per lead) | ✅ |
| N8 | L | The per-host `BEACON_LIMITER` was charged before the token was checked, so forged reports (no `Origin`) could drain a real clone's budget | Token first; invalid reports use `beacon-invalid:<host>` | ✅ |
| N9 | L | With more than 10,000 active blocks, reconcile treated the unread ones' list items as orphans and deleted them | Orphan removal is skipped when the D1 read hit its cap | ✅ |
| N10 | N | Unread response bodies on error paths (IP ranges, DoH, Access certs) | Cancelled | ✅ |

Also closed in this pass: the open parts of **H1** (block to decoy) and **H2** (the Workflow's `expired`/`closed` writes), and **L6**, **L9** (docs), **L11**, **L16** below.

### Follow-up (2026-11-26)

Closed: **H2** part b (the stuck abuse-report claim), **L3** (D1 write retries), the rest of **L14** (`MaintenanceWorkflow` tests) and **Digest context** from the live-test designs. Each fix has a test that fails without it.
- **H2b.** `POST /cases/{id}/abuse-report/reset` (`npm run hp -- abuse-report-reset <id>`) clears a `submitting` claim older than 10 minutes. It first looks for `abuse-report-result.json` in R2 and lists the account's [submitted reports](https://developers.cloudflare.com/api/resources/abuse_reports/subresources/submitted/methods/list/) since the claim (`CfApi.listSubmittedAbuseReports`). A report for the case's host (or with no domain) means it was filed: its record replaces the claim instead. The clear is conditional (`UPDATE … WHERE id = ? AND abuse_report = <claim>`).
- **L3.** `src/storage/retry.ts`: `envWithD1WriteRetries(env)` wraps `DB` for the admin router and the Discord interactions endpoint. Writes retry the three transient errors from the D1 guide, with jittered exponential backoff and at most 5 attempts; reads pass through.
- **L14.** `test/maintenance.test.ts` drives `MaintenanceWorkflow`: expiry, a WAF removal that fails (rows kept), reconcile, Referer lead steps, the digest, and `POST /maintenance/run` through `introspectWorkflow`.
- **Digest context.** The pending-flags digest marks an IP that is also in an open case ("Also in case …: decide there"); `pendingFlagDigest` in `src/approvals/digest.ts` serves the Workflow and `POST /notify/flags`.

## Code review findings (2026-11-24)

The review checked the code against the [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), the D1 guides ([query](https://developers.cloudflare.com/d1/best-practices/query-d1/), [indexes](https://developers.cloudflare.com/d1/best-practices/use-indexes/), [retries](https://developers.cloudflare.com/d1/best-practices/retry-queries/), [import and export](https://developers.cloudflare.com/d1/best-practices/import-export-data/)) and the Workflows [Workers API](https://developers.cloudflare.com/workflows/build/workers-api/) and [step context](https://developers.cloudflare.com/workflows/build/step-context/) pages.

**Status:** ✅ fixed in this session, 🟡 partly fixed, ⬜ open. Severity: **H** high, **M** medium, **L** low or hardening, **R** repository hygiene.

### Summary

| ID | Finding | Status |
|---|---|---|
| H1 | Expired WAF blocks could stay in the list forever (and block-to-decoy left list items) | ✅ |
| H2 | Concurrent approvals raced (duplicate Workflows, stuck cases, double abuse reports) | ✅ |
| H3 | WAF list writes collided (one write per IP; `429` swallowed) | ✅ |
| M1 | Manual flags accepted any string as an IP, including CIDRs covering Cloudflare ranges | ✅ |
| M2 | One public token could create unlimited beacon leads | ✅ |
| M3 | Trap writes scaled with the attacker's IP count | ✅ |
| M4 | The `form` carrier shadowed real `_csrf` fields | ✅ |
| M5 | Evidence capture failed on pages over 2 MiB | ✅ |
| M6 | D1 read replication was assumed but never enabled | ✅ (docs) |
| M7 | A D1 read on every HTML request is the scaling ceiling | ⬜ (an Enterprise blocker: [E3](#e3-take-d1-off-the-hot-path)) |
| M8 | AES-GCM key volume, and only one previous key for decoding | ✅ (rotation still manual) |
| M9 | Workflow steps weren't idempotent | ✅ |
| L1–L19 | D1, Workflow, privacy, robots.txt, tooling and docs hardening | see below |
| R1–R2 | IDs in tracked files and in git history | ✅ |

### High

**H1. Expired WAF blocks could stay in the list forever.** ✅
- *Was:* the daily purge deleted the D1 rows first. `removeBlocksFromWaf` then swallowed errors, so the step's retries never ran, and nothing ever retried later.
- *Now:* `MaintenanceWorkflow` finds expired flags, removes their list items (with retries), and deletes only the rows whose removal succeeded. A new daily **reconcile** step removes `cf-honeypot:` list items that have no active block flag and re-adds missing ones. Manual `unflag` removes the list item before the row.
- ✅ *Fixed 2026-11-25:* switching a flag from block to decoy used to leave the list item until the next reconcile. `upsertActiveFlag` now returns the row it replaced (read in the same `db.batch()` transaction), and `applyFlag` and case decisions remove the list item of a downgraded active block (`downgradedBlockIp`).

**H2. Concurrent approvals raced.** ✅
- *Was:* every action read the state, then acted. A double click could start two cases and two Workflows for one host. A late `applying` write could overwrite the Workflow's `closed` forever (blocking that host). Two clicks could file the same abuse report twice.
- *Now:* every action claims its row with a conditional `UPDATE … WHERE status = …` and checks [`meta.changes`](https://developers.cloudflare.com/d1/worker-api/return-object/). Migration `0003` adds a partial unique index for one open case per host. A failed `INVESTIGATE.create` marks the case `errored` and puts the lead back to `pending`. An abuse report is claimed (`submitting`) before the API call.
- *Was open, now fixed:*
  - ✅ *Fixed 2026-11-26:* if the Worker died during the abuse-report API call, the `submitting` marker blocked the case for good. `POST /cases/{id}/abuse-report/reset` clears a marker older than 10 minutes, after checking R2 and the account's [submitted reports](https://developers.cloudflare.com/api/resources/abuse_reports/subresources/submitted/methods/list/) since the claim (a filed report is recorded, never reset), with `UPDATE cases SET abuse_report = NULL WHERE id = ? AND abuse_report = ?`.
  - ✅ *Fixed 2026-11-25:* the Workflow wrote `expired` and `closed` unconditionally, so a click that claimed the case as the 7-day wait timed out was told "delivered" and then overwritten as `expired`. Both writes are now conditional (`setCaseStatusIf`), and after a late claim a second `waitForEvent` ("wait for late decision", 10 minutes) picks up the buffered event and applies it.

**H3. WAF list writes collided.** ✅
- *Was:* a case decision made one `POST /items` per IP. The [Lists API](https://developers.cloudflare.com/waf/tools/lists/lists-api/#rate-limiting-for-lists-api-requests) answers `429` while an earlier write is still processing, and that error was swallowed. The [bulk operation](https://developers.cloudflare.com/api/resources/rules/subresources/lists/subresources/bulk_operations/methods/get/) was never checked.
- *Now:* one deduplicated bulk write per decision, in its own Workflow step with retries. `CfApi` retries `429` (and `5xx` for idempotent calls) with jittered backoff, honours `retry-after`, and caps each call's time (8 s on request paths). `waitForListOperation` polls until `completed` or `failed`.

### Medium

**M1. Manual flags accepted any string as an IP.** ✅ `POST /flags {"ip": "104.0.0.0/8"}` used to reach the WAF list, because `isCloudflareIp` can't parse a CIDR. Now `canonicalIp()` accepts only a single IPv4 or IPv6 address, stores it in canonical form (matching `CF-Connecting-IP` and the list's [normalised IPv6](https://developers.cloudflare.com/waf/tools/lists/custom-lists/)), and the route returns `400` otherwise. JA4 values must match `[a-z0-9_]{1,64}`.

**M2. One public token could create unlimited beacon leads.** ✅ Anyone can get a valid token by loading a page, and the limiter was keyed only per clone host. Now a beacon must pass an `Origin` check (when the header is present), a per-token key on `BEACON_LIMITER`, and a global `LEAD_LIMITER` (30 per minute per location) before a lead is written.

**M3. Trap writes scaled with the attacker's IP count.** ✅ A crawl over 100,000 proxy IPs meant 100,000 D1 upserts. Now `TRAP_GLOBAL_LIMITER` (30 per minute per location) bounds them; the decoy is still served.

**M4. The `form` carrier shadowed real `_csrf` fields.** ✅ Spring Security and Express csurf post `_csrf`, and a second field broke their validation. Now the input goes in before `</form>`, and uses `request_id` when the form already has the field.

**M5. Evidence capture failed on pages over 2 MiB.** ✅ A padded clone made the capture step fail. Now `fetchPage` keeps the first 2 MiB and sets `truncated`, which the Workflow stores in R2 metadata and the report shows. The hash covers exactly what was captured.

**M6. D1 read replication was assumed but never enabled.** ✅ (docs) [Read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) is off by default and automatic provisioning doesn't enable it. The README now has the dashboard and API steps. **Possible follow-up:** have `GET /__hp/whoami` (or a new health route) report whether replication is on, using the [D1 database API](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/get/).

**M7. A D1 read on every HTML request is the scaling ceiling.** ⬜ It's cheap (a primary-key lookup) and runs in parallel with the origin fetch for GET, but every replica serves every request, and POSTs wait for it. **Fix options, from simplest:**
1. Keep a per-location "any active decoy flags?" bit in the [Cache API](https://developers.cloudflare.com/workers/runtime-apis/cache/) (30–60 s TTL) and skip D1 entirely when there are none. Most sites have zero or a handful of active decoys.
2. Cache negative lookups per indicator in the Cache API for 30–60 s.
3. Put decoy IPs in a second [WAF IP list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/) and let a [request header transform rule](https://developers.cloudflare.com/rules/transform/request-header-modification/) set a header such as `x-hp-decoy: 1` when `ip.src in $honeypot_decoy`, if your plan allows lists in that rule type. The Worker then needs no D1 read at all.

Measure first: [D1 metrics](https://developers.cloudflare.com/d1/observability/metrics-analytics/) and Workers CPU time under load. For high-traffic sites this is a blocker, and option 3 is the recommended design: see [E3](#e3-take-d1-off-the-hot-path).

**M8. AES-GCM key volume.** ✅ With random 96-bit IVs, [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) limits one key to about 2³² encryptions. That's roughly 43 days at 100 million pages a day. An IV collision allows forged tokens, which could frame someone else.
- *Was:* `loadTokenKeys` kept only `TOKEN_KEY` and one `TOKEN_KEY_PREVIOUS`, and decode tried each key in turn, so rotating often lost the ability to decode older copies.
- *Now (2026-11-26):*
  - Token version 2 carries a 1-byte key ID in a 2-byte header (masked with the IV so tokens still look random, authenticated as additional data). It stays 91 characters: country and colo are packed into 4 bytes, and the inner version byte moved to the header.
  - The optional `TOKEN_KEYS` secret holds a JSON key ring (`{"3":"<base64>","2":"…"}`). The highest ID seals, every ID decodes, and malformed entries are logged and skipped. A `TOKEN_KEYS_STORE` [Secrets Store](https://developers.cloudflare.com/secrets-store/) binding can replace it, so a rotation needs no redeploy.
  - Version 1 tokens still decode with `TOKEN_KEY` and `TOKEN_KEY_PREVIOUS`. Without a ring, the Worker keeps sealing version 1.
  - The beacon, admin decode and the Workflow log `token_retired_key` when a token from a retired key shows up. The [rotation runbook](src/identity/README.md#key-rotation) explains how to read it.
- *Open:* rotation is manual, though `npm run token-keys -- add` / `upload` (2026-11-26) removes the hand-edited JSON. The demo uses the ring since 2026-11-26. A Worker secret caps it at about 95 keys (5 KB); Secrets Store holds all 256. That is enough up to about 100 million pages a day; beyond that, see [E1](#e1-volume-free-sealing-token-version-3) (per-day subkeys) and [E2](#e2-staged-key-promotion).

**M9. Workflow steps weren't idempotent.** ✅ A retry after a failed D1 write re-posted the Discord message, and one failing host redid every lead upsert. Now "notify reviewers" and "save notification ref" are separate steps (and the first skips if a ref exists), and maintenance makes one step per lead host. See [rules of Workflows](https://developers.cloudflare.com/workflows/build/rules-of-workflows/).

### Low and hardening

| ID | Finding | Status | Fix |
|---|---|---|---|
| L1 | The purge filtered on `expires_at` alone, and `openCaseForHost` on an unindexed `host` | ✅ | Migration `0003`: `idx_flags_expires`, the partial unique index on `cases(host)`, and [`PRAGMA optimize`](https://developers.cloudflare.com/d1/sql-api/sql-statements/#pragma-optimize) |
| L2 | `approveFlags`/`rejectFlags` made one round trip per indicator; `upsertActiveFlag` re-selected the row | ✅ | [`db.batch()`](https://developers.cloudflare.com/d1/worker-api/d1-database/) in chunks of 100; `RETURNING *` |
| L3 | D1 writes outside Workflows are not retried (D1 retries only reads) | ✅ | `envWithD1WriteRetries` (`src/storage/retry.ts`) wraps `DB` for the admin router and Discord callbacks, per [Retry queries](https://developers.cloudflare.com/d1/best-practices/retry-queries/): writes retry on "Network connection lost", "storage caused object to be reset" and "reset because its code was updated", with jittered exponential backoff, at most 5 attempts; reads pass through. Claims are idempotent: a retry of a committed claim sees `meta.changes` = 0 and reports "already handled" |
| L4 | `updateCase` built column names from object keys | ✅ | Runtime allowlist |
| L5 | Beacon events kept the clone visitor's User-Agent, city, ASN, RTT and Ray ID | ✅ | `visitorSafeSignals()` blanks them |
| L6 | `loadCloudflareRanges` trusted any non-empty API answer | ✅ | The live list is unioned with `CLOUDFLARE_IPS_SNAPSHOT` (`unionWithSnapshot`), so a protected range can never be dropped. CI runs `scripts/check-ip-snapshot.mjs`, which warns when the snapshot differs from the live list and prints a replacement with the new etag. The quarterly scheduled run fails instead, so GitHub notifies the owner. The refresh itself is a manual paste |
| L7 | Discord's failure message said "Nothing was changed" | ✅ | It now says which actions roll back and how to check |
| L8 | `/maintenance/run` instance IDs could collide within a millisecond | ✅ | Random suffix |
| L9 | Dead code: `setFlagListItem` and the `flags.list_item_id` column are never written | ✅ | `setFlagListItem` was removed (T8). The column stays (documented as legacy on `FlagRow`); list items are looked up by IP |
| L10 | Production `CANONICAL_HOSTS` includes `localhost,127.0.0.1`, and the beacon script embeds them | ✅ | Local hosts moved to `env.dev` ([Wrangler environments](https://developers.cloudflare.com/workers/wrangler/environments/)), which `npm run dev` uses. Environments don't inherit bindings, so `env.dev` repeats them, and `scripts/check-config.mjs` (in `npm run lint`) fails if it drifts or if production lists a local host. `env.dev` has no routes, so it can't take the production hostname. Not in `.dev.vars`: `--secrets-file` would upload it as a secret, and a name can't be both a var and a secret |
| L11 | Discord User-Agent said `0.2` while `package.json` says `0.1.0` | ✅ | Both say `0.1.0`. Bump them together with each tag |
| L12 | No `no-floating-promises` lint, which the best practices recommend | ✅ | `npm run lint`: oxlint with [`typescript/no-floating-promises`](https://oxc.rs/docs/guide/usage/linter/rules/typescript/no-floating-promises.html) (`ignoreVoid: false`, since `void` doesn't keep a Worker alive), `no-misused-promises` and `await-thenable`, type-aware through `oxlint-tsgolint`. `src/` and `test/` had no findings (`writeEvent`'s `writeDataPoint` returns `void`). CI runs it |
| L13 | No CI, and no staging environment | 🟡 | ✅ `.github/workflows/ci.yml` runs `npm ci`, typecheck, tests and lint on pushes to `main` and on pull requests (actions pinned by commit SHA, read-only token). ⬜ An `env.staging` with its own keys and resources ([environments](https://developers.cloudflare.com/workers/wrangler/environments/)) |
| L14 | No end-to-end Workflow tests | ✅ | `test/investigate.test.ts` and `test/maintenance.test.ts` drive `InvestigateWorkflow` and `MaintenanceWorkflow` with the Vitest [Workflows test APIs](https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/#workflows) |
| L15 | Discord clicks run in [`ctx.waitUntil`](https://developers.cloudflare.com/workers/runtime-apis/context/) (30 s after the response) | 🟡 | Request-path WAF calls now cap at 8 s. If flag approvals grow, run them in a Workflow and post the result |
| L16 | `report.md` included attacker-influenced strings (PTR names, AS organization, registrar) unescaped | ✅ | `escapeMd()` for every untrusted value in the Markdown (the copy's URL, User-Agent, DNS answers, URL Scanner and Intel fields) |
| L17 | Shared egress IPs outside Cloudflare's ranges (VPNs, relays, CGNAT) can still be flagged | ⬜ | See production-readiness item 1; show [Managed IP List](https://developers.cloudflare.com/waf/tools/lists/managed-lists/) membership (`cf.vpn`, `cf.anonymizer`) in the approval message |
| L19 | robots.txt disallowed the trap only under `User-agent: *`, which [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.1) crawlers with their own group ignore | ✅ | `addTrapDisallow` adds the rule to every group (origin file read with a 512 KiB cap). The README documents route coverage and per-host scope |
| L18 | Docs drift: deploy steps disagreed, three vars were undocumented, the abuse-report path was marked unverified, an Analytics example ignored sampling | ✅ | Fixed in this session, with reference links added to every README |

### Repository hygiene

**R1. `old_files/` was tracked.** ✅ The legacy prototype (with an older D1 `database_id`) was removed from the repository.

**R2. Real IDs in git history.** ✅ Early commits contained the real `account_id`, D1 `database_id` and `WAF_LIST_ID` in `wrangler.jsonc`. These are [identifiers, not credentials](https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/), but the history was squashed into a single commit before the repository went public. A pre-publication audit also replaced a real (production-key) token in the OpenAPI example with a test-key one and stripped editor metadata from `public/favicon.png`.

## Live test findings and scraper bypasses (2026-11-25)

A live end-to-end test played the scraper against the production demo:
- **Scrape:** a curl crawler with a spoofed Chrome UA ignored robots.txt, followed the trap link, and copied the pages.
- **Static clone:** a rebranded copy ran in a Worker on another zone (a second zone in the same account), hotlinking CSS and favicons from the original.
- **Live reverse proxy:** the same Worker served `/live/*` by fetching the original for every visitor.
- **Cloaking clone:** `/stealth/*` served the tokenized page to people and a stripped page to anything that looked like the investigator.

Every stage worked on current code:
- the beacon created a lead, and a Discord click approved it;
- the Workflow built the evidence and a decoy was applied;
- an edge block went onto the WAF list (with the Worker's 403 fallback behind it);
- the Cloudflare IP was skipped;
- every concurrency guard held.

The test also surfaced the findings below. The bypass list combines what the test proved with published research on scraper honeypot avoidance and phishing-kit cloaking (for example [PhishFarm](https://sefcom.asu.edu/publications/phishfarm-oakland2019.pdf), [PhishDecloaker](https://usenix.org/system/files/usenixsecurity24-teoh.pdf), [Thinkst on cloned-site tokens and reverse proxies](https://blog.thinkst.com/2023/09/cloned-website-token-and-reverse-proxies.html), and [Netskope on Workers-based reverse-proxy phishing](https://www.netskope.com/blog/phishing-with-cloudflare-workers-transparent-phishing-and-html-smuggling)).

**Status:** ✅ fixed in this session, 🟡 partly fixed, ⬜ open (design below), ➖ accepted limitation.

### Findings from the live test

| ID | Finding | Status |
|---|---|---|
| T1 | The deployed Worker was 3 commits behind `main`, with migration `0003` unapplied (favicons returned 404, old robots.txt logic) | ✅ deployed; ✅ drift check (`npm run doctor`) |
| T2 | `hotlink` events stored the clone visitor's IP, User-Agent, JA4 and city, contradicting the beacon-privacy rule (the same innocent people) | ✅ `scrubVisitorSignals()` for hotlinks too |
| T3 | Once a host's lead was approved, a re-scrape from a new IP (new token) only added a hit: no notification, and `token_ray` kept the first value | ✅ lead re-opens on a new scraper IP (24 h cooldown) |
| T4 | Live-proxy cases had empty enrichment (UA `n/a`, no `CF-Worker` zone): the token is minted during the capture and Analytics Engine lags about a minute. "Live proxy" wasn't flagged | ✅ 90 s ingestion wait for fresh tokens; live-proxy marker; zone in report and abuse draft |
| T5 | `scanHtml` missed a token with one HTML-entity-encoded character (lol-html returns raw attribute values) while browsers and the beacon decoded it: lead created, case `no_evidence` | ✅ `decodeCharRefs()` + trim |
| T6 | `POST /__hp/decode` with `html_b64` was Managed-Challenged by a zone "WAF Attack Score < 20" rule; the CLI printed the challenge HTML | ✅ CLI detects `cf-mitigated: challenge` / edge 403; Access now protects `/__hp/*` and the demo's rule excludes it |
| T7 | Case and digest messages both had a "Decoy" button for the same IP; the approver clicked the case one. The case upsert also erased the trap flag's provenance | ✅ distinct labels; provenance kept in `reason` |
| T8 | Minor: UA cut mid-word at 80 chars; DMCA draft pre-filled `agree: 1`; dead `setFlagListItem`; `blob20` (`CF-Worker` zone) undocumented; a "pretend browser" zone rule matches every beacon | ✅ (zone rule documented in `src/honeypot/README.md`) |

### Scraper bypasses

| ID | Bypass | Why it works here | Status |
|---|---|---|---|
| B1 | **Fetch twice and diff** | Only the token and Cloudflare's JS Detections snippet (`__CF$cv$params`, Ray ID in clear) change per request | ⬜ |
| B2 | **Strip by signature** | Open source with recognizable defaults; `rum.js` contains the token regex `{91}`; a 91-char base64url CSRF token on a form-less page is unusual | 🟡 names are configurable (documented); ⬜ per-deployment shapes |
| B3 | **Break the token** | Encoding a character fooled the scanner (fixed). Changing or dropping one makes it unopenable for everyone | ✅ encoding; 🟡 beacon fallback for the rest |
| B4 | **Cloak the investigator** | It sent a fixed UA (fixed). A Worker fetch still carries `CF-Worker` and Cloudflare's ASN; URL Scanner also egresses from Cloudflare | 🟡 browser UA + beacon fallback; ⬜ browser capture |
| B5 | **Silence the beacon** | Strip the tag, stub `navigator.sendBeacon` (the script trusts its return value), or send a strict CSP on the clone | ⬜ second channel |
| B6 | **Kill Referer discovery** | Self-host assets or send `Referrer-Policy: no-referrer` | ➖ (B5's second channel helps) |
| B7 | **Avoid the trap** | Scraping libraries skip `hidden`/`aria-hidden` links and honor robots.txt; headless browsers with bot score ≥ 30 are never flagged | ➖ the trap is a bonus signal |
| B8 | **Scrape from Cloudflare** (Workers, Browser Run) | Cloudflare IPs are never blocked by design | 🟡 detected and named; abuse report is the channel |
| B9 | **Launder attribution** | Residential proxies, CGNAT, iCloud Private Relay, translators, archives, link unfurlers put someone else's IP in the token | 🟡 verified bots skipped; ⬜ risk scoring (see Ideas) |
| B10 | **Swap tokens** | A scraper can present any genuine token it obtained; tokens are not bound to the host they appear on | ⬜ |
| B11 | **Rotate IPv6** | Flags and blocks are single addresses; a `/64` has 2⁶⁴ | ⬜ |
| B12 | **Detect the decoy** | Every path returns the same 5-row "Catalog export" after +5 s with random prices | ⬜ |
| B13 | **Flood leads** | Tokens cost one page load; many throwaway hosts exhaust `LEAD_LIMITER`/`NOTIFY_LIMITER` and the real lead is dropped | ⬜ |
| B14 | **Re-scrape onto a decided host** | Same as T3 | ✅ |
| B15 | *Opportunity:* Cloudflare's JS Detections snippet carries the Ray ID into copies | Strippers that remove *our* carriers by name often keep it | ⬜ |

### Open items, with designs

**T1 Deploy drift check.** ✅ `npm run doctor` (`scripts/doctor.mjs`) compares the newest code deployment from `npx wrangler deployments list --json` with the last commit on `main` that changes what gets deployed (folder `README.md` files excluded), and fails on a rollback or when `npx wrangler d1 migrations list DB --remote` lists pending migrations. Secret-change deployments are skipped, because they keep the deployed code. Still open: run it in [Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/) or a scheduled CI job, which needs a read-only API token as a CI secret.

**B1/B2 Diff- and signature-resistant carriers.**
- Deterministic per-visitor tokens (already an Idea under *Detection quality*) make a two-fetch diff show nothing.
- Make shapes per-deployment: `META_NAME` plus a token *encoding* that matches a real framework (Rails: 88-char base64 with `+/=`; Laravel: 40 chars). That needs a second, shorter token format (for example an 8-byte Ray + 4-byte issuedAt + GCM tag, looked up in WAE) and `TOKEN_PATTERN` per format.
- Drop the literal `{91}` from `rum.js`: look up the meta by name (`meta[name=…]`) instead.
- Document that origins can send `Cache-Control: no-transform` to stop Cloudflare injecting the JS Detections snippet, at the cost of JS detections (see [JavaScript detections](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)).

**B4 Browser-based, non-Worker capture.** When the direct capture finds no token, capture again with [Browser Run](https://developers.cloudflare.com/browser-run/) (a real browser, no `CF-Worker` header; renders JavaScript-built clones). Also pull URL Scanner's rendered DOM for the already-submitted scan and run `scanHtml` on it. Both still egress from Cloudflare, so an ASN-cloaking clone can hide; the beacon fallback (done) remains the last resort. Gate it like other quota calls: only after approval and when the lead has a valid beacon token.

**B5 Second discovery channel.** Add an opt-in `css` carrier: a `<style>` rule with `background-image: url(<origin>/assets/img/p.gif?t=<token>)` on an element that always renders. It fires without JavaScript, survives CSP `connect-src` (but not `img-src`), and is hard to stub. Cost: one extra request per page view, so only on cache-busting misses (`Cache-Control` on the pixel), with the Referer check of the beacon. In `rum.js`, fall back to `fetch(…, {keepalive})` and an `Image` beacon when `sendBeacon` returns `true` suspiciously fast. That is a heuristic, so keep it optional.

**B9/B10 Attribution hardening.**
- Show in the report whether the token IP also hit the trap or appears in WAE with the same JA4 as the scrape. That corroborates a scraper versus a laundered or swapped token.
- Flag tokens whose IP is in the iCloud Private Relay list, a VPN/anonymizer [Managed IP List](https://developers.cloudflare.com/waf/tools/lists/managed-lists/), or a known translator or archive range, and pre-select **No action** for them (see "Risk-scored enforcement" in Ideas).

**B11 IPv6 `/64` flags and blocks.** [WAF IP lists accept IPv6 `/12`–`/128`](https://developers.cloudflare.com/waf/tools/lists/custom-lists/). Design:
- `flagIndicators()` adds `ip:<v6 /64>` for IPv6 requests;
- trap flags and case decisions store IPv6 as `/64` (IPv4 stays `/32`);
- `canonicalIp` grows a `canonicalPrefix` for exactly `/64`;
- the Cloudflare-range check tests the prefix's network address (Cloudflare's IPv6 ranges are `/29`–`/32`, so a `/64` is either inside or outside);
- `syncBlocksToWaf`, `removeBlocksFromWafDetailed` and `reconcileWafList` compare normalized prefixes.

It touches every enforcement path, so it needs its own change with tests for each.

**B12 Decoy realism.** Make decoys path-aware: keep the requested page's layout (fetch it, then HTMLRewriter-replace prices and product text with plausible fake values), vary the tarpit between 1 and 8 s, and keep the fake data stable per IP per day so diffs don't reveal it.

**B13 Lead-flood resistance.** Instead of dropping beacons when `LEAD_LIMITER` is exhausted, keep a small queue in D1 (one row per host, upsert-only, bounded to N rows) and let maintenance notify the top hosts by distinct token IPs. Also rate-limit per token *IP* (one scraper fetching many pages to mint tokens), not only per token Ray.

**B15 JS Detections Ray as a secondary identifier.**
- `scanHtml` extracts `r:'<16 hex>'` from `__CF$cv$params` scripts.
- `decode` and the Workflow look those Rays up in Analytics Engine (our page events are indexed by Ray ID) and show matches as **unauthenticated hints**, never as decision targets. Anyone can write a Ray, but only Rays we served exist in WAE.
- It only works on zones with Bot Management JS detections.

**Re-open identity.** A live proxy's Worker egress IP can change, which re-opens its lead (bounded to once per 24 h). Treat all Cloudflare IPs as one identity in `recordLead` if that turns out noisy.

**Digest context.** ✅ *Built 2026-11-26:* the pending-flags digest annotates an IP that is also part of an open case ("Also in case …: decide there"), so approvers don't decide the same IP twice. The buttons stay, since rejecting the trap flag is still a valid choice.

## Production-readiness review

### Fixed during review
- **Hotlink false positives.** Link clicks from other sites (navigations) used to count as clone signals. Now only subresource loads count ([`Sec-Fetch-Dest`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest)).
- **CSRF meta collision.** Pages that already use `<meta name="csrf-token">` (Rails, Laravel) could have had their real token shadowed. The identifier now falls back to `<meta name="request-id">`. The `form` carrier now does the same for `_csrf` fields (M4).
- **Account-specific IDs in the repo.** Moved to [Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/) and `.env` (see AGENTS.md, "Public-repo hygiene"). The git history was squashed before publishing (R2).
- **The code review above:** H1, H3, M1–M6, M9 and most low items.

### Review carefully before going live
1. **Shared and innocent IPs.** This is the biggest risk. The IP inside a token is whoever fetched the page, and that is often:
   - a residential proxy, meaning a real person's device rented out by a scraping network
   - carrier-grade NAT (CGNAT), mobile carriers or a corporate egress
   - Tor or a VPN (Enterprise [Managed IP Lists](https://developers.cloudflare.com/waf/tools/lists/managed-lists/) cover anonymizers and VPNs)
   - [iCloud Private Relay](https://developer.apple.com/icloud/prepare-your-network-for-icloud-private-relay/) (the account already keeps an `icloud_private_relay_egress_ips` list)

   An IP decoy or block can therefore hit many innocent users. Before approving, check the [Intel IP](https://developers.cloudflare.com/security-center/intel-apis/) type (`isp` or `hosting`) and the ASN. Prefer short decoys over blocks for residential addresses. See risk-scored enforcement below.
2. **Decoys shown to real people.** A mis-flagged human sees fake catalog data. Keep decoys clearly non-transactional (no real prices or checkout), use short TTLs, and get legal or consumer-protection advice for your market.
3. **Privacy and retention (GDPR and similar laws).**
   - **Analytics Engine** stores IP and User-Agent for *every* page view for [3 months](https://developers.cloudflare.com/analytics/analytics-engine/limits/), and individual rows can't be deleted.
   - **Workflow instance state** ([7 days by default](https://developers.cloudflare.com/workflows/reference/limits/) on Workers Paid) and **R2 evidence** (no [lifecycle rule](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) yet) also hold IPs.
   - **Before launch:** define a legal basis, privacy notice, retention policy and a process for data-subject requests. Consider a data-minimization mode (see Ideas).
4. **Cost and caching of tokenizing every page.**
   - Every HTML response is rewritten and gets `Cache-Control: private, no-cache` (or `private, no-store` when the origin sent `no-store`, C1), so downstream shared caches and some browser caching stop working for HTML. The edge cache in front of your origin still works, because the [Worker runs before it](https://developers.cloudflare.com/cache/interaction-cloudflare-products/workers/).
   - [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/) adds CPU per page.
   - The flag lookup is one D1 read per non-static request. For GET it runs in parallel with the origin fetch; for POST it runs first and adds latency (M7). Enable [read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) first (M6); high-traffic sites need [E3](#e3-take-d1-off-the-hot-path).
   - On a `/*` route the Worker is invoked, and billed, for every static asset too ([E5](#e5-invoke-the-worker-for-html-only)).
   - Measure under load before launch.
5. **Key management.** Anyone holding a token key can forge tokens and frame others. Use separate keys per environment, the `TOKEN_KEYS` ring with the [rotation runbook](src/identity/README.md#key-rotation) (M8), and least-privilege access to secrets (for example the `TOKEN_KEYS_STORE` [Secrets Store](https://developers.cloudflare.com/secrets-store/) binding).
6. **Detectability.**
   - Fetching twice and diffing reveals the token.
   - The beacon script is a visible extra request.
   - A strict, nonce-based Content Security Policy (CSP) blocks the beacon silently.
   - Capable scrapers will strip all of it. Treat the system as tripwires and evidence, not as prevention.
7. **Admin surface.**
   - ✅ [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/) protects `/__hp/*` on the demo (an Owner policy plus a service token for the CLI). The Worker verifies the Access JWT, ignores the bearer token, and attributes actions to the Access identity ([setup](src/admin/README.md#cloudflare-access)).
   - Still open: an append-only audit log (see Ideas), and the same Access setup on every deployment (the bearer token is the fallback when the two secrets are unset).
8. **Investigator fingerprint.** The evidence capture now sends a browser-like User-Agent (`CAPTURE_USER_AGENT`), but it still fetches from Cloudflare and carries [`CF-Worker: <your zone>`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-worker), so clone operators can recognize and cloak it (the live test proved it). If the beacon reported a token, the case continues as *unconfirmed*. [Browser Run](https://developers.cloudflare.com/browser-run/) capture is the next step (B4 above).
9. **Abuse reports are legal statements.** DMCA reports are made under penalty of perjury. Keep `ABUSE_REPORTS="draft"` unless a responsible person reviews every submission. The API path segment (`report_param`) is the report type, the same value as `act`, as the [Abuse Reports API](https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/) documents.
10. **Layering expectations.** Account-level rules on this zone already block many scrapers before they reach the honeypot: unwanted User-Agents such as python, undici and scrapy, Workers from other zones, and managed IP lists. The honeypot only sees what gets past the [WAF](https://developers.cloudflare.com/waf/). That is intended, but it means trap and decoy numbers are not a scraping census.
11. **Config hygiene.**
    - `CANONICAL_HOSTS` must list every legitimate host (www, staging, preview URLs), or your own environments will file leads. Local hosts belong in `env.dev` only (L10); `npm run lint` fails if production lists one.
    - Tune the trap's [bot score](https://developers.cloudflare.com/bots/concepts/bot-score/) threshold (30) per site.
    - Keep the Discord [WAF skip rules](https://developers.cloudflare.com/waf/custom-rules/skip/) scoped to Discord's ASN and User-Agent.

## Ideas

### Operations and safety
- **Risk-scored enforcement.**
  - Before showing approval buttons, classify each IP as residential, hosting or VPN/relay, using [Intel IP](https://developers.cloudflare.com/security-center/intel-apis/) type, [Managed IP Lists](https://developers.cloudflare.com/waf/tools/lists/managed-lists/) and the iCloud Private Relay list.
  - Default to a short decoy for residential addresses, and allow **Block** only for hosting ASNs.
  - Show the score in the Discord message.
- **Two-person rule.** Require approval from two different approvers before blocks and abuse-report submissions. The atomic claims (H2) are a good base for a `pending_second_approval` state.
- **Audit log.** An append-only `audit_log` table recording who approved what, when and from which channel, with export to R2 or [Logpush](https://developers.cloudflare.com/logs/logpush/).
- ✅ **Cloudflare Access on `/__hp/*`** (built 2026-11-25): SSO plus a service token, with [`Cf-Access-Jwt-Assertion` validated](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/) in the Worker (`src/admin/access.ts`). Next: put the Access app, policies and service token in Terraform.
- **Approval UI.** A small Access-protected page for reviewing pending flags, leads and cases, as an alternative to Discord and the CLI.
- **More notifier adapters.** Slack ([Block Kit, signing-secret verification](https://docs.slack.dev/authentication/verifying-requests-from-slack)) and Telegram ([inline keyboards, `secret_token` webhooks](https://core.telegram.org/bots/api)) behind the existing `Notifier` interface. A [design sketch is in src/notify/README.md](src/notify/README.md#using-another-channel-slack-telegram-).
- **Discord upgrades.** Slash commands (`/honeypot leads`), a thread per case, and reminders before a case expires.
- **Rule-based auto-approval (opt-in).** A policy engine for narrow, well-understood cases, for example a trap hit with Bot Management score < 5 from a hosting ASN. Every auto-approval would be logged and reversible.
- **Retired-key alert.** The key ring, key IDs and retired-key logs exist (M8), and `npm run token-keys` adds and uploads keys without showing them. Still to do: an alert (a Workers Logs alert, or a Discord message) on `token_retired_key` events whose `newestIssuedAt` is later than that key's retirement, with the grace window from [E2](#e2-staged-key-promotion). *Superseded:* scheduled rotation through the [Secrets Store API](https://developers.cloudflare.com/api/resources/secrets_store/). It would give the Worker write access to its own keys and leave the operator's backup of the ring out of date; [E1](#e1-volume-free-sealing-token-version-3) removes the need for frequent rotation instead.
- **Infrastructure as code.** [Terraform](https://developers.cloudflare.com/terraform/) for the WAF list, block rule, Discord skip rules and Worker. They're currently created through the API by hand.
- **Staging and CI.** An `env.staging` ([Wrangler environments](https://developers.cloudflare.com/workers/wrangler/environments/)) with its own keys and resources; GitHub Actions for typecheck, tests and lint is done (L12, L13); Dependabot or Renovate; [gradual deployments](https://developers.cloudflare.com/workers/versions-and-deployments/gradual-deployments/) for risky changes.

### Privacy and cost
- **Selective tokenization.** Modes `all` / `suspicious` ([bot score](https://developers.cloudflare.com/bots/concepts/bot-score/) < N, or no [JavaScript detection](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/)) / `sampled`. These lower CPU use and keep normal visitors' HTML cacheable.
- **Data minimization.** For ordinary page views, store a salted hash of the IP in Analytics Engine, and keep full detail only for trap, decoy and beacon events.
- **Retention controls.** Set the Workflow [`retention`](https://developers.cloudflare.com/workflows/build/workers-api/) option, add [R2 lifecycle rules](https://developers.cloudflare.com/r2/buckets/object-lifecycles/) (with [bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/) for evidence you must keep), and provide data-subject request tooling (find and delete by IP or Ray ID).
- **Avoid the per-request flag lookup.** See M7 and [E3](#e3-take-d1-off-the-hot-path).
- **Load testing and profiling.** CPU per page for HTMLRewriter, D1 latency percentiles, and a Grafana dashboard on [Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/grafana/).

### Detection quality
- **Deterministic per-visitor tokens.** A SIV-style construction would give one visitor the same token per day. Diffing two fetches then reveals nothing, but each token is no longer tied to a single request. It would also reduce the random-IV volume limit (M8), since one key then seals fewer distinct messages; it doesn't remove it ([E1](#e1-volume-free-sealing-token-version-3) does).
- **Carriers that survive clean-up.** Put the token where cleaners and AI pipelines usually keep it: a cache-busting query string on stylesheet and image URLs (`/styles.css?v=<token>`), a framework-style `data-*` attribute on content elements, or a JSON-LD `@id`. `scanHtml` would then need to match tokens inside attribute values, not only whole values.
- **CSP nonce support.** Reuse the page's script nonce for the beacon, or turn the beacon off automatically under a strict CSP.
- **Live-mirror signals in the Worker.** Flag `X-Forwarded-Host`, `Forwarded` or `Origin` headers that name a foreign host, and many-User-Agents-per-IP patterns.
- **Search-based discovery.** Periodically search for unique sentences from your pages to find republished text that dropped all markup.
- **AI paraphrase detection.** Embed your own articles ([Workers AI](https://developers.cloudflare.com/workers-ai/)) into [Vectorize](https://developers.cloudflare.com/vectorize/), then compare suspected pages semantically. It gives a lead, not proof.
- **Image watermarking.** An invisible watermark per image, for clones that keep media but drop markup.
- **Scraper clustering.** Aggregate [JA4](https://developers.cloudflare.com/bots/additional-configurations/ja3-ja4-fingerprint/), ASN and User-Agent combinations across trap hits and decoded tokens, and suggest [WAF custom rules](https://developers.cloudflare.com/waf/custom-rules/) for them.

### Evidence and takedown
- **Browser-based capture.** Capture with [Browser Run](https://developers.cloudflare.com/browser-run/) for JavaScript-rendered clones, and to avoid the `CF-Worker` fingerprint.
- **Long-term archive.** For forensic retention beyond Analytics Engine's 3 months, stream decoded and enriched records to R2 ([Basin Pipelines](https://developers.cloudflare.com/basin-pipelines/) or [Logpush](https://developers.cloudflare.com/logs/logpush/)) with [bucket locks](https://developers.cloudflare.com/r2/buckets/bucket-locks/).
- **Abuse report follow-up.** Poll [`GET /abuse-reports/submitted/{id}`](https://developers.cloudflare.com/api/resources/abuse_reports/methods/get/) and post status changes to the approval channel.
- **Cloudforce One Brand Protection (v2).** Domain and logo match APIs with quality filters ([Brand Protection](https://developers.cloudflare.com/security-center/brand-protection/), [Cloudforce One](https://developers.cloudflare.com/security-center/cloudforce-one/)), plus **draft** takedown notices and letters generated from case reports (sent by a human).
- **Signed evidence manifests.** Sign `report.json` (hashes of every artifact) so the bundle's integrity can be checked later.

### Scale
- **Multi-site.** Per-host config (carriers, paths, canonical hosts) for one Worker in front of several zones. See [E7](#e7-several-zones-and-hosts).
- **Enterprise readiness.** The scale blockers and their designs are in the [Enterprise readiness review](#enterprise-readiness-review-2026-11-27).
