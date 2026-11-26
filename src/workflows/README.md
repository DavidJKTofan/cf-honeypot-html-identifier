# `src/workflows/`: durable pipelines

| File | Purpose |
|---|---|
| `investigate.ts` | `InvestigateWorkflow`: one instance per **approved** lead or manual case (at most 5 run at once through the [`concurrency.limit`](https://developers.cloudflare.com/workflows/build/concurrency-limits/); instances waiting for a decision don't use a slot) |
| `maintenance.ts` | `MaintenanceWorkflow`: daily via [`schedules`](https://developers.cloudflare.com/workflows/build/trigger-workflows/) (`17 3 * * *`), or on demand |
| `report.ts` | `writeReport()` → `report.json` and `report.md`, plus R2 key helpers |
| `evidence.ts` | Pure, unit-tested helpers: live-mirror detection, the Analytics Engine ingestion wait, `capCaseTokens()` (at most `MAX_CASE_TOKENS` per case) and `decisionTargets()` (which case IPs a decision may flag) |
| `types.ts` | Serializable step results shared by the Workflow and the report |

## InvestigateWorkflow steps

1. **capture suspected copy:** [R2](https://developers.cloudflare.com/r2/) snapshot and SHA-256 (pages above 2 MiB are truncated, not rejected). Sent with ordinary browser headers (`CAPTURE_USER_AGENT`, default: a desktop Chrome UA), because a clone can serve a token-free page to a self-identifying UA
2. **extract and open tokens:** flags tokens whose fetching IP is a Cloudflare IP, and records how many seconds before the capture each token was issued. At most `MAX_CASE_TOKENS` (50) valid tokens are kept: the earliest fetches plus the 5 newest (a live proxy's own fetch). The rest are counted (`omittedTokens`, shown in the report), so a page stuffed with genuine tokens can't push the step past the [1 MiB step-result limit](https://developers.cloudflare.com/workflows/reference/limits/) or turn one decision into thousands of flags. Every candidate is still decoded, so junk token-shaped values can't hide the real one. **If the capture holds no valid token** but the case came from a lead with a beacon token **for the same host**, that token becomes the evidence, marked `source: "beacon"` and **unconfirmed** (`beaconOnly`): the copy may cloak the investigator by the two tells a Worker can't hide (`CF-Worker` header, Cloudflare's ASN), or the beacon report may be forged
3. **wait for analytics ingestion** (90 s, only when a token is less than 2 minutes old). A **live reverse proxy** mints its token during our own capture; without the wait its Analytics Engine row (User-Agent, JA4, `CF-Worker` zone) isn't queryable yet and the report shows `n/a`
4. **enrich from Analytics Engine:** User-Agent, JA4, path and `CF-Worker` zone for each Ray ID
5. **record decoded tokens:** writes to D1, or closes as `no_evidence` if none was found
6. **Cloudflare hosting check:** [DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/) lookup. If the copy is on Cloudflare **and the capture holds a token**, also writes `abuse-report-draft.json` (naming the scraper's `CF-Worker` zone and a live proxy when known). Beacon-only evidence never gets a draft: an abuse report states the page contains our identifier
7. **[URL Scanner](https://developers.cloudflare.com/radar/investigate/url-scanner/):** Unlisted scan and screenshot (best-effort). For a beacon-only case its screenshot is the quickest way to confirm the copy
8. **[Threat Intel](https://developers.cloudflare.com/security-center/intel-apis/):** WHOIS with parent-domain fallback, plus domain and IP intel (best-effort, quota-capped)
9. **write evidence report** (evidence strength, live-proxy and verified-bot markers), then **notify reviewers** (Discord buttons, …) and **save notification ref** as a separate step, so a retry never posts a second message
10. **wait for human decision** ([`waitForEvent("decision")`](https://developers.cloudflare.com/workflows/build/events-and-parameters/), 7 days). On timeout, **expire undecided case** is conditional (`awaiting_decision` → `expired`). If an approver's click claimed the case (`applying`) just as the wait timed out, its event is already [buffered](https://developers.cloudflare.com/workflows/build/events-and-parameters/) for this instance: **wait for late decision** (10 minutes) picks it up and the decision is applied, instead of the case being overwritten as `expired` after the approver was told it was delivered
11. **apply human decision:** writes the D1 flags, skipping Cloudflare IPs (`skippedCloudflareIps`) and IPs whose token says the fetch was a **verified bot** (`skippedVerifiedBotIps`: a clone made from a crawler's or archiver's fetch must not get Googlebot blocked). Then **sync WAF list** in one bulk write with its own retries (a final failure is recorded as `waf: ["error"]` and doesn't fail the case). A **decoy** for an IP that had an active block runs **remove downgraded blocks from WAF list** instead: otherwise the edge rule keeps blocking it and the decoy never shows. Then **close case** (conditional: only from `applying`, or `awaiting_decision` for an event sent without a claim)

If a step fails for good, the case becomes `errored` and its lead goes back to `pending` (only if it is still linked to this case) and is posted again as "Investigation failed", so it can be investigated again or dismissed.

Integration failures are written into the report as `skipped: …` instead of failing the case. Nothing is enforced or submitted without a human.

### Reading a report

| Marker | Meaning |
|---|---|
| **Evidence: confirmed** | The captured page contains our sealed token(s). This is the proof the abuse draft relies on |
| **Evidence: unconfirmed** (beacon only) | The capture holds no token; a visitor's browser reported one from this host. Check the URL Scanner screenshot or open the page before acting. Decisions still target the token's IP, which is whoever fetched our page (the scraper, or whoever forged the report) |
| **Live reverse proxy** | A token was issued within 30 s of the capture: the copy fetches our page for every visitor. The IP is the proxy's egress (often a Cloudflare Worker: then the `CF-Worker` zone names it, and the right channel is an abuse report) |
| **verified bot: never flagged** | The token says a verified bot fetched the page; the decision skips that IP |

## MaintenanceWorkflow steps

It runs these steps:
- **find expired flags** (read-only, at most 1,000 per run)
- **remove expired WAF list items**: retried; IPs whose removal still fails are reported
- **delete expired flags**, except rows whose list item couldn't be removed, so the next run retries them
- **reconcile WAF list**: removes `cf-honeypot:` list items that have no active block flag, and re-adds missing active blocks (Cloudflare IPs skipped). Items without that comment prefix are never touched. Bounded to 10 pages of 500 items and 500 changes each way
- purge stale leads
- foreign Referers (Analytics Engine) → leads, **one step per host** (at most 50)
- Brand Protection matches from the last 2 days (at most 25) → leads, one step per host; a failure is recorded in the summary instead of failing the run
- **pending-flag digest** to the notifier. An IP that is also part of an open case (`collecting`, `awaiting_decision`, `applying`) says so ("Also in case …: decide there"), so it isn't decided twice

`test/maintenance.test.ts` drives these steps end to end with the [Workflows test APIs](https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/#workflows).

## Usage

```bash
npm run hp -- case https://suspected-clone.example/
```

```bash
npx wrangler workflows instances describe honeypot-investigate <caseId>
```

([`wrangler workflows`](https://developers.cloudflare.com/workers/wrangler/commands/workflows/))

```bash
npm run hp -- maintenance
```

## References

[Workflows](https://developers.cloudflare.com/workflows/) · [Events and `waitForEvent`](https://developers.cloudflare.com/workflows/build/events-and-parameters/) · [Trigger and schedule](https://developers.cloudflare.com/workflows/build/trigger-workflows/) · [Rules of Workflows](https://developers.cloudflare.com/workflows/build/rules-of-workflows/) · [Workers API](https://developers.cloudflare.com/workflows/build/workers-api/) · [Step context](https://developers.cloudflare.com/workflows/build/step-context/) · [Concurrency limits](https://developers.cloudflare.com/workflows/build/concurrency-limits/) · [Limits and retention](https://developers.cloudflare.com/workflows/reference/limits/)
