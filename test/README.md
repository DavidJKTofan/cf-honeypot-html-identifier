# `test/`: Vitest in the Workers runtime

The tests run inside `workerd` through [`@cloudflare/vitest-plugin`](https://developers.cloudflare.com/workers/testing/vitest-integration/), using the bindings from `wrangler.jsonc`.
- `vitest.config.ts` overrides the secrets with test-only values, sets `TARPIT_MS=0`, and only collects `test/**/*.test.ts` (agent worktrees under `.claude/` are ignored).
- D1 migrations are applied by `apply-migrations.ts`.

| File | Covers |
|---|---|
| `token.test.ts` | Seal and open, fixed length, tampered or wrong key, key rotation, IPv4/IPv6 packing |
| `carriers.test.ts` | Injection and extraction for every carrier, renamed meta tags, a `<head>` without `</head>`, zero-width text, cache headers, beacon obfuscation; entity-encoded and whitespace-padded tokens (`decodeCharRefs`); junk candidates can't hide the real token |
| `cloudflare.test.ts` | Cloudflare IP range matching (a partial live list never drops a snapshot range); abuse-report draft and submission building (no pre-filled `agree`, Worker zone and live proxy in the evidence) |
| `discord.test.ts` | Ed25519 verification, PING/PONG, unauthorized clicks, approver flow (deferred update and D1 change), message helpers and wording (case vs digest buttons, beacon-only cases, re-scraped leads) |
| `evidence.test.ts` | Live reverse proxy detection, the Analytics Engine ingestion wait, the per-case token cap, decision targets (Cloudflare IPs and verified bots skipped), report rows and Markdown escaping |
| `investigate.test.ts` | `InvestigateWorkflow` end to end with the [Workflows test APIs](https://developers.cloudflare.com/workers/testing/vitest-integration/test-apis/#workflows): expiry, a decision claimed as the wait times out, block-to-decoy list removal, the token cap, no beacon token across hosts, an errored case releasing its lead |
| `leads.test.ts` | Beacon token and scraper IP on leads; re-opening an investigated host after a re-scrape (cooldown, dismissed, open case); corroboration (once, even when `NOTIFY_LIMITER` is exhausted); flag provenance on upsert |
| `access.test.ts` | Cloudflare Access JWT verification (real RSA keys: audience, issuer, expiry, tampering, `alg: none`, key rotation) and the admin router's Access-only auth |
| `openapi.test.ts` | `src/admin/openapi.yaml` documents 20 operations and every one is routed by the Worker |
| `hotlink.test.ts` | Foreign-Referer hotlink events: navigations ignored, subresources counted, benign hosts ignored, visitor data scrubbed |
| `approvals.test.ts` | Concurrency-safe approvals: concurrent lead approvals start one Workflow, a failed start rolls back, one open case per host (partial unique index), concurrent case decisions deliver one event, an abuse report is submitted once, D1 batch helpers, a lead's override URL must stay on its host, TTL bounds |
| `waf.test.ts` | `canonicalIp`, Lists API retries, one bulk write per decision, expired-block removal, reconcile (and its D1 cap), block-to-decoy list removal, admin flag validation |
| `robots.test.ts` | The trap `Disallow` reaches every crawler group (own groups, multi-agent groups, comments, CRLF, missing `*` group, empty file) |
| `abuse.test.ts` | Beacon bounds (Origin check, per-token and global lead limits), visitor-data scrubbing, trap global limit, form-carrier fallback, capture truncation, error-page previews (`describeErrorPage`) |
| `worker.test.ts` | End to end: tokenized pages, decode, 206 passthrough, static assets, robots.txt, the approval-gated trap and decoy, block fallback, Cloudflare IP protection, beacon leads (forged reports can't use up a host's budget), admin 404 |

## Usage

```bash
npm test
```

```bash
npx vitest --watch
```

## Notes

- `remoteBindings: false` keeps the tests offline ([remote bindings](https://developers.cloudflare.com/workers/local-development/#remote-bindings)). The [Analytics SQL binding](https://developers.cloudflare.com/analytics/sql-api/workers-binding/) is remote-only, so its "needs to be run remotely" messages are expected, and the code handles that failure.
- Without network access, the Cloudflare IP range fetch times out after 1.5 s and the bundled snapshot is used.
- Discord calls go to `DISCORD_API_BASE=http://127.0.0.1:9` and fail fast. Nothing ever reaches Discord from tests.
