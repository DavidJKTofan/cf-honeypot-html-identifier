# `test/`: Vitest in the Workers runtime

The tests run inside `workerd` through [`@cloudflare/vitest-plugin`](https://developers.cloudflare.com/workers/testing/vitest-integration/), using the bindings from `wrangler.jsonc`.
- `vitest.config.ts` overrides the secrets with test-only values, sets `TARPIT_MS=0`, and only collects `test/**/*.test.ts` (agent worktrees under `.claude/` are ignored).
- D1 migrations are applied by `apply-migrations.ts`.

| File | Covers |
|---|---|
| `token.test.ts` | Seal and open, fixed length, tampered or wrong key, key rotation, IPv4/IPv6 packing |
| `carriers.test.ts` | Injection and extraction for every carrier, renamed meta tags, zero-width text, cache headers, beacon obfuscation; entity-encoded and whitespace-padded tokens (`decodeCharRefs`) |
| `cloudflare.test.ts` | Cloudflare IP range matching; abuse-report draft and submission building (no pre-filled `agree`, Worker zone and live proxy in the evidence) |
| `discord.test.ts` | Ed25519 verification, PING/PONG, unauthorized clicks, approver flow (deferred update and D1 change), message helpers and wording (case vs digest buttons, beacon-only cases, re-scraped leads) |
| `evidence.test.ts` | Live reverse proxy detection, the Analytics Engine ingestion wait, decision targets (Cloudflare IPs and verified bots skipped), report rows |
| `leads.test.ts` | Beacon token and scraper IP on leads; re-opening an investigated host after a re-scrape (cooldown, dismissed, open case); flag provenance on upsert |
| `access.test.ts` | Cloudflare Access JWT verification (real RSA keys: audience, issuer, expiry, tampering, `alg: none`, key rotation) and the admin router's Access-only auth |
| `openapi.test.ts` | `src/admin/openapi.yaml` documents 20 operations and every one is routed by the Worker |
| `hotlink.test.ts` | Foreign-Referer hotlink events: navigations ignored, subresources counted, benign hosts ignored, visitor data scrubbed |
| `approvals.test.ts` | Concurrency-safe approvals: concurrent lead approvals start one Workflow, a failed start rolls back, one open case per host (partial unique index), concurrent case decisions deliver one event, an abuse report is submitted once, D1 batch helpers |
| `robots.test.ts` | The trap `Disallow` reaches every crawler group (own groups, multi-agent groups, comments, CRLF, missing `*` group, empty file) |
| `abuse.test.ts` | Beacon bounds (Origin check, per-token and global lead limits), visitor-data scrubbing, trap global limit, form-carrier fallback, capture truncation |
| `worker.test.ts` | End to end: tokenized pages, decode, static assets, robots.txt, the approval-gated trap and decoy, block fallback, Cloudflare IP protection, beacon leads, admin 404 |

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
