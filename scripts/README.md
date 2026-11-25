# `scripts/`: admin CLI

`hp.mjs` is a dependency-free Node CLI for the [admin API](../src/admin/README.md).

**Setup**
- **With Cloudflare Access (production):** put the service token in `.env` (gitignored) as `HP_ACCESS_CLIENT_ID` and `HP_ACCESS_CLIENT_SECRET`, or export them. The CLI sends them as `CF-Access-Client-Id` / `CF-Access-Client-Secret`, and Access forwards a JWT the Worker verifies. Don't put them in `.dev.vars`: `wrangler deploy --secrets-file .dev.vars` would upload them as Worker secrets. See [src/admin/README.md](../src/admin/README.md#cloudflare-access).
- **Without Access (local dev):** the bearer token is read from `ADMIN_TOKEN` in `.dev.vars`, or from `HP_ADMIN_TOKEN`. It's sent when present, and the Worker ignores it once Access is configured.
- `HP_BASE` sets the target, which defaults to `https://honeypot.automatic-demo.com`.
- **Edge verdicts.** If Access asks for a login (no or missing service token) or rejects the token (`401`), the CLI says so. If Cloudflare challenges an admin call (`cf-mitigated: challenge`, for example an attack-score rule scoring a pasted page) or blocks it with a non-JSON `403` (for example your IP is in `honeypot_blocked`), the CLI prints what happened and the Ray ID, and exits with status 1, instead of printing the challenge page. See [src/admin/README.md](../src/admin/README.md#zone-waf-and-the-admin-path).

```bash
npm run hp -- <command> [args]
```

| Command | What it does |
|---|---|
| `whoami` | Token and fingerprint for your own request, plus who you're authenticated as (`actor`, `auth`) |
| `decode <url\|file.html\|token>` | Extract and verify identifiers. Files are sent base64-encoded so the zone's [WAF managed rules](https://developers.cloudflare.com/waf/managed-rules/) usually don't block them (an attack-score rule still can: then pass the raw token) |
| `leads [pending\|approved\|dismissed\|all]` | List clone leads |
| `approve-lead <id> [url]` · `dismiss-lead <id>` | Start or skip an investigation |
| `case <url>` · `cases` · `case-status <id>` | Manual case, list, status |
| `report <id> [json]` · `evidence <id> <file>` | Read the evidence bundle (for example `abuse-report-draft.json`) |
| `decide <id> <decoy\|block\|none> [ttlDays]` | Human decision for a case awaiting one |
| `abuse-report <id>` | Submit the Cloudflare abuse report draft (needs `ABUSE_REPORTS="submit"`) |
| `flags [status]` · `approve-flags <ind…>\|--all [--block]` · `reject-flags <ind…>` | Pending trap flags |
| `flag <ip> [decoy\|block] [ttlDays]` · `unflag <indicator>` | Manual flag for a single IPv4 or IPv6 address (CIDR ranges and Cloudflare IPs are refused) |
| `notify-test` · `notify-flags` | Test the notifier, or send the pending-flag digest now |
| `maintenance` | Run `MaintenanceWorkflow` now (it also runs daily on its [schedule](https://developers.cloudflare.com/workflows/build/trigger-workflows/)) |

## Examples

```bash
npm run hp -- decode ./saved-copy.html
```

```bash
npm run hp -- approve-lead 3
```

```bash
npm run hp -- report case-mwurl1pf-982048f6
```

```bash
npm run hp -- decide case-mwurl1pf-982048f6 none
```
