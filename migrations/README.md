# `migrations/`: D1 schema

| Migration | Adds |
|---|---|
| `0001_init.sql` | `flags`, `leads`, `cases`, `case_tokens` and their indexes |
| `0002_notifications_abuse.sql` | `leads.notify_ref`, `cases.notify_ref`, `cases.hosted_on_cloudflare`, `cases.abuse_report`, `cases.decided_by` |
| `0003_approval_guards.sql` | Marks older duplicate open cases per host as `errored`, then adds the partial unique index `idx_cases_open_host` (one open case per host), `idx_flags_expires` for the daily purge, and runs [`PRAGMA optimize`](https://developers.cloudflare.com/d1/sql-api/sql-statements/#pragma-optimize) |
| `0004_lead_tokens.sql` | `leads.token` (the full beacon-reported token, evidence when the capture finds none), `leads.token_ip` (the scraper IP inside it, re-opens a host after a re-scrape) and `leads.reopened_at` |

The tables are small and bounded by design: nothing is written per request. Rows come from deduplicated, rate-limited honeypot events and from human actions, and expired rows are purged daily.

## Usage

```bash
npm run db:migrate:local
```

```bash
npm run db:migrate:remote
```

```bash
npx wrangler d1 migrations list DB --remote --env=""
```

([`wrangler d1 migrations`](https://developers.cloudflare.com/workers/wrangler/commands/d1/)) `db:migrate:local` targets the `dev` environment's local database, the one `npm run dev` uses. `npm run doctor` fails while the remote database has unapplied migrations.

Tests apply these migrations automatically (`test/apply-migrations.ts`). Add new changes as `000N_description.sql`, and never edit a migration that has already been applied.

## References

[D1 migrations](https://developers.cloudflare.com/d1/reference/migrations/) · [D1 SQL statements](https://developers.cloudflare.com/d1/sql-api/sql-statements/) · [Use indexes](https://developers.cloudflare.com/d1/best-practices/use-indexes/) · [Time Travel (point-in-time restore)](https://developers.cloudflare.com/d1/reference/time-travel/)
