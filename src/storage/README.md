# `src/storage/`: D1 and Analytics Engine

| File | Purpose |
|---|---|
| `d1.ts` | All SQL. The hot path is one indexed read (`activeFlagAction`) through the [Sessions API](https://developers.cloudflare.com/d1/best-practices/read-replication/), served by the nearest read replica once [read replication is enabled](https://developers.cloudflare.com/d1/best-practices/read-replication/#enable-read-replication) on the database (see [Test and deploy](../../README.md#test-and-deploy) in the root README), and it fails open. Writes are bounded: leads are deduped by host, trap writes are rate-limited, and rows expire daily. Approval state changes are atomic claims (`UPDATE … WHERE status = …`, checked with `meta.changes`; a lead's first beacon token with `WHERE token IS NULL`), and multi-row approvals use [`batch()`](https://developers.cloudflare.com/d1/worker-api/d1-database/) |
| `analytics.ts` | `writeEvent()` writes one non-blocking [Workers Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/) data point. `lookupRay()` and `topForeignHosts()` read it through the [**Analytics SQL Workers binding**](https://developers.cloudflare.com/analytics/sql-api/workers-binding/), with no API token |

## Tables

All tables are defined in [`migrations/`](../../migrations/README.md).

| Table | Rows created by | Key columns |
|---|---|---|
| `flags` | trap hits (pending), approvals | `indicator`, `action` decoy/block, `status` pending/active/rejected, `expires_at` |
| `leads` | beacons, hotlinks, Brand Protection | `host` (unique), `status`, `notify_ref`, `token` and `token_ip` (the scraper's beacon-reported token and the IP inside it, never the visitor's), `reopened_at` |
| `cases` | approved leads / manual cases | `status`, `report_key`, `hosted_on_cloudflare`, `abuse_report`, `decided_by`. A partial unique index allows one open case per host |
| `case_tokens` | `InvestigateWorkflow` | decoded `ray_id`, `ip`, `asn`, `issued_at` per case |

## Analytics Engine `honeypot_events`

| Column | Meaning |
|---|---|
| `index1` | Ray ID (page, decoy, trap) or foreign host (hotlink, beacon) |
| `blob1` | type: `page` · `decoy` · `trap` · `hotlink` · `beacon` · `beacon_invalid` |
| `blob2`–`blob4` | host, path, ip |
| `blob5`–`blob7` | User-Agent, JA4, JA3 |
| `blob8`–`blob11` | ASN organization, country, colo, city |
| `blob12`–`blob15` | HTTP protocol, TLS version, Referer, Accept-Language |
| `blob16`–`blob18` | detection IDs, verified-bot category, Ray ID |
| `blob19` | foreign host |
| `blob20` | note, or the `CF-Worker` zone (page, decoy and trap events from a Cloudflare Worker) |

`beacon` and `hotlink` events come from a clone's *visitor*: their IP, User-Agent, JA3/JA4, city, ASN, AS organization, RTT, detection IDs, Accept-Language, `CF-Worker` and Ray ID columns are always empty. `beacon` events carry the scraper's token Ray ID in `blob20`.
| `double1`–`double4` | bot score, ASN, issuedAt, client TCP RTT |

Retention is [3 months](https://developers.cloudflare.com/analytics/analytics-engine/limits/); the token itself never expires. Beacon events never carry the clone visitor's IP, JA4, User-Agent, city, ASN or Ray ID.

## Usage

```bash
npx wrangler d1 execute DB --remote --command "SELECT status, COUNT(*) FROM flags GROUP BY status"
```

([`wrangler d1 execute`](https://developers.cloudflare.com/workers/wrangler/commands/d1/))

```bash
curl "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/analytics_engine/sql" \
  -H "Authorization: Bearer $TOKEN" \
  --data "SELECT blob1 AS type, SUM(_sample_interval) AS events FROM honeypot_events WHERE timestamp > NOW() - INTERVAL '1' DAY GROUP BY type"
```

The [Analytics Engine SQL API](https://developers.cloudflare.com/analytics/analytics-engine/sql-api/) needs an `Account Analytics Read` token. Count with `SUM(_sample_interval)`, not `count()`: Analytics Engine [samples](https://developers.cloudflare.com/analytics/analytics-engine/sampling/) busy indexes. Queries through the Workers binding (the newer [SQL API](https://developers.cloudflare.com/analytics/sql-api/)) apply sample weights to `COUNT` automatically.

## References

[D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/) · [D1 indexes](https://developers.cloudflare.com/d1/best-practices/use-indexes/) · [D1 retries](https://developers.cloudflare.com/d1/best-practices/retry-queries/) · [D1 limits](https://developers.cloudflare.com/d1/platform/limits/) · [Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/) · [Analytics SQL binding](https://developers.cloudflare.com/analytics/sql-api/workers-binding/)
