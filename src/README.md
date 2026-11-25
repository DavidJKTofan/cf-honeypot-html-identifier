# `src/`: Worker source

`index.ts` is the entry point. Its [`fetch` handler](https://developers.cloudflare.com/workers/runtime-apis/handlers/fetch/) routes every request, and it exports the two [Workflow](https://developers.cloudflare.com/workflows/) classes. Each folder has its own README.

| Folder | Responsibility |
|---|---|
| [`core/`](core/README.md) | Typed config from [`vars`](https://developers.cloudflare.com/workers/configuration/environment-variables/), and shared helpers ([Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/), bounded body reads, [structured logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)) |
| [`identity/`](identity/README.md) | Request fingerprint → sealed 91-character token → hidden HTML carriers via [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/) (and extracting them again) |
| [`honeypot/`](honeypot/README.md) | Trap link, decoy and tarpit, robots.txt, foreign-Referer events, clone-discovery beacon |
| [`storage/`](storage/README.md) | [D1](https://developers.cloudflare.com/d1/) (flags, leads, cases) and [Workers Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/) (per-request detail) |
| [`approvals/`](approvals/README.md) | The only place that enforces: shared human-approved actions, cases, [WAF list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/) sync, Cloudflare-IP protection |
| [`notify/`](notify/README.md) | Human-in-the-loop channels (Discord bot or webhook; Slack and Telegram via the same interface) |
| [`admin/`](admin/README.md) | Bearer-protected admin API (`/__hp/*`), split into route modules |
| [`integrations/cloudflare/`](integrations/cloudflare/README.md) | [REST APIs](https://developers.cloudflare.com/fundamentals/api/how-to/make-api-calls/) that have no [binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/) (Lists, Intel, URL Scanner, Brand Protection, Abuse Reports), [Cloudflare IP ranges](https://www.cloudflare.com/ips/) |
| [`workflows/`](workflows/README.md) | `InvestigateWorkflow` (per case) and `MaintenanceWorkflow` (daily) |

## Request routing (`index.ts`)

```
/__hp/*                               → admin/router.ts      (404 without bearer token)
POST /integrations/discord/interactions → notify/discord/interactions.ts (Ed25519-verified)
POST /api/rum                         → honeypot/beacon.ts   (pending lead)
(any request with a foreign Referer   → Analytics Engine "hotlink" event)
/assets/js/rum.js                     → beacon script
/catalog/full-export                  → honeypot/trap.ts     (pending flag + decoy)
/robots.txt                           → upstream + Disallow trap (in every user-agent group)
static assets                         → pass through
everything else                       → active-flag lookup ∥ origin fetch → decoy | 403 | tokenized HTML
```

Dependencies point inward:

```
admin, notify, workflows → approvals → storage, integrations → identity, core
```

`core` imports nothing from the other folders.
