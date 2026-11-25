# `src/honeypot/`: trap, decoy and beacon

| File | Purpose |
|---|---|
| `trap.ts` | Trap-path hit → **pending** flag (skipped for [verified bots](https://developers.cloudflare.com/bots/concepts/bot/verified-bots/), [bot score](https://developers.cloudflare.com/bots/concepts/bot-score/) ≥ 30 and [Cloudflare IPs](https://www.cloudflare.com/ips/)). D1 writes are bounded per IP (`TRAP_LIMITER`, 2/min) **and** globally (`TRAP_GLOBAL_LIMITER`, 30/min), both [Rate Limiting bindings](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) counted per Cloudflare location; the decoy is served either way. Also: decoy HTML or JSON (still tokenized), tarpit ([`scheduler.wait`](https://developers.cloudflare.com/workers/runtime-apis/scheduler/), wall time only), robots.txt (`addTrapDisallow` adds `Disallow: <TRAP_PATH>` to **every** `User-agent` group, because under [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.1) a crawler with its own group ignores `*`; the origin file is read with a 512 KiB cap), foreign Referer on a **subresource** load ([`Sec-Fetch-Dest`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Dest); never a link click) → `hotlink` event. A hotlink is loaded by the clone's *visitor*, so it is scrubbed exactly like a beacon event (`scrubVisitorSignals`): only our path, coarse country/colo, the clone page (Referer) and the clone host are stored |
| `beacon.ts` | Beacon script (canonical hosts and endpoint stored as character codes) and the `POST /api/rum` receiver → **pending** lead via `approvals/leads.ts`. A beacon becomes a lead only if its token opens, its `Origin` (when present) matches the reported page, and it passes three limits: per clone host and per token (`BEACON_LIMITER`, 10/min each) and global (`LEAD_LIMITER`, 30/min). The token is checked before the per-host budget is charged, and invalid reports have their own key (`beacon-invalid:<host>`), so forged reports can't use up a real clone's budget. Everything that could identify the clone's visitor is dropped before the Analytics Engine write: IP, JA3/JA4, User-Agent, city, ASN and AS organization, RTT, detection IDs, `CF-Worker`, Accept-Language and the visitor's Ray ID. The lead keeps the **scraper's** full token and the IP inside it (`leads.token`, `leads.token_ip`): evidence when a copy cloaks the investigator, and the signal that re-opens an investigated host after a re-scrape from a new IP ([approvals](../approvals/README.md#re-scraped-hosts)). The script trims the meta value before matching |

**Nothing here enforces anything.** Decoys are served only for flags a human has approved (see [approvals](../approvals/README.md)).

## Usage

```bash
curl -s https://honeypot.automatic-demo.com/robots.txt
```

Every `User-agent` group in that file includes `Disallow: /catalog/full-export`. On this zone, Cloudflare's [managed robots.txt](https://developers.cloudflare.com/bots/additional-configurations/managed-robots-txt/) (Content Signals and AI crawler rules) is prepended above the Worker's output, and the trap rule stays.

robots.txt [applies per host](https://developers.google.com/crawling/docs/robots-txt/robots-txt-spec): `https://automatic-demo.com/robots.txt` doesn't govern `honeypot.automatic-demo.com`, so the apex site's file needs no change. Any other host that serves tokenized pages must route `/robots.txt` and `TRAP_PATH` through this Worker (see [Route coverage, robots.txt and the trap](../../README.md#route-coverage-robotstxt-and-the-trap) in the root README).

```bash
npm run hp -- flags pending
```

That lists the trap hits waiting for approval. A beacon fires only when a page runs on a host outside `CANONICAL_HOSTS`. Benign proxies (Google Translate, the Wayback Machine, archive.today, Google cache) and the hosts in `REFERER_IGNORE` are ignored.

## Zone configuration notes

- **Don't challenge or block the beacon.** `POST <BEACON_PATH>` comes from the browsers of a clone's visitors: `sendBeacon` sends a browser User-Agent without JavaScript-detection cookies for your zone, so "pretend browser" or bot-score rules match it. On the demo account a rule like `ACCOUNT-LEVEL LOG Pretend-Browsers` logs every beacon; if such a rule is switched to *Block* or *Managed Challenge*, discovery silently stops. Exclude `BEACON_PATH` (POST, small body) from those rules.
- **Hotlinks need no skip.** They are ordinary asset loads; Hotlink Protection (Scrape Shield) would block image hotlinks before the Worker sees them, so keep it off if you rely on Referer discovery for images.

## Known bypasses

A determined scraper can silence discovery: strip the script, stub `navigator.sendBeacon`, send a strict CSP (`connect-src 'self'`) or `Referrer-Policy: no-referrer`, self-host every asset, or skip `hidden` links and robots-disallowed paths so the trap never fires. These carriers are tripwires for verbatim copies, not prevention. See [ROADMAP.md, "Live test findings and scraper bypasses"](../../ROADMAP.md#live-test-findings-and-scraper-bypasses-2026-11-25) for what is planned.
