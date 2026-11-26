# `src/integrations/cloudflare/`: Cloudflare APIs without bindings

| File | Purpose |
|---|---|
| `api.ts` | REST client: WAF Lists, Threat Intel, URL Scanner, Brand Protection, Abuse Reports (`CF_API_TOKEN`). Retries `429` (and `5xx` for idempotent calls only: GET, DELETE, list-item upserts) up to 4 times with jittered exponential backoff, honours `retry-after` up to 8 s, and caps each call's total time (8 s on request paths, longer in Workflow steps). List writes are [asynchronous](https://developers.cloudflare.com/waf/tools/lists/lists-api/endpoints/#manage-items-in-a-list): `waitForListOperation` polls the bulk operation until `completed` or `failed`. A new write sent while one is still processing gets `429` ([Lists API rate limits](https://developers.cloudflare.com/waf/tools/lists/lists-api/#rate-limiting-for-lists-api-requests)). Abuse reports and URL Scanner submissions are never retried on `5xx` |
| `ip-ranges.ts` | Cloudflare IP ranges (live and edge-cached for 24 h, with a bundled snapshot fallback), `isCloudflareIp`, and a DNS-over-HTTPS hosting check |
| `abuse.ts` | Drafts a Cloudflare abuse report (DMCA, phishing or general) and builds the submission body |

## Token permissions (`CF_API_TOKEN`, optional)

[Create the token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) yourself (permission names: [API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)) and set it with:

```bash
npx wrangler secret put CF_API_TOKEN
```

| Feature | Permission |
|---|---|
| [WAF List](https://developers.cloudflare.com/waf/tools/lists/lists-api/) sync | Account Filter Lists Edit |
| [Threat Intel](https://developers.cloudflare.com/security-center/intel-apis/), [Brand Protection](https://developers.cloudflare.com/security-center/brand-protection/) | Intel Read (shares the [2,500 calls/month](https://developers.cloudflare.com/security-center/intel-apis/limits/) Enterprise quota) |
| [URL Scanner](https://developers.cloudflare.com/radar/investigate/url-scanner/) | URL Scanner Edit |
| [Submit abuse reports](https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/) | Trust and Safety Write. The account also needs the abuse-reports entitlement, which Enterprise has by default |
| [List submitted abuse reports](https://developers.cloudflare.com/api/resources/abuse_reports/subresources/submitted/methods/list/) (stuck-claim reset) | Trust and Safety Read or Write |

The token is used together with the **secrets** `ACCOUNT_ID` and `WAF_LIST_ID` (the ID of your `honeypot_blocked` IP list). They are kept out of the public repo; put them in `.dev.vars` and deploy with `--secrets-file`. Without the token, the Workflow steps that need it show as `skipped` in the report.

## Cloudflare IP ranges

`loadCloudflareRanges()` fetches <https://api.cloudflare.com/client/v4/ips> with [`cf.cacheTtl`](https://developers.cloudflare.com/workers/runtime-apis/request/) `= 86400` and **unions** the answer with `CLOUDFLARE_IPS_SNAPSHOT` (the snapshot alone if the fetch fails), so a partial answer can add ranges but never drop a protected one. They are used to:
- **never flag Cloudflare IPs** (trap, manual flags, approvals, case decisions, WAF sync)
- tell a reviewer when a *scraper* used Cloudflare infrastructure (a Cloudflare IP plus the [`CF-Worker`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-worker) zone stored in Analytics Engine `blob20`)
- detect copies **proxied by or hosted on Cloudflare**: `checkCloudflareHosting()` resolves A and AAAA records over [DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/) (`cloudflare-dns.com`, no quota) and reports `onCloudflare` when every address is a Cloudflare address

## Abuse reports

If a copy is on Cloudflare, the right channel is a [Cloudflare abuse report](https://developers.cloudflare.com/fundamentals/reference/report-abuse/). Cloudflare forwards it to the hosting provider and site owner. Otherwise, report to the host (URL Scanner ASN) or registrar (WHOIS abuse contact).

1. **Draft (default, `ABUSE_REPORTS="draft"`).** The Workflow writes `cases/<id>/abuse-report-draft.json`. It has the type (`ABUSE_REPORT_TYPE`: `abuse_dmca` · `abuse_phishing` · `abuse_general`), the URLs, the original work and an evidence summary (SHA-256, Ray IDs). When known, the summary also says the copy is a **live reverse proxy** and names the scraper's **`CF-Worker` zone**, which lets Cloudflare find the Worker. It holds **no personal data**, and it never pre-fills `agree` or `signature`: those are added only when a human submits. Review it and submit it at <https://abuse.cloudflare.com/>.
   - A draft is written only when the **capture itself** contains our token. A case whose only evidence is the beacon-reported token ("unconfirmed copy") gets no draft, because the report would claim the page contains our identifier, and a beacon report can be forged.
2. **Submit (opt-in, `ABUSE_REPORTS="submit"`).** An approver clicks *Submit Cloudflare abuse report*, or runs:
   ```bash
   npm run hp -- abuse-report <caseId>
   ```
   The draft is merged with the reporter identity from the `ABUSE_REPORTER_JSON` secret (plus `signature` = your name and, for DMCA, `agree: 1`, both set at this point only) and sent to `POST /accounts/{id}/abuse-reports/{report_type}`. The result is saved as `abuse-report-result.json`.

   The case is claimed (`abuse_report` = `{"status":"submitting",…}`) before the call, so two clicks never file twice. If the Worker dies during the call, that claim blocks the case. `npm run hp -- abuse-report-reset <caseId>` clears a claim older than 10 minutes, but only after it finds no `abuse-report-result.json` and no report for the case's host in the account's [submitted reports](https://developers.cloudflare.com/api/resources/abuse_reports/subresources/submitted/methods/list/) (`GET /accounts/{id}/abuse-reports/submitted`, Trust and Safety Read or Write) since the claim. A filed report is recorded on the case instead.
   ```bash
   npx wrangler secret put ABUSE_REPORTER_JSON
   ```
   ```json
   {"name":"Jane Doe","email":"legal@example.com","company":"Example Co","address1":"1 Main St","city":"Berlin","state":"BE","country":"DE"}
   ```

> [!WARNING]
> DMCA reports can't be anonymous. `signature` and `agree: 1` are statements made **under penalty of perjury**, and contact details may be shared with the host, the site owner and third parties such as the [Lumen Database](https://lumendatabase.org/). Submit only after reviewing the evidence. The API path segment `{report_param}` is the report type, the same value as `act` (for example `abuse_dmca`), as the [API reference](https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/) documents.

## References

[Report abuse](https://developers.cloudflare.com/fundamentals/reference/report-abuse/) · [Submit a report](https://developers.cloudflare.com/fundamentals/reference/report-abuse/submit-report/) · [Abuse Reports API](https://developers.cloudflare.com/api/resources/abuse_reports/methods/create/) · [Cloudflare IP ranges](https://www.cloudflare.com/ips/) · [WAF Lists API](https://developers.cloudflare.com/waf/tools/lists/lists-api/) · [Threat Intel APIs](https://developers.cloudflare.com/security-center/intel-apis/) · [URL Scanner](https://developers.cloudflare.com/radar/investigate/url-scanner/) · [Brand Protection](https://developers.cloudflare.com/security-center/brand-protection/) · [DNS over HTTPS (JSON)](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
