# `src/admin/`: admin API

Everything lives under `ADMIN_PREFIX` (default `/__hp`). **The endpoint contract is [`openapi.yaml`](openapi.yaml)** (OpenAPI 3.1); `test/openapi.test.ts` fails if a documented operation isn't routed.

Authentication, one of:
- **Cloudflare Access (production).** With `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` set, the Worker requires the `Cf-Access-Jwt-Assertion` header that Access adds after a person or a service token passes its policies. It verifies the JWT against the team's public keys (RS256, `aud`, `iss`, `exp`/`nbf`, 60 s skew). The bearer token is ignored, and actions are attributed to `access:<email>` or `access-service:<client id>`. Setup: [below](#cloudflare-access).
- **Bearer token (local dev, or no Access app).** `Authorization: Bearer $ADMIN_TOKEN`, compared in constant time ([`timingSafeEqual`](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)); the actor is `admin`.

Anything unauthenticated gets a plain **404**, so the surface isn't advertised. That's why a browser shows `Not Found` at `/__hp/whoami` without Access, and the Access login page with it.

| File | Purpose |
|---|---|
| `router.ts` | `authenticate()` (Access JWT, else bearer), then hands the request to the route modules (each returns a `Response` or `null`). Their `env.DB` retries transient write errors ([`storage/retry.ts`](../storage/README.md)) |
| `access.ts` | `verifyAccessJwt()`: Access JWT verification with Web Crypto; keys from `https://<team>/cdn-cgi/access/certs`, edge-cached 5 min and refetched once on an unknown `kid` |
| `openapi.yaml` | OpenAPI 3.1 description of every admin endpoint, its auth schemes and schemas |
| `context.ts` | `AdminContext`, the admin `Actor`, and shared helpers |
| `decode.ts` | `fetchPage()` (keeps the first 2 MiB and sets `truncated` instead of failing on bigger pages; 15 s timeout; ordinary browser headers with `CAPTURE_USER_AGENT`, so a clone can't cloak by User-Agent), `decodeTokens()` (open the tokens, enrich from [Analytics Engine](https://developers.cloudflare.com/analytics/analytics-engine/)), `describeErrorPage()` (for a non-2xx capture: the Cloudflare error code from [`cf-error-type`](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-error-headers/) or an `error code: 1xxx` body, and a short plain-text preview) |
| `routes/decode.ts` | `GET /whoami` (token, fingerprint, `actor`, `auth`) · `POST /decode {token \| html \| html_b64 \| url}` (a `url` response includes `fetched.truncated`, and `fetched.error` when the URL didn't answer 2xx) |
| `routes/leads.ts` | `GET /leads?status=` · `POST /leads/:id/approve` · `POST /leads/:id/dismiss` |
| `routes/cases.ts` | `GET/POST /cases` · `GET /cases/:id` · `/report` · `/evidence/:file` · `POST /cases/:id/decision` · `POST /cases/:id/abuse-report` · `POST /cases/:id/abuse-report/reset` |
| `routes/flags.ts` | `GET/POST /flags` · `POST /flags/approve` · `POST /flags/reject` · `DELETE /flags/:indicator`. `POST /flags` returns `400` for a CIDR range, an unparseable IP or a malformed JA4. `DELETE` canonicalises the IP first; if the WAF list item couldn't be removed, the response carries a `note` and the daily reconcile removes it |
| `routes/ops.ts` | `POST /notify/test` · `POST /notify/flags` · `POST /maintenance/run` |

Approvals made here and approvals made with Discord buttons go through the same [`approvals/actions.ts`](../approvals/README.md). An approval made here also updates the matching Discord message.

## Usage

Use the CLI wrapper (see [`scripts/`](../../scripts/README.md)):

```bash
npm run hp -- decode https://suspected-clone.example/page
```

If the URL doesn't answer with a 2xx page, the result says so in `fetched.error` instead of reporting only `candidates: 0`. For example, a Pages hostname with no live project behind it gives:

```json
"error": { "cloudflareError": "1016", "preview": "error code: 1016", "note": "HTTP 530: no page was served, so a missing token proves nothing" }
```

`1016` is Cloudflare's [Origin DNS error](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1016/); other codes are listed under [Cloudflare 1xxx errors](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/). The preview comes from a third-party page, so treat it as data.

```bash
npm run hp -- report case-mwurl1pf-982048f6
```

Or call the API directly (with Access, send the service token; Access forwards the JWT):

```bash
curl -s -X POST https://honeypot.automatic-demo.com/__hp/decode \
  -H "CF-Access-Client-Id: $HP_ACCESS_CLIENT_ID" -H "CF-Access-Client-Secret: $HP_ACCESS_CLIENT_SECRET" \
  -H "content-type: application/json" -d '{"url":"https://suspected-clone.example/page"}'
```

Without Access (local dev), send `-H "Authorization: Bearer $ADMIN_TOKEN"` instead.

Send pasted HTML as `html_b64`. Raw `<script>` markup in a JSON body can be blocked by [WAF managed rules](https://developers.cloudflare.com/waf/managed-rules/).

## Cloudflare Access

Access authenticates admin requests at the edge, before the Worker runs, and replaces the shared bearer token with per-person SSO plus a revocable service token for automation. It's the recommended production setup.

### What the demo uses

| Piece | Setting |
|---|---|
| Application | Self-hosted, **"Demo · Honeypot Admin API"**, destination `honeypot.automatic-demo.com/__hp` (a path app covers every sub-path), session 24 h, hidden from the App Launcher, **`service_auth_401_redirect: true`** (a rejected service token gets `401`, not a login redirect) |
| Policy 1 (people) | The account's reusable **"Allow · Owner (Passkey)"** policy: browser login, then `GET /__hp/whoami` works |
| Policy 2 (automation) | A reusable **"Service · Honeypot Admin CLI"** policy, action **Service Auth** (`non_identity`), including one [service token](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) "Honeypot Admin CLI" (1-year duration: renew it before it expires) |
| Worker secrets | `ACCESS_TEAM_DOMAIN` (`<team>.cloudflareaccess.com`) and `ACCESS_AUD` (the application's AUD tag). Account-specific, so secrets, not `vars` |
| CLI | `HP_ACCESS_CLIENT_ID` and `HP_ACCESS_CLIENT_SECRET` in `.env` (gitignored). **Never in `.dev.vars`**: `wrangler deploy --secrets-file .dev.vars` would upload them to the Worker |

### Set it up

1. **Service token:** Zero Trust → Access controls → Service credentials → **Create service token**. Copy the Client ID and Secret now; the secret is shown once.
2. **Service policy:** Access controls → Policies → **Add a policy**, action **Service Auth**, include *Service Token* = that token.
3. **Application:** Access controls → Applications → **Self-hosted** → public hostname `<your-host>` with path `__hp`. Add your people policy first, then the service policy. Under advanced settings, turn on **Return 401 response for service auth policies**.
4. **Worker secrets:** copy the application's **AUD** tag (Overview tab), then:
   ```bash
   npx wrangler secret put ACCESS_TEAM_DOMAIN --env=""
   ```
   ```bash
   npx wrangler secret put ACCESS_AUD --env=""
   ```
   Then deploy. From now on the bearer token is no longer accepted in production.
5. **CLI:** put the service token in `.env`, then check:
   ```bash
   npm run hp -- whoami
   ```
   The response should show `"auth": "access"` and an `access-service:` actor.

The same through the API ([applications](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/create/), [policies](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/policies/methods/create/), [service tokens](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/create/); token permissions *Access: Apps and Policies Write* and *Access: Service Tokens Write*):

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/access/service_tokens" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "content-type: application/json" \
  --data '{"name":"Honeypot Admin CLI","duration":"8760h"}'
```

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/access/policies" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "content-type: application/json" \
  --data '{"name":"Service · Honeypot Admin CLI","decision":"non_identity","include":[{"service_token":{"token_id":"<token-id>"}}]}'
```

```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/access/apps" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H "content-type: application/json" \
  --data '{"type":"self_hosted","name":"Honeypot Admin API","domain":"<your-host>/__hp","destinations":[{"type":"public","uri":"<your-host>/__hp"}],"session_duration":"24h","app_launcher_visible":false,"service_auth_401_redirect":true,"policies":[{"id":"<people-policy-id>","precedence":1},{"id":"<service-policy-id>","precedence":2}]}'
```

The response's `aud` is the value for `ACCESS_AUD`.

### Security notes

- **Fail closed.** With the secrets set, a request without a valid JWT gets `404`, even if the Access app was deleted or doesn't cover the path. Access also overwrites any client-supplied `Cf-Access-Jwt-Assertion` header, which the live test confirmed.
- **Only `ADMIN_PREFIX` is behind Access.** The site, the beacon, the trap and the Discord Interactions Endpoint stay public by design, and Discord's clicks are verified with Ed25519.
- **Attribution.** `decided_by`, logs and Discord summaries name the Access identity. Revoke a leaked service token in Zero Trust; nothing in the Worker changes.
- **Local dev** has no Access: `secrets.required` doesn't load the two secrets locally, so `npm run dev` keeps using the bearer token.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `302` to `…cloudflareaccess.com/cdn-cgi/access/login/…` | No Access session or service token (CLI: set `HP_ACCESS_CLIENT_ID`/`_SECRET`) |
| `401` from Access | Wrong or expired service token, or it isn't in the app's Service Auth policy |
| `404 Not Found` with a valid login | The Worker rejected the JWT: `ACCESS_AUD` isn't this app's AUD, `ACCESS_TEAM_DOMAIN` is wrong, or the app doesn't cover the path. Workers Logs show `admin: access jwt rejected` with the reason |
| `cf-mitigated: challenge` | A zone WAF rule, see below |

## Zone WAF and the admin path

The zone's WAF runs before the Worker, so admin calls go through it too:
- **Attack-score rules can still challenge base64 bodies.** In the live test, a rule `cf.waf.score lt 20 → Managed Challenge` challenged `POST /__hp/decode` with `html_b64` for one page and not another. On the demo zone that rule now excludes `honeypot.automatic-demo.com` + `/__hp/*` (Access and the JWT check authenticate every admin request). The response is a challenge page with [`cf-mitigated: challenge`](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/); the CLI detects it and prints the Ray ID instead of the HTML. Fixes, best first:
  1. Put [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/) with a [service token](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) in front of `ADMIN_PREFIX`. Then a narrowly scoped [skip rule](https://developers.cloudflare.com/waf/custom-rules/skip/) for the attack-score rule on `(http.host eq "<host>" and starts_with(http.request.uri.path, "/__hp/") and http.request.method in {"GET" "POST" "DELETE"})` is reasonable, because Access still authenticates every request and the bearer token is still checked.
  2. Without Access, don't skip the WAF for a public path that anyone can hit; decode a raw token (`hp decode <token>`) instead of a whole page.
- **A blocked IP is blocked here too.** The `honeypot_blocked` rule matches every path on the host. If you approve a block for your own IP while testing, remove the list item in the dashboard or through the API; the admin route itself runs before the Worker's flag lookup, so the Worker's `403` fallback never locks you out.
- **`decode` by URL is a Worker fetch.** It carries `CF-Worker: <your zone>` and comes from Cloudflare's network, which a clone can detect even with a browser User-Agent.
