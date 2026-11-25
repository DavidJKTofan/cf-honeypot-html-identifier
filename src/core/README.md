# `src/core/`: config and helpers

| File | Purpose |
|---|---|
| `config.ts` | `loadConfig(env)`: typed, validated view of `wrangler.jsonc` [`vars`](https://developers.cloudflare.com/workers/configuration/environment-variables/) (carriers, paths, TTLs, notify and Discord settings, abuse-report mode, the evidence-capture User-Agent `CAPTURE_USER_AGENT`, which defaults to `DEFAULT_CAPTURE_USER_AGENT`, a desktop Chrome UA, and `access` from the `ACCESS_TEAM_DOMAIN`/`ACCESS_AUD` secrets, which switches the admin API to Cloudflare Access). Parsed per request, with no module-level state |
| `util.ts` | base64url, SHA-256, constant-time compare ([`crypto.subtle.timingSafeEqual`](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)), Web Crypto random numbers, bounded body reads (`readStreamLimited`, `readJson`), structured JSON logs, static-asset detection, HTML escaping |

## Conventions

These follow the [Workers Best Practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/):

- Never store request data in module scope; isolates are reused across requests.
- Use `crypto.getRandomValues` / `randomInt`, never `Math.random`.
- Compare secrets with `timingSafeEqualStr`.
- Log with `log(level, message, fields)` so [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/) gets JSON.
- Read bodies through `readJson` / `readStreamLimited`, which have size caps.

## Usage

```ts
import { loadConfig } from "./core/config";
import { log, readJson } from "./core/util";

const cfg = loadConfig(env);
const body = await readJson<{ url?: string }>(request, 64 * 1024);
log("info", "decoded", { carriers: [...cfg.carriers] });
```
