# `src/identity/`: the hidden identifier

This folder turns a request into a sealed token, hides the token in HTML, and finds it again in a copy.

| File | Purpose |
|---|---|
| `fingerprint.ts` | `collectSignals(request)`, from trusted sources only: [`CF-Connecting-IP`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip), [`cf-ray`](https://developers.cloudflare.com/fundamentals/reference/cloudflare-ray-id/), [`CF-Worker`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-worker), [`request.cf`](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties) (ASN, geo, TLS, [Bot Management](https://developers.cloudflare.com/bots/reference/bot-management-variables/)). `scrubVisitorSignals()` blanks everything that identifies a clone's visitor (beacon and hotlink events). `verifiedBot` is set from `request.cf.botManagement.verifiedBot` **or** `request.cf.verifiedBotCategory`, the Workers equivalents of `cf.bot_management.verified_bot` / `cf.client.bot` ([verified bots](../approvals/README.md#verified-bots)) |
| `token.ts` | Binary fingerprint → AES-256-GCM ([Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)) → 91-character base64url token, with a key ID in version 2; IPv4/IPv6 packing; the `TOKEN_KEYS` key ring and [key rotation](#key-rotation) |
| `carriers.ts` | `injectCarriers()` (streaming [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/)) and `scanHtml()` (extracts every token-shaped attribute and zero-width runs, labelled `meta`, `meta-fallback`, `form`, `form-fallback` or `attr:<tag>[<attr>]`). Attribute values are entity-decoded (`decodeCharRefs`) and trimmed before matching, see below |
| `zerowidth.ts` | Opt-in text watermark: 272 invisible characters, 2 bits each |

**Token layout:** every version seals to 68 bytes, which is 91 base64url characters, so carriers, the scanner, the beacon and the zero-width carrier don't depend on the version. Tampered tokens and tokens from another key fail to open.

| | Version 1 (`TOKEN_KEY`) | Version 2 (`TOKEN_KEYS`) |
|---|---|---|
| Clear header | none | version (`2`) and key ID (0–255), XORed with the first two IV bytes, authenticated as additional data |
| IV | 12 random bytes | 12 random bytes |
| Encrypted payload | 40 bytes: version · issuedAt · IP (16 bytes) · ASN · country (2) · colo (3) · bot score · flags · Ray ID (8 bytes) | 38 bytes: the same fields without the version byte, and country plus colo packed into 4 bytes (five 6-bit symbols) |
| GCM tag | 16 bytes | 16 bytes |
| Decode | tries `TOKEN_KEY`, then `TOKEN_KEY_PREVIOUS` | reads the key ID and uses that one key |

The header is masked so that every token still looks uniformly random, like a version 1 token or a framework CSRF token. A constant per-key prefix would give scrapers a signature to strip ([ROADMAP B2](../../ROADMAP.md#live-test-findings-and-scraper-bypasses-2026-11-25)). This is camouflage, not secrecy: anyone can unmask the header (`readTokenHeader`), and only the key makes a token valid. About 1 in 256 version 1 tokens look like a version 2 header by chance; decode then falls back to the version 1 keys.

## Carriers (`CARRIERS`)

| Carrier | Default | Markup |
|---|---|---|
| `meta` | on | `<meta name="csrf-token" content="…">`, or `request-id` when the page already has a real CSRF meta tag. Goes before `</head>`; if the page omits `</head>` (valid HTML, common when minified), at the start of `<body>`, else at the end of the document |
| `trap` | on | `<a href="/catalog/full-export" rel="nofollow" hidden aria-hidden tabindex=-1>` |
| `beacon` | on | `<script src="https://<host>/assets/js/rum.js" defer>` |
| `zw` | off | zero-width characters after the first text chunk of the first `<p>` |
| `form` | off | `<input type="hidden" name="_csrf">` just before `</form>`, or `request_id` when the form already has a real `_csrf` field (Spring Security, Express csurf). Forms without an end tag are skipped |

## The scanner sees what a browser sees

HTMLRewriter (lol-html) hands attribute values to handlers **raw**: `content="&#100;gCj…"` reaches `scanHtml` with the `&#100;` still in it, while a browser decodes it to `d`. A live test showed the bypass: encoding one character left the page and the beacon working (the browser decodes it, so the visitor's beacon reports a valid token), but the investigator found 0 candidates and the case closed as `no_evidence`. `scanHtml` therefore decodes numeric references (`&#100;`, `&#x64;`, with or without `;`) and the named references that can produce token or URL characters, and trims whitespace, before it applies the token pattern. Over-decoding is harmless: a wrong string just fails AES-GCM.

A copy that changes or drops a character still defeats every scanner: the token simply no longer opens. The lead's beacon token is the fallback evidence for that case (see [workflows](../workflows/README.md#investigateworkflow-steps)).

## Usage

```ts
const s = collectSignals(request);
const token = await sealToken(s, await loadSealingKey(env)); // newest TOKEN_KEYS ID, else TOKEN_KEY (v1)
return injectCarriers(response, { token, cfg, origin: url.origin });

const { tokens } = await scanHtml(copiedHtml, cfg);
const ring = await loadTokenKeys(env);
const opened = await openToken(tokens[0].token, ring); // null if forged, tampered or the key is gone
// opened: { fingerprint, version, keyId, legacyKey, retired }
if (opened) logRetiredKeys("decode", [opened], ring.currentKeyId);
```

## Key rotation

AES-GCM with random 96-bit IVs should seal at most about 2³² tokens per key ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), section 8.3). That's roughly 43 days at 100 million pages a day. Past that, the chance of an IV collision grows, and a collision lets someone forge tokens, which could frame an innocent IP. Rotate on a schedule sized to your traffic: monthly is a safe default up to about 100 million pages a day.

### The key ring

`TOKEN_KEYS` is an optional secret holding a JSON object of key ID to base64 key:

```json
{"3": "<base64 32-byte key>", "2": "<base64 32-byte key>", "1": "<base64 32-byte key>"}
```

- The **highest ID seals** new tokens (version 2). **Every ID decodes.** Entry order doesn't matter.
- IDs are integers from 0 to 255, written without leading zeros. Never reuse an ID for a different key: copies sealed under the old key would stop decoding.
- A malformed entry (bad ID, a key that isn't 32 bytes) is skipped and logged as `token_keys_entry_skipped` by the decode paths (beacon, admin decode, Workflow). An unparseable value is logged as `token_keys_invalid`. Neither is ever fatal. The HTML path logs nothing (it runs on every page), so a malformed newest entry silently leaves the previous ID sealing: check with step 4 below.
- Without `TOKEN_KEYS`, or when it has no usable entry, the Worker seals version 1 tokens with `TOKEN_KEY`, as before.
- `TOKEN_KEY` (required) and `TOKEN_KEY_PREVIOUS` keep decoding version 1 tokens forever. Once the ring is in use, don't change `TOKEN_KEY`: it only decodes old copies. Ring keys never open version 1 tokens.

`TOKEN_KEYS` isn't in `secrets.required`, so `wrangler dev` doesn't load it from `.dev.vars` (only listed secrets load locally). Tests set it in `vitest.config.ts`.

### Runbook

1. **Add a key under a new, higher ID**, keeping every older entry: `npm run token-keys -- add`. It generates a random 32-byte key on your machine and writes the ring to `.dev.vars` (gitignored) as one line, `TOKEN_KEYS='{"2":"…","1":"…"}'`, printing only key IDs. `npm run token-keys -- status` shows which ID seals. On first adoption this creates `{"1": …}`; leave `TOKEN_KEY` and `TOKEN_KEY_PREVIOUS` as they are, since they decode your version 1 copies. By hand instead: `openssl rand -base64 32` on a trusted machine, never pasted into tickets or chat, added under the next ID.
2. **Back up the ring:** copy the `TOKEN_KEYS` line into your password manager. Cloudflare can't show a secret again, and every later rotation needs the older keys. Losing an old key makes the copies sealed with it undecodable (they then look like forgeries).
3. **Upload it:** `npm run token-keys -- upload`, which pipes the ring into `npx wrangler secret put TOKEN_KEYS --env=""` without showing it. This deploys a new version of the Worker (same code; `npm run doctor` ignores secret-only deploys). With the Secrets Store binding (below), update the store secret instead; no deploy is needed.
4. **Check it seals with the new ID:** `npm run hp -- whoami` returns a fresh token; `npm run hp -- decode <token>` must show `"version": 2`, the new `"keyId"` and `"retiredKey": false`. If it shows the previous ID, the new entry was skipped: look for `token_keys_entry_skipped` in Workers Logs (the decode call just logged it).
5. **Watch for retired keys.** Every decode path logs `token_retired_key` (level `warn`) with `source` (`beacon`, `decode` or `workflow`), `tokenVersion`, `keyId` or `legacyKey`, `currentKeyId`, `count`, `oldestIssuedAt`, `newestIssuedAt` and `newestRayId`. Old copies carrying an old key are expected. A retired key whose `newestIssuedAt` is **later than the rotation** is not: something still seals with that key (a stale deployment or a second Worker), or the key leaked and someone is forging tokens. Treat those tokens as unconfirmed until you know which.
6. **Retire old keys for decoding only.** Keep an ID in the ring as long as you may need to decode copies sealed with it; the token never expires. Remove an ID only when you accept that copies sealed with it become undecodable (they then look like forgeries). There is room for 256 IDs: at monthly rotation that's over 20 years.

A suspected key leak is different from a scheduled rotation: add a new ID right away, and treat any token from the leaked ID issued after the leak as possibly forged.

### Secrets Store

[Secrets Store](https://developers.cloudflare.com/secrets-store/) keeps account-level secrets with their own [access roles](https://developers.cloudflare.com/secrets-store/access-control/) and audit logs, so fewer people need Worker edit rights to rotate a key. To use it, create a secret holding the same JSON and bind it as `TOKEN_KEYS_STORE` in your own `wrangler.jsonc` (the store ID is account-specific, so it isn't in this repo):

```jsonc
"secrets_store_secrets": [
	{ "binding": "TOKEN_KEYS_STORE", "store_id": "<your-store-id>", "secret_name": "honeypot-token-keys" }
]
```

When bound, `TOKEN_KEYS_STORE` replaces `TOKEN_KEYS`. It's read with `get()` on every HTML response and decode, so a rotation takes effect without a redeploy. If the read fails, the Worker logs `token_keys_store_failed` and falls back to `TOKEN_KEYS`, then to `TOKEN_KEY`, so pages keep getting a valid token.

## References

[HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/) · [NIST SP 800-38D (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final) · [Secrets](https://developers.cloudflare.com/workers/configuration/secrets/) · [Secrets Store](https://developers.cloudflare.com/secrets-store/integrations/workers/) · [Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/) · [`request.cf`](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties) · [Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/)
