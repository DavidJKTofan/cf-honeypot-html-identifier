# `src/identity/`: the hidden identifier

This folder turns a request into a sealed token, hides the token in HTML, and finds it again in a copy.

| File | Purpose |
|---|---|
| `fingerprint.ts` | `collectSignals(request)`, from trusted sources only: [`CF-Connecting-IP`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-connecting-ip), [`cf-ray`](https://developers.cloudflare.com/fundamentals/reference/cloudflare-ray-id/), [`CF-Worker`](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-worker), [`request.cf`](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties) (ASN, geo, TLS, [Bot Management](https://developers.cloudflare.com/bots/reference/bot-management-variables/)). `scrubVisitorSignals()` blanks everything that identifies a clone's visitor (beacon and hotlink events). `verifiedBot` is set from `request.cf.botManagement.verifiedBot` **or** `request.cf.verifiedBotCategory`, the Workers equivalents of `cf.bot_management.verified_bot` / `cf.client.bot` ([verified bots](../approvals/README.md#verified-bots)) |
| `token.ts` | 40-byte binary layout → AES-256-GCM ([Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)) → 91-character base64url token; IPv4/IPv6 packing; key rotation (`TOKEN_KEY_PREVIOUS`) |
| `carriers.ts` | `injectCarriers()` (streaming [HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/)) and `scanHtml()` (extracts every token-shaped attribute and zero-width runs, labelled `meta`, `meta-fallback`, `form`, `form-fallback` or `attr:<tag>[<attr>]`). Attribute values are entity-decoded (`decodeCharRefs`) and trimmed before matching, see below |
| `zerowidth.ts` | Opt-in text watermark: 272 invisible characters, 2 bits each |

**Token layout:** version · issuedAt · IP (16 bytes) · ASN · country · colo · bot score · flags · Ray ID (8 bytes). Tampered tokens and tokens from another key fail to open.

## Carriers (`CARRIERS`)

| Carrier | Default | Markup |
|---|---|---|
| `meta` | on | `<meta name="csrf-token" content="…">`, or `request-id` when the page already has a real CSRF meta tag |
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
const token = await sealToken(s, await importTokenKey(env.TOKEN_KEY));
return injectCarriers(response, { token, cfg, origin: url.origin });

const { tokens } = await scanHtml(copiedHtml, cfg);
const fp = await openToken(tokens[0].token, await loadTokenKeys(env)); // null if forged or tampered
```

## References

[HTMLRewriter](https://developers.cloudflare.com/workers/runtime-apis/html-rewriter/) · [Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/) · [`request.cf`](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties) · [Bot Management variables](https://developers.cloudflare.com/bots/reference/bot-management-variables/)
