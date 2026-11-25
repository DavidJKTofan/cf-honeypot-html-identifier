# `src/notify/`: human-in-the-loop notifications

This folder asks a human before anything consequential happens, so automation can't overwhelm Workflows or run unnecessary ones.

- New leads, cases awaiting a decision, and pending trap flags are posted to a chat channel.
- Nothing starts or enforces until someone clicks (or runs the CLI).
- The actual work lives in [`src/approvals/actions.ts`](../approvals/README.md). Every channel calls the same actions.

| File | Purpose |
|---|---|
| `types.ts` | The `Notifier` interface and the notice payloads (`LeadNotice`, `CaseNotice`, `FlagNotice`) |
| `index.ts` | `getNotifier()` (picks the adapter from `NOTIFY_CHANNEL`), `notifySafe()`, `resolveSafe()` and `updateOrPostLead()` (edit a lead message in place, else post one). Notifications never throw and are rate-limited by `NOTIFY_LIMITER` (a [Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)) |
| [`discord/`](discord/README.md) | Discord bot with buttons, or a Discord webhook (notify-only) |

## Configuration

| Setting | Values |
|---|---|
| `NOTIFY_CHANNEL` (var) | `discord` (bot and buttons, recommended) · `discord-webhook` (notify-only) · `none` |
| Credentials | See [discord/README.md](discord/README.md). Missing credentials mean notifications are off; the CLI still works |

## Safeguards against flooding

- **Leads:** notified **once per host**, on first sight. Repeat beacons only increase the lead's hit count, and lead writes themselves are capped per host, per token and globally (see [honeypot](../honeypot/README.md)). Two bounded exceptions: the first beacon token for a pending `referer` or `brand_protection` lead updates its message once ([corroborated](../approvals/README.md#corroborated-leads)), and a re-scrape re-opens an investigated host at most once per 24 hours ([re-scraped](../approvals/README.md#re-scraped-hosts)).
- **Rate limit:** `NOTIFY_LIMITER` allows 20 notifications per minute per location. When it's exceeded, the notification is skipped and the lead stays visible in `npm run hp -- leads`.
- **Trap flags:** these can be numerous, so they arrive as **one daily digest** of the top 5 (`npm run hp -- notify-flags` sends one now).
- **Duplicate approvals** never start a second Workflow: the lead is claimed atomically, and a partial unique index in D1 allows only one open case per host.
- **Concurrency:** the `honeypot-investigate` Workflow is capped at 5 running instances in `wrangler.jsonc` ([concurrency limits](https://developers.cloudflare.com/workflows/build/concurrency-limits/)). Instances waiting for a decision don't count.

## Using another channel (Slack, Telegram, …)

Discord is one adapter, and any chat tool with buttons or callbacks can do the same job:
1. Implement `Notifier` in `src/notify/<channel>/`. `updateLead` may return `false` when the channel can't edit a posted message; a new message is posted instead.
2. Add a case to `getNotifier()`.
3. Add an endpoint that **verifies the platform's signature** and maps button clicks to `approvals/actions.ts`.

| Channel | Post | Buttons | Callback verification |
|---|---|---|---|
| **Slack** | `chat.postMessage` (bot token), or an Incoming Webhook (notify-only) | Block Kit `actions` block | [`X-Slack-Signature`](https://docs.slack.dev/authentication/verifying-requests-from-slack): HMAC-SHA256 of `v0:{timestamp}:{body}` with the signing secret. Reply within 3 s, update through `response_url` |
| **Telegram** | [Bot API](https://core.telegram.org/bots/api) `sendMessage` | `reply_markup.inline_keyboard` (`callback_data` ≤ 64 bytes) | `setWebhook` with a `secret_token`, then check the `X-Telegram-Bot-Api-Secret-Token` header. Handle `callback_query`, `answerCallbackQuery`, `editMessageReplyMarkup` |
| **Email / ticketing** | Send the report link | n/a | Approve through the CLI or admin API |

Every adapter must keep two rules: an **approver allowlist**, and the rule that **values from beacons are untrusted** (render them as code, never as links or mentions).

## Usage

```bash
npm run hp -- notify-test
```

```bash
npm run hp -- notify-flags
```

`notify-test` posts a test message (with a **Check access** button on Discord). `notify-flags` posts the pending-flag digest now.
