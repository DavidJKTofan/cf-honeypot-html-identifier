# `demo/`: demo kit

Everything a presenter needs to run the live demo in [DEMO.md](../DEMO.md): a scraper, a clone, and the screenshots for the guide.

| File | Purpose |
|---|---|
| `scrape.sh` | Copies **your own** honeypot site the way a careless cloner would: a browser User-Agent, robots.txt ignored, the hidden trap link followed, rebranded, assets hotlinked. Writes to `clone/site/` and prints the tokens it captured |
| `clone/worker.js` · `clone/wrangler.jsonc` | The clone: the scraped files as [Static Assets](https://developers.cloudflare.com/workers/static-assets/), plus `/live/*`, a reverse proxy of the original, like a mirror running on Workers. Deploy it on a hostname in a **second zone** you control |
| `screenshots/` | Images used by DEMO.md, named `NN-short-name.png` (the list is in [DEMO.md](../DEMO.md#screenshots)) |

## Usage

```bash
demo/scrape.sh
```

```bash
npx wrangler deploy --config demo/clone/wrangler.jsonc
```

```bash
npx wrangler delete --config demo/clone/wrangler.jsonc
```

Set the clone hostname in `clone/wrangler.jsonc` first, and use a fresh subdomain for every demo: the honeypot notifies once per clone host. `scrape.sh` takes `ORIGIN`, `BRAND_FROM`/`BRAND_TO`, `HOTLINK=0` and `SKIP_TRAP=1` (see the header of the script).

## Ground rules

- **Only against a site you operate.** The kit copies and republishes a site. Point it at your honeypot deployment, nothing else.
- **`clone/site/` is gitignored.** Its pages hold tokens that name the machine that ran the scraper.
- **The scraper's IP gets attributed, and maybe decoyed or blocked.** Run `scrape.sh` from a network you can afford to have blocked on the honeypot host (a phone hotspot or a cloud VM), not the office network you present from.
- **Delete the clone after the demo.**
