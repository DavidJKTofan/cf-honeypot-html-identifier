# `public/`: demo site (Workers Static Assets)

`index.html`, `article.html`, `styles.css`, `robots.txt` and the favicons (`favicon.ico`, `favicon.png`) make up a fictional outdoor shop ("Example Trail Co.") with original demo text. They're served through `env.ASSETS` with `run_worker_first: true`, so every page passes through the Worker and gets tokenized.

- `robots.txt`: the Worker appends `Disallow: <TRAP_PATH>` at runtime.
- `favicon.ico` (32×32) and `favicon.png` (also used as the Apple touch icon) are linked from both pages and from the decoy page. They're static files, so they skip all honeypot logic.
- `.assetsignore`: keeps this README and macOS `.DS_Store` files out of the deployed assets.

In front of a real origin, remove the `assets` block from `wrangler.jsonc`. The Worker then forwards requests with `fetch(request)`.

[Static Assets](https://developers.cloudflare.com/workers/static-assets/) · [`run_worker_first`](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/) · [`.assetsignore`](https://developers.cloudflare.com/workers/static-assets/binding/#ignoring-assets)
