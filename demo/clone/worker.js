/**
 * Demo clone of YOUR OWN honeypot site (see DEMO.md). Two modes on one hostname:
 *
 * - Static copy (every path except /live/*): the files demo/scrape.sh saved, served as
 *   Static Assets. The tokens inside name the machine that ran the scraper.
 * - Live reverse proxy (/live/*): fetches ORIGIN on every request, like a mirror running
 *   on Workers. Each token then names the Worker's egress (a Cloudflare IP), which the
 *   honeypot never blocks: the report names the CF-Worker zone for an abuse report instead.
 *
 * Delete it after the demo: npx wrangler delete --config demo/clone/wrangler.jsonc
 */
export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (url.pathname !== "/live" && !url.pathname.startsWith("/live/")) return env.ASSETS.fetch(request);

		const upstream = new URL(url.pathname.slice("/live".length) || "/", env.ORIGIN);
		upstream.search = url.search;
		const res = await fetch(upstream, {
			headers: { "user-agent": request.headers.get("user-agent") ?? "Mozilla/5.0", accept: "text/html,*/*" },
		});
		const type = res.headers.get("content-type") ?? "";
		if (!type.includes("text/html")) return new Response(res.body, { status: res.status, headers: { "content-type": type } });
		const html = (await res.text()).replaceAll(env.BRAND_FROM, env.BRAND_TO).replace(/(href|src)="\/(?!\/)/g, '$1="/live/');
		return new Response(html, { status: res.status, headers: { "content-type": "text/html; charset=utf-8" } });
	},
};
