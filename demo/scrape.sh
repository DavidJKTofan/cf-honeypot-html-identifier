#!/usr/bin/env bash
# Demo scraper: copies YOUR OWN honeypot site the way a careless cloner would.
# Only run it against a site you operate (the honeypot demo). See DEMO.md.
#
#   demo/scrape.sh [origin] [out-dir]
#     origin   default https://honeypot.automatic-demo.com (or $ORIGIN)
#     out-dir  default demo/clone/site (gitignored: the pages carry tokens that name this machine)
#   BRAND_FROM / BRAND_TO   rebranding (default "Example Trail Co." -> "TrailDeals Outlet")
#   HOTLINK=0               copy CSS and favicons instead of hotlinking them from the origin
#   SKIP_TRAP=1             don't follow the hidden trap link (no pending flag, no tarpit)
set -euo pipefail

ORIGIN="${1:-${ORIGIN:-https://honeypot.automatic-demo.com}}"
ORIGIN="${ORIGIN%/}"
OUT="${2:-${OUT:-$(dirname "$0")/clone/site}}"
export ORIGIN BRAND_FROM="${BRAND_FROM:-Example Trail Co.}" BRAND_TO="${BRAND_TO:-TrailDeals Outlet}"
# Real scrapers spoof a browser. (The demo zone blocks curl/python/go User-Agents outright.)
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

fetch() { curl -sS -A "$UA" -o "$2" -w "HTTP %{http_code} in %{time_total}s" "$ORIGIN$1"; }

mkdir -p "$OUT/catalog"
echo "Scraping $ORIGIN into $OUT"
echo "  robots.txt says:"
curl -sS -A "$UA" "$ORIGIN/robots.txt" | grep -i "^disallow: /catalog" | sort -u | sed 's/^/    /'
echo "  ...and this scraper ignores it."
echo "  GET /         -> $(fetch / "$OUT/index.html")"
echo "  GET /article  -> $(fetch /article "$OUT/article.html")"
if [ "${SKIP_TRAP:-0}" != "1" ]; then
	echo "  GET /catalog/full-export (hidden link) -> $(fetch /catalog/full-export "$OUT/catalog/full-export.html")   <- the tarpit delay"
fi
for asset in styles.css favicon.ico favicon.png; do fetch "/$asset" "$OUT/$asset" >/dev/null; done

for f in "$OUT"/*.html "$OUT"/catalog/*.html; do
	[ -f "$f" ] || continue
	perl -pi -e 's/\Q$ENV{BRAND_FROM}\E/$ENV{BRAND_TO}/g' "$f"
	# Lazy cloners hotlink assets from the original, which shows up as a foreign Referer.
	if [ "${HOTLINK:-1}" = "1" ]; then
		perl -pi -e 's#(href|src)="/(styles\.css|favicon\.ico|favicon\.png)"#$1="$ENV{ORIGIN}/$2"#g' "$f"
	fi
done

echo "Tokens in the copy (each one names this machine's request):"
grep -ho 'csrf-token" content="[A-Za-z0-9_-]\{91\}' "$OUT"/*.html "$OUT"/catalog/*.html 2>/dev/null | cut -d'"' -f3 | sed 's/^/  /'
echo "Decode one offline:  npm run hp -- decode $OUT/index.html"
