/**
 * Workers Analytics Engine: one non-blocking data point per tokenized page or
 * honeypot event. Cheap at millions/day, 3-month retention, queryable via the
 * Analytics SQL Workers binding (no API token).
 * https://developers.cloudflare.com/analytics/analytics-engine/
 * https://developers.cloudflare.com/analytics/sql-api/workers-binding/
 *
 * Column map (keep in sync with AGENTS.md):
 *   index1  Ray ID (page/decoy/trap) or foreign host (hotlink/beacon)
 *   blob1 type      blob2 host        blob3 path         blob4 ip
 *   blob5 userAgent blob6 ja4         blob7 ja3Hash      blob8 asOrganization
 *   blob9 country   blob10 colo       blob11 city        blob12 httpProtocol
 *   blob13 tlsVersion blob14 referer  blob15 acceptLanguage blob16 detectionIds
 *   blob17 verifiedBotCategory blob18 rayId blob19 foreignHost blob20 note | CF-Worker zone
 *   double1 botScore (-1 = n/a)  double2 asn  double3 issuedAt  double4 clientTcpRtt (-1 = n/a)
 */
import type { RequestSignals } from "../identity/fingerprint";
import { log, errorMessage, truncate } from "../core/util";

export type EventType = "page" | "decoy" | "trap" | "hotlink" | "beacon" | "beacon_invalid";

export const DATASET = "honeypot_events";
const TABLE = `events.analyticsEngine.${DATASET}`;

export function writeEvent(
	env: Env,
	type: EventType,
	s: RequestSignals,
	opts: { index?: string; foreignHost?: string; note?: string } = {},
): void {
	try {
		// Not awaited by design: writeDataPoint is non-blocking.
		env.EVENTS.writeDataPoint({
			indexes: [truncate(opts.index ?? s.rayId, 96)],
			blobs: [
				type,
				s.host,
				s.path,
				s.ip,
				s.userAgent,
				s.ja4,
				s.ja3Hash,
				s.asOrganization,
				s.country,
				s.colo,
				s.city,
				s.httpProtocol,
				s.tlsVersion,
				s.referer,
				s.acceptLanguage,
				s.detectionIds.join(","),
				s.verifiedBotCategory,
				s.rayId,
				truncate(opts.foreignHost, 256),
				truncate(opts.note ?? s.cfWorker, 256),
			],
			doubles: [s.botScore ?? -1, s.asn, s.issuedAt, s.clientTcpRtt ?? -1],
		});
	} catch (err) {
		log("warn", "analytics engine write failed", { error: errorMessage(err) });
	}
}

// A type alias (not an interface) so it satisfies Record<string, unknown> and Rpc.Serializable.
export type RayEnrichment = {
	timestamp: string;
	type: string;
	host: string;
	path: string;
	ip: string;
	user_agent: string;
	ja4: string;
	ja3_hash: string;
	as_organization: string;
	country: string;
	colo: string;
	city: string;
	http_protocol: string;
	tls_version: string;
	referer: string;
	accept_language: string;
	detection_ids: string;
	verified_bot_category: string;
	bot_score: number;
	asn: number;
	/** blob20: note, or the CF-Worker zone for requests made by a Cloudflare Worker. */
	note: string;
};

/** Look up the full request record for a Ray ID (within WAE's retention window). */
export async function lookupRay(env: Env, rayId: string, issuedAt: number): Promise<RayEnrichment | null> {
	const since = new Date((issuedAt - 3600) * 1000).toISOString();
	const result = await env.ANALYTICS_SQL.query<RayEnrichment>({
		query: `SELECT timestamp, blob1 AS type, blob2 AS host, blob3 AS path, blob4 AS ip,
			blob5 AS user_agent, blob6 AS ja4, blob7 AS ja3_hash, blob8 AS as_organization,
			blob9 AS country, blob10 AS colo, blob11 AS city, blob12 AS http_protocol,
			blob13 AS tls_version, blob14 AS referer, blob15 AS accept_language,
			blob16 AS detection_ids, blob17 AS verified_bot_category,
			double1 AS bot_score, double2 AS asn, blob20 AS note
			FROM ${TABLE}
			WHERE index1 = $ray AND timestamp >= $since
			LIMIT 1`,
		params: { ray: rayId, since },
	});
	return result.data[0] ?? null;
}

export interface HostHits {
	host: string;
	hits: number;
}

/** Foreign hosts that hotlinked our pages/assets (clone candidates). */
export async function topForeignHosts(env: Env, sinceUnix: number, limit = 50): Promise<HostHits[]> {
	const result = await env.ANALYTICS_SQL.query<{ host: string; hits: number | string }>({
		query: `SELECT blob19 AS host, COUNT(*) AS hits
			FROM ${TABLE}
			WHERE blob1 = 'hotlink' AND timestamp >= $since
			GROUP BY host
			ORDER BY hits DESC
			LIMIT ${Math.max(1, Math.min(limit, 500))}`,
		params: { since: new Date(sinceUnix * 1000).toISOString() },
	});
	return result.data.filter((r) => r.host).map((r) => ({ host: r.host, hits: Number(r.hits) }));
}
