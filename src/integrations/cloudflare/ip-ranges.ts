/**
 * Cloudflare IP ranges: never flag, decoy or block them.
 *
 * Requests from Cloudflare IPs are Cloudflare itself (Workers subrequests,
 * URL Scanner, Browser Rendering, health checks…) or a customer's Worker.
 * Blocking those breaks Cloudflare features and punishes the wrong party;
 * the right channel for abuse on Cloudflare is an abuse report.
 *
 * Source of truth: https://api.cloudflare.com/client/v4/ips (public, no auth),
 * cached at the edge for 24h, with a bundled snapshot as fallback.
 */
import { ipToBytes } from "../../identity/token";
import { errorMessage, log } from "../../core/util";

export const CLOUDFLARE_IPS_URL = "https://api.cloudflare.com/client/v4/ips";

/** Snapshot taken 2026-11-24 (etag 38f79d050aa027e3be3865e495dcc9bc). */
export const CLOUDFLARE_IPS_SNAPSHOT = {
	ipv4_cidrs: [
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	],
	ipv6_cidrs: [
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	],
};

interface Cidr {
	bytes: Uint8Array;
	/** Prefix length in the 128-bit (IPv4-mapped) space. */
	bits: number;
}

export interface CloudflareRanges {
	cidrs: Cidr[];
	source: "api" | "snapshot";
}

export function parseCidr(cidr: string): Cidr | null {
	const [addr, len] = cidr.split("/");
	const bytes = ipToBytes(addr ?? "");
	const n = Number(len);
	if (!bytes || !Number.isInteger(n)) return null;
	const isV4 = (addr ?? "").includes(".");
	const bits = isV4 ? n + 96 : n;
	return bits >= 0 && bits <= 128 ? { bytes, bits } : null;
}

export function cidrContains(cidr: Cidr, ip: Uint8Array): boolean {
	const full = Math.floor(cidr.bits / 8);
	for (let i = 0; i < full; i++) if (cidr.bytes[i] !== ip[i]) return false;
	const rest = cidr.bits % 8;
	if (rest === 0) return true;
	const mask = (0xff << (8 - rest)) & 0xff;
	return ((cidr.bytes[full] ?? 0) & mask) === ((ip[full] ?? 0) & mask);
}

function build(list: { ipv4_cidrs?: string[]; ipv6_cidrs?: string[] }, source: CloudflareRanges["source"]): CloudflareRanges {
	const cidrs = [...(list.ipv4_cidrs ?? []), ...(list.ipv6_cidrs ?? [])]
		.map(parseCidr)
		.filter((c): c is Cidr => c !== null);
	return { cidrs, source };
}

/** Live list (edge-cached 24h), falling back to the bundled snapshot. */
export async function loadCloudflareRanges(): Promise<CloudflareRanges> {
	try {
		const res = await fetch(CLOUDFLARE_IPS_URL, {
			cf: { cacheTtl: 86_400, cacheEverything: true },
			signal: AbortSignal.timeout(1_500),
		});
		if (res.ok) {
			const body = (await res.json()) as { result?: { ipv4_cidrs?: string[]; ipv6_cidrs?: string[] } };
			const ranges = build(body.result ?? {}, "api");
			if (ranges.cidrs.length > 0) return ranges;
		}
	} catch (err) {
		log("warn", "cloudflare ip ranges: using bundled snapshot", { error: errorMessage(err) });
	}
	return build(CLOUDFLARE_IPS_SNAPSHOT, "snapshot");
}

export function isCloudflareIp(ip: string, ranges: CloudflareRanges): boolean {
	const bytes = ipToBytes(ip);
	return bytes !== null && ranges.cidrs.some((c) => cidrContains(c, bytes));
}

export interface HostingCheck {
	host: string;
	ips: string[];
	/** Every resolved address is a Cloudflare address (proxied by / hosted on Cloudflare). */
	onCloudflare: boolean;
	error?: string;
}

/** Resolve A/AAAA over DNS-over-HTTPS (1.1.1.1) and test against Cloudflare ranges. No quota. */
export async function checkCloudflareHosting(host: string, ranges: CloudflareRanges): Promise<HostingCheck> {
	const ips: string[] = [];
	try {
		for (const type of ["A", "AAAA"]) {
			const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`;
			const res = await fetch(url, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(5_000) });
			if (!res.ok) continue;
			const body = (await res.json()) as { Answer?: { type: number; data: string }[] };
			for (const a of body.Answer ?? []) if (a.type === 1 || a.type === 28) ips.push(a.data);
		}
	} catch (err) {
		return { host, ips, onCloudflare: false, error: errorMessage(err) };
	}
	return { host, ips, onCloudflare: ips.length > 0 && ips.every((ip) => isCloudflareIp(ip, ranges)) };
}
