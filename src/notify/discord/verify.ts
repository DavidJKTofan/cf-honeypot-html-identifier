/**
 * Discord interaction signature verification (Ed25519, Web Crypto).
 * Signed message = X-Signature-Timestamp + raw body; key = app public key (hex).
 * https://docs.discord.com/developers/interactions/receiving-and-responding
 */

function hexToBytes(hex: string): Uint8Array | null {
	if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2 !== 0) return null;
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

/** Reject stale timestamps to limit replay of captured requests. */
const MAX_SKEW_SECONDS = 300;

export async function verifyDiscordSignature(
	publicKeyHex: string,
	signatureHex: string | null,
	timestamp: string | null,
	rawBody: string,
	nowSeconds = Math.floor(Date.now() / 1000),
): Promise<boolean> {
	if (!signatureHex || !timestamp || !publicKeyHex) return false;
	const ts = Number(timestamp);
	if (!Number.isFinite(ts) || Math.abs(nowSeconds - ts) > MAX_SKEW_SECONDS) return false;
	const key = hexToBytes(publicKeyHex);
	const sig = hexToBytes(signatureHex);
	if (!key || key.byteLength !== 32 || !sig || sig.byteLength !== 64) return false;
	try {
		const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "Ed25519" }, false, ["verify"]);
		return await crypto.subtle.verify("Ed25519", cryptoKey, sig, new TextEncoder().encode(timestamp + rawBody));
	} catch {
		return false;
	}
}
