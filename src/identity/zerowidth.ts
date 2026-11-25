/**
 * Zero-width text watermark (opt-in carrier "zw").
 *
 * Encodes the 68 sealed token bytes as 272 invisible characters (2 bits each),
 * so the token survives scrapers that keep only the text. Caveat: legitimate
 * quoting carries it too, and the decoded token then names the quoter's page
 * load, not a scraper. Off by default for that reason.
 */
import { SEALED_LENGTH } from "./token";
import { b64urlEncode } from "../core/util";

// U+200B ZERO WIDTH SPACE, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER.
// None of these are Unicode White_Space, so String.trim() keeps them.
const SYMBOLS = ["​", "‌", "‍", "⁠"] as const;
const INDEX = new Map<string, number>(SYMBOLS.map((s, i) => [s, i]));

export const ZW_LENGTH = SEALED_LENGTH * 4;
export const ZW_RUN = new RegExp(`[${SYMBOLS.join("")}]{${ZW_LENGTH}}`, "g");

export function encodeZeroWidth(bytes: Uint8Array): string {
	let out = "";
	for (const byte of bytes) {
		for (let shift = 6; shift >= 0; shift -= 2) out += SYMBOLS[(byte >> shift) & 3];
	}
	return out;
}

export function decodeZeroWidth(text: string): Uint8Array | null {
	const chars = Array.from(text);
	if (chars.length % 4 !== 0) return null;
	const out = new Uint8Array(chars.length / 4);
	for (let i = 0; i < out.length; i++) {
		let byte = 0;
		for (let j = 0; j < 4; j++) {
			const v = INDEX.get(chars[i * 4 + j] ?? "");
			if (v === undefined) return null;
			byte = (byte << 2) | v;
		}
		out[i] = byte;
	}
	return out;
}

/** Find every complete zero-width token run in a text and return base64url tokens. */
export function findZeroWidthTokens(text: string): string[] {
	const tokens: string[] = [];
	for (const match of text.matchAll(ZW_RUN)) {
		const bytes = decodeZeroWidth(match[0]);
		if (bytes && bytes.byteLength === SEALED_LENGTH) tokens.push(b64urlEncode(bytes));
	}
	return tokens;
}

export function isZeroWidthChar(ch: string): boolean {
	return INDEX.has(ch);
}
