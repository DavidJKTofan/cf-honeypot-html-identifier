// Optional secrets not listed in `secrets.required` (so `wrangler types` omits them).
interface OptionalSecrets {
	// Account-specific identifiers, kept as secrets so they never appear in the (public) repo.
	/** Cloudflare account ID used for REST calls (Lists, Intel, URL Scanner, Brand Protection, abuse reports). */
	ACCOUNT_ID?: string;
	/** ID of the account-level WAF IP list (e.g. "honeypot_blocked"); empty = block sync disabled. */
	WAF_LIST_ID?: string;
	DISCORD_APPLICATION_ID?: string;
	/** Discord application public key (hex), used to verify interaction signatures. */
	DISCORD_PUBLIC_KEY?: string;
	DISCORD_CHANNEL_ID?: string;
	/** Comma-separated Discord user IDs allowed to click approval buttons. */
	DISCORD_APPROVER_IDS?: string;
	/** Comma-separated Discord role IDs allowed to click approval buttons. */
	DISCORD_APPROVER_ROLE_IDS?: string;
	/** Access team domain, e.g. "<team>.cloudflareaccess.com". With ACCESS_AUD set, the admin API requires a valid Access JWT. */
	ACCESS_TEAM_DOMAIN?: string;
	/** Audience (AUD) tag of the Access application that protects ADMIN_PREFIX. */
	ACCESS_AUD?: string;

	/** Previous TOKEN_KEY, tried on decode of version 1 tokens. */
	TOKEN_KEY_PREVIOUS?: string;
	/**
	 * Token key ring, JSON `{"3":"<base64>","2":"<base64>"}` (IDs 0-255): the highest ID seals
	 * version 2 tokens, every ID decodes. Unset = version 1 tokens sealed with TOKEN_KEY.
	 * Malformed entries are logged and skipped. Runbook: src/identity/README.md#key-rotation.
	 */
	TOKEN_KEYS?: string;
	/** Scoped API token: Account Filter Lists Edit, Intel Read, URL Scanner Edit (+ Trust and Safety Write to submit abuse reports). */
	CF_API_TOKEN?: string;
	/** Discord bot token (Bot page of your Discord application). Enables interactive approvals. */
	DISCORD_BOT_TOKEN?: string;
	/** Discord channel webhook URL: notification-only fallback (no buttons). */
	DISCORD_WEBHOOK_URL?: string;
	/** JSON with the abuse reporter's identity (name, email, address…); needed only to submit reports. */
	ABUSE_REPORTER_JSON?: string;
}

// Optional bindings you add to your own wrangler.jsonc (they need account-specific IDs).
interface OptionalBindings {
	/**
	 * Secrets Store secret holding the TOKEN_KEYS JSON (`secrets_store_secrets` binding). When
	 * bound, it replaces TOKEN_KEYS and is read at request time, so a rotation needs no redeploy.
	 */
	TOKEN_KEYS_STORE?: SecretsStoreSecret;
}

interface Env extends OptionalSecrets, OptionalBindings {}

declare namespace Cloudflare {
	interface Env extends OptionalSecrets, OptionalBindings {}
}
