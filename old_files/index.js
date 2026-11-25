/**
 * Cloudflare Workers Selective Honeypot with IP Logging
 * 
 * This worker:
 * 1. Extracts client IP from multiple headers
 * 2. Logs all requests to D1 database
 * 3. Checks if IP is in blocklist
 * 4. Returns fake data for blocked IPs (with delay)
 * 5. Forwards legitimate requests to origin server
 * 
 * Required: D1 database binding named "DB"
 */
export default {
	async fetch(request, env) {
		try {
			// Extract client IP from all possible headers (CF, proxy, CDN, etc.)
			const clientIP = this.getClientIP(request);

			// Gather request metadata for logging
			const userAgent = request.headers.get('User-Agent') || 'unknown';
			const method = request.method;
			const url = request.url;
			const timestamp = new Date().toISOString();

			// Log in D1 and get unique token for this IP
			const token = await this.logClientIP(env.DB, clientIP, userAgent, method, url, timestamp);

			// Check if this IP should be blocked (return fake data)
			const shouldBlock = await this.isBlockedIP(env.DB, clientIP);

			if (shouldBlock) {
				const delay_in_seconds = 5;
				await new Promise((resolve) => setTimeout(resolve, delay_in_seconds * 1000));
				return this.getFakeResponse(request);
			}

			// Fetch the original request to forward legitimate traffic
			const response = await fetch(request);
			// Forward legitimate requests to origin server
			const contentType = response.headers.get('Content-Type') || '';
			// Add Token Tracker into the HTML response, at random location
			if (contentType.includes('text/html')) {
				let html = await response.text();
				if (token) {
					const injection = `<!-- tracker:${token} -->`;

					// Find all safe injection points between tags: ><
					const safeMatches = [...html.matchAll(/>(\s*)</g)];

					if (safeMatches.length > 0) {
						const match = safeMatches[Math.floor(Math.random() * safeMatches.length)];
						const index = match.index + 1; // position right after `>`

						// Inject the token between tags
						html = html.slice(0, index) + injection + html.slice(index);
					} else {
						// Fallback: inject at end of body
						html = html.replace(/<\/body>/i, `${injection}</body>`);
					}
				}
				return new Response(html, {
					status: response.status,
					headers: {
						'Content-Type': 'text/html',
						'X-Tracker-Injected': 'true',
						'X-Tracker-Token': token || 'none'
					}
				});
			}
			// For non-HTML content, just add header
			const newHeaders = new Headers(response.headers);
			if (token) newHeaders.set('X-Tracker-Token', token);

			return new Response(response.body, {
				status: response.status,
				headers: newHeaders,
			});

		} catch (error) {
			console.error('Worker error:', error);
			// Fallback: forward to origin on error to maintain availability
			const response = await fetch(request);
			return response;
		}
	},

	/**
	 * Check if an IP address exists in the suspicious_requests table (return fake data)
	 * Add suspicious/malicious IPs to this list
	 */
	async isBlockedIP(db, clientIP) {
		try {
			const result = await db.prepare(
				`SELECT 1 FROM suspicious_requests WHERE ip_address = ? LIMIT 1`
			).bind(clientIP).first();

			if (result) {
				console.log(`Blocked IP found in suspicious_requests: ${clientIP}`);
				return true;
			}

			return false;
		} catch (error) {
			console.error('Failed to query suspicious_requests table:', error);
			// Default to not blocking on error
			return false;
		}
	},

	/**
	 * Log client IP and request details to D1 database
	 * Uses UPSERT to either insert new IP or update existing with incremented count
	 * Tracks both legitimate and blocked IPs for analysis
	 */
	async logClientIP(db, ip, userAgent, method, url, timestamp) {
		try {

			// Check if IP already exists and retrieve existing token if any
			const result = await db
				.prepare(`SELECT token FROM ip_logs WHERE ip_address = ?`)
				.bind(ip)
				.first();

			let token = result?.token;// If no token exists yet, generate and assign one
			if (!token) {
				token = crypto.randomUUID(); // Generates a unique identifier

				await db.prepare(`
        INSERT INTO ip_logs (ip_address, user_agent, method, url, timestamp, last_seen, request_count, token) 
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(ip_address) DO UPDATE SET 
          request_count = request_count + 1,
          last_seen = ?,
          user_agent = ?,
          method = ?,
          url = ?
      `).bind(
					ip, userAgent, method, url, timestamp, timestamp, token,
					timestamp, userAgent, method, url
				).run();
			} else {
				// Just update the log if token exists
				await db.prepare(`
        UPDATE ip_logs SET 
          request_count = request_count + 1,
          last_seen = ?,
          user_agent = ?,
          method = ?,
          url = ?
        WHERE ip_address = ?
      `).bind(timestamp, userAgent, method, url, ip).run();
			}

			console.log(`Logged request from IP: ${ip}, Token: ${token}`);
			return token;
		} catch (error) {
			console.error('Failed to log IP/token:', error);
			return null;
		}
	},

	/**
	 * Extract client IP from comprehensive list of headers
	 * Checks 15+ different headers used by various proxies, CDNs, and load balancers
	 */
	getClientIP(request) {
		// List of headers that might contain client IP (in order of preference)
		const ipHeaders = [
			'CF-Connecting-IP',           // Cloudflare's standard header
			'CF-Connecting-IPv6',         // Cloudflare IPv6
			'True-Client-IP',             // Cloudflare Enterprise feature
			'X-Forwarded-For',            // Standard proxy header (comma-separated list)
			'X-Real-IP',                  // Nginx proxy
			'X-Forwarded',                // Older variant
			'X-Cluster-Client-IP',        // Cluster environments  
			'X-Client-IP',                // Generic client IP header
			'Client-IP',                  // Some CDNs/proxies
			'Forwarded-For',              // Alternative name
			'Forwarded',                  // RFC 7239 standard
			'X-Originating-IP',           // Some proxies
			'X-Remote-IP',                // Remote IP header
			'X-Remote-Addr'               // Remote address header
		];

		// Try each header in order of preference
		for (const header of ipHeaders) {
			const value = request.headers.get(header);
			if (value) {
				// Handle comma-separated values (common in X-Forwarded-For)
				if (header === 'X-Forwarded-For' || header === 'Forwarded-For') {
					// Take the first IP (original client) from comma-separated list
					return value.split(',')[0].trim();
				}
				// Handle RFC 7239 Forwarded header format: "for=192.168.1.1;proto=https"
				else if (header === 'Forwarded') {
					const forMatch = value.match(/for=([^;,\s]+)/i);
					if (forMatch) {
						let ip = forMatch[1];
						// Remove quotes and brackets if present
						return ip.replace(/["'\[\]]/g, '');
					}
				}
				// Direct IP value in header
				return value.trim();
			}
		}

		// Fallback: try Cloudflare Workers specific request object
		if (request.cf && request.cf.ip) {
			return request.cf.ip;
		}

		return 'unknown';
	},

	/**
	 * Generate fake responses for blocked IPs based on requested path
	 * Returns different fake JSON data depending on the endpoint
	 * Only called for IPs in the blocklist
	 */
	getFakeResponse(request) {
		const url = new URL(request.url);
		const pathname = url.pathname;
		const clientIP = this.getClientIP(request);

		// Fake response configurations for different endpoints
		const fakeResponses = {
			'/api/users': {
				status: 200,
				data: {
					users: [
						{ id: 1, name: "John Doe", email: "john@example.com" },
						{ id: 2, name: "Jane Smith", email: "jane@example.com" }
					],
					total: 2
				}
			},

			'/api/products': {
				status: 200,
				data: {
					products: [
						{ id: 1, name: "Widget A", price: 19.99 },
						{ id: 2, name: "Widget B", price: 29.99 }
					]
				}
			},

			'/admin': {
				status: 403,
				data: { error: "Access denied" }
			},

			'/login': {
				status: 200,
				data: { message: "Please enter credentials" }
			},

			// Default fake response for unmatched paths
			'default': {
				status: 200,
				data: {
					message: "Service temporarily unavailable",
					status: "maintenance",
					retry_after: 3600
				}
			}
		};

		// Find matching fake response configuration or use default
		const responseConfig = fakeResponses[pathname] || fakeResponses['default'];

		// Return fake JSON response with custom headers for blocked IPs
		return new Response(JSON.stringify(responseConfig.data), {
			status: responseConfig.status,
			headers: {
				'Content-Type': 'application/json',
				//'X-Fake-Response': 'true', // Identifier for fake responses
				//'X-Client-IP-Blocked': clientIP || 'unknown', // Show blocked IP in response
				//'X-Block-Reason': 'IP in blocklist' // Reason for blocking
			}
		});
	}
};
