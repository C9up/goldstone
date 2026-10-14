/**
 * What an inbound handler needs from the HTTP request, structurally — a
 * Ream `HttpContext` fits, and so does a plain object in a test.
 */

export interface InboundResponse {
	status(code: number): InboundResponse;
	json(data: unknown): void;
}

export interface InboundHttpContext {
	request: {
		/**
		 * The parsed BODY only — never merged with the query string, where a
		 * caller could set a field the provider did not sign.
		 */
		body(): unknown;
	};
	response: InboundResponse;
}

/**
 * Remembers the tokens of deliveries already handled, so a captured
 * request cannot be replayed. The in-memory default covers one process;
 * several instances need a shared store (Redis…) behind this interface.
 */
export interface ReplayGuard {
	/**
	 * Take the token for `ttlSeconds`. `false` when it is already taken — a
	 * delivery handled, or being handled right now. Must be atomic: two
	 * requests racing with the same token must not both get `true`.
	 */
	claim(token: string, ttlSeconds: number): boolean | Promise<boolean>;
	/** Give a token back, so a delivery whose handling failed can be retried. */
	release(token: string): void | Promise<void>;
}

/** One process's tokens, each kept for its TTL, at most `capacity` of them. */
export class MemoryReplayGuard implements ReplayGuard {
	readonly #capacity: number;
	readonly #tokens = new Map<string, number>();

	constructor(capacity = 100_000) {
		this.#capacity = capacity;
	}

	claim(token: string, ttlSeconds: number): boolean {
		const until = this.#tokens.get(token);
		if (until !== undefined && until > Date.now()) return false;
		this.#store(token, ttlSeconds);
		return true;
	}

	release(token: string): void {
		this.#tokens.delete(token);
	}

	#store(token: string, ttlSeconds: number): void {
		if (this.#tokens.size >= this.#capacity) {
			const now = Date.now();
			for (const [key, until] of this.#tokens) {
				if (until <= now) this.#tokens.delete(key);
			}
			// Still full: drop the oldest. Map keeps insertion order.
			while (this.#tokens.size >= this.#capacity) {
				const oldest = this.#tokens.keys().next();
				if (oldest.done) break;
				this.#tokens.delete(oldest.value);
			}
		}
		this.#tokens.set(token, Date.now() + ttlSeconds * 1000);
	}
}

/** A body field as a single string, or `undefined`. */
export function field(body: unknown, name: string): string | undefined {
	if (typeof body !== "object" || body === null) return undefined;
	const value: unknown = Reflect.get(body, name);
	if (typeof value === "string") return value;
	// A field sent twice arrives as a list: ambiguous, refused.
	return undefined;
}
