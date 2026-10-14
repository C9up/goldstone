/**
 * Who really sent a message: DKIM, SPF, DMARC and ARC, checked in Rust
 * against DNS.
 *
 *   const authenticity = await authenticate(raw)
 *   if (authenticity.summary !== 'pass') {
 *     // the From cannot be trusted
 *   }
 *
 * `summary` is `pass` only when the From domain's DMARC passes — through a
 * DKIM signature or an SPF result aligned with that domain. A check that
 * could not complete (DNS down, too slow) is `temperror`, never a pass.
 */

import { fromEngine, GoldstoneError } from "./errors.js";
import type { JsAuthOptions, JsVerdict } from "./native/generated.js";
import { engine } from "./native.js";

/** A check's outcome, in the words of RFC 8601. */
export type AuthResult =
	| "pass"
	| "fail"
	| "softfail"
	| "neutral"
	| "none"
	| "temperror"
	| "permerror";

export type DmarcPolicy = "none" | "quarantine" | "reject" | "unspecified";

export interface DkimVerdict {
	readonly result: AuthResult;
	/** The signing domain (`d=`). */
	readonly domain?: string;
	readonly selector?: string;
	/** Why it did not pass. */
	readonly reason?: string;
}

export interface Authenticity {
	/** One per signature checked (at most `maxDkimSignatures`). */
	readonly dkim: readonly DkimVerdict[];
	/** `none` when no envelope was given. */
	readonly spf: AuthResult;
	readonly dmarc: AuthResult;
	readonly dmarcPolicy: DmarcPolicy;
	/** The From domain DMARC was evaluated for. */
	readonly dmarcDomain?: string;
	readonly arc: AuthResult;
	/** `pass` only when DMARC passed; `temperror` when a check could not complete. */
	readonly summary: "pass" | "fail" | "none" | "temperror";
}

export interface AuthenticateOptions {
	/**
	 * The IP of the server that delivered the message — with `helo` and
	 * `mailFrom`, what SPF checks. A provider's inbound webhook usually gives
	 * it; a message read over IMAP usually does not, and SPF is then `none`.
	 */
	ip?: string;
	helo?: string;
	/** The SMTP MAIL FROM (return path). */
	mailFrom?: string;
	/** DKIM signatures checked, at most — each is a DNS lookup. Default 5. */
	maxDkimSignatures?: number;
	/** For the whole check; past it, `temperror`. Default 10 000 ms. */
	timeoutMs?: number;
	/** Size of the raw message, checked first. Default 25 MiB. */
	maxBytes?: number;
}

function result(value: string): AuthResult {
	switch (value) {
		case "pass":
		case "fail":
		case "softfail":
		case "neutral":
		case "none":
		case "temperror":
		case "permerror":
			return value;
		default:
			// Not something the engine answers; whatever it is, not a pass.
			return "permerror";
	}
}

function policy(value: string): DmarcPolicy {
	switch (value) {
		case "none":
		case "quarantine":
		case "reject":
			return value;
		default:
			return "unspecified";
	}
}

function summary(value: string): Authenticity["summary"] {
	switch (value) {
		case "pass":
		case "fail":
		case "none":
			return value;
		default:
			return "temperror";
	}
}

function fromNative(v: JsVerdict): Authenticity {
	return {
		dkim: v.dkim.map((d) => ({
			result: result(d.result),
			domain: d.domain,
			selector: d.selector,
			reason: d.reason,
		})),
		spf: result(v.spf),
		dmarc: result(v.dmarc),
		dmarcPolicy: policy(v.dmarcPolicy),
		dmarcDomain: v.dmarcDomain,
		arc: result(v.arc),
		summary: summary(v.summary),
	};
}

const BOUNDED = ["maxDkimSignatures", "timeoutMs", "maxBytes"] as const;

function nativeOptions(
	options: AuthenticateOptions | undefined,
): JsAuthOptions | undefined {
	if (options === undefined) return undefined;
	for (const key of BOUNDED) {
		const value = options[key];
		if (
			value !== undefined &&
			!(Number.isInteger(value) && value > 0 && value <= 0xffff_ffff)
		) {
			throw new GoldstoneError(
				"E_GOLDSTONE_INVALID_OPTIONS",
				`Goldstone: ${key} must be a positive integer under 2^32, got ${String(value)}`,
			);
		}
	}
	return { ...options };
}

/** Check one received message — raw RFC 5322 bytes. */
export async function authenticate(
	raw: Uint8Array,
	options?: AuthenticateOptions,
): Promise<Authenticity> {
	const bounds = nativeOptions(options);
	const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
	try {
		return fromNative(await engine().authenticateMessage(bytes, bounds));
	} catch (error) {
		if (error instanceof GoldstoneError) throw error;
		throw fromEngine(error);
	}
}
