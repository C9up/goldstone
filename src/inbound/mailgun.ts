/**
 * Mailgun inbound: a route that forwards to the application receives every
 * mail as a form POST — the raw message in `body-mime`.
 *
 *   router.post('/inbound/mailgun/mime', createMailgunInboundHandler({
 *     signingKey: env.get('MAILGUN_SIGNING_KEY'),
 *     async onMessage(message, { recipient }) { … },
 *   }))
 *
 * Configure the Mailgun route to forward to a URL ending in `mime`: that is
 * what makes Mailgun send `body-mime`, the message as received.
 *
 * Mailgun signs `timestamp` + `token` with the webhook signing key — and
 * nothing else: the signature does not cover the message. So a signature is
 * only worth what its freshness and uniqueness are worth, and both are
 * enforced: a timestamp older than `maxAgeSeconds` is refused, and a token is
 * handled once — claimed before handling, so two requests racing with it
 * cannot both get through. A delivery whose handling failed gives its token
 * back, so Mailgun's retry is handled; one already handled is acknowledged
 * and not handled again.
 */

import { Buffer } from "node:buffer";
import { createHmac, timingSafeEqual } from "node:crypto";
import type { AuthenticateOptions } from "../authenticity.js";
import { GoldstoneError } from "../errors.js";
import {
	type Limits,
	type ReceivedMessage,
	readMessage,
} from "../ReceivedMessage.js";
import {
	field,
	type InboundHttpContext,
	MemoryReplayGuard,
	type ReplayGuard,
} from "./context.js";

export interface InboundMeta {
	/** The SMTP envelope recipient Mailgun received it for. */
	recipient?: string;
	/** The SMTP envelope sender (return path). */
	sender?: string;
}

export interface MailgunInboundOptions {
	/** The webhook signing key (Mailgun → Settings → Webhooks). */
	signingKey: string;
	onMessage: (message: ReceivedMessage, meta: InboundMeta) => unknown;
	/** A signed request older than this is refused. Default 120 (Mailgun's own guidance). */
	maxAgeSeconds?: number;
	/** Default: tokens kept in this process's memory. */
	replayGuard?: ReplayGuard;
	limits?: Limits;
	/** DKIM / DMARC on each message (`message.authenticity`). Default `true`. */
	authenticate?: boolean | Omit<AuthenticateOptions, "ip" | "helo">;
}

type Handler = (
	ctx: InboundHttpContext,
	next?: () => Promise<void>,
) => Promise<void>;

function expectedSignature(
	signingKey: string,
	timestamp: string,
	token: string,
): Buffer {
	return createHmac("sha256", signingKey)
		.update(timestamp + token)
		.digest();
}

/** Constant time; a malformed hex string is simply not equal. */
function sameSignature(expected: Buffer, given: string): boolean {
	if (!/^[0-9a-f]{64}$/i.test(given)) return false;
	return timingSafeEqual(expected, Buffer.from(given, "hex"));
}

export function createMailgunInboundHandler(
	options: MailgunInboundOptions,
): Handler {
	if (!options.signingKey) {
		throw new GoldstoneError(
			"E_GOLDSTONE_INVALID_CONFIG",
			"createMailgunInboundHandler: signingKey is required to verify Mailgun's signature",
		);
	}
	const { signingKey, onMessage } = options;
	const maxAge = options.maxAgeSeconds ?? 120;
	const guard = options.replayGuard ?? new MemoryReplayGuard();

	return async (ctx) => {
		const body = ctx.request.body();
		const timestamp = field(body, "timestamp");
		const token = field(body, "token");
		const signature = field(body, "signature");
		// One answer for every way a signature can be wrong, so the response
		// does not say which check refused it.
		const refuse = () =>
			ctx.response.status(401).json({ error: "invalid_signature" });
		if (!timestamp || !token || !signature) return refuse();

		const seconds = Number(timestamp);
		if (
			!Number.isFinite(seconds) ||
			Math.abs(Date.now() / 1000 - seconds) > maxAge
		) {
			return refuse();
		}
		if (
			!sameSignature(expectedSignature(signingKey, timestamp, token), signature)
		) {
			return refuse();
		}

		const mime = field(body, "body-mime");
		if (mime === undefined) {
			ctx.response.status(422).json({ error: "missing_body_mime" });
			return;
		}

		// Twice the window: a token older than that is refused on its
		// timestamp anyway. Taken before handling, so a request racing with
		// the same token is acknowledged instead of handled twice.
		if (!(await guard.claim(token, maxAge * 2))) {
			ctx.response.status(204).json({});
			return;
		}
		try {
			await handle(body, mime, ctx);
		} catch (error) {
			// Not handled: give the token back so Mailgun's retry gets through.
			await guard.release(token);
			throw error;
		}
	};

	async function handle(
		body: unknown,
		mime: string,
		ctx: InboundHttpContext,
	): Promise<void> {
		let message: ReceivedMessage;
		try {
			const authenticate =
				options.authenticate === false
					? false
					: {
							...(options.authenticate === true ||
							options.authenticate === undefined
								? {}
								: options.authenticate),
							mailFrom: field(body, "sender"),
						};
			message = await readMessage(Buffer.from(mime, "utf8"), {
				limits: options.limits,
				authenticate,
			});
		} catch (error) {
			if (error instanceof GoldstoneError) {
				// 406 tells Mailgun not to retry: the same bytes would be refused
				// again. The token stays taken.
				ctx.response.status(406).json({ error: error.code });
				return;
			}
			throw error;
		}

		// A handler that throws answers 500: Mailgun retries.
		await onMessage(message, {
			recipient: field(body, "recipient"),
			sender: field(body, "sender"),
		});
		ctx.response.status(204).json({});
	}
}
