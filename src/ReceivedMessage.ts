/**
 * A received mail, parsed as the hostile input it is.
 *
 *   const message = parseMessage(raw)
 *   message.subject
 *   message.html            // sanitized: safe to render
 *   message.attachments[0].fileName   // safe to save under
 *
 * The parsing happens in Rust, in one call: the raw bytes go in, this comes
 * out. The size is checked before a byte is parsed, the structure is bounded
 * after, and what the sender controls — the HTML, the attachment names — is
 * made safe before it reaches the application.
 */

import {
	type AuthenticateOptions,
	type Authenticity,
	authenticate,
} from "./authenticity.js";
import { fromEngine, GoldstoneError } from "./errors.js";
import type { JsLimits, JsMessage } from "./native/generated.js";
import { engine } from "./native.js";

/** Bounds on one message; each one left out keeps its default. */
export interface Limits {
	/** Size of the raw message, checked before parsing. Default 25 MiB. */
	maxBytes?: number;
	/** MIME parts, the message itself included. Default 1 000. */
	maxParts?: number;
	/** Nesting depth of multiparts. Default 32. */
	maxDepth?: number;
	/** Number of attachments. Default 100. */
	maxAttachments?: number;
	/** Size of one decoded attachment. Default 25 MiB. */
	maxAttachmentBytes?: number;
}

export interface Mailbox {
	readonly name?: string;
	readonly address?: string;
}

export interface Header {
	readonly name: string;
	/** As received, encoded words included. */
	readonly value: string;
}

export interface Attachment {
	/**
	 * Safe to save under: the last path segment of what the sender wrote,
	 * without control characters, leading dots or a Windows device name.
	 */
	readonly fileName: string;
	/** The name as the sender wrote it. For display only — never a path. */
	readonly originalName?: string;
	readonly contentType: string;
	readonly size: number;
	readonly content: Uint8Array;
	readonly contentId?: string;
	readonly inline: boolean;
}

export class ReceivedMessage {
	readonly messageId?: string;
	readonly subject?: string;
	readonly date?: Date;
	readonly from: readonly Mailbox[];
	readonly to: readonly Mailbox[];
	readonly cc: readonly Mailbox[];
	readonly bcc: readonly Mailbox[];
	readonly replyTo: readonly Mailbox[];
	readonly inReplyTo: readonly string[];
	readonly references: readonly string[];
	readonly headers: readonly Header[];
	readonly text?: string;
	/** Sanitized for display: no script, no event handler, no `javascript:` URL. */
	readonly html?: string;
	readonly attachments: readonly Attachment[];
	/**
	 * Who really sent it — present when the message was read with
	 * {@link readMessage} (as a mailbox reads it), absent from
	 * {@link parseMessage}, which does no DNS.
	 */
	readonly authenticity?: Authenticity;
	readonly #unsanitizedHtml?: string;

	constructor(parsed: JsMessage, authenticity?: Authenticity) {
		this.authenticity = authenticity;
		this.messageId = parsed.messageId;
		this.subject = parsed.subject;
		this.date = parsed.date === undefined ? undefined : new Date(parsed.date);
		this.from = parsed.from;
		this.to = parsed.to;
		this.cc = parsed.cc;
		this.bcc = parsed.bcc;
		this.replyTo = parsed.replyTo;
		this.inReplyTo = parsed.inReplyTo;
		this.references = parsed.references;
		this.headers = parsed.headers;
		this.text = parsed.text;
		this.html = parsed.html;
		this.#unsanitizedHtml = parsed.unsanitizedHtml;
		this.attachments = parsed.attachments.map((a) => ({
			fileName: a.fileName,
			originalName: a.originalName,
			contentType: a.contentType,
			size: a.content.length,
			content: a.content,
			contentId: a.contentId,
			inline: a.inline,
		}));
	}

	/** The first header of that name, any case. */
	header(name: string): string | undefined {
		const wanted = name.toLowerCase();
		return this.headers.find((h) => h.name.toLowerCase() === wanted)?.value;
	}

	/**
	 * The HTML exactly as the sender wrote it. Never render it: it can carry
	 * scripts. It exists for what has to see the original — archiving,
	 * forwarding, forensic inspection.
	 */
	unsanitizedHtml(): string | undefined {
		return this.#unsanitizedHtml;
	}
}

const LIMIT_KEYS = [
	"maxBytes",
	"maxParts",
	"maxDepth",
	"maxAttachments",
	"maxAttachmentBytes",
] as const;

function nativeLimits(limits: Limits | undefined): JsLimits | undefined {
	if (limits === undefined) return undefined;
	for (const key of LIMIT_KEYS) {
		const value = limits[key];
		if (
			value !== undefined &&
			!(Number.isInteger(value) && value > 0 && value <= 0xffff_ffff)
		) {
			throw new GoldstoneError(
				"E_GOLDSTONE_INVALID_LIMITS",
				`Goldstone: ${key} must be a positive integer under 2^32, got ${String(value)}`,
			);
		}
	}
	return { ...limits };
}

/**
 * Parse one received message — raw RFC 5322 bytes, as IMAP fetches them or
 * a provider posts them.
 *
 * Throws a `GoldstoneError` on a message over a limit
 * (`E_GOLDSTONE_MESSAGE_TOO_LARGE`, `…_TOO_MANY_PARTS`, `…_TOO_DEEP`,
 * `…_TOO_MANY_ATTACHMENTS`, `…_ATTACHMENT_TOO_LARGE`) or not a message at
 * all (`E_GOLDSTONE_NOT_A_MESSAGE`).
 */
export function parseMessage(
	raw: Uint8Array,
	limits?: Limits,
): ReceivedMessage {
	return new ReceivedMessage(parseNative(raw, limits));
}

function parseNative(raw: Uint8Array, limits: Limits | undefined): JsMessage {
	const bounds = nativeLimits(limits);
	const bytes = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
	try {
		return engine().parseMessage(bytes, bounds);
	} catch (error) {
		if (error instanceof GoldstoneError) throw error;
		throw fromEngine(error);
	}
}

export interface ReadOptions {
	limits?: Limits;
	/**
	 * Check DKIM, SPF and DMARC — `true` (the default), `false`, or the
	 * envelope and bounds {@link authenticate} takes.
	 */
	authenticate?: boolean | AuthenticateOptions;
}

/**
 * Parse a received message AND check who sent it: {@link parseMessage},
 * then {@link authenticate}, the verdict on `message.authenticity`.
 */
export async function readMessage(
	raw: Uint8Array,
	options: ReadOptions = {},
): Promise<ReceivedMessage> {
	const parsed = parseNative(raw, options.limits);
	if (options.authenticate === false) return new ReceivedMessage(parsed);
	const authOptions =
		options.authenticate === true || options.authenticate === undefined
			? { maxBytes: options.limits?.maxBytes }
			: { maxBytes: options.limits?.maxBytes, ...options.authenticate };
	return new ReceivedMessage(parsed, await authenticate(raw, authOptions));
}
