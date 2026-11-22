/**
 * A received mail, parsed as the hostile input it is.
 *
 *   const message = await parseMessage(raw)
 *   message.subject
 *   message.html            // sanitized: safe to render
 *   message.attachments[0].fileName   // safe to save under
 *
 * The parsing happens in Rust, in one call and off the JavaScript thread:
 * the raw bytes go in, this comes out. The size is checked before a byte is
 * parsed, the structure is bounded after, and what the sender controls — the
 * HTML, the attachment names — is made safe before it reaches the
 * application.
 */

import {
	type AuthenticateOptions,
	type Authenticity,
	fromNative,
	nativeOptions,
} from "./authenticity.js";
import { fromEngine, GoldstoneError } from "./errors.js";
import type { JsHtmlOptions, JsLimits, JsMessage } from "./native/generated.js";
import { engine, snapshot } from "./native.js";

/** Bounds on one message; each one left out keeps its default. */
export interface Limits {
	/** Size of the raw message, checked before parsing. Default 25 MiB. */
	maxBytes?: number;
	/**
	 * MIME parts, the message itself included, and the parts of the
	 * messages it carries (message/rfc822). Default 1 000.
	 */
	maxParts?: number;
	/** Nesting depth of multiparts and carried messages. Default 32. */
	maxDepth?: number;
	/** Header fields in one header block, the message's or a part's. Default 1 000. */
	maxHeaders?: number;
	/** Size of one header block. Default 1 MiB. */
	maxHeaderBytes?: number;
	/** Number of attachments. Default 100. */
	maxAttachments?: number;
	/** Size of one decoded attachment. Default 25 MiB. */
	maxAttachmentBytes?: number;
	/**
	 * Size of the HTML body that is sanitized. Over it, the message is still
	 * read, without `html` (see `htmlError`). Default 512 KiB.
	 */
	maxHtmlBytes?: number;
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
	 * Safe to save under, on any system: the last path segment of what the
	 * sender wrote, with control, invisible and bidi characters and the
	 * characters Windows refuses (`< > : " | ? *`, `:` naming an NTFS stream)
	 * replaced by `_`, without leading dots, trailing dots or spaces, or a
	 * Windows device name (`CON`, `COM1`, `CONIN$`…), at most 255 bytes.
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
	/**
	 * Sanitized for display: no script, no event handler, no `javascript:`
	 * URL, and no remote content unless `remoteContent: "allow"`.
	 */
	readonly html?: string;
	/**
	 * Why `html` is absent although the message has an HTML body: over
	 * `maxHtmlBytes` (`E_GOLDSTONE_HTML_TOO_LARGE`), nested too deep
	 * (`…_HTML_TOO_DEEP`), or building a tree out of proportion to its markup
	 * (`…_HTML_TOO_COMPLEX`). Sanitizing such HTML would cost time that grows
	 * faster than its size; the text and the rest of the message are there.
	 */
	readonly htmlError?: GoldstoneError;
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
		this.htmlError =
			parsed.htmlError === undefined ? undefined : fromEngine(parsed.htmlError);
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

	/**
	 * The first header of that name, any case: the copy the message's
	 * fields (`from`, `subject`…) read too. Every copy is in `headers`.
	 */
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
	"maxHeaders",
	"maxHeaderBytes",
	"maxAttachments",
	"maxAttachmentBytes",
	"maxHtmlBytes",
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

export interface ParseOptions {
	limits?: Limits;
	/**
	 * Whether the sanitized `html` may load remote content by itself —
	 * images, backgrounds, video posters. `"block"` (the default) removes
	 * those URLs: rendering a remote image tells the sender the message was
	 * opened, when, and from where. `cid:` references to the message's own
	 * parts are kept either way. Links stay: they are followed only when
	 * clicked.
	 */
	remoteContent?: "block" | "allow";
}

function htmlOptions(options: ParseOptions): JsHtmlOptions {
	const { remoteContent } = options;
	if (
		remoteContent !== undefined &&
		remoteContent !== "block" &&
		remoteContent !== "allow"
	) {
		throw new GoldstoneError(
			"E_GOLDSTONE_INVALID_OPTIONS",
			`Goldstone: remoteContent must be "block" or "allow", got ${String(remoteContent)}`,
		);
	}
	return { remoteContent: remoteContent === "allow" };
}

/**
 * Parse one received message — raw RFC 5322 bytes, as IMAP fetches them or
 * a provider posts them. The work runs off the event loop.
 *
 * Rejects with a `GoldstoneError` on a message over a limit
 * (`E_GOLDSTONE_MESSAGE_TOO_LARGE`, `…_TOO_MANY_PARTS`, `…_TOO_DEEP`,
 * `…_TOO_MANY_HEADERS`, `…_HEADERS_TOO_LARGE`, `…_MISSING_BOUNDARIES`,
 * `…_BOUNDARY_TOO_LONG`, `…_TOO_MANY_ATTACHMENTS`, `…_ATTACHMENT_TOO_LARGE`) or not a message at
 * all (`E_GOLDSTONE_NOT_A_MESSAGE`).
 */
export async function parseMessage(
	raw: Uint8Array,
	options: ParseOptions = {},
): Promise<ReceivedMessage> {
	return new ReceivedMessage(await parseNative(raw, options));
}

async function parseNative(
	raw: Uint8Array,
	options: ParseOptions,
): Promise<JsMessage> {
	const bounds = nativeLimits(options.limits);
	const html = htmlOptions(options);
	const bytes = snapshot(raw);
	try {
		return await engine().parseMessage(bytes, bounds, html);
	} catch (error) {
		if (error instanceof GoldstoneError) throw error;
		throw fromEngine(error);
	}
}

export interface ReadOptions extends ParseOptions {
	/**
	 * Check DKIM, SPF and DMARC — `true` (the default), `false`, or the
	 * envelope and bounds {@link authenticate} takes.
	 */
	authenticate?: boolean | AuthenticateOptions;
}

/**
 * Parse a received message AND check who sent it, the verdict on
 * `message.authenticity`. Both come from one parse: the From the verdict
 * speaks for is the From the message shows.
 */
export async function readMessage(
	raw: Uint8Array,
	options: ReadOptions = {},
): Promise<ReceivedMessage> {
	if (options.authenticate === false) {
		return new ReceivedMessage(await parseNative(raw, options));
	}
	const bounds = nativeLimits(options.limits);
	const html = htmlOptions(options);
	const authOptions = nativeOptions(
		options.authenticate === true || options.authenticate === undefined
			? { maxBytes: options.limits?.maxBytes }
			: { maxBytes: options.limits?.maxBytes, ...options.authenticate },
	);
	const bytes = snapshot(raw);
	try {
		const read = await engine().readMessage(bytes, bounds, authOptions, html);
		return new ReceivedMessage(read.message, fromNative(read.authenticity));
	} catch (error) {
		if (error instanceof GoldstoneError) throw error;
		throw fromEngine(error);
	}
}
