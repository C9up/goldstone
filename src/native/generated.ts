// GENERATED FROM THE RUST — do not edit.
//
// Produced by scripts/generate-napi-types.mjs from napi-derive's type-def
// output. Editing this file by hand puts it back where it started: a
// description that can disagree with the code it describes.

/** Bounds on one message; an absent field keeps the engine's default. */

export interface JsLimits {
	maxBytes?: number;
	maxParts?: number;
	maxDepth?: number;
	maxHeaders?: number;
	maxHeaderBytes?: number;
	maxAttachments?: number;
	maxAttachmentBytes?: number;
	maxHtmlBytes?: number;
}

/** What the sanitized HTML may load by itself. */

export interface JsHtmlOptions {
	/**
	 * Keep remote images and other URLs a browser loads unasked. Default
	 * false.
	 */
	remoteContent?: boolean;
}

export interface JsMailbox {
	name?: string;
	address?: string;
}

export interface JsHeader {
	name: string;
	value: string;
}

export interface JsAttachment {
	fileName: string;
	originalName?: string;
	contentType: string;
	content: Buffer;
	contentId?: string;
	inline: boolean;
}

export interface JsMessage {
	messageId?: string;
	subject?: string;
	date?: string;
	from: Array<JsMailbox>;
	to: Array<JsMailbox>;
	cc: Array<JsMailbox>;
	bcc: Array<JsMailbox>;
	replyTo: Array<JsMailbox>;
	inReplyTo: Array<string>;
	references: Array<string>;
	headers: Array<JsHeader>;
	text?: string;
	html?: string;
	/** `E_GOLDSTONE_HTML_*: …` when the HTML body was not sanitized. */
	htmlError?: string;
	unsanitizedHtml?: string;
	attachments: Array<JsAttachment>;
}

/** The envelope SPF checks, and the bounds on the whole check. */

export interface JsAuthOptions {
	ip?: string;
	helo?: string;
	mailFrom?: string;
	maxDkimSignatures?: number;
	timeoutMs?: number;
	maxBytes?: number;
}

export interface JsDkimVerdict {
	result: string;
	domain?: string;
	selector?: string;
	reason?: string;
}

export interface JsVerdict {
	dkim: Array<JsDkimVerdict>;
	spf: string;
	dmarc: string;
	dmarcPolicy: string;
	dmarcDomain?: string;
	fromDomain?: string;
	arc: string;
	summary: string;
}

export interface JsReadMessage {
	message: JsMessage;
	authenticity: JsVerdict;
}

/**
 * Parse one received message, off the JavaScript thread: parsing and
 * sanitizing are CPU work on bytes a stranger sent. Rejects with
 * `E_GOLDSTONE_*: …` on a message that breaks a limit or is not a message.
 *
 * `raw`, here and in the two calls below, is read on a runtime thread while
 * JavaScript runs on: it must be memory nothing writes to meanwhile, which
 * the TypeScript side ensures by handing a copy (`snapshot` in native.ts).
 * A copy made here would be made on the runtime thread, too late.
 */

export declare function parseMessage(
	raw: Buffer,
	limits?: JsLimits | undefined | null,
	html?: JsHtmlOptions | undefined | null,
): Promise<JsMessage>;

/**
 * DKIM, SPF (when the envelope is given), DMARC and ARC for one received
 * message. Resolves with `temperror` verdicts when DNS cannot answer in
 * time — never with a pass.
 */

export declare function authenticateMessage(
	raw: Buffer,
	options?: JsAuthOptions | undefined | null,
): Promise<JsVerdict>;

/**
 * Parse one received message and check who sent it, from the same parse:
 * the From the verdict speaks for is the From the message shows.
 */

export declare function readMessage(
	raw: Buffer,
	limits?: JsLimits | undefined | null,
	options?: JsAuthOptions | undefined | null,
	html?: JsHtmlOptions | undefined | null,
): Promise<JsReadMessage>;
