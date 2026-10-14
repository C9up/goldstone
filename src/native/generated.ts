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
	maxAttachments?: number;
	maxAttachmentBytes?: number;
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
	unsanitizedHtml?: string;
	attachments: Array<JsAttachment>;
}

/**
 * Parse one received message. Throws `E_GOLDSTONE_*: …` on a message that
 * breaks a limit or is not a message at all.
 */

export declare function parseMessage(
	raw: Buffer,
	limits?: JsLimits | undefined | null,
): JsMessage;
