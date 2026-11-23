/**
 * Goldstone errors, one class per code. An application branches on
 * `error.code` or on `error instanceof errors.E_…`; every one is a flare
 * `Exception`, with the HTTP status an exception handler answers with.
 *
 * The refusals of a message's content answer 422: the bytes were received,
 * the message in them is not one goldstone will read. The rest are faults of
 * the application, its config or the host.
 */

import { createError } from "@c9up/flare";

/** A message is over `maxBytes`. */
export const E_GOLDSTONE_MESSAGE_TOO_LARGE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_MESSAGE_TOO_LARGE",
	422,
);

/** The bytes are not a mail message. */
export const E_GOLDSTONE_NOT_A_MESSAGE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_NOT_A_MESSAGE",
	422,
);

/** A message has more MIME parts than allowed. */
export const E_GOLDSTONE_TOO_MANY_PARTS = createError<[string]>(
	"%s",
	"E_GOLDSTONE_TOO_MANY_PARTS",
	422,
);

/** MIME parts are nested deeper than allowed. */
export const E_GOLDSTONE_TOO_DEEP = createError<[string]>(
	"%s",
	"E_GOLDSTONE_TOO_DEEP",
	422,
);

/** A header block has more fields than allowed. */
export const E_GOLDSTONE_TOO_MANY_HEADERS = createError<[string]>(
	"%s",
	"E_GOLDSTONE_TOO_MANY_HEADERS",
	422,
);

/** A header block is over the size limit. */
export const E_GOLDSTONE_HEADERS_TOO_LARGE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_HEADERS_TOO_LARGE",
	422,
);

/** A multipart message declares boundaries that never appear. */
export const E_GOLDSTONE_MISSING_BOUNDARIES = createError<[string]>(
	"%s",
	"E_GOLDSTONE_MISSING_BOUNDARIES",
	422,
);

/** A multipart boundary is too long. */
export const E_GOLDSTONE_BOUNDARY_TOO_LONG = createError<[string]>(
	"%s",
	"E_GOLDSTONE_BOUNDARY_TOO_LONG",
	422,
);

/** A message has more attachments than allowed. */
export const E_GOLDSTONE_TOO_MANY_ATTACHMENTS = createError<[string]>(
	"%s",
	"E_GOLDSTONE_TOO_MANY_ATTACHMENTS",
	422,
);

/** An attachment is over the size limit. */
export const E_GOLDSTONE_ATTACHMENT_TOO_LARGE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_ATTACHMENT_TOO_LARGE",
	422,
);

/** The HTML body is over `maxHtmlBytes` (on `htmlError`). */
export const E_GOLDSTONE_HTML_TOO_LARGE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_HTML_TOO_LARGE",
	422,
);

/** The HTML body is nested too deep (on `htmlError`). */
export const E_GOLDSTONE_HTML_TOO_DEEP = createError<[string]>(
	"%s",
	"E_GOLDSTONE_HTML_TOO_DEEP",
	422,
);

/** The HTML body has too many elements (on `htmlError`). */
export const E_GOLDSTONE_HTML_TOO_COMPLEX = createError<[string]>(
	"%s",
	"E_GOLDSTONE_HTML_TOO_COMPLEX",
	422,
);

/** A sender check needed DNS and DNS failed. */
export const E_GOLDSTONE_DNS_UNAVAILABLE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_DNS_UNAVAILABLE",
);

/** The envelope given to a sender check is invalid. */
export const E_GOLDSTONE_INVALID_ENVELOPE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_INVALID_ENVELOPE",
);

/** The engine failed without one of the codes above. */
export const E_GOLDSTONE_ENGINE = createError<[string]>(
	"%s",
	"E_GOLDSTONE_ENGINE",
);

/** A sender check option, `remoteContent` or a replay TTL is invalid. */
export const E_GOLDSTONE_INVALID_OPTIONS = createError<[string]>(
	"%s",
	"E_GOLDSTONE_INVALID_OPTIONS",
);

/** The inbox config or the inbound handler's options are invalid. */
export const E_GOLDSTONE_INVALID_CONFIG = createError<[string]>(
	"%s",
	"E_GOLDSTONE_INVALID_CONFIG",
);

/** A mailbox would connect without TLS or without checking the certificate. */
export const E_GOLDSTONE_INSECURE_CONNECTION = createError<[string]>(
	"%s",
	"E_GOLDSTONE_INSECURE_CONNECTION",
);

/** The Rust mail engine is not loaded. */
export const E_GOLDSTONE_NATIVE_REQUIRED = createError<[string]>(
	"The Rust mail engine is required but not loaded — %s.\n" +
		"Install the prebuilt binary for this platform, or build it with `pnpm build:napi`.",
	"E_GOLDSTONE_NATIVE_REQUIRED",
);

/** A parsing limit is not a positive integer under 2^32. */
export const E_GOLDSTONE_INVALID_LIMITS = createError<[string, string]>(
	"Goldstone: %s must be a positive integer under 2^32, got %s",
	"E_GOLDSTONE_INVALID_LIMITS",
);

/** A mailbox name is not configured. */
export const E_GOLDSTONE_UNKNOWN_MAILBOX = createError<[string, string]>(
	'[inbox] no mailbox "%s" — got %s',
	"E_GOLDSTONE_UNKNOWN_MAILBOX",
);

/** A watched folder renumbered its messages. */
export const E_GOLDSTONE_UIDVALIDITY_CHANGED = createError<[string, string]>(
	"[inbox] %s/%s renumbered its messages; watching resumes from the newest",
	"E_GOLDSTONE_UIDVALIDITY_CHANGED",
);

/** `GoldstoneProvider` registered with no `config/inbox.ts`. */
export const E_GOLDSTONE_MISSING_CONFIG = createError(
	"[inbox] missing config/inbox.ts",
	"E_GOLDSTONE_MISSING_CONFIG",
);

/** The `services/main` inbox was used before it was set. */
export const E_GOLDSTONE_NOT_BOOTED = createError(
	"[inbox] accessed before initialization — register GoldstoneProvider, or call setInbox() yourself.",
	"E_GOLDSTONE_NOT_BOOTED",
);
