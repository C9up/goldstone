/**
 * The engine's failures, back as goldstone errors.
 *
 * The engine cannot throw a JavaScript class across the NAPI boundary, so it
 * prefixes the code onto the message (`E_GOLDSTONE_<REASON>: <message>`) and
 * this puts it back.
 */

import { type ErrorClass, Exception } from "@c9up/flare";
import * as errors from "./errors.js";

/** The error class of each code the engine raises. */
const ENGINE_ERRORS = {
	E_GOLDSTONE_MESSAGE_TOO_LARGE: errors.E_GOLDSTONE_MESSAGE_TOO_LARGE,
	E_GOLDSTONE_NOT_A_MESSAGE: errors.E_GOLDSTONE_NOT_A_MESSAGE,
	E_GOLDSTONE_TOO_MANY_PARTS: errors.E_GOLDSTONE_TOO_MANY_PARTS,
	E_GOLDSTONE_TOO_DEEP: errors.E_GOLDSTONE_TOO_DEEP,
	E_GOLDSTONE_TOO_MANY_HEADERS: errors.E_GOLDSTONE_TOO_MANY_HEADERS,
	E_GOLDSTONE_HEADERS_TOO_LARGE: errors.E_GOLDSTONE_HEADERS_TOO_LARGE,
	E_GOLDSTONE_TOO_MANY_ADDRESSES: errors.E_GOLDSTONE_TOO_MANY_ADDRESSES,
	E_GOLDSTONE_MISSING_BOUNDARIES: errors.E_GOLDSTONE_MISSING_BOUNDARIES,
	E_GOLDSTONE_BOUNDARY_TOO_LONG: errors.E_GOLDSTONE_BOUNDARY_TOO_LONG,
	E_GOLDSTONE_TOO_MANY_ATTACHMENTS: errors.E_GOLDSTONE_TOO_MANY_ATTACHMENTS,
	E_GOLDSTONE_ATTACHMENT_TOO_LARGE: errors.E_GOLDSTONE_ATTACHMENT_TOO_LARGE,
	E_GOLDSTONE_HTML_TOO_LARGE: errors.E_GOLDSTONE_HTML_TOO_LARGE,
	E_GOLDSTONE_HTML_TOO_DEEP: errors.E_GOLDSTONE_HTML_TOO_DEEP,
	E_GOLDSTONE_HTML_TOO_COMPLEX: errors.E_GOLDSTONE_HTML_TOO_COMPLEX,
	E_GOLDSTONE_DNS_UNAVAILABLE: errors.E_GOLDSTONE_DNS_UNAVAILABLE,
	E_GOLDSTONE_INVALID_ENVELOPE: errors.E_GOLDSTONE_INVALID_ENVELOPE,
} as const satisfies Record<string, ErrorClass<[string]>>;

function isEngineCode(code: string): code is keyof typeof ENGINE_ERRORS {
	return Object.hasOwn(ENGINE_ERRORS, code);
}

/**
 * The engine's `CODE: message`, back as a coded error. A message without a
 * known code is kept whole under `E_GOLDSTONE_ENGINE` rather than guessed at.
 */
export function fromEngine(error: unknown): Exception {
	const message = error instanceof Error ? error.message : String(error);
	const separator = message.indexOf(": ");
	const code = separator > 0 ? message.slice(0, separator) : "";
	if (isEngineCode(code)) {
		return new ENGINE_ERRORS[code]([message.slice(separator + 2)], {
			cause: error,
		});
	}
	return new errors.E_GOLDSTONE_ENGINE([message], { cause: error });
}

/** Whether `error` is one goldstone raised. */
export function isGoldstoneError(error: unknown): error is Exception {
	return (
		error instanceof Exception &&
		error.code !== undefined &&
		error.code.startsWith("E_GOLDSTONE_")
	);
}
