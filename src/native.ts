/**
 * Loader for the Rust mail engine.
 *
 * The engine is not optional: received mail is hostile input, and its parser
 * is the one place this package will not fall back to JavaScript. A missing
 * binary is a hard failure with an actionable message.
 */

import { GoldstoneNativeRequiredError } from "./errors.js";
import {
	hasFunctions,
	loadNativeBinary,
	unavailableReason as vendorUnavailableReason,
} from "./vendor/nativeBinary.js";

/** What this package calls, as the Rust declares it (`pnpm build:napi-types`). */
const NATIVE_CALLS = [
	"parseMessage",
	"readMessage",
	"authenticateMessage",
] as const;

type NativeGoldstone = Pick<
	typeof import("./native/generated.js"),
	(typeof NATIVE_CALLS)[number]
>;

/** The same three calls, checked at load: a stale binary loads just as well. */
function isNativeGoldstone(value: unknown): value is NativeGoldstone {
	return hasFunctions(value, NATIVE_CALLS);
}

const attempt = loadNativeBinary(isNativeGoldstone, NATIVE_CALLS);
const native = attempt.loaded ? attempt.binary : undefined;
const loadError = attempt.loaded ? undefined : attempt.cause;

export function isNativeAvailable(): boolean {
	return native !== undefined;
}

/**
 * The bytes handed to the engine: a copy, taken here on the JavaScript
 * thread. The engine reads them later, off this thread, more than once (the
 * walk that bounds the structure, then the parse); on a view of the caller's
 * memory, a buffer reused or written meanwhile would make it bound one
 * message and parse another.
 */
export function snapshot(raw: Uint8Array): Buffer {
	return Buffer.from(raw);
}

/** The engine, or a refusal explaining how to get one. */
export function engine(): NativeGoldstone {
	if (native === undefined) {
		throw new GoldstoneNativeRequiredError(
			loadError === undefined
				? vendorUnavailableReason()
				: `failed to load (${loadError instanceof Error ? loadError.message : String(loadError)})`,
		);
	}
	return native;
}
