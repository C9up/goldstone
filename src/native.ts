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
type NativeGoldstone = Pick<
	typeof import("./native/generated.js"),
	"parseMessage" | "readMessage" | "authenticateMessage"
>;

/** The same three calls, checked at load: a stale binary loads just as well. */
function isNativeGoldstone(value: unknown): value is NativeGoldstone {
	return hasFunctions(value, [
		"parseMessage",
		"readMessage",
		"authenticateMessage",
	]);
}

const attempt = loadNativeBinary(isNativeGoldstone);
const native = attempt.loaded ? attempt.binary : undefined;
const loadError = attempt.loaded ? undefined : attempt.cause;

export function isNativeAvailable(): boolean {
	return native !== undefined;
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
