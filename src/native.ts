/**
 * Loader for the Rust mail engine.
 *
 * The engine is not optional: received mail is hostile input, and its parser
 * is the one place this package will not fall back to JavaScript. A missing
 * binary is a hard failure with an actionable message.
 */

import { arch, platform } from "node:process";
import { E_GOLDSTONE_NATIVE_REQUIRED } from "./errors.js";
import {
	hasFunctions,
	loadNativeBinary,
	muslHint,
	supportedTargets,
} from "./vendor/nativeBinary.js";

/**
 * The npm name the platform packages derive from: `@c9up/goldstone-<suffix>`,
 * one per target, each an optional dependency pinned to this version.
 */
const PACKAGE_NAME = "@c9up/goldstone";

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

const attempt = loadNativeBinary(isNativeGoldstone, NATIVE_CALLS, {
	packageName: PACKAGE_NAME,
});

export function isNativeAvailable(): boolean {
	return attempt.loaded;
}

/**
 * What to do about a missing engine, phrased for whoever has to fix it.
 *
 * An application installs the platform package; a checkout of goldstone builds
 * the local binary. The load error itself is not in here: it names paths on
 * the host, so it travels as the refusal's `cause` instead of its message.
 */
function remedy(
	suffix: string | undefined,
	platformPackage: string | undefined,
): string {
	if (suffix === undefined) {
		return `no prebuilt binary for ${platform}-${arch}; goldstone ships one for ${supportedTargets().join(", ")}.`;
	}
	if (platformPackage === undefined) {
		return `index.${suffix}.node failed to load. Rebuild it: cd packages/goldstone && pnpm build:napi`;
	}
	return (
		`install ${platformPackage} at the exact version of ${PACKAGE_NAME}: it is the optional dependency that carries the ${suffix} binary, ` +
		"and an install that omits optional dependencies skips it. " +
		`In a checkout of goldstone, build it instead: pnpm build:napi.${muslHint()}`
	);
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

/** The engine, or a refusal naming the fix, with the load error as its cause. */
export function engine(): NativeGoldstone {
	if (attempt.loaded) return attempt.binary;
	throw new E_GOLDSTONE_NATIVE_REQUIRED(
		[remedy(attempt.suffix, attempt.platformPackage)],
		{ cause: attempt.cause },
	);
}
