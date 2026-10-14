/**
 * Goldstone errors. No upstream package exists, so every code carries the
 * namespace.
 */

export class GoldstoneError extends Error {
	readonly code: string;

	constructor(code: string, message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = new.target.name;
		this.code = code;
	}
}

/** The codes the engine raises, `E_GOLDSTONE_<REASON>: <message>`. */
const ENGINE_CODES = new Set([
	"E_GOLDSTONE_MESSAGE_TOO_LARGE",
	"E_GOLDSTONE_NOT_A_MESSAGE",
	"E_GOLDSTONE_TOO_MANY_PARTS",
	"E_GOLDSTONE_TOO_DEEP",
	"E_GOLDSTONE_TOO_MANY_ATTACHMENTS",
	"E_GOLDSTONE_ATTACHMENT_TOO_LARGE",
]);

/** The engine's `CODE: message`, back as a coded error. */
export function fromEngine(error: unknown): GoldstoneError {
	const message = error instanceof Error ? error.message : String(error);
	const separator = message.indexOf(": ");
	const code = separator > 0 ? message.slice(0, separator) : "";
	if (ENGINE_CODES.has(code)) {
		return new GoldstoneError(code, message.slice(separator + 2), {
			cause: error,
		});
	}
	return new GoldstoneError("E_GOLDSTONE_ENGINE", message, { cause: error });
}

/** Raised when parsing needs the Rust engine and it is not there. */
export class GoldstoneNativeRequiredError extends GoldstoneError {
	constructor(reason: string) {
		super(
			"E_GOLDSTONE_NATIVE_REQUIRED",
			`The Rust mail engine is required but not loaded — ${reason}.\n` +
				"Install the prebuilt binary for this platform, or build it with `pnpm build:napi`.",
		);
	}
}
