import { describe, expect, it } from "vitest";
import {
	defineConfig,
	GoldstoneError,
	type InboxConfig,
	InboxManager,
	type MailboxConfig,
} from "../src/index.js";

const auth = { user: "alice", pass: "secret" };

function codeOf(run: () => unknown): string | undefined {
	try {
		run();
	} catch (error) {
		return error instanceof GoldstoneError
			? error.code
			: "not a GoldstoneError";
	}
	return undefined;
}

describe("defineConfig", () => {
	it("refuses no mailbox, and a default that is not declared", () => {
		// Typed loosely on purpose: the compiler already refuses both, and this
		// is the check for a config built at runtime.
		const none: InboxConfig<Record<string, MailboxConfig>> = {
			mailbox: "main",
			mailboxes: {},
		};
		const undeclared: InboxConfig<Record<string, MailboxConfig>> = {
			mailbox: "other",
			mailboxes: { main: { host: "h", auth } },
		};
		expect(codeOf(() => defineConfig(none))).toBe("E_GOLDSTONE_INVALID_CONFIG");
		expect(codeOf(() => defineConfig(undeclared))).toBe(
			"E_GOLDSTONE_INVALID_CONFIG",
		);
	});

	it("refuses a mailbox that would talk without TLS or without checking the certificate", () => {
		expect(
			codeOf(() =>
				defineConfig({
					mailbox: "m",
					mailboxes: { m: { host: "h", secure: false, auth } },
				}),
			),
		).toBe("E_GOLDSTONE_INSECURE_CONNECTION");
		expect(
			codeOf(() =>
				defineConfig({
					mailbox: "m",
					mailboxes: {
						m: { host: "h", tls: { rejectUnauthorized: false }, auth },
					},
				}),
			),
		).toBe("E_GOLDSTONE_INSECURE_CONNECTION");
	});

	it("accepts TLS, STARTTLS, and an insecure test server named as such", () => {
		expect(() =>
			defineConfig({
				mailbox: "tls",
				mailboxes: {
					tls: { host: "h", auth },
					starttls: { host: "h", secure: false, starttls: true, auth },
					local: {
						host: "localhost",
						secure: false,
						allowInsecure: true,
						auth,
					},
				},
			}),
		).not.toThrow();
	});
});

describe("InboxManager", () => {
	const manager = new InboxManager(
		defineConfig({
			mailbox: "main",
			mailboxes: { main: { host: "h", auth }, billing: { host: "h", auth } },
		}),
	);

	it("hands out the default mailbox, the same instance each time, without connecting", () => {
		expect(manager.mailbox().name).toBe("main");
		expect(manager.mailbox("main")).toBe(manager.mailbox());
		expect(manager.mailbox("billing").name).toBe("billing");
	});

	it("names an unknown mailbox", () => {
		// @ts-expect-error — not a declared mailbox
		expect(codeOf(() => manager.mailbox("nope"))).toBe(
			"E_GOLDSTONE_UNKNOWN_MAILBOX",
		);
	});
});
