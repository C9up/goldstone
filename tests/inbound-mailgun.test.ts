import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createMailgunInboundHandler,
	type InboundHttpContext,
	type InboundMeta,
	MemoryReplayGuard,
	type ReceivedMessage,
} from "../src/index.js";

const KEY = "key-test-signing";
const MIME =
	"From: bob@example.test\r\nTo: support@example.test\r\nSubject: help\r\n\r\nIt broke.\r\n";

let counter = 0;
function signed(
	fields: Record<string, string> = {},
	at = Math.floor(Date.now() / 1000),
) {
	const timestamp = String(at);
	const token = `token-${++counter}-${"x".repeat(40)}`;
	const signature = createHmac("sha256", KEY)
		.update(timestamp + token)
		.digest("hex");
	return {
		timestamp,
		token,
		signature,
		"body-mime": MIME,
		recipient: "support@example.test",
		sender: "bob@example.test",
		...fields,
	};
}

interface Sent {
	status?: number;
	json?: unknown;
}

function context(body: unknown): { ctx: InboundHttpContext; sent: Sent } {
	const sent: Sent = {};
	const response = {
		status(code: number) {
			sent.status = code;
			return response;
		},
		json(data: unknown) {
			sent.json = data;
		},
	};
	return { ctx: { request: { body: () => body }, response }, sent };
}

function handler(
	overrides: Partial<Parameters<typeof createMailgunInboundHandler>[0]> = {},
) {
	const received: { message: ReceivedMessage; meta: InboundMeta }[] = [];
	const handle = createMailgunInboundHandler({
		signingKey: KEY,
		authenticate: false,
		onMessage: (message, meta) => void received.push({ message, meta }),
		...overrides,
	});
	return { handle, received };
}

describe("createMailgunInboundHandler", () => {
	it("hands over a signed delivery, parsed, with its envelope", async () => {
		const { handle, received } = handler();
		const { ctx, sent } = context(signed());
		await handle(ctx);
		expect(sent.status).toBe(204);
		expect(received).toHaveLength(1);
		expect(received[0]?.message.subject).toBe("help");
		expect(received[0]?.meta).toEqual({
			recipient: "support@example.test",
			sender: "bob@example.test",
		});
	});

	it.each([
		["a wrong signature", { signature: "0".repeat(64) }],
		["a signature that is not hex", { signature: "not-hex" }],
		["no signature", { signature: "" }],
		["no token", { token: "" }],
	])("refuses %s with the same 401", async (_, fields) => {
		const { handle, received } = handler();
		const { ctx, sent } = context(signed(fields));
		await handle(ctx);
		expect(sent).toEqual({ status: 401, json: { error: "invalid_signature" } });
		expect(received).toHaveLength(0);
	});

	it("refuses a signed request older than the window", async () => {
		const { handle, received } = handler();
		const { ctx, sent } = context(
			signed({}, Math.floor(Date.now() / 1000) - 600),
		);
		await handle(ctx);
		expect(sent.status).toBe(401);
		expect(received).toHaveLength(0);
	});

	it("handles a token once: a replay is acknowledged, not handled again", async () => {
		const { handle, received } = handler();
		const body = signed();
		await handle(context(body).ctx);
		const replayed = {
			...body,
			"body-mime": MIME.replace("It broke.", "Wire the money."),
		};
		const { ctx, sent } = context(replayed);
		await handle(ctx);
		expect(sent.status).toBe(204);
		expect(received).toHaveLength(1);
		expect(received[0]?.message.text).toContain("It broke.");
	});

	it("lets only one of two racing requests with the same token through", async () => {
		let release: () => void = () => {};
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		const { handle, received } = handler({
			onMessage: async (message) => {
				await gate;
				received.push({ message, meta: {} });
			},
		});
		const body = signed();
		const first = handle(context(body).ctx);
		const second = handle(context(body).ctx);
		release();
		await Promise.all([first, second]);
		expect(received).toHaveLength(1);
	});

	it("reads the body only: a field in a list (sent twice) is not taken", async () => {
		const { handle, received } = handler();
		const body = signed();
		const { ctx, sent } = context({
			...body,
			"body-mime": [MIME, "From: x@y.test\r\n\r\nother\r\n"],
		});
		await handle(ctx);
		expect(sent.status).toBe(422);
		expect(received).toHaveLength(0);
	});

	it("answers 406 to a message it refuses, so Mailgun stops retrying", async () => {
		const { handle, received } = handler({ limits: { maxBytes: 20 } });
		const { ctx, sent } = context(signed());
		await handle(ctx);
		expect(sent).toEqual({
			status: 406,
			json: { error: "E_GOLDSTONE_MESSAGE_TOO_LARGE" },
		});
		expect(received).toHaveLength(0);
	});

	it("gives the token back when handling fails, so the retry is handled", async () => {
		let fail = true;
		const received: string[] = [];
		const handle = createMailgunInboundHandler({
			signingKey: KEY,
			authenticate: false,
			onMessage: (message) => {
				if (fail) throw new Error("database down");
				received.push(message.subject ?? "");
			},
		});
		const body = signed();
		await expect(handle(context(body).ctx)).rejects.toThrow("database down");
		fail = false;
		const { ctx, sent } = context(body);
		await handle(ctx);
		expect(sent.status).toBe(204);
		expect(received).toEqual(["help"]);
	});

	it("refuses to be created without a signing key", () => {
		expect(() =>
			createMailgunInboundHandler({ signingKey: "", onMessage: () => {} }),
		).toThrow(expect.objectContaining({ code: "E_GOLDSTONE_INVALID_CONFIG" }));
	});

	it("checks DKIM and DMARC by default, the envelope sender as MAIL FROM", async () => {
		const { handle, received } = handler({ authenticate: undefined });
		await handle(context(signed()).ctx);
		expect(received[0]?.message.authenticity?.summary).not.toBe("pass");
	}, 30_000);
});

describe("MemoryReplayGuard", () => {
	it("keeps a token for its TTL and stays within its capacity", () => {
		const guard = new MemoryReplayGuard(2);
		expect(guard.claim("a", 60)).toBe(true);
		expect(guard.claim("a", 60)).toBe(false);
		guard.release("a");
		expect(guard.claim("a", 60)).toBe(true);
		expect(guard.claim("b", 60)).toBe(true);
		// Full: the oldest gives way.
		expect(guard.claim("c", 60)).toBe(true);
		expect(guard.claim("a", 60)).toBe(true);
		// Expired immediately: free again.
		expect(guard.claim("d", 0)).toBe(true);
		expect(guard.claim("d", 60)).toBe(true);
	});
});
