import { describe, expect, it } from "vitest";
import {
	authenticate,
	GoldstoneError,
	parseMessage,
	readMessage,
} from "../src/index.js";

const bytes = (text: string) => new TextEncoder().encode(text);

// A signature that claims gmail.com and cannot verify: the body hash is
// made up. With DNS it fails on the hash, without DNS it cannot be checked —
// in neither case is it a pass.
const forged = bytes(
	"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com; s=20230601; h=from:to:subject; bh=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=; b=AAAAAAAAAAAAAAAAAAAA\r\nFrom: someone@gmail.com\r\nTo: alice@example.test\r\nSubject: urgent\r\n\r\nwire the money\r\n",
);
const unsigned = bytes(
	"From: bob@example.test\r\nTo: alice@example.test\r\nSubject: hi\r\n\r\nhello\r\n",
);

async function codeOf(
	run: () => Promise<unknown>,
): Promise<string | undefined> {
	try {
		await run();
	} catch (error) {
		return error instanceof GoldstoneError
			? error.code
			: "not a GoldstoneError";
	}
	return undefined;
}

describe("authenticate", () => {
	it("never passes a forged signature", async () => {
		const verdict = await authenticate(forged);
		expect(verdict.dkim).toHaveLength(1);
		expect(verdict.dkim[0]?.domain).toBe("gmail.com");
		expect(verdict.dkim[0]?.result).not.toBe("pass");
		expect(verdict.summary).not.toBe("pass");
	}, 30_000);

	it("has nothing to pass on an unsigned message without an envelope", async () => {
		const verdict = await authenticate(unsigned);
		expect(verdict.dkim).toEqual([]);
		expect(verdict.spf).toBe("none");
		expect(verdict.summary).not.toBe("pass");
	}, 30_000);

	it("refuses an envelope IP that is not one, and bounds that are not bounds", async () => {
		expect(
			await codeOf(() =>
				authenticate(unsigned, {
					ip: "not-an-ip",
					helo: "h",
					mailFrom: "a@b.test",
				}),
			),
		).toBe("E_GOLDSTONE_INVALID_ENVELOPE");
		expect(await codeOf(() => authenticate(unsigned, { timeoutMs: 0 }))).toBe(
			"E_GOLDSTONE_INVALID_OPTIONS",
		);
	});

	it("refuses an oversized message before checking it", async () => {
		expect(
			await codeOf(() => authenticate(new Uint8Array(101), { maxBytes: 100 })),
		).toBe("E_GOLDSTONE_MESSAGE_TOO_LARGE");
	});
});

describe("readMessage", () => {
	it("parses and checks — the verdict on message.authenticity", async () => {
		const message = await readMessage(forged);
		expect(message.subject).toBe("urgent");
		expect(message.authenticity?.summary).not.toBe("pass");
		expect(message.authenticity?.dkim[0]?.domain).toBe("gmail.com");
	}, 30_000);

	it("skips the check when told to, and parseMessage never does one", async () => {
		expect(
			(await readMessage(forged, { authenticate: false })).authenticity,
		).toBeUndefined();
		expect(parseMessage(forged).authenticity).toBeUndefined();
	});
});
