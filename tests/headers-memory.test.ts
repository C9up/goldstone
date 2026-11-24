/**
 * What a hostile header costs in memory, measured as the peak resident size
 * of this process (Linux: /proc), reset before each parse.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { Exception } from "@c9up/flare";
import { describe, expect, it } from "vitest";
import { parseMessage } from "../src/index.js";

const MIB = 1024 * 1024;

function status(field: "VmHWM" | "VmRSS"): number {
	const kb = new RegExp(`${field}:\\s+(\\d+)`).exec(
		readFileSync("/proc/self/status", "utf8"),
	)?.[1];
	return Number(kb ?? 0) / 1024;
}

/** The parse's outcome, and how far it raised the peak, in MiB. */
async function measured(raw: Buffer): Promise<{ code: string; cost: number }> {
	// Resets the peak to the current resident size.
	writeFileSync("/proc/self/clear_refs", "5");
	const before = status("VmRSS");
	let code = "parsed";
	try {
		await parseMessage(raw);
	} catch (error) {
		code = error instanceof Exception ? (error.code ?? "") : String(error);
	}
	return { code, cost: status("VmHWM") - before };
}

// Lines of 800 bytes, folded: no line is long.
const FOLD = `${"a,".repeat(399)}\r\n `;
const list = (bytes: number) => FOLD.repeat(Math.floor(bytes / FOLD.length));

/** A multipart/mixed of `count` parts, each with one header block of `blockBytes`. */
function parts(
	count: number,
	blockBytes: number,
	header: (bytes: number) => string,
): Buffer {
	let body = "";
	for (let i = 0; i < count; i++)
		body += `--b\r\n${header(blockBytes - 200)}\r\n\r\nx\r\n`;
	return Buffer.from(
		`From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n${body}--b--\r\n`,
		"latin1",
	);
}

describe("hostile headers in memory", () => {
	// Before these bounds, each of these messages was parsed, at 25 (parts)
	// to 120 (the message's own To) times its size: 4 MiB of To in parts cost
	// 109 MiB, the message's own To of 1 MiB 123 MiB. Now each is refused
	// before the message is parsed, at the cost of reading one header block.
	const own = (field: string) =>
		Buffer.from(
			`From: a@example.com\r\nSubject: s\r\n${field}: ${list(MIB - 200)}x@y\r\n\r\nx\r\n`,
			"latin1",
		);
	const shapes: [string, Buffer, string][] = [
		[
			"the message's own To, 1 MiB",
			own("To"),
			"E_GOLDSTONE_TOO_MANY_ADDRESSES",
		],
		[
			"To in 4 parts of 1 MiB",
			parts(4, MIB, (n) => `To: ${list(n)}x@y`),
			"E_GOLDSTONE_TOO_MANY_ADDRESSES",
		],
		[
			"Cc in 4 parts of 1 MiB",
			parts(4, MIB, (n) => `Cc: ${list(n)}x@y`),
			"E_GOLDSTONE_TOO_MANY_ADDRESSES",
		],
		[
			"To in 256 parts of 16 KiB",
			parts(256, 16 * 1024, (n) => `To: ${list(n)}x@y`),
			"E_GOLDSTONE_TOO_MANY_ADDRESSES",
		],
		[
			"Keywords in 4 parts of 1 MiB",
			parts(4, MIB, (n) => `Keywords: ${list(n)}x`),
			"E_GOLDSTONE_HEADERS_TOO_LARGE",
		],
	];

	it.each(shapes)(
		"refuses %s before parsing the message",
		async (_, raw, refusal) => {
			await parseMessage(
				Buffer.from("From: a@example.com\r\nSubject: s\r\n\r\nx\r\n"),
			);
			const { code, cost } = await measured(raw);
			expect(code).toBe(refusal);
			// One header block parsed by the pre-scan, at most: a bound that does
			// not grow with the message.
			expect(cost).toBeLessThan(40);
		},
	);

	it("reads a message with thousands of recipients, in proportion to its size", async () => {
		const many = Array.from(
			{ length: 4_000 },
			(_, i) => `"Doe, J${i}" <j${i}@example.test>`,
		).join(",\r\n ");
		const raw = Buffer.from(
			`From: a@example.com\r\nSubject: s\r\nTo: ${many}\r\n\r\nx\r\n`,
		);
		const { code, cost } = await measured(raw);
		expect(code).toBe("parsed");
		expect(cost).toBeLessThan(16 * (raw.length / MIB) + 8);
		const m = await parseMessage(raw);
		expect(m.to).toHaveLength(4_000);
		expect(m.to[3_999]).toEqual({
			name: "Doe, J3999",
			address: "j3999@example.test",
		});
	});
});
