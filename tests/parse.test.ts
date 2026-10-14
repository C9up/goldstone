import { describe, expect, it } from "vitest";
import {
	fromEngine,
	GoldstoneError,
	isNativeAvailable,
	parseMessage,
} from "../src/index.js";

const HEAD =
	"From: Bob <bob@example.test>\r\nTo: alice@example.test\r\nSubject: =?utf-8?Q?Facture_n=C2=B0_42?=\r\nDate: Tue, 13 Oct 2026 21:00:00 +0200\r\nMessage-ID: <m1@example.test>\r\nMIME-Version: 1.0\r\n";

const bytes = (text: string) => new TextEncoder().encode(text);

function multipart(boundary: string, parts: string[]): string {
	return `Content-Type: multipart/mixed; boundary=${boundary}\r\n\r\n${parts
		.map((p) => `--${boundary}\r\n${p}\r\n`)
		.join("")}--${boundary}--\r\n`;
}

const attachment = (name: string, base64: string) =>
	`Content-Type: application/pdf\r\nContent-Disposition: attachment; filename="${name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${base64}`;

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

describe("parseMessage", () => {
	it("runs on the native engine", () => {
		expect(isNativeAvailable()).toBe(true);
	});

	it("gives back the message: addresses, date, text, attachments", () => {
		const m = parseMessage(
			bytes(
				HEAD +
					multipart("B", [
						"Content-Type: text/plain; charset=utf-8\r\n\r\nHello Alice",
						attachment("invoice.pdf", "JVBERi0="),
					]),
			),
		);
		expect(m.subject).toBe("Facture n° 42");
		expect(m.from).toEqual([{ name: "Bob", address: "bob@example.test" }]);
		expect(m.to[0]?.address).toBe("alice@example.test");
		expect(m.messageId).toBe("m1@example.test");
		expect(m.date?.toISOString()).toBe("2026-10-13T19:00:00.000Z");
		expect(m.text).toBe("Hello Alice");
		expect(m.header("message-id")).toBe("<m1@example.test>");
		expect(m.attachments).toHaveLength(1);
		const [pdf] = m.attachments;
		expect(pdf?.fileName).toBe("invoice.pdf");
		expect(pdf?.contentType).toBe("application/pdf");
		expect(pdf?.size).toBe(5);
		expect(new TextDecoder().decode(pdf?.content)).toBe("%PDF-");
	});

	it("reads bytes that do not start at the beginning of their buffer", () => {
		const raw = bytes(`garbage${HEAD}Content-Type: text/plain\r\n\r\nbody\r\n`);
		expect(parseMessage(raw.subarray(7)).subject).toBe("Facture n° 42");
	});

	it("sanitizes the HTML, and hands the original only to the method that says so", () => {
		const m = parseMessage(
			bytes(
				`${HEAD}Content-Type: text/html\r\n\r\n<p onclick="alert(1)">hi</p><script>alert(2)</script><a href="javascript:alert(3)">x</a>\r\n`,
			),
		);
		expect(m.html).toContain("<p>hi</p>");
		for (const banned of ["<script", "onclick", "javascript:"]) {
			expect(m.html).not.toContain(banned);
		}
		expect(m.unsanitizedHtml()).toContain("<script>alert(2)</script>");
		expect(JSON.stringify(m)).not.toContain("<script>");
	});

	it("names attachments so they cannot leave the directory they are saved to", () => {
		const m = parseMessage(
			bytes(
				HEAD +
					multipart("N", [
						attachment("../../etc/passwd", "eA=="),
						attachment("..\\\\..\\\\boot.ini", "eA=="),
						attachment("con.txt", "eA=="),
					]),
			),
		);
		expect(m.attachments.map((a) => a.fileName)).toEqual([
			"passwd",
			"boot.ini",
			"_con.txt",
		]);
		expect(m.attachments[0]?.originalName).toBe("../../etc/passwd");
	});
});

describe("parseMessage — limits", () => {
	it("refuses an oversized message before parsing it", () => {
		expect(
			codeOf(() => parseMessage(new Uint8Array(101), { maxBytes: 100 })),
		).toBe("E_GOLDSTONE_MESSAGE_TOO_LARGE");
	});

	it("refuses deep nesting, too many parts, attachments too many or too large", () => {
		let deep = "leaf\r\n";
		for (let i = 0; i < 40; i++) {
			deep = `Content-Type: multipart/mixed; boundary=b${i}\r\n\r\n--b${i}\r\n${deep}\r\n--b${i}--\r\n`;
		}
		expect(codeOf(() => parseMessage(bytes(HEAD + deep)))).toBe(
			"E_GOLDSTONE_TOO_DEEP",
		);

		const parts = Array.from(
			{ length: 20 },
			() => "Content-Type: text/plain\r\n\r\nx",
		);
		expect(
			codeOf(() =>
				parseMessage(bytes(HEAD + multipart("P", parts)), { maxParts: 10 }),
			),
		).toBe("E_GOLDSTONE_TOO_MANY_PARTS");

		const files = Array.from({ length: 3 }, (_, i) =>
			attachment(`f${i}.pdf`, "eA=="),
		);
		expect(
			codeOf(() =>
				parseMessage(bytes(HEAD + multipart("A", files)), {
					maxAttachments: 2,
				}),
			),
		).toBe("E_GOLDSTONE_TOO_MANY_ATTACHMENTS");
		expect(
			codeOf(() =>
				parseMessage(
					bytes(HEAD + multipart("A", [attachment("b.pdf", "AAAAAAAA")])),
					{
						maxAttachmentBytes: 4,
					},
				),
			),
		).toBe("E_GOLDSTONE_ATTACHMENT_TOO_LARGE");
	});

	it.each([0, -1, 1.5, 2 ** 32, Number.NaN])(
		"refuses %s as a limit",
		(value) => {
			expect(codeOf(() => parseMessage(bytes(HEAD), { maxParts: value }))).toBe(
				"E_GOLDSTONE_INVALID_LIMITS",
			);
		},
	);

	it("refuses what is not a message, and survives random bytes", () => {
		expect(codeOf(() => parseMessage(new Uint8Array()))).toBe(
			"E_GOLDSTONE_NOT_A_MESSAGE",
		);
		const random = new Uint8Array(1024 * 1024);
		let state = 68;
		for (let i = 0; i < random.length; i++) {
			state = (state * 1103515245 + 12345) >>> 0;
			random[i] = state >>> 24;
		}
		expect(() => {
			try {
				parseMessage(random);
			} catch (error) {
				if (!(error instanceof GoldstoneError)) throw error;
			}
		}).not.toThrow();
	});
});

describe("fromEngine", () => {
	it("keeps an engine code and labels anything else", () => {
		expect(fromEngine(new Error("E_GOLDSTONE_TOO_DEEP: nests 40")).code).toBe(
			"E_GOLDSTONE_TOO_DEEP",
		);
		expect(
			fromEngine(new Error("E_GOLDSTONE_TOO_DEEP: nests 40")).message,
		).toBe("nests 40");
		expect(fromEngine(new Error("boom")).code).toBe("E_GOLDSTONE_ENGINE");
		expect(fromEngine("not an error").code).toBe("E_GOLDSTONE_ENGINE");
	});
});
