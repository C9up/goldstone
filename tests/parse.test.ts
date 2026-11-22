import { describe, expect, it } from "vitest";
import {
	authenticate,
	fromEngine,
	GoldstoneError,
	isNativeAvailable,
	parseMessage,
	readMessage,
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

describe("parseMessage", () => {
	it("runs on the native engine", () => {
		expect(isNativeAvailable()).toBe(true);
	});

	it("gives back the message: addresses, date, text, attachments", async () => {
		const m = await parseMessage(
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

	it("reads bytes that do not start at the beginning of their buffer", async () => {
		const raw = bytes(`garbage${HEAD}Content-Type: text/plain\r\n\r\nbody\r\n`);
		expect((await parseMessage(raw.subarray(7))).subject).toBe("Facture n° 42");
	});

	it("reads the bytes as they were when called, whatever the caller writes after", async () => {
		// A read buffer reused at once: the engine runs off this thread and
		// must not see the next message half-written over this one.
		const text = `${HEAD}Content-Type: text/plain\r\n\r\n${"line of the body\r\n".repeat(300_000)}`;
		const calls = [
			(raw: Uint8Array) => parseMessage(raw),
			(raw: Uint8Array) => readMessage(raw, { authenticate: false }),
			(raw: Uint8Array) => readMessage(raw, { authenticate: { timeoutMs: 1 } }),
		];
		for (const call of calls) {
			const raw = bytes(text);
			const pending = call(raw);
			raw.fill(0x2d);
			const message = await pending;
			expect(message.subject).toBe("Facture n° 42");
			expect(message.text?.startsWith("line of the body")).toBe(true);
		}
		const raw = bytes(text);
		const pending = authenticate(raw, { timeoutMs: 1 });
		raw.fill(0x2d);
		expect((await pending).fromDomain).toBe("example.test");
	});

	it("sanitizes the HTML, and hands the original only to the method that says so", async () => {
		const m = await parseMessage(
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

	it("names attachments so they cannot leave the directory they are saved to", async () => {
		const m = await parseMessage(
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
	it("refuses an oversized message before parsing it", async () => {
		expect(
			await codeOf(() =>
				parseMessage(new Uint8Array(101), { limits: { maxBytes: 100 } }),
			),
		).toBe("E_GOLDSTONE_MESSAGE_TOO_LARGE");
	});

	it("refuses deep nesting, too many parts, attachments too many or too large", async () => {
		let deep = "leaf\r\n";
		for (let i = 0; i < 40; i++) {
			deep = `Content-Type: multipart/mixed; boundary=b${i}\r\n\r\n--b${i}\r\n${deep}\r\n--b${i}--\r\n`;
		}
		expect(await codeOf(() => parseMessage(bytes(HEAD + deep)))).toBe(
			"E_GOLDSTONE_TOO_DEEP",
		);

		const parts = Array.from(
			{ length: 20 },
			() => "Content-Type: text/plain\r\n\r\nx",
		);
		expect(
			await codeOf(() =>
				parseMessage(bytes(HEAD + multipart("P", parts)), {
					limits: { maxParts: 10 },
				}),
			),
		).toBe("E_GOLDSTONE_TOO_MANY_PARTS");

		const files = Array.from({ length: 3 }, (_, i) =>
			attachment(`f${i}.pdf`, "eA=="),
		);
		expect(
			await codeOf(() =>
				parseMessage(bytes(HEAD + multipart("A", files)), {
					limits: { maxAttachments: 2 },
				}),
			),
		).toBe("E_GOLDSTONE_TOO_MANY_ATTACHMENTS");
		expect(
			await codeOf(() =>
				parseMessage(
					bytes(HEAD + multipart("A", [attachment("b.pdf", "AAAAAAAA")])),
					{
						limits: { maxAttachmentBytes: 4 },
					},
				),
			),
		).toBe("E_GOLDSTONE_ATTACHMENT_TOO_LARGE");
	});

	it.each([0, -1, 1.5, 2 ** 32, Number.NaN])(
		"refuses %s as a limit",
		async (value) => {
			expect(
				await codeOf(() =>
					parseMessage(bytes(HEAD), { limits: { maxParts: value } }),
				),
			).toBe("E_GOLDSTONE_INVALID_LIMITS");
		},
	);

	it("refuses what is not a message, and survives random bytes", async () => {
		expect(await codeOf(() => parseMessage(new Uint8Array()))).toBe(
			"E_GOLDSTONE_NOT_A_MESSAGE",
		);
		const random = new Uint8Array(1024 * 1024);
		let state = 68;
		for (let i = 0; i < random.length; i++) {
			state = (state * 1103515245 + 12345) >>> 0;
			random[i] = state >>> 24;
		}
		const outcome = await parseMessage(random).then(
			() => "parsed",
			(error: unknown) =>
				error instanceof GoldstoneError ? "refused" : "crashed",
		);
		expect(outcome).not.toBe("crashed");
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

describe("parseMessage — hostile HTML", () => {
	const html = (body: string) =>
		bytes(`${HEAD}Content-Type: text/html\r\n\r\n${body}\r\n`);

	it("parses off the event loop: timers keep firing during a parse", async () => {
		// Heavy but within every bound: half a megabyte of dense markup,
		// a formatting element re-opened in each paragraph, and 20 MB of text.
		let markup = '<div><b id="1"></div>';
		while (markup.length < 500 * 1024) markup += "<p>x";
		const raw = bytes(
			HEAD +
				multipart("H", [
					`Content-Type: text/html\r\n\r\n${markup}`,
					`Content-Type: text/plain\r\n\r\n${"lorem ipsum ".repeat(1_700_000)}`,
				]),
		);
		let ticks = 0;
		const timer = setInterval(() => {
			ticks += 1;
		}, 1);
		try {
			const pending = parseMessage(raw);
			expect(pending).toBeInstanceOf(Promise);
			const m = await pending;
			expect(m.html).toBeDefined();
		} finally {
			clearInterval(timer);
		}
		expect(ticks).toBeGreaterThan(0);
	}, 30_000);

	it("does not sanitize HTML nested 100 000 deep, and says why", async () => {
		const started = performance.now();
		const m = await parseMessage(html("<div>".repeat(100_000)));
		expect(performance.now() - started).toBeLessThan(2_000);
		expect(m.html).toBeUndefined();
		expect(m.htmlError?.code).toBe("E_GOLDSTONE_HTML_TOO_DEEP");
		expect(m.unsanitizedHtml()).toContain("<div>");
	});

	it("does not sanitize HTML whose tree outgrows its markup", async () => {
		let markup = "";
		for (let i = 0; i < 2_000; i++) markup += `<div><b id=${i}></div>`;
		markup += "<p>x".repeat(2_000);
		const started = performance.now();
		const m = await parseMessage(html(markup));
		expect(performance.now() - started).toBeLessThan(2_000);
		expect(m.html).toBeUndefined();
		expect(m.htmlError?.code).toBe("E_GOLDSTONE_HTML_TOO_COMPLEX");
	});

	it("does not sanitize HTML over maxHtmlBytes, and reads the rest", async () => {
		const m = await parseMessage(html("<p>hello</p>".repeat(100)), {
			limits: { maxHtmlBytes: 100 },
		});
		expect(m.subject).toBe("Facture n° 42");
		expect(m.html).toBeUndefined();
		expect(m.htmlError?.code).toBe("E_GOLDSTONE_HTML_TOO_LARGE");
		expect(m.text).toContain("hello");
	});
});

describe("parseMessage — structure bounded before parsing", () => {
	const manyParts = (n: number) =>
		`From: x@y.test\r\nContent-Type: multipart/mixed; boundary=I\r\n\r\n${"--I\r\n\r\nx\r\n".repeat(n)}--I--\r\n`;
	const carried = (inner: string) =>
		`${HEAD}Content-Type: multipart/mixed; boundary=O\r\n\r\n--O\r\nContent-Type: message/rfc822\r\n\r\n${inner}\r\n--O--\r\n`;

	it("refuses millions of headers without building them", async () => {
		const raw = bytes(
			`From: x@y.test\r\n${"a:b\r\n".repeat(4_800_000)}\r\nbody\r\n`,
		);
		const started = performance.now();
		expect(await codeOf(() => parseMessage(raw))).toBe(
			"E_GOLDSTONE_TOO_MANY_HEADERS",
		);
		expect(performance.now() - started).toBeLessThan(1_000);
	});

	it("bounds headers with maxHeaders and maxHeaderBytes", async () => {
		expect(
			await codeOf(() =>
				parseMessage(bytes(HEAD), { limits: { maxHeaders: 3 } }),
			),
		).toBe("E_GOLDSTONE_TOO_MANY_HEADERS");
		expect(
			await codeOf(() =>
				parseMessage(bytes(HEAD), { limits: { maxHeaderBytes: 64 } }),
			),
		).toBe("E_GOLDSTONE_HEADERS_TOO_LARGE");
	});

	it("counts the parts and the nesting of a carried message", async () => {
		expect(
			await codeOf(() => parseMessage(bytes(carried(manyParts(20_000))))),
		).toBe("E_GOLDSTONE_TOO_MANY_PARTS");
		let inner = "Subject: leaf\r\n\r\nleaf\r\n";
		for (let i = 0; i < 2_000; i++) {
			inner = `From: x@y.test\r\nContent-Type: message/rfc822\r\n\r\n${inner}`;
		}
		expect(await codeOf(() => parseMessage(bytes(HEAD + inner)))).toBe(
			"E_GOLDSTONE_TOO_DEEP",
		);
	});

	it("refuses boundaries that never occur before searching the message for each", async () => {
		// 900 parts declaring a boundary that never comes, in front of 20 MB:
		// each was searched for up to the end, 8 s of work per call.
		const parts = Array.from(
			{ length: 900 },
			(_, i) =>
				`--X\r\nContent-Type: multipart/mixed; boundary=never-${i}\r\n\r\nx\r\n`,
		).join("");
		const filler = "filler text that holds no delimiter at all\r\n".repeat(
			(20 * 1024 * 1024) / 44,
		);
		const raw = bytes(
			`${HEAD}Content-Type: multipart/mixed; boundary=X\r\n\r\n${parts}--X\r\n\r\n${filler}--X--\r\n`,
		);
		const calls = [
			() => parseMessage(raw),
			() => readMessage(raw, { authenticate: false }),
			() => readMessage(raw, { authenticate: { timeoutMs: 1 } }),
			() => authenticate(raw, { timeoutMs: 1 }),
		];
		for (const call of calls) {
			const started = performance.now();
			expect(await codeOf(call)).toBe("E_GOLDSTONE_MISSING_BOUNDARIES");
			expect(performance.now() - started).toBeLessThan(1_000);
		}
	});

	it("refuses a boundary too long to compare at every dash", async () => {
		const raw = bytes(
			`${HEAD}Content-Type: multipart/mixed; boundary="${"-".repeat(500_000)}x"\r\n\r\n${"-".repeat(4 * 1024 * 1024)}\r\n`,
		);
		expect(await codeOf(() => parseMessage(raw))).toBe(
			"E_GOLDSTONE_BOUNDARY_TOO_LONG",
		);
	});
});

describe("parseMessage — remote content", () => {
	const tracked = bytes(
		`${HEAD}Content-Type: text/html\r\n\r\n<p>Hi</p><img src="https://tracker.evil.test/open?u=victim" width="1" height="1"><img src="cid:logo@corp.test"><a href="https://evil.test/login">Bank</a>\r\n`,
	);

	it("blocks what a browser would load by itself, keeps cid: and links", async () => {
		const m = await parseMessage(tracked);
		expect(m.html).not.toContain("tracker.evil.test");
		expect(m.html).toContain('src="cid:logo@corp.test"');
		expect(m.html).toContain('href="https://evil.test/login"');
	});

	it("keeps remote content when the application allows it", async () => {
		const m = await parseMessage(tracked, { remoteContent: "allow" });
		expect(m.html).toContain("https://tracker.evil.test/open");
	});

	it("refuses a remoteContent that is neither block nor allow", async () => {
		expect(
			await codeOf(() =>
				parseMessage(tracked, {
					remoteContent: JSON.parse('"yes"'),
				}),
			),
		).toBe("E_GOLDSTONE_INVALID_OPTIONS");
	});
});
