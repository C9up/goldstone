import { afterEach, describe, expect, it } from "vitest";
import { GoldstoneError, Mailbox } from "../src/index.js";
import { ScriptedImap, type SizeAnswer } from "./support/scripted-imap.js";

const MAX_BYTES = 1024 * 1024;
const SIXTY_MIB = 60 * 1024 * 1024;

const servers: ScriptedImap[] = [];
const boxes: Mailbox[] = [];
afterEach(async () => {
	await Promise.all(boxes.splice(0).map((box) => box.close()));
	await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function scripted(size: SizeAnswer, bodyBytes: number) {
	const server = new ScriptedImap(size, bodyBytes);
	await server.listen();
	servers.push(server);
	const box = new Mailbox(
		"scripted",
		{
			host: "127.0.0.1",
			port: server.port,
			secure: false,
			allowInsecure: true,
			auth: { user: "u", pass: "p" },
		},
		{ authenticate: false, limits: { maxBytes: MAX_BYTES } },
	);
	boxes.push(box);
	return { server, box };
}

async function codeOf(run: () => Promise<unknown>): Promise<string> {
	try {
		await run();
		return "resolved";
	} catch (error) {
		return error instanceof GoldstoneError ? error.code : String(error);
	}
}

describe("Mailbox — the download is bounded by maxBytes, not by the server", () => {
	it.each<SizeAnswer>(["lie", "omit"])(
		"refuses a 60 MiB message when the server's size answer is a %s",
		async (size) => {
			const { server, box } = await scripted(size, SIXTY_MIB);
			expect(await codeOf(() => box.fetch(1))).toBe(
				"E_GOLDSTONE_MESSAGE_TOO_LARGE",
			);
			// What sat in socket buffers when the client hung up, not 60 MiB.
			expect(server.bodyBytesWritten).toBeLessThan(16 * 1024 * 1024);
		},
		30_000,
	);

	it("still reads a message within the limit when the size is missing", async () => {
		const { box } = await scripted("omit", 4096);
		const message = await box.fetch(1);
		expect(message?.subject).toBe("big");
	});
});
