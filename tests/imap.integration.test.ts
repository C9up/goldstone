import { ImapFlow } from "imapflow";
import { afterEach, describe, expect, it } from "vitest";
import {
	GoldstoneError,
	Mailbox,
	type MailboxConfig,
	type ReceivedMessage,
} from "../src/index.js";
import {
	imapHost,
	imapPort,
	Relay,
	sendMail,
	serverAvailable,
	until,
} from "./support/imap.js";

// GreenMail is started with one user per test (see the CI workflow):
//   alice, dave, erin, frank — password "secret", at example.test.
const describeImap = serverAvailable ? describe : describe.skip;

function config(
	user: string,
	overrides: Partial<MailboxConfig> = {},
): MailboxConfig {
	return {
		host: imapHost,
		port: imapPort,
		// GreenMail's certificate is self-signed.
		allowInsecure: true,
		tls: { rejectUnauthorized: false },
		auth: { user, pass: "secret" },
		...overrides,
	};
}

const opened: Mailbox[] = [];
function mailbox(
	user: string,
	overrides: Partial<MailboxConfig> = {},
	maxBytes?: number,
): Mailbox {
	const box = new Mailbox(user, config(user, overrides), {
		limits: maxBytes ? { maxBytes } : undefined,
	});
	opened.push(box);
	return box;
}

afterEach(async () => {
	await Promise.all(opened.splice(0).map((box) => box.close()));
});

async function createFolder(user: string, path: string): Promise<void> {
	const client = new ImapFlow({
		host: imapHost,
		port: imapPort,
		secure: true,
		tls: { rejectUnauthorized: false },
		auth: { user, pass: "secret" },
		logger: false,
	});
	await client.connect();
	await client.mailboxCreate(path).catch(() => {});
	await client.logout();
}

describeImap("Mailbox", () => {
	it("lists, searches, reads, flags, moves and deletes", async () => {
		const box = mailbox("alice");
		await sendMail("alice@example.test", "first");
		await sendMail("alice@example.test", "=?utf-8?Q?Facture_n=C2=B0_42?=");

		expect(await box.folders()).toContain("INBOX");
		const uids = await box.search({ all: true });
		expect(uids.length).toBeGreaterThanOrEqual(2);
		const newest = uids.at(-1) ?? 0;

		const message = await box.fetch(newest);
		expect(message?.subject).toBe("Facture n° 42");
		expect(message?.from[0]?.address).toBe("bob@example.test");
		expect(await box.fetch(999_999)).toBeUndefined();

		await box.markSeen(newest);
		expect(await box.search({ seen: true })).toContain(newest);
		await box.markUnseen(newest);
		expect(await box.search({ seen: false })).toContain(newest);

		await createFolder("alice", "Archive");
		const archived = (await box.search({ all: true }, "Archive")).length;
		await box.move(newest, "Archive");
		expect(await box.search({ all: true })).not.toContain(newest);
		expect((await box.search({ all: true }, "Archive")).length).toBe(
			archived + 1,
		);

		const first = uids[0] ?? 0;
		await box.delete(first);
		expect(await box.search({ all: true })).not.toContain(first);
		await box.markSeen([]);
	});

	it("refuses a message over the size limit before downloading it", async () => {
		const box = mailbox("frank", {}, 500);
		await sendMail("frank@example.test", "big", "x".repeat(2_000));
		const [uid] = await box.search({ all: true });
		const error = await box.fetch(uid ?? 0).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(GoldstoneError);
		expect(error).toMatchObject({ code: "E_GOLDSTONE_MESSAGE_TOO_LARGE" });
	});

	it("watches: delivers live, survives a lost connection, misses and repeats nothing", async () => {
		const relay = new Relay();
		await relay.open();
		const box = mailbox("dave", { port: relay.port });
		const seen: string[] = [];
		const errors: unknown[] = [];
		const stop = box.watch(
			(message: ReceivedMessage) => void seen.push(message.subject ?? ""),
			{
				onError: (error) => errors.push(error),
			},
		);
		// Already there before watching: not delivered.
		await sendMail("dave@example.test", "before");
		await new Promise((r) => setTimeout(r, 1500));
		seen.length = 0;

		await sendMail("dave@example.test", "live-1");
		await until(() => seen.includes("live-1"));

		await relay.cut();
		await sendMail("dave@example.test", "during-the-cut");
		await new Promise((r) => setTimeout(r, 1000));
		await relay.open();
		await until(() => seen.includes("during-the-cut"), 30_000);

		await sendMail("dave@example.test", "after");
		await until(() => seen.includes("after"));
		await stop();

		expect(seen).toEqual(["live-1", "during-the-cut", "after"]);
		expect(errors.length).toBeGreaterThan(0); // the cut was reported, not thrown
		await relay.cut();
	}, 60_000);

	it("asks for the token again on every connection, so an expired one is replaced", async () => {
		const tokens = ["expired", "secret"];
		let asked = 0;
		const box = mailbox("erin", {
			auth: {
				user: "erin",
				accessToken: () => tokens[Math.min(asked++, 1)] ?? "",
			},
		});
		await sendMail("erin@example.test", "with a token");
		const seen: string[] = [];
		const errors: unknown[] = [];
		const stop = box.watch((message) => void seen.push(message.subject ?? ""), {
			afterUid: 0,
			onError: (error) => errors.push(error),
		});
		await until(() => seen.includes("with a token"), 20_000);
		await stop();
		expect(asked).toBeGreaterThanOrEqual(2);
		expect(errors.length).toBeGreaterThanOrEqual(1); // the expired token was refused
	}, 30_000);
});

describe("Mailbox — refusals that need no server", () => {
	it("refuses a mailbox that would talk without TLS", () => {
		expect(
			() =>
				new Mailbox("m", {
					host: "h",
					secure: false,
					auth: { user: "u", pass: "p" },
				}),
		).toThrow(
			expect.objectContaining({ code: "E_GOLDSTONE_INSECURE_CONNECTION" }),
		);
	});
});
