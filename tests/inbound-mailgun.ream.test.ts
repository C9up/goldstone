/**
 * The Mailgun handler on Ream's real stack — native server, router, body
 * parser — as the README sets it up. The handler reads `request.body()`,
 * which holds the fields only once the body parser has read the form Mailgun
 * posts: multipart/form-data, or urlencoded.
 */

import { createHmac } from "node:crypto";
import { BodyParserMiddleware, type HttpContext, Ignitor } from "@c9up/ream";
import { createHyperServerFactory } from "@c9up/ream/bootstrap";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createMailgunInboundHandler,
	type ReceivedMessage,
} from "../src/index.js";

const KEY = "key-test-signing";
const MIME =
	"From: bob@example.test\r\nTo: support@example.test\r\nSubject: help\r\n\r\nIt broke.\r\n";

let counter = 0;
function signedFields(mime = MIME): Record<string, string> {
	const timestamp = String(Math.floor(Date.now() / 1000));
	const token = `ream-${++counter}-${"x".repeat(40)}`;
	return {
		timestamp,
		token,
		signature: createHmac("sha256", KEY)
			.update(timestamp + token)
			.digest("hex"),
		"body-mime": mime,
		recipient: "support@example.test",
		sender: "bob@example.test",
	};
}

// A message up to goldstone's 25 MiB, in either form Mailgun posts: the
// parser's limits, and the native server's, read from the same config.
const limits = { form: { limit: "30mb" }, multipart: { limit: "30mb" } };
const bodyParser = new BodyParserMiddleware(limits);
const parseBody = (ctx: HttpContext, next: () => Promise<void>) =>
	bodyParser.handle(ctx, next);

describe("createMailgunInboundHandler — on a Ream route", () => {
	const received: ReceivedMessage[] = [];
	let ignitor: Ignitor;
	let base = "";

	beforeAll(async () => {
		const serverFactory = createHyperServerFactory();
		if (serverFactory === undefined) {
			throw new Error("no prebuilt Ream server binary for this platform");
		}
		const handler = createMailgunInboundHandler({
			signingKey: KEY,
			authenticate: false,
			onMessage: (message) => void received.push(message),
		});
		ignitor = await new Ignitor({
			port: 0,
			gracefulShutdown: false,
			serverFactory,
		})
			.configure("bodyparser", limits)
			.routes((router) => {
				router.post("/inbound/mailgun/mime", handler).use(parseBody);
				router.post("/unparsed/mailgun/mime", handler);
			})
			.httpServer()
			.start();
		base = `http://127.0.0.1:${await ignitor.port()}`;
	});

	afterAll(async () => {
		await ignitor.stop();
	});

	it("receives a delivery posted as multipart/form-data", async () => {
		const form = new FormData();
		for (const [name, value] of Object.entries(signedFields())) {
			form.append(name, value);
		}
		const response = await fetch(`${base}/inbound/mailgun/mime`, {
			method: "POST",
			body: form,
		});
		expect(response.status).toBe(204);
		expect(received.at(-1)?.subject).toBe("help");
	});

	it("receives a delivery posted urlencoded, a message of several MiB too", async () => {
		const large = `${MIME}${"a line of the body\r\n".repeat(200_000)}`;
		const response = await fetch(`${base}/inbound/mailgun/mime`, {
			method: "POST",
			body: new URLSearchParams(signedFields(large)),
		});
		expect(response.status).toBe(204);
		expect(received.at(-1)?.text?.length).toBeGreaterThan(3_000_000);
	});

	it("sees no field on a route the body parser does not run on", async () => {
		const before = received.length;
		const response = await fetch(`${base}/unparsed/mailgun/mime`, {
			method: "POST",
			body: new URLSearchParams(signedFields()),
		});
		expect(response.status).toBe(401);
		expect(received).toHaveLength(before);
	});
});
