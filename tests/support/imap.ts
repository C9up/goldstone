/**
 * What the IMAP tests need around a test server (GreenMail): where it is,
 * a way to drop mail into it over SMTP, and a TCP relay that can be cut to
 * stand for a lost network.
 *
 * GOLDSTONE_IMAP_TEST_HOST (default 127.0.0.1), GOLDSTONE_IMAP_TEST_PORT
 * (IMAPS, e.g. 3993) and GOLDSTONE_SMTP_TEST_PORT (e.g. 3025). Without a
 * port, the suites that need a server are skipped, not failed.
 */

import { connect, createServer, type Server, type Socket } from "node:net";

export const imapHost = process.env.GOLDSTONE_IMAP_TEST_HOST ?? "127.0.0.1";
export const imapPort = Number(process.env.GOLDSTONE_IMAP_TEST_PORT ?? 0);
export const smtpPort = Number(process.env.GOLDSTONE_SMTP_TEST_PORT ?? 0);
export const serverAvailable = imapPort > 0 && smtpPort > 0;

/** Send one mail through the test server's SMTP port. */
export function sendMail(
	to: string,
	subject: string,
	body = "hello",
	extraHeaders = "",
): Promise<void> {
	const lines = [
		"HELO test",
		"MAIL FROM:<bob@example.test>",
		`RCPT TO:<${to}>`,
		"DATA",
		`From: bob@example.test\r\nTo: ${to}\r\nSubject: ${subject}\r\n${extraHeaders}\r\n${body}\r\n.`,
		"QUIT",
	];
	return new Promise((resolve, reject) => {
		const socket = connect(smtpPort, imapHost);
		let step = 0;
		let buffer = "";
		socket.setEncoding("utf8");
		socket.on("error", reject);
		socket.on("data", (chunk: string) => {
			buffer += chunk;
			// One reply per command (the greeting first); each ends a line.
			while (buffer.includes("\r\n")) {
				const end = buffer.indexOf("\r\n");
				const reply = buffer.slice(0, end);
				buffer = buffer.slice(end + 2);
				if (/^\d{3}-/.test(reply)) continue; // multi-line reply, not its last line
				if (!/^[23]\d\d/.test(reply)) {
					reject(new Error(`SMTP refused: ${reply}`));
					socket.destroy();
					return;
				}
				const line = lines[step++];
				if (line === undefined) {
					socket.end();
					resolve();
					return;
				}
				socket.write(`${line}\r\n`);
			}
		});
	});
}

/** A relay to the IMAP port that can be cut, as a lost network would. */
export class Relay {
	readonly #sockets = new Set<Socket>();
	#server: Server | undefined;
	port = 0;

	async open(): Promise<void> {
		const server = createServer((client) => {
			const upstream = connect(imapPort, imapHost);
			for (const socket of [client, upstream]) {
				this.#sockets.add(socket);
				socket.on("close", () => this.#sockets.delete(socket));
				socket.on("error", () => {});
			}
			client.pipe(upstream).pipe(client);
		});
		await new Promise<void>((resolve) =>
			server.listen(this.port, "127.0.0.1", resolve),
		);
		const address = server.address();
		if (address && typeof address === "object") this.port = address.port;
		this.#server = server;
	}

	/** Drop every connection and stop listening. */
	async cut(): Promise<void> {
		for (const socket of this.#sockets) socket.destroy();
		const server = this.#server;
		this.#server = undefined;
		if (server)
			await new Promise<void>((resolve) => server.close(() => resolve()));
	}
}

/** Resolve once `check` holds, or fail after `ms`. */
export async function until(check: () => boolean, ms = 15_000): Promise<void> {
	const start = Date.now();
	while (!check()) {
		if (Date.now() - start > ms) throw new Error("timed out waiting");
		await new Promise((r) => setTimeout(r, 50));
	}
}
