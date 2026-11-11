/**
 * A scripted IMAP server for what a real one will not do: lie about a
 * message's size, leave it out, then send a literal far over the limit.
 * Counts the body bytes the client actually took off the socket.
 */

import { createServer, type Server, type Socket } from "node:net";

export type SizeAnswer = "lie" | "omit" | "truth";

export class ScriptedImap {
	readonly #server: Server;
	readonly #sockets = new Set<Socket>();
	port = 0;
	/** Body bytes the kernel accepted before the client went away. */
	bodyBytesWritten = 0;
	/** The client asked to upgrade the plaintext connection. */
	startTlsAsked = false;

	constructor(
		readonly size: SizeAnswer,
		readonly bodyBytes: number,
		/** Offer STARTTLS, and decline it when asked. */
		readonly offersStartTls = false,
	) {
		this.#server = createServer((socket) => this.#serve(socket));
	}

	async listen(): Promise<void> {
		await new Promise<void>((resolve) =>
			this.#server.listen(0, "127.0.0.1", resolve),
		);
		const address = this.#server.address();
		if (address !== null && typeof address === "object") {
			this.port = address.port;
		}
	}

	async close(): Promise<void> {
		for (const socket of this.#sockets) socket.destroy();
		await new Promise<void>((resolve) => this.#server.close(() => resolve()));
	}

	#serve(socket: Socket): void {
		this.#sockets.add(socket);
		socket.on("close", () => this.#sockets.delete(socket));
		socket.on("error", () => {});
		const startTls = this.offersStartTls ? " STARTTLS" : "";
		socket.write(
			`* OK [CAPABILITY IMAP4rev1 UIDPLUS LITERAL+${startTls}] ready\r\n`,
		);
		let buffer = "";
		socket.on("data", (chunk) => {
			buffer += chunk.toString("latin1");
			for (
				let end = buffer.indexOf("\r\n");
				end >= 0;
				end = buffer.indexOf("\r\n")
			) {
				const line = buffer.slice(0, end);
				buffer = buffer.slice(end + 2);
				void this.#answer(socket, line);
			}
		});
	}

	async #answer(socket: Socket, line: string): Promise<void> {
		const [tag = "", command = "", ...rest] = line.split(" ");
		const verb = command.toUpperCase();
		const args = rest.join(" ");
		if (verb === "STARTTLS") {
			this.startTlsAsked = true;
			socket.end(`${tag} NO not today\r\n`);
		} else if (verb === "LOGIN") {
			socket.write(`${tag} OK [CAPABILITY IMAP4rev1 UIDPLUS LITERAL+] in\r\n`);
		} else if (verb === "SELECT" || verb === "EXAMINE") {
			socket.write(
				`* 1 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n* OK [UIDNEXT 2] n\r\n${tag} OK [READ-WRITE] done\r\n`,
			);
		} else if (verb === "UID" && /^FETCH/i.test(args)) {
			if (/RFC822\.SIZE/i.test(args)) {
				const size =
					this.size === "omit"
						? ""
						: ` RFC822.SIZE ${this.size === "lie" ? 100 : this.bodyBytes}`;
				socket.write(`* 1 FETCH (UID 1${size})\r\n${tag} OK done\r\n`);
			} else {
				await this.#sendBody(socket, tag);
			}
		} else if (verb === "LOGOUT") {
			socket.end(`* BYE\r\n${tag} OK bye\r\n`);
		} else {
			socket.write(`${tag} OK done\r\n`);
		}
	}

	/** The literal in chunks, as fast as the client reads it, until it stops. */
	async #sendBody(socket: Socket, tag: string): Promise<void> {
		socket.write(`* 1 FETCH (UID 1 BODY[] {${this.bodyBytes}}\r\n`);
		const head = "From: a@x.test\r\nSubject: big\r\n\r\n";
		const chunk = Buffer.alloc(64 * 1024, 0x61);
		let sent = 0;
		const start = socket.bytesWritten;
		while (sent < this.bodyBytes && !socket.destroyed) {
			const size = Math.min(chunk.length, this.bodyBytes - sent);
			const piece =
				sent === 0
					? Buffer.concat([Buffer.from(head), chunk]).subarray(0, size)
					: chunk.subarray(0, size);
			sent += size;
			if (!socket.write(piece)) {
				const flowing = await new Promise<boolean>((resolve) => {
					socket.once("drain", () => resolve(true));
					socket.once("close", () => resolve(false));
				});
				if (!flowing) break;
			}
		}
		this.bodyBytesWritten = socket.bytesWritten - start;
		if (!socket.destroyed) socket.write(`)\r\n${tag} OK done\r\n`);
	}
}
