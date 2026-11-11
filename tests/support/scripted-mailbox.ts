/**
 * A scripted IMAP mailbox for watch(): it answers SEARCH, FETCH and IDLE,
 * and can announce a new message (an untagged EXISTS) in the middle of a
 * FETCH, as a real server does whenever mail arrives during one.
 */

import { createServer, type Server, type Socket } from "node:net";

function message(uid: number): string {
	return `From: a@x.test\r\nSubject: message ${uid}\r\n\r\nbody ${uid}\r\n`;
}

export class ScriptedMailbox {
	readonly #server: Server;
	readonly #sockets = new Set<Socket>();
	port = 0;
	/** The UIDs in the mailbox, 1 to `count`. */
	count: number;
	/** While the body of this UID is sent, one more message arrives. */
	arrivesDuringFetchOf: number | undefined;

	constructor(count: number, arrivesDuringFetchOf?: number) {
		this.count = count;
		this.arrivesDuringFetchOf = arrivesDuringFetchOf;
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
		socket.write("* OK [CAPABILITY IMAP4rev1 UIDPLUS IDLE] ready\r\n");
		let idling: string | undefined;
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
				if (line === "DONE" && idling !== undefined) {
					socket.write(`${idling} OK idle done\r\n`);
					idling = undefined;
					continue;
				}
				const [tag = "", command = "", ...rest] = line.split(" ");
				if (command.toUpperCase() === "IDLE") {
					idling = tag;
					socket.write("+ idling\r\n");
				} else {
					this.#answer(socket, tag, command.toUpperCase(), rest.join(" "));
				}
			}
		});
	}

	#answer(socket: Socket, tag: string, verb: string, args: string): void {
		if (verb === "LOGIN") {
			socket.write(`${tag} OK [CAPABILITY IMAP4rev1 UIDPLUS IDLE] in\r\n`);
		} else if (verb === "SELECT" || verb === "EXAMINE") {
			socket.write(
				`* ${this.count} EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n* OK [UIDNEXT ${this.count + 1}] n\r\n${tag} OK [READ-WRITE] done\r\n`,
			);
		} else if (verb === "UID" && /^SEARCH/i.test(args)) {
			const from = Number(/UID (\d+):/i.exec(args)?.[1] ?? "1");
			const uids = [];
			for (let uid = from; uid <= this.count; uid++) uids.push(uid);
			socket.write(`* SEARCH ${uids.join(" ")}\r\n${tag} OK done\r\n`);
		} else if (verb === "UID" && /^FETCH/i.test(args)) {
			const uid = Number(/^FETCH (\d+)/i.exec(args)?.[1] ?? "0");
			const body = message(uid);
			if (/RFC822\.SIZE/i.test(args)) {
				socket.write(
					`* ${uid} FETCH (UID ${uid} RFC822.SIZE ${body.length})\r\n${tag} OK done\r\n`,
				);
				return;
			}
			let arrived = "";
			if (uid === this.arrivesDuringFetchOf) {
				this.arrivesDuringFetchOf = undefined;
				this.count += 1;
				arrived = `* ${this.count} EXISTS\r\n`;
			}
			socket.write(
				`* ${uid} FETCH (UID ${uid} BODY[] {${body.length}}\r\n${body})\r\n${arrived}${tag} OK done\r\n`,
			);
		} else if (verb === "LOGOUT") {
			socket.end(`* BYE\r\n${tag} OK bye\r\n`);
		} else {
			socket.write(`${tag} OK done\r\n`);
		}
	}
}
