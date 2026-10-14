/**
 * One IMAP mailbox: its connection, opened on first use, and what the
 * application does with it.
 *
 *   const support = inbox.mailbox('support')
 *   for (const uid of await support.search({ seen: false })) {
 *     const message = await support.fetch(uid)
 *   }
 *   const stop = support.watch(async (message, { uid }) => { … })
 *
 * Every message read goes through {@link readMessage}: its size is asked of
 * the server first, so one over the limit is refused without being
 * downloaded; it is then parsed, and its sender checked (DKIM, SPF, DMARC)
 * unless `authenticate: false`.
 */

import { ImapFlow, type SearchObject } from "imapflow";
import { assertSecure, type MailboxConfig } from "./config.js";
import { GoldstoneError } from "./errors.js";
import {
	type Limits,
	type ReceivedMessage,
	readMessage,
} from "./ReceivedMessage.js";

export type SearchCriteria = SearchObject;

export interface WatchOptions {
	/** Default `INBOX`. */
	folder?: string;
	/**
	 * Deliver messages after this UID. Default: none of those already there —
	 * only what arrives once watching started.
	 */
	afterUid?: number;
	/**
	 * Told about what does not stop the watch: a lost connection (it
	 * reconnects), a message refused by the limits, a handler that threw, a
	 * mailbox whose UIDs were reset. Default: `console.error`.
	 */
	onError?: (error: unknown) => void;
}

/** Wait before reconnect attempt `n`: 0.5 s, 1 s, 2 s… up to 30 s. */
export function reconnectDelay(attempt: number): number {
	return Math.min(500 * 2 ** Math.max(attempt - 1, 0), 30_000);
}

const DEFAULT_MAX_BYTES = 25 * 1024 * 1024;

export interface MailboxOptions {
	/** Bounds on every message read. */
	limits?: Limits;
	/**
	 * Check DKIM, SPF and DMARC on every message read — the verdict lands on
	 * `message.authenticity`. Default `true`: it costs DNS lookups (cached),
	 * and a From nobody checked is the From a phisher wrote.
	 */
	authenticate?: boolean;
}

export class Mailbox {
	readonly name: string;
	readonly #config: MailboxConfig;
	readonly #limits: Limits | undefined;
	readonly #authenticate: boolean;
	#client: Promise<ImapFlow> | undefined;
	readonly #watches = new Set<() => Promise<void>>();

	constructor(
		name: string,
		config: MailboxConfig,
		options: MailboxOptions = {},
	) {
		assertSecure(name, config);
		this.name = name;
		this.#config = config;
		this.#limits = options.limits;
		this.#authenticate = options.authenticate ?? true;
	}

	/** Every folder's path, as the server names it. */
	async folders(): Promise<string[]> {
		const client = await this.#connection();
		return (await client.list()).map((folder) => folder.path);
	}

	/** UIDs of the messages that match, in `folder` (default `INBOX`). */
	async search(criteria: SearchCriteria, folder = "INBOX"): Promise<number[]> {
		return this.#in(folder, async (client) => {
			const uids = await client.search(criteria, { uid: true });
			return Array.isArray(uids) ? [...uids].sort((a, b) => a - b) : [];
		});
	}

	/**
	 * One message, parsed — or `undefined` when no message has that UID.
	 * Refused with `E_GOLDSTONE_MESSAGE_TOO_LARGE` before download when the
	 * server says it is over the limit.
	 */
	async fetch(
		uid: number,
		folder = "INBOX",
	): Promise<ReceivedMessage | undefined> {
		return this.#in(folder, (client) => this.#read(client, uid));
	}

	async markSeen(uids: number | number[], folder = "INBOX"): Promise<void> {
		if (isEmpty(uids)) return;
		await this.#in(folder, (client) =>
			client.messageFlagsAdd(range(uids), ["\\Seen"], { uid: true }),
		);
	}

	async markUnseen(uids: number | number[], folder = "INBOX"): Promise<void> {
		if (isEmpty(uids)) return;
		await this.#in(folder, (client) =>
			client.messageFlagsRemove(range(uids), ["\\Seen"], { uid: true }),
		);
	}

	async move(
		uids: number | number[],
		to: string,
		folder = "INBOX",
	): Promise<void> {
		if (isEmpty(uids)) return;
		await this.#in(folder, (client) =>
			client.messageMove(range(uids), to, { uid: true }),
		);
	}

	async delete(uids: number | number[], folder = "INBOX"): Promise<void> {
		if (isEmpty(uids)) return;
		await this.#in(folder, (client) =>
			client.messageDelete(range(uids), { uid: true }),
		);
	}

	/**
	 * Call `handler` for every new message, as it arrives (IDLE), on a
	 * connection of its own. A lost connection is reopened with a growing
	 * wait, and what arrived meanwhile is delivered on return: messages are
	 * followed by UID, so none is skipped and none delivered twice.
	 *
	 * A handler that throws does not stop the watch, and the message is not
	 * offered again — a message that always fails would otherwise stall the
	 * mailbox. Resolves the returned function once the watch has stopped.
	 */
	watch(
		handler: (message: ReceivedMessage, meta: { uid: number }) => unknown,
		options: WatchOptions = {},
	): () => Promise<void> {
		const folder = options.folder ?? "INBOX";
		const report =
			options.onError ??
			((error: unknown) =>
				console.error(`[inbox] ${this.name}/${folder}:`, error));
		let last = options.afterUid;
		let uidValidity: bigint | undefined;
		let stopped = false;
		let current: ImapFlow | undefined;
		let wake: (() => void) | undefined;

		const deliverNew = async (client: ImapFlow): Promise<void> => {
			const after = last ?? 0;
			const found = await client.search(
				{ uid: `${after + 1}:*` },
				{ uid: true },
			);
			const uids = (Array.isArray(found) ? found : [])
				.filter((uid) => uid > after)
				.sort((a, b) => a - b);
			for (const uid of uids) {
				if (stopped) return;
				try {
					const message = await this.#read(client, uid);
					if (message) await handler(message, { uid });
				} catch (error) {
					report(error);
				}
				last = uid;
			}
		};

		const run = async (): Promise<void> => {
			let attempt = 0;
			while (!stopped) {
				try {
					const client = await this.#open();
					current = client;
					const opened = await client.mailboxOpen(folder);
					if (uidValidity !== undefined && opened.uidValidity !== uidValidity) {
						report(
							new GoldstoneError(
								"E_GOLDSTONE_UIDVALIDITY_CHANGED",
								`[inbox] ${this.name}/${folder} renumbered its messages; watching resumes from the newest`,
							),
						);
						last = undefined;
					}
					uidValidity = opened.uidValidity;
					if (last === undefined) last = opened.uidNext - 1;
					attempt = 0;
					await deliverNew(client);
					await new Promise<void>((resolve) => {
						let queue = Promise.resolve();
						client.on("exists", () => {
							queue = queue.then(() => deliverNew(client)).catch(report);
						});
						client.on("close", () => resolve());
						client.on("error", () => {});
						wake = resolve;
						if (stopped) resolve();
					});
				} catch (error) {
					if (!stopped) report(error);
				}
				current?.close();
				current = undefined;
				if (stopped) break;
				attempt += 1;
				await new Promise<void>((resolve) => {
					const timer = setTimeout(resolve, reconnectDelay(attempt));
					wake = () => {
						clearTimeout(timer);
						resolve();
					};
				});
			}
		};

		const done = run();
		const stop = async (): Promise<void> => {
			stopped = true;
			wake?.();
			await current?.logout().catch(() => {});
			await done;
			this.#watches.delete(stop);
		};
		this.#watches.add(stop);
		return stop;
	}

	/** Stop every watch and log out. */
	async close(): Promise<void> {
		await Promise.all([...this.#watches].map((stop) => stop()));
		const client = this.#client;
		this.#client = undefined;
		if (client) {
			await client.then((c) => c.logout()).catch(() => {});
		}
	}

	async #read(
		client: ImapFlow,
		uid: number,
	): Promise<ReceivedMessage | undefined> {
		const maxBytes = this.#limits?.maxBytes ?? DEFAULT_MAX_BYTES;
		const sized = await client.fetchOne(
			String(uid),
			{ uid: true, size: true },
			{ uid: true },
		);
		if (!sized) return undefined;
		if (sized.size !== undefined && sized.size > maxBytes) {
			throw new GoldstoneError(
				"E_GOLDSTONE_MESSAGE_TOO_LARGE",
				`[inbox] message ${uid} is ${sized.size} bytes, over the ${maxBytes} allowed — not downloaded`,
			);
		}
		const full = await client.fetchOne(
			String(uid),
			{ uid: true, source: true },
			{ uid: true },
		);
		if (full === false || full === undefined || full.source === undefined) {
			return undefined;
		}
		return readMessage(full.source, {
			limits: this.#limits,
			authenticate: this.#authenticate,
		});
	}

	async #in<T>(
		folder: string,
		work: (client: ImapFlow) => Promise<T>,
	): Promise<T> {
		const client = await this.#connection();
		const lock = await client.getMailboxLock(folder);
		try {
			return await work(client);
		} finally {
			lock.release();
		}
	}

	/** The shared connection, opened on first use and again after a loss. */
	#connection(): Promise<ImapFlow> {
		if (!this.#client) {
			const opening = this.#open();
			this.#client = opening;
			opening.then(
				(client) =>
					client.on("close", () => {
						if (this.#client === opening) this.#client = undefined;
					}),
				() => {
					if (this.#client === opening) this.#client = undefined;
				},
			);
		}
		return this.#client;
	}

	async #open(): Promise<ImapFlow> {
		const config = this.#config;
		const secure = config.secure ?? true;
		const auth =
			"pass" in config.auth
				? { user: config.auth.user, pass: config.auth.pass }
				: {
						user: config.auth.user,
						accessToken:
							typeof config.auth.accessToken === "function"
								? await config.auth.accessToken()
								: config.auth.accessToken,
					};
		const client = new ImapFlow({
			host: config.host,
			port: config.port ?? (secure ? 993 : 143),
			secure,
			// Never the silent fallback to cleartext: either TLS from the start,
			// or STARTTLS that must succeed, or a plaintext test server allowed
			// by name.
			doSTARTTLS:
				!secure && config.allowInsecure !== true
					? true
					: config.starttls === true,
			tls: config.tls,
			auth,
			logger: false,
			// IDLE starts after this much quiet; the default (15 s) delays every
			// new-message notification by as much.
			autoIdleDelay: 1000,
		});
		client.on("error", () => {});
		await client.connect();
		return client;
	}
}

/** An empty list is nothing to do — and an empty range a protocol error. */
function isEmpty(uids: number | number[]): boolean {
	return Array.isArray(uids) && uids.length === 0;
}

function range(uids: number | number[]): string {
	return Array.isArray(uids) ? uids.join(",") : String(uids);
}
