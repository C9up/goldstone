/**
 * The configured mailboxes, each opened on first use.
 *
 *   inbox.mailbox()            // the default one
 *   inbox.mailbox('billing')
 */

import type { InboxConfig, MailboxConfig } from "./config.js";
import { GoldstoneError } from "./errors.js";
import { Mailbox } from "./Mailbox.js";

export class InboxManager<
	Mailboxes extends Record<string, MailboxConfig> = Record<
		string,
		MailboxConfig
	>,
> {
	readonly #config: InboxConfig<Mailboxes>;
	readonly #open = new Map<string, Mailbox>();

	constructor(config: InboxConfig<Mailboxes>) {
		this.#config = config;
	}

	/** A mailbox by name; the default one without. Opens nothing yet. */
	mailbox(name: keyof Mailboxes & string = this.#config.mailbox): Mailbox {
		const existing = this.#open.get(name);
		if (existing) return existing;
		const config = this.#config.mailboxes[name];
		if (config === undefined) {
			throw new GoldstoneError(
				"E_GOLDSTONE_UNKNOWN_MAILBOX",
				`[inbox] no mailbox "${name}" — got ${Object.keys(this.#config.mailboxes).join(", ")}`,
			);
		}
		const mailbox = new Mailbox(name, config, this.#config.limits);
		this.#open.set(name, mailbox);
		return mailbox;
	}

	/** Stop every watch and log out of every mailbox. */
	async closeAll(): Promise<void> {
		const mailboxes = [...this.#open.values()];
		this.#open.clear();
		await Promise.all(mailboxes.map((mailbox) => mailbox.close()));
	}
}
