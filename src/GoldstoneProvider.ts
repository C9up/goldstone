/**
 * Wires `config/inbox.ts` into the container as `'inbox'`, and seats the
 * manager on `@c9up/goldstone/services/main`.
 *
 *   // reamrc.ts
 *   providers: [() => import('@c9up/goldstone/provider')]
 *
 * The host is duck-typed — this package stays publishable without importing
 * `@c9up/ream`. `register` opens no connection: mailboxes open on first use.
 */

import "./augmentations.js";
import type { InboxConfig, MailboxConfig } from "./config.js";
import { InboxManager } from "./InboxManager.js";
import { clearInbox, setInbox } from "./services/main.js";

interface GoldstoneContainer {
	singleton(token: unknown, factory: () => unknown): void;
}
interface GoldstoneConfigStore {
	get(key: string): unknown;
}
export interface GoldstoneAppContext {
	container: GoldstoneContainer;
	config: GoldstoneConfigStore;
}

function isInboxConfig(
	value: unknown,
): value is InboxConfig<Record<string, MailboxConfig>> {
	if (typeof value !== "object" || value === null) return false;
	const mailboxes = Reflect.get(value, "mailboxes");
	return (
		typeof Reflect.get(value, "mailbox") === "string" &&
		typeof mailboxes === "object" &&
		mailboxes !== null
	);
}

export default class GoldstoneProvider {
	readonly #app: GoldstoneAppContext;
	#manager: InboxManager | undefined;

	constructor(app: GoldstoneAppContext) {
		this.#app = app;
	}

	register(): void {
		const raw = this.#app.config.get("inbox");
		if (raw === undefined) throw new Error("[inbox] missing config/inbox.ts");
		if (!isInboxConfig(raw)) {
			throw new Error(
				"[inbox] config/inbox.ts must export defineConfig({ mailbox, mailboxes }).",
			);
		}
		const manager = new InboxManager(raw);
		this.#manager = manager;
		setInbox(manager);
		this.#app.container.singleton(InboxManager, () => manager);
		this.#app.container.singleton("goldstone.inbox", () => manager);
		this.#app.container.singleton("inbox", () => manager);
	}

	/**
	 * Log out of every mailbox and stop every watch. Without it, an IDLE
	 * connection keeps the process alive and the server looks hung on stop.
	 */
	async shutdown(): Promise<void> {
		const manager = this.#manager;
		if (!manager) return;
		await manager.closeAll();
		clearInbox(manager);
		this.#manager = undefined;
	}
}
