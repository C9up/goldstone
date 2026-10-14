import { describe, expect, it } from "vitest";
import GoldstoneProvider from "../src/GoldstoneProvider.js";
import { defineConfig, InboxManager } from "../src/index.js";
import inbox, { getInbox } from "../src/services/main.js";

class Container {
	readonly bound = new Map<unknown, () => unknown>();
	singleton(token: unknown, factory: () => unknown): void {
		this.bound.set(token, factory);
	}
}

function boot(config: unknown) {
	const container = new Container();
	const provider = new GoldstoneProvider({
		container,
		config: { get: (key) => (key === "inbox" ? config : undefined) },
	});
	return { container, provider };
}

const config = defineConfig({
	mailbox: "main",
	mailboxes: {
		main: { host: "imap.example.test", auth: { user: "u", pass: "p" } },
	},
});

describe("GoldstoneProvider", () => {
	it("binds one manager under its class, goldstone.inbox and inbox, opening nothing", async () => {
		const { container, provider } = boot(config);
		provider.register();
		const manager = container.bound.get(InboxManager)?.();
		expect(manager).toBeInstanceOf(InboxManager);
		expect(container.bound.get("goldstone.inbox")?.()).toBe(manager);
		expect(container.bound.get("inbox")?.()).toBe(manager);
		expect(getInbox()).toBe(manager);
		expect(inbox.mailbox().name).toBe("main");
		await provider.shutdown();
		expect(getInbox()).toBeUndefined();
	});

	it("refuses to start without config/inbox.ts, or with a config of another shape", () => {
		expect(() => boot(undefined).provider.register()).toThrow(
			"[inbox] missing config/inbox.ts",
		);
		expect(() => boot({ mailboxes: {} }).provider.register()).toThrow(
			/must export defineConfig/,
		);
	});
});

describe("services/main", () => {
	it("does not look thenable while unseated, and says what is missing on use", () => {
		expect(Reflect.get(inbox, "then")).toBeUndefined();
		expect(() => inbox.mailbox()).toThrow(
			"[inbox] accessed before initialization",
		);
	});
});
