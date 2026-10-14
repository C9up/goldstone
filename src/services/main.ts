/**
 * The {@link InboxManager}, reachable without threading it through every
 * call site — mirroring `@c9up/quasar/services/main`.
 *
 *   import inbox from "@c9up/goldstone/services/main"
 *
 *   const unread = await inbox.mailbox().search({ seen: false })
 *
 * Importing this module loads nothing: the instance is resolved on the first
 * member access, so a unit test that pulls it in transitively needs no booted
 * provider.
 */

import type { InboxManager } from "../InboxManager.js";

let instance: InboxManager | undefined;

/** Seat the instance — called by GoldstoneProvider, or by an app wiring its own. */
export function setInbox(inbox: InboxManager): void {
	instance = inbox;
}

/** The seated instance, if there is one. */
export function getInbox(): InboxManager | undefined {
	return instance;
}

/** Drop the instance IF it is still the one passed in (ownership guard). */
export function clearInbox(inbox: InboxManager): void {
	if (instance === inbox) instance = undefined;
}

const inbox: InboxManager = new Proxy(Object.create(null), {
	get(_target, property) {
		// A module loader reads `then` and various symbols off what it imports
		// before anyone uses it. They are not members, so answer undefined and
		// let a genuine access be the one that reports.
		if (typeof property === "symbol" || property === "then") {
			return undefined;
		}
		if (!instance) {
			throw new Error(
				"[inbox] accessed before initialization — register GoldstoneProvider, or call setInbox() yourself.",
			);
		}
		const value = Reflect.get(instance, property, instance);
		return typeof value === "function" ? value.bind(instance) : value;
	},
});

export default inbox;
