/**
 * Teach ream's `ContainerBindings` what `container.make(...)` returns for the
 * tokens goldstone binds.
 *
 * Type-only, and ream stays an OPTIONAL peer: nothing here reaches a runtime
 * import, and a `declare module` for a specifier that does not resolve is
 * simply inert.
 */

// Referenced so the augmentation below resolves the module it augments.
import type {} from "@c9up/ream/types";

import type { InboxManager } from "./InboxManager.js";

declare module "@c9up/ream/types" {
	interface ContainerBindings {
		/** The configured mailboxes, bound by `GoldstoneProvider`. */
		"goldstone.inbox": InboxManager;
		/** The same binding under the bare role name. */
		inbox: InboxManager;
	}
}
