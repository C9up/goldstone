import "./augmentations.js";

export {
	defineConfig,
	type InboxConfig,
	type MailboxConfig,
	type PasswordAuth,
	type TokenAuth,
} from "./config.js";
export {
	fromEngine,
	GoldstoneError,
	GoldstoneNativeRequiredError,
} from "./errors.js";
export { InboxManager } from "./InboxManager.js";
export {
	Mailbox,
	reconnectDelay,
	type SearchCriteria,
	type WatchOptions,
} from "./Mailbox.js";
export { isNativeAvailable } from "./native.js";
export {
	type Attachment,
	type Header,
	type Limits,
	type Mailbox as Address,
	parseMessage,
	ReceivedMessage,
} from "./ReceivedMessage.js";
