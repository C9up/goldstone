import "./augmentations.js";

export {
	type AuthenticateOptions,
	type Authenticity,
	type AuthResult,
	authenticate,
	type DkimVerdict,
	type DmarcPolicy,
} from "./authenticity.js";
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
	type InboundHttpContext,
	type InboundResponse,
	MemoryReplayGuard,
	type ReplayGuard,
} from "./inbound/context.js";
export {
	createMailgunInboundHandler,
	type InboundMeta,
	type MailgunInboundOptions,
} from "./inbound/mailgun.js";
export {
	Mailbox,
	type MailboxOptions,
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
	type ReadOptions,
	ReceivedMessage,
	readMessage,
} from "./ReceivedMessage.js";
