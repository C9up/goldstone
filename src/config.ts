/**
 * The shape `config/inbox.ts` returns: the mailboxes the application reads.
 *
 *   export default defineConfig({
 *     mailbox: 'support',
 *     mailboxes: {
 *       support: {
 *         host: 'imap.example.com',
 *         auth: { user: env.get('IMAP_USER'), pass: env.get('IMAP_PASSWORD') },
 *       },
 *       billing: {
 *         host: 'outlook.office365.com',
 *         auth: { user: 'billing@example.com', accessToken: () => tokens.for('billing') },
 *       },
 *     },
 *   })
 */

import { GoldstoneError } from "./errors.js";
import type { Limits } from "./ReceivedMessage.js";

export interface PasswordAuth {
	user: string;
	pass: string;
}

export interface TokenAuth {
	user: string;
	/**
	 * An OAuth2 access token for XOAUTH2 — or a function that answers one. The
	 * function is called on every connection, so a token that expired is
	 * asked for again when the connection is made anew.
	 */
	accessToken: string | (() => string | Promise<string>);
}

export interface MailboxConfig {
	host: string;
	/** Default 993 with `secure`, 143 with `starttls`. */
	port?: number;
	/**
	 * TLS from the first byte (port 993). The default. Turn it off only for
	 * `starttls`, or — on a development machine — with `allowInsecure`.
	 */
	secure?: boolean;
	/**
	 * Upgrade a plaintext connection with STARTTLS, and refuse to go on if
	 * the server does not offer it. Without this, a client upgrades only when
	 * the server says it can — and an attacker on the path can remove that.
	 */
	starttls?: boolean;
	/**
	 * Allow a connection without TLS, or without verifying the server's
	 * certificate. For a local test server only.
	 */
	allowInsecure?: boolean;
	/** Passed to Node's TLS: `ca` for a private CA, `servername`… */
	tls?: {
		ca?: string | Buffer;
		servername?: string;
		rejectUnauthorized?: boolean;
	};
	auth: PasswordAuth | TokenAuth;
}

export interface InboxConfig<Mailboxes extends Record<string, MailboxConfig>> {
	/** The mailbox `inbox.mailbox()` returns with no argument. */
	mailbox: keyof Mailboxes & string;
	mailboxes: Mailboxes;
	/** Bounds applied to every message read; see {@link Limits}. */
	limits?: Limits;
	/**
	 * Check DKIM, SPF and DMARC on every message read. Default `true`; see
	 * `message.authenticity`.
	 */
	authenticate?: boolean;
}

/**
 * Type helper for `config/inbox.ts`. Refuses, at boot: no mailbox, a default
 * that is not declared, and a mailbox that would talk without TLS or without
 * checking the server's certificate unless `allowInsecure` says so.
 */
export function defineConfig<Mailboxes extends Record<string, MailboxConfig>>(
	config: InboxConfig<Mailboxes>,
): InboxConfig<Mailboxes> {
	const names = Object.keys(config.mailboxes);
	if (names.length === 0) {
		throw new GoldstoneError(
			"E_GOLDSTONE_INVALID_CONFIG",
			"[inbox] config declares no mailbox",
		);
	}
	if (!names.includes(config.mailbox)) {
		throw new GoldstoneError(
			"E_GOLDSTONE_INVALID_CONFIG",
			`[inbox] default mailbox "${config.mailbox}" is not declared — got ${names.join(", ")}`,
		);
	}
	for (const [name, mailbox] of Object.entries(config.mailboxes)) {
		assertSecure(name, mailbox);
	}
	return config;
}

export function assertSecure(name: string, mailbox: MailboxConfig): void {
	if (mailbox.allowInsecure === true) return;
	if (mailbox.secure === false && mailbox.starttls !== true) {
		throw new GoldstoneError(
			"E_GOLDSTONE_INSECURE_CONNECTION",
			`[inbox] mailbox "${name}" would connect without TLS — set starttls: true, or allowInsecure for a local test server`,
		);
	}
	if (mailbox.tls?.rejectUnauthorized === false) {
		throw new GoldstoneError(
			"E_GOLDSTONE_INSECURE_CONNECTION",
			`[inbox] mailbox "${name}" would not check the server's certificate — give its CA in tls.ca, or allowInsecure for a local test server`,
		);
	}
}
