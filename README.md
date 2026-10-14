# @c9up/goldstone

Reading mail for the Ream framework.

Goldstone reads IMAP mailboxes — in real time with IDLE — and receives the
inbound mail that providers post to a webhook. Every message it hands over has
been parsed as the hostile input it is: HTML sanitized for display, attachments
bounded, file names cleaned, and the sender's DKIM, SPF and DMARC verdict
attached.

Sending stays with `@c9up/rover`.

## Status

Nothing usable yet: this repository holds the package skeleton.

## License

MIT
