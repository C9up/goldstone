# @c9up/goldstone

Reading mail for the Ream framework.

Goldstone reads IMAP mailboxes — in real time with IDLE — and receives the
inbound mail that providers post to a webhook. Every message it hands over has
been parsed as the hostile input it is: HTML sanitized for display, attachments
bounded, file names cleaned, and the sender's DKIM, SPF and DMARC verdict
attached.

Sending stays with `@c9up/rover`.

## Status

Here: parsing a received message. Reading IMAP mailboxes, inbound webhooks
and the DKIM / SPF / DMARC verdict land in later releases.

## Parsing a received message

```ts
import { parseMessage } from "@c9up/goldstone"

const message = parseMessage(raw) // raw RFC 5322 bytes

message.subject
message.from            // [{ name, address }]
message.date            // Date
message.text
message.html            // sanitized: safe to render
message.attachments     // [{ fileName, originalName, contentType, size, content, … }]
message.header("List-Unsubscribe")
```

Parsing runs in Rust ([mail-parser](https://github.com/stalwartlabs/mail-parser)),
in one call: the bytes go in, the message comes out. A received mail is input
from whoever sent it, so:

- **the size is checked before a byte is parsed**, then the structure is
  bounded — parts, nesting depth, number and size of attachments. Each limit
  has a default and can be set per call (`parseMessage(raw, { maxBytes })`);
  over one, a `GoldstoneError` names it (`E_GOLDSTONE_MESSAGE_TOO_LARGE`,
  `…_TOO_MANY_PARTS`, `…_TOO_DEEP`, `…_TOO_MANY_ATTACHMENTS`,
  `…_ATTACHMENT_TOO_LARGE`);
- **`html` is sanitized** — no script, no event handler, no `javascript:` URL.
  The HTML as received is only reachable through `unsanitizedHtml()`, for what
  has to see the original; never render it;
- **`fileName` is safe to save under**: the last path segment of what the
  sender wrote, without control characters, leading dots or a Windows device
  name. What the sender wrote stays in `originalName`, for display only.

The engine is a native binary, prebuilt for Linux, macOS and Windows; there is
no JavaScript fallback.

## License

MIT
