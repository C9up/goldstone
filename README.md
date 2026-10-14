# @c9up/goldstone

Reading mail for the Ream framework.

Goldstone reads IMAP mailboxes — in real time with IDLE — and receives the
inbound mail that providers post to a webhook. Every message it hands over has
been parsed as the hostile input it is: HTML sanitized for display, attachments
bounded, file names cleaned, and the sender's DKIM, SPF and DMARC verdict
attached.

Sending stays with `@c9up/rover`.

## Status

Here: reading IMAP mailboxes, receiving Mailgun's inbound mail, parsing what
arrives, and checking who sent it (DKIM, SPF, DMARC, ARC).

## Reading a mailbox

```ts
// config/inbox.ts
import { defineConfig } from "@c9up/goldstone"

export default defineConfig({
  mailbox: "support",
  mailboxes: {
    support: {
      host: "imap.example.com",
      auth: { user: env.get("IMAP_USER"), pass: env.get("IMAP_PASSWORD") },
    },
    billing: {
      host: "outlook.office365.com",
      // XOAUTH2. Called on every connection, so an expired token is asked
      // for again when the connection is made anew.
      auth: { user: "billing@example.com", accessToken: () => tokens.for("billing") },
    },
  },
})

// reamrc.ts
providers: [() => import("@c9up/goldstone/provider")]
```

```ts
import inbox from "@c9up/goldstone/services/main"

const support = inbox.mailbox() // the default; inbox.mailbox("billing")

for (const uid of await support.search({ seen: false })) {
  const message = await support.fetch(uid)   // parsed, see below
  await support.markSeen(uid)
}
await support.move(uid, "Archive")

const stop = support.watch(async (message, { uid }) => {
  // every new message, as it arrives
})
```

- **TLS is required**: implicit TLS by default (993), or `starttls: true`,
  which refuses to go on when the server does not offer STARTTLS. Plaintext
  or an unchecked certificate need `allowInsecure`, for a local test server.
- A mailbox opens on first use. `watch()` keeps its own connection in IDLE;
  when it is lost, it reconnects with a growing wait and delivers what
  arrived meanwhile — messages are followed by UID, so none is skipped and
  none delivered twice. A handler that throws is reported to `onError` and
  the watch goes on.
- A message's size is asked of the server before it is downloaded: one over
  `limits.maxBytes` is refused without being fetched.
- The provider logs out of every mailbox on shutdown, so an IDLE connection
  does not keep the process alive.

## Receiving inbound mail (Mailgun)

```ts
import { createMailgunInboundHandler } from "@c9up/goldstone"

router.post("/inbound/mailgun/mime", createMailgunInboundHandler({
  signingKey: env.get("MAILGUN_SIGNING_KEY"),
  async onMessage(message, { recipient, sender }) {
    // parsed, checked (message.authenticity)
  },
}))
```

Point the Mailgun route's *forward* action at a URL ending in `mime`: that is
what makes Mailgun send the message as received.

Mailgun signs a timestamp and a token — not the message. So the handler
refuses a timestamp older than two minutes and handles each token once,
claimed before handling so two racing requests cannot both get through; a
delivery whose handler throws gives its token back, and Mailgun's retry is
handled. Fields are read from the request body only, never the query string.
The tokens live in this process's memory; with several instances, pass a
shared `replayGuard`. A message the parser refuses is answered 406, which
stops Mailgun from retrying it.

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

## Who sent it

The From header is whatever the sender typed. A message read from a mailbox
carries the verdict on `message.authenticity`; for raw bytes, `readMessage()`
parses and checks, `authenticate()` only checks:

```ts
import { authenticate, readMessage } from "@c9up/goldstone"

const message = await readMessage(raw)
message.authenticity.summary   // "pass" | "fail" | "none" | "temperror"
message.authenticity.dkim      // [{ result, domain, selector, reason }]
message.authenticity.dmarc     // and dmarcPolicy, dmarcDomain, spf, arc

// SPF needs to know who delivered the message — a webhook usually says:
await authenticate(raw, { ip: "203.0.113.7", helo: "mx.sender.test", mailFrom: "bounces@sender.test" })
```

- `summary` is `pass` only when the From domain's DMARC passes, through a
  DKIM signature or an SPF result aligned with that domain. A message signed
  by another domain than its From does not pass.
- A check that cannot complete — DNS down, too slow — is `temperror`,
  never a pass. The whole check has a deadline (10 s by default), at most 5
  DKIM signatures are verified (each is a lookup), and DNS answers are cached.
- Read over IMAP, a message usually does not carry who delivered it
  reliably, so SPF is `none` there and DMARC rests on DKIM.
- Turn it off with `authenticate: false` in `config/inbox.ts`, or
  `readMessage(raw, { authenticate: false })`; `parseMessage()` never checks.

## License

MIT
