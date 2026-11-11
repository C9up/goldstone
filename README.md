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

- **TLS is required**: implicit TLS by default (993), or `starttls: true`
  (143, plaintext upgraded: `secure` need not be set), which refuses to go on
  when the server does not offer STARTTLS. `secure: true` with
  `starttls: true` is refused at `defineConfig`. Plaintext
  or an unchecked certificate need `allowInsecure`, for a local test server.
- A mailbox opens on first use. `watch()` keeps its own connection in IDLE;
  when it is lost, it reconnects with a growing wait and delivers what
  arrived meanwhile — messages are followed by UID, so none is skipped and
  none delivered twice. A handler that throws is reported to `onError` and
  the watch goes on.
- A message's size is asked of the server before it is downloaded: one over
  `limits.maxBytes` is refused without being fetched. The answer is only a
  claim, so the connection also refuses any message literal over
  `maxBytes` (and caps every response) before buffering it: a server that
  lies about the size, or leaves it out, is cut off with
  `E_GOLDSTONE_MESSAGE_TOO_LARGE` instead of pushing a gigabyte into memory.
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

The handler reads the fields from `request.body()`, which Ream fills only
when its body parser has read the request: the route must run behind
`BodyParserMiddleware` (registered globally in a scaffolded app). Mailgun
posts `multipart/form-data`, or urlencoded; raise both limits above the
largest message you accept (25 MiB by default; the parser's defaults are
1 MB for a form and 20 MB for multipart), in `config/bodyparser.ts` so the
server applies them too:

```ts
// config/bodyparser.ts
export default {
  form: { limit: "30mb" },
  multipart: { limit: "30mb" },
}
```

Without the parser, every delivery is answered 401, its fields missing.

Mailgun signs a timestamp and a token — not the message. So the handler
refuses a timestamp older than two minutes (`maxAgeSeconds`, an integer
from 1 to 86 400 — anything else is refused when the handler is created,
since a `NaN` read from an unset variable would turn the check off) and
handles each token once,
claimed before handling so two racing requests cannot both get through; a
delivery whose handler throws gives its token back, and Mailgun's retry is
handled. Fields are read from the request body only, never the query string.
The tokens live in this process's memory; with several instances, pass a
shared `replayGuard`. A message the parser refuses is answered 406, which
stops Mailgun from retrying it.

## Parsing a received message

```ts
import { parseMessage } from "@c9up/goldstone"

const message = await parseMessage(raw) // raw RFC 5322 bytes

message.subject
message.from            // [{ name, address }]
message.date            // Date
message.text
message.html            // sanitized: safe to render, loads nothing remote
message.attachments     // [{ fileName, originalName, contentType, size, content, … }]
message.header("List-Unsubscribe")
```

Parsing runs in Rust ([mail-parser](https://github.com/stalwartlabs/mail-parser)),
in one call and off the JavaScript thread: the bytes go in, the message comes
out, and the event loop keeps serving requests meanwhile. A received mail is
input from whoever sent it, so:

- **the size is checked before a byte is parsed**, then the structure is
  bounded — parts, nesting depth, header fields and header size, number and
  size of attachments. Parts and nesting count through the messages a message
  carries (message/rfc822), encoded or not. Parts and headers are bounded
  before the parse too: the message is first walked the way the parser walks
  it, keeping only counts, so a message made of millions of tiny parts or
  headers is refused before it costs any memory.
  Each limit has a default and can be set per call
  (`parseMessage(raw, { limits: { maxBytes } })`); over one, a `GoldstoneError` names it
  (`E_GOLDSTONE_MESSAGE_TOO_LARGE`, `…_TOO_MANY_PARTS`, `…_TOO_DEEP`,
  `…_TOO_MANY_HEADERS`, `…_HEADERS_TOO_LARGE`, `…_TOO_MANY_ATTACHMENTS`,
  `…_ATTACHMENT_TOO_LARGE`). A part starts only at a delimiter of the
  boundary its multipart declared, or after the header of a carried message:
  a `-- ` signature, a pasted log or a large attachment is body, whatever it
  says;
- **`html` is sanitized** — no script, no event handler, no `javascript:` URL,
  and nothing a browser would load by itself: remote images, backgrounds and
  posters are removed, because loading one tells the sender the message was
  opened, when and from where. `cid:` references to the message's own parts
  stay, and so do links, which are only followed when clicked. An application
  that shows remote content on purpose passes `remoteContent: "allow"` (to
  `parseMessage`, `readMessage`, the inbox config or the Mailgun handler).
  The HTML as received is only reachable through `unsanitizedHtml()`, for what
  has to see the original; never render it;
- **the HTML is bounded before it is sanitized**: over `maxHtmlBytes`
  (512 KiB by default), nested deeper than 1 000 elements, or building a tree
  out of proportion to its markup, it is not sanitized at all — the HTML
  standard's tree building costs more than linear time on such markup.
  `html` is then absent and `htmlError` says why
  (`E_GOLDSTONE_HTML_TOO_LARGE`, `…_HTML_TOO_DEEP`, `…_HTML_TOO_COMPLEX`);
  the message, its text and its attachments are read as usual;
- **`fileName` is safe to save under**, on any system: the last path segment
  of what the sender wrote, with control, invisible and bidi characters and
  the characters Windows refuses (`< > : " | ? *` — a `:` would write into an
  NTFS stream) replaced by `_`, without leading dots, trailing dots or
  spaces, or a Windows device name (`CON`, `COM1`, `CONIN$`…). A right-to-left
  override cannot dress `fdp.exe` up as `exe.pdf`. What the sender wrote stays in `originalName`, for display only.

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
- The verdict and the message come from one parse, and a pass speaks for the
  From the message shows: exactly one From header, holding exactly one
  address, whose domain is `authenticity.fromDomain`. A repeated From, a From
  with several addresses, or a header allowed once (Subject, Date, To,
  Message-ID…) that appears twice is a `fail`: an unsigned copy added to a
  signed message is how a phisher rides on someone else's signature.
- Only the address's domain is checked, never the display name:
  `"ceo@bank.test" <a@evil.test>` can pass — for `evil.test`. Show
  `fromDomain`, or the address, next to the verdict.
- A repeated header is read from its first copy everywhere: `message.from`,
  `message.subject` and `message.header("from")` agree, and every copy stays
  in `message.headers`.
- A DKIM signature made with rsa-sha1 (RFC 8301), or whose `h=` leaves out
  From (RFC 6376 §6.1.1), is a `permerror` whatever its cryptography says,
  and DMARC cannot pass on it: SHA-1 is broken, and a From the signature does
  not cover can be rewritten at will.
- A check that cannot complete — DNS down, too slow — is `temperror`,
  never a pass. The whole check has a deadline (10 s by default), at most 5
  DKIM signatures are verified (each is a lookup; the refused ones above are
  not counted), and DNS answers are cached.
- Read over IMAP, a message usually does not carry who delivered it
  reliably, so SPF is `none` there and DMARC rests on DKIM.
- Turn it off with `authenticate: false` in `config/inbox.ts`, or
  `readMessage(raw, { authenticate: false })`; `parseMessage()` never checks.

## License

MIT
