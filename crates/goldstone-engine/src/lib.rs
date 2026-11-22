//! Parses a received mail as the hostile input it is.
//!
//! The bytes come from whoever sent the mail. Before anything else the size
//! is checked, so an oversized message is refused without being read; then
//! the structure is bounded (parts, nesting, attachments); then what reaches
//! the application is made safe to use: HTML sanitized for display,
//! attachment names stripped of anything that could leave the directory they
//! are saved to.
//!
//! The parser underneath (mail-parser) is told the limits on parts and
//! nesting; what it does not bound, and every count handed to the
//! application, is checked here (see structure.rs).

pub mod auth;
pub mod html;
mod structure;

use mail_parser::{AddressList, HeaderName, HeaderValue, MessagePart, PartKind, PartRole};
use std::borrow::Cow;
use std::fmt;

/// Bounds on one message. The defaults suit an inbox, not an archive import.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Size of the raw message. Checked before parsing.
    pub max_bytes: usize,
    /// Number of MIME parts, the message itself included, and the parts of
    /// the messages it carries (message/rfc822).
    pub max_parts: usize,
    /// Nesting depth of multiparts and carried messages.
    pub max_depth: usize,
    /// Header fields in one header block: the message's or a part's.
    pub max_headers: usize,
    /// Size of one header block.
    pub max_header_bytes: usize,
    /// Number of attachments.
    pub max_attachments: usize,
    /// Size of one decoded attachment.
    pub max_attachment_bytes: usize,
    /// Size of the HTML body handed to the sanitizer. Over it, the message
    /// is still read, without `html`.
    pub max_html_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 25 * 1024 * 1024,
            max_parts: 1_000,
            max_depth: 32,
            max_headers: 1_000,
            max_header_bytes: 1024 * 1024,
            max_attachments: 100,
            max_attachment_bytes: 25 * 1024 * 1024,
            max_html_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge {
        size: usize,
        max: usize,
    },
    NotAMessage,
    TooManyParts {
        count: usize,
        max: usize,
    },
    TooDeep {
        depth: usize,
        max: usize,
    },
    TooManyHeaders {
        count: usize,
        max: usize,
    },
    TooManyHeaderFields {
        count: usize,
        max: usize,
    },
    HeadersTooLarge {
        size: usize,
        max: usize,
    },
    /// Before parsing: more lines that could each start a header field than
    /// a message of the allowed size may hold (see structure.rs).
    TooManyFieldLines {
        max: usize,
    },
    TooManyAttachments {
        count: usize,
        max: usize,
    },
    AttachmentTooLarge {
        size: usize,
        max: usize,
    },
    HtmlTooLarge {
        size: usize,
        max: usize,
    },
    HtmlTooDeep {
        max: usize,
    },
    HtmlTooComplex {
        max: usize,
    },
}

impl ParseError {
    /// The `E_GOLDSTONE_*` code the TypeScript side raises.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "E_GOLDSTONE_MESSAGE_TOO_LARGE",
            Self::NotAMessage => "E_GOLDSTONE_NOT_A_MESSAGE",
            Self::TooManyParts { .. } => "E_GOLDSTONE_TOO_MANY_PARTS",
            Self::TooDeep { .. } => "E_GOLDSTONE_TOO_DEEP",
            Self::TooManyHeaders { .. }
            | Self::TooManyHeaderFields { .. }
            | Self::TooManyFieldLines { .. } => "E_GOLDSTONE_TOO_MANY_HEADERS",
            Self::HeadersTooLarge { .. } => "E_GOLDSTONE_HEADERS_TOO_LARGE",
            Self::TooManyAttachments { .. } => "E_GOLDSTONE_TOO_MANY_ATTACHMENTS",
            Self::AttachmentTooLarge { .. } => "E_GOLDSTONE_ATTACHMENT_TOO_LARGE",
            Self::HtmlTooLarge { .. } => "E_GOLDSTONE_HTML_TOO_LARGE",
            Self::HtmlTooDeep { .. } => "E_GOLDSTONE_HTML_TOO_DEEP",
            Self::HtmlTooComplex { .. } => "E_GOLDSTONE_HTML_TOO_COMPLEX",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size, max } => {
                write!(f, "the message is {size} bytes, over the {max} allowed")
            }
            Self::NotAMessage => write!(f, "the bytes are not a mail message"),
            Self::TooManyParts { count, max } => write!(
                f,
                "the message has at least {count} MIME parts, over the {max} allowed"
            ),
            Self::TooDeep { depth, max } => write!(
                f,
                "the message nests {depth} levels deep, over the {max} allowed"
            ),
            Self::TooManyHeaders { count, max } => write!(
                f,
                "a header block holds {count} fields, over the {max} allowed"
            ),
            Self::TooManyHeaderFields { count, max } => write!(
                f,
                "the message holds {count} header fields in all, over the {max} its limits leave room for"
            ),
            Self::HeadersTooLarge { size, max } => write!(
                f,
                "a header block is {size} bytes, over the {max} allowed"
            ),
            Self::TooManyFieldLines { max } => write!(
                f,
                "the message holds more than {max} lines that could each start a header field"
            ),
            Self::TooManyAttachments { count, max } => write!(
                f,
                "the message has {count} attachments, over the {max} allowed"
            ),
            Self::AttachmentTooLarge { size, max } => {
                write!(f, "an attachment is {size} bytes, over the {max} allowed")
            }
            Self::HtmlTooLarge { size, max } => {
                write!(f, "the HTML body is {size} bytes, over the {max} sanitized")
            }
            Self::HtmlTooDeep { max } => {
                write!(f, "the HTML body nests deeper than {max} elements")
            }
            Self::HtmlTooComplex { max } => write!(
                f,
                "the HTML body builds more than {max} nodes, out of proportion to its markup"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: Option<String>,
}

#[derive(Debug)]
pub struct Attachment {
    /// Safe to use as a file name: see [`safe_file_name`].
    pub file_name: String,
    /// The name as the sender wrote it, for display only.
    pub original_name: Option<String>,
    pub content_type: String,
    pub content: Vec<u8>,
    pub content_id: Option<String>,
    pub inline: bool,
}

#[derive(Debug)]
pub struct Message {
    pub message_id: Option<String>,
    pub subject: Option<String>,
    /// RFC 3339, when the Date header parses.
    pub date: Option<String>,
    pub from: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    /// Every header, name and raw value, in order.
    pub headers: Vec<(String, String)>,
    pub text: Option<String>,
    /// Sanitized for display: no script, no event handler, no
    /// `javascript:` URL.
    pub html: Option<String>,
    /// Why there is no `html` although the message has an HTML body: it
    /// broke a bound of [`html::check`], and was not sanitized.
    pub html_error: Option<ParseError>,
    /// The HTML as received. Never render it.
    pub unsanitized_html: Option<String>,
    pub attachments: Vec<Attachment>,
}

/// How the sanitized HTML may reach outside the message.
#[derive(Clone, Copy, Debug, Default)]
pub struct HtmlPolicy {
    /// Keep the URLs a browser fetches by itself (images, backgrounds,
    /// posters). Off by default: loading them tells the sender the message
    /// was opened, when and from where. `cid:` references to the message's
    /// own parts are kept either way.
    pub remote_content: bool,
}

/// Parse one received message: [`parse_mail`], then [`message_of`], remote
/// content blocked.
pub fn parse(raw: &[u8], limits: &Limits) -> Result<Message, ParseError> {
    parse_with(raw, limits, &HtmlPolicy::default())
}

pub fn parse_with(raw: &[u8], limits: &Limits, policy: &HtmlPolicy) -> Result<Message, ParseError> {
    message_of(&parse_mail(raw, limits)?, limits, policy)
}

/// The parse everything else reads: the message handed to the application
/// and the headers its authenticity is checked on both come from this one
/// value, so the two can never disagree on what the headers are.
pub fn parse_mail<'x>(
    raw: &'x [u8],
    limits: &Limits,
) -> Result<mail_parser::Message<'x>, ParseError> {
    if raw.len() > limits.max_bytes {
        return Err(ParseError::TooLarge {
            size: raw.len(),
            max: limits.max_bytes,
        });
    }
    structure::prescan(raw, limits)?;
    let message = structure::parser(limits)
        .parse(raw)
        .ok_or(ParseError::NotAMessage)?;
    structure::check(&message, limits)?;
    let attachments = attachment_parts(&message).count();
    if attachments > limits.max_attachments {
        return Err(ParseError::TooManyAttachments {
            count: attachments,
            max: limits.max_attachments,
        });
    }
    Ok(message)
}

/// The parts handed out as attachments, in document order: what RFC 8621
/// calls attachments, and the images, audio and video shown in the body too.
/// mail-parser 1.0 leaves media shown in both bodies out of its list; they
/// stay here, because a `cid:` reference in the HTML needs the part it names.
fn attachment_parts<'m>(
    message: &'m mail_parser::Message<'_>,
) -> impl Iterator<Item = MessagePart<'m>> {
    message
        .root()
        .parts()
        .filter(|part| part.is_attachment() || part.role() == PartRole::MediaBody)
}

/// What the application gets from a parsed message.
///
/// A header that should occur once but occurs several times is read from
/// its FIRST occurrence, everywhere: the fields, and `headers` in order.
/// That is the one a mail client displays; the authenticity verdict never
/// passes such a message (see [`auth::from_domain`]).
pub fn message_of(
    message: &mail_parser::Message<'_>,
    limits: &Limits,
    policy: &HtmlPolicy,
) -> Result<Message, ParseError> {
    let mut attachments = Vec::new();
    for (index, part) in attachment_parts(message).enumerate() {
        // Measured before it is decoded.
        let size = part.decoded_len();
        if size > limits.max_attachment_bytes {
            return Err(ParseError::AttachmentTooLarge {
                size,
                max: limits.max_attachment_bytes,
            });
        }
        let content = part.decoded();
        let original_name = part.attachment_name().map(str::to_owned);
        attachments.push(Attachment {
            file_name: safe_file_name(original_name.as_deref(), index),
            original_name,
            content_type: part
                .content_type()
                .map(|ct| match ct.subtype() {
                    Some(sub) => format!("{}/{}", ct.ctype(), sub),
                    None => ct.ctype().to_owned(),
                })
                .unwrap_or_else(|| "application/octet-stream".into()),
            content: content.to_vec(),
            content_id: part.content_id().map(str::to_owned),
            inline: part
                .content_disposition()
                .is_some_and(|d| d.ctype().eq_ignore_ascii_case("inline")),
        });
    }

    // Only a part that IS html: body_html() would also turn a text part
    // into html, which is not what the sender wrote.
    let unsanitized_html = message.html_body().find_map(|part| match part.kind() {
        PartKind::Html => part.text().map(Cow::into_owned),
        _ => None,
    });
    let (html, html_error) = match unsanitized_html.as_deref() {
        None => (None, None),
        Some(raw) => match html::check(raw, limits.max_html_bytes) {
            Ok(()) => (Some(html::sanitize(raw, policy.remote_content)), None),
            Err(refused) => (None, Some(refused)),
        },
    };

    let headers = message.headers();
    let first = |name: HeaderName<'static>| headers.all(name).next().map(|h| h.value());
    let addresses = |name: HeaderName<'static>| mailboxes(first(name).and_then(|v| v.as_address()));
    let list = |name: HeaderName<'static>| ids(first(name));
    let raw = message.raw();
    Ok(Message {
        message_id: first(HeaderName::MessageId)
            .and_then(|v| first_text(&v))
            .map(str::to_owned),
        subject: first(HeaderName::Subject)
            .and_then(|v| v.as_text())
            .map(str::to_owned),
        date: first(HeaderName::Date)
            .and_then(|v| v.as_datetime())
            .map(|d| d.to_rfc3339()),
        from: addresses(HeaderName::From),
        to: addresses(HeaderName::To),
        cc: addresses(HeaderName::Cc),
        bcc: addresses(HeaderName::Bcc),
        reply_to: addresses(HeaderName::ReplyTo),
        in_reply_to: list(HeaderName::InReplyTo),
        references: list(HeaderName::References),
        // Every header, a value that is not UTF-8 included: dropping one
        // would hide a duplicate from whoever reads the list.
        headers: message
            .root_part()
            .headers()
            .iter()
            .map(|h| {
                let value = raw
                    .get(h.offset_start() as usize..h.offset_end() as usize)
                    .unwrap_or_default();
                (
                    h.name().as_str().to_owned(),
                    String::from_utf8_lossy(value).trim().to_owned(),
                )
            })
            .collect(),
        text: message.body_text(0).map(Cow::into_owned),
        html,
        html_error,
        unsanitized_html,
        attachments,
    })
}

fn mailboxes(address: Option<AddressList<'_>>) -> Vec<Mailbox> {
    match address {
        Some(address) => address
            .mailboxes()
            .map(|a| Mailbox {
                name: a.name().map(str::to_owned),
                address: a.address().map(str::to_owned),
            })
            .collect(),
        None => Vec::new(),
    }
}

/// The first identifier of a field: mail-parser keeps them as a list.
fn first_text<'m>(value: &HeaderValue<'m>) -> Option<&'m str> {
    match value {
        HeaderValue::TextList(ids) => ids.first(),
        other => other.as_text(),
    }
}

fn ids(value: Option<HeaderValue<'_>>) -> Vec<String> {
    match value {
        Some(HeaderValue::TextList(ids)) => ids.iter().map(str::to_owned).collect(),
        Some(HeaderValue::Text(id)) => vec![id.to_owned()],
        _ => Vec::new(),
    }
}

/// Windows opens a device for these names, with any extension and with
/// spaces before it.
const RESERVED: [&str; 32] = [
    "con",
    "prn",
    "aux",
    "nul",
    "conin$",
    "conout$",
    "com0",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "com\u{b9}",
    "com\u{b2}",
    "com\u{b3}",
    "lpt0",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
    "lpt\u{b9}",
    "lpt\u{b2}",
    "lpt\u{b3}",
];

/// Characters Windows refuses in a name; `:` also names an NTFS stream.
const WINDOWS_INVALID: [char; 7] = ['<', '>', ':', '"', '|', '?', '*'];

/// Unicode format characters (category Cf): invisible, and the bidi ones
/// reorder what is shown (`invoice\u{202e}fdp.exe` reads `invoiceexe.pdf`).
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

fn trim_name(name: &str) -> &str {
    name.trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' '])
}

/// A name that cannot leave the directory it is saved to, nor mean anything
/// else than a file there, on any system: the last path segment only (both
/// separators); control, format (bidi) and Windows-invalid characters
/// replaced by `_`; no leading dots, no trailing dots or spaces; no Windows
/// device name; at most 255 bytes. What is left of a hostile name may be
/// nothing; it becomes `attachment-<n>`.
pub fn safe_file_name(name: Option<&str>, index: usize) -> String {
    let fallback = || format!("attachment-{}", index + 1);
    let Some(name) = name else { return fallback() };
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let replaced: String = last
        .chars()
        .map(|c| {
            if c.is_control() || is_format(c) || WINDOWS_INVALID.contains(&c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = trim_name(&replaced);
    if cleaned.is_empty() {
        return fallback();
    }
    let stem = cleaned
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_lowercase();
    let reserved = RESERVED.contains(&stem.as_str());
    let mut safe = if reserved {
        format!("_{cleaned}")
    } else {
        cleaned.to_owned()
    };
    if safe.len() > 255 {
        let mut cut = 255;
        while !safe.is_char_boundary(cut) {
            cut -= 1;
        }
        safe.truncate(cut);
        // The cut can leave a trailing dot or space, which Windows drops.
        let kept = safe.trim_end_matches(['.', ' ']).len();
        safe.truncate(kept);
    }
    if safe.is_empty() {
        return fallback();
    }
    safe
}
