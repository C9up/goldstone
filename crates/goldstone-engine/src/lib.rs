//! Parses a received mail as the hostile input it is.
//!
//! The bytes come from whoever sent the mail. Before anything else the size
//! is checked, so an oversized message is refused without being read; then
//! the structure is bounded (parts, nesting, attachments); then what reaches
//! the application is made safe to use: HTML sanitized for display,
//! attachment names stripped of anything that could leave the directory they
//! are saved to.
//!
//! The parser underneath (mail-parser) has no limits of its own — it will
//! happily walk 5 000 nested multiparts or 100 000 parts. Every bound lives
//! here.

pub mod auth;
pub mod html;
mod structure;

use mail_parser::{Address, HeaderName, HeaderValue, MessageParser, MimeHeaders, PartType};
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
    /// Before parsing: more places a part could start than the parts
    /// allowed leave room for.
    TooManyBoundaries {
        count: usize,
        max: usize,
    },
    TooManyEncodedMessages {
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
            Self::TooManyBoundaries { .. } | Self::TooManyEncodedMessages { .. } => {
                "E_GOLDSTONE_TOO_MANY_PARTS"
            }
            Self::TooManyHeaders { .. } | Self::TooManyHeaderFields { .. } => {
                "E_GOLDSTONE_TOO_MANY_HEADERS"
            }
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
                "the message has {count} MIME parts, over the {max} allowed"
            ),
            Self::TooDeep { depth, max } => write!(
                f,
                "the message nests {depth} levels deep, over the {max} allowed"
            ),
            Self::TooManyBoundaries { count, max } => write!(
                f,
                "the message has {count} places a part can start, over the {max} its parts limit leaves room for"
            ),
            Self::TooManyEncodedMessages { max } => write!(
                f,
                "the message carries more than {max} encoded messages"
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
    let message = MessageParser::default()
        .parse(raw)
        .ok_or(ParseError::NotAMessage)?;
    check_structure(&message, limits)?;
    if message.attachments.len() > limits.max_attachments {
        return Err(ParseError::TooManyAttachments {
            count: message.attachments.len(),
            max: limits.max_attachments,
        });
    }
    Ok(message)
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
    let mut attachments = Vec::with_capacity(message.attachments.len());
    for (index, part) in message.attachments().enumerate() {
        let content = part.contents();
        if content.len() > limits.max_attachment_bytes {
            return Err(ParseError::AttachmentTooLarge {
                size: content.len(),
                max: limits.max_attachment_bytes,
            });
        }
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
    let unsanitized_html =
        message
            .html_body
            .iter()
            .find_map(|id| match &message.parts.get(*id as usize)?.body {
                PartType::Html(html) => Some(html.to_string()),
                _ => None,
            });
    let (html, html_error) = match unsanitized_html.as_deref() {
        None => (None, None),
        Some(raw) => match html::check(raw, limits.max_html_bytes) {
            Ok(()) => (Some(html::sanitize(raw, policy.remote_content)), None),
            Err(refused) => (None, Some(refused)),
        },
    };

    let first = |name: HeaderName<'static>| message.header_values(name).next();
    let addresses = |name: HeaderName<'static>| mailboxes(first(name).and_then(|v| v.as_address()));
    let list = |name: HeaderName<'static>| ids(first(name).unwrap_or(&HeaderValue::Empty));
    let raw = message.raw_message.as_ref();
    Ok(Message {
        message_id: first(HeaderName::MessageId)
            .and_then(|v| v.as_text())
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
                    .get(h.offset_start as usize..h.offset_end as usize)
                    .unwrap_or_default();
                (
                    h.name.as_str().to_owned(),
                    String::from_utf8_lossy(value).trim().to_owned(),
                )
            })
            .collect(),
        text: message.body_text(0).map(|t| t.into_owned()),
        html,
        html_error,
        unsanitized_html,
        attachments,
    })
}

/// The exact counts, through the parts of every carried message too:
/// parts, nesting (a carried message is one level), headers per part.
/// Walked iteratively, so depth costs no stack.
fn check_structure(message: &mail_parser::Message<'_>, limits: &Limits) -> Result<(), ParseError> {
    let mut parts = 0usize;
    let mut messages = vec![(message, 0usize)];
    while let Some((message, base)) = messages.pop() {
        parts += message.parts.len();
        if parts > limits.max_parts {
            return Err(ParseError::TooManyParts {
                count: parts,
                max: limits.max_parts,
            });
        }
        if let Some(part) = message
            .parts
            .iter()
            .find(|p| p.headers.len() > limits.max_headers)
        {
            return Err(ParseError::TooManyHeaders {
                count: part.headers.len(),
                max: limits.max_headers,
            });
        }
        let mut depth_of = vec![base; message.parts.len()];
        let mut walk = vec![0usize];
        while let Some(id) = walk.pop() {
            let depth = depth_of[id];
            if depth > limits.max_depth {
                return Err(ParseError::TooDeep {
                    depth,
                    max: limits.max_depth,
                });
            }
            if let Some(PartType::Multipart(children)) = message.parts.get(id).map(|p| &p.body) {
                // A child always comes after its parent: no cycle to follow.
                for child in children.iter().map(|c| *c as usize) {
                    if child > id && child < depth_of.len() {
                        depth_of[child] = depth + 1;
                        walk.push(child);
                    }
                }
            }
        }
        for (id, part) in message.parts.iter().enumerate() {
            if let PartType::Message(carried) = &part.body {
                messages.push((carried, depth_of[id] + 1));
            }
        }
    }
    Ok(())
}

fn mailboxes(address: Option<&Address<'_>>) -> Vec<Mailbox> {
    match address {
        Some(address) => address
            .iter()
            .map(|a| Mailbox {
                name: a.name().map(str::to_owned),
                address: a.address().map(str::to_owned),
            })
            .collect(),
        None => Vec::new(),
    }
}

fn ids(value: &HeaderValue<'_>) -> Vec<String> {
    match value {
        HeaderValue::Text(id) => vec![id.to_string()],
        HeaderValue::TextList(ids) => ids.iter().map(|id| id.to_string()).collect(),
        _ => Vec::new(),
    }
}

/// Windows refuses these as file names, with any extension.
const RESERVED: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// A name that cannot leave the directory it is saved to: the last path
/// segment only (both separators), no control characters, no leading dots,
/// no Windows device name, at most 255 bytes. What is left of a hostile name
/// may be nothing; it becomes `attachment-<n>`.
pub fn safe_file_name(name: Option<&str>, index: usize) -> String {
    let fallback = || format!("attachment-{}", index + 1);
    let Some(name) = name else { return fallback() };
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' ']);
    if cleaned.is_empty() {
        return fallback();
    }
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_lowercase();
    let mut safe = if RESERVED.contains(&stem.as_str()) {
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
    }
    safe
}
