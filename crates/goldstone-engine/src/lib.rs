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

use mail_parser::{Address, HeaderValue, MessageParser, MimeHeaders, PartType};
use std::fmt;

/// Bounds on one message. The defaults suit an inbox, not an archive import.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Size of the raw message. Checked before parsing.
    pub max_bytes: usize,
    /// Number of MIME parts, the message itself included.
    pub max_parts: usize,
    /// Nesting depth of multiparts.
    pub max_depth: usize,
    /// Number of attachments.
    pub max_attachments: usize,
    /// Size of one decoded attachment.
    pub max_attachment_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 25 * 1024 * 1024,
            max_parts: 1_000,
            max_depth: 32,
            max_attachments: 100,
            max_attachment_bytes: 25 * 1024 * 1024,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge { size: usize, max: usize },
    NotAMessage,
    TooManyParts { count: usize, max: usize },
    TooDeep { depth: usize, max: usize },
    TooManyAttachments { count: usize, max: usize },
    AttachmentTooLarge { size: usize, max: usize },
}

impl ParseError {
    /// The `E_GOLDSTONE_*` code the TypeScript side raises.
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "E_GOLDSTONE_MESSAGE_TOO_LARGE",
            Self::NotAMessage => "E_GOLDSTONE_NOT_A_MESSAGE",
            Self::TooManyParts { .. } => "E_GOLDSTONE_TOO_MANY_PARTS",
            Self::TooDeep { .. } => "E_GOLDSTONE_TOO_DEEP",
            Self::TooManyAttachments { .. } => "E_GOLDSTONE_TOO_MANY_ATTACHMENTS",
            Self::AttachmentTooLarge { .. } => "E_GOLDSTONE_ATTACHMENT_TOO_LARGE",
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
            Self::TooManyAttachments { count, max } => write!(
                f,
                "the message has {count} attachments, over the {max} allowed"
            ),
            Self::AttachmentTooLarge { size, max } => {
                write!(f, "an attachment is {size} bytes, over the {max} allowed")
            }
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
    /// The HTML as received. Never render it.
    pub unsanitized_html: Option<String>,
    pub attachments: Vec<Attachment>,
}

pub fn parse(raw: &[u8], limits: &Limits) -> Result<Message, ParseError> {
    if raw.len() > limits.max_bytes {
        return Err(ParseError::TooLarge {
            size: raw.len(),
            max: limits.max_bytes,
        });
    }
    let message = MessageParser::default()
        .parse(raw)
        .ok_or(ParseError::NotAMessage)?;
    if message.parts.len() > limits.max_parts {
        return Err(ParseError::TooManyParts {
            count: message.parts.len(),
            max: limits.max_parts,
        });
    }
    let depth = nesting_depth(&message);
    if depth > limits.max_depth {
        return Err(ParseError::TooDeep {
            depth,
            max: limits.max_depth,
        });
    }
    if message.attachments.len() > limits.max_attachments {
        return Err(ParseError::TooManyAttachments {
            count: message.attachments.len(),
            max: limits.max_attachments,
        });
    }

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
    let html = unsanitized_html.as_deref().map(ammonia::clean);

    Ok(Message {
        message_id: message.message_id().map(str::to_owned),
        subject: message.subject().map(str::to_owned),
        date: message.date().map(|d| d.to_rfc3339()),
        from: mailboxes(message.from()),
        to: mailboxes(message.to()),
        cc: mailboxes(message.cc()),
        bcc: mailboxes(message.bcc()),
        reply_to: mailboxes(message.reply_to()),
        in_reply_to: ids(message.in_reply_to()),
        references: ids(message.references()),
        headers: message
            .headers_raw()
            .map(|(name, value)| (name.to_owned(), value.trim().to_owned()))
            .collect(),
        text: message.body_text(0).map(|t| t.into_owned()),
        html,
        unsanitized_html,
        attachments,
    })
}

/// Deepest multipart nesting, walked iteratively.
fn nesting_depth(message: &mail_parser::Message<'_>) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(0usize, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        deepest = deepest.max(depth);
        if let Some(PartType::Multipart(children)) = message.parts.get(id).map(|p| &p.body) {
            stack.extend(children.iter().map(|child| (*child as usize, depth + 1)));
        }
    }
    deepest
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
