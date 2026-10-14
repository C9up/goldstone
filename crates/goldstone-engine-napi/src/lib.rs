//! NAPI bindings for goldstone-engine: one call per message — the raw bytes
//! in, the parsed message out.

use goldstone_engine::{Limits, Mailbox, ParseError};
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;

/// Bounds on one message; an absent field keeps the engine's default.
#[napi(object)]
pub struct JsLimits {
    pub max_bytes: Option<u32>,
    pub max_parts: Option<u32>,
    pub max_depth: Option<u32>,
    pub max_attachments: Option<u32>,
    pub max_attachment_bytes: Option<u32>,
}

#[napi(object)]
pub struct JsMailbox {
    pub name: Option<String>,
    pub address: Option<String>,
}

#[napi(object)]
pub struct JsHeader {
    pub name: String,
    pub value: String,
}

#[napi(object)]
pub struct JsAttachment {
    pub file_name: String,
    pub original_name: Option<String>,
    pub content_type: String,
    pub content: Buffer,
    pub content_id: Option<String>,
    pub inline: bool,
}

#[napi(object)]
pub struct JsMessage {
    pub message_id: Option<String>,
    pub subject: Option<String>,
    pub date: Option<String>,
    pub from: Vec<JsMailbox>,
    pub to: Vec<JsMailbox>,
    pub cc: Vec<JsMailbox>,
    pub bcc: Vec<JsMailbox>,
    pub reply_to: Vec<JsMailbox>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub headers: Vec<JsHeader>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub unsanitized_html: Option<String>,
    pub attachments: Vec<JsAttachment>,
}

fn limits_of(limits: Option<JsLimits>) -> Limits {
    let mut out = Limits::default();
    if let Some(l) = limits {
        if let Some(v) = l.max_bytes {
            out.max_bytes = v as usize;
        }
        if let Some(v) = l.max_parts {
            out.max_parts = v as usize;
        }
        if let Some(v) = l.max_depth {
            out.max_depth = v as usize;
        }
        if let Some(v) = l.max_attachments {
            out.max_attachments = v as usize;
        }
        if let Some(v) = l.max_attachment_bytes {
            out.max_attachment_bytes = v as usize;
        }
    }
    out
}

fn mailboxes(list: Vec<Mailbox>) -> Vec<JsMailbox> {
    list.into_iter()
        .map(|m| JsMailbox {
            name: m.name,
            address: m.address,
        })
        .collect()
}

/// `CODE: message`, which the TypeScript side turns back into a coded error.
fn engine_error(error: ParseError) -> Error {
    Error::new(Status::InvalidArg, format!("{}: {}", error.code(), error))
}

/// Parse one received message. Throws `E_GOLDSTONE_*: …` on a message that
/// breaks a limit or is not a message at all.
#[napi]
pub fn parse_message(raw: Buffer, limits: Option<JsLimits>) -> Result<JsMessage> {
    let message = goldstone_engine::parse(&raw, &limits_of(limits)).map_err(engine_error)?;
    Ok(JsMessage {
        message_id: message.message_id,
        subject: message.subject,
        date: message.date,
        from: mailboxes(message.from),
        to: mailboxes(message.to),
        cc: mailboxes(message.cc),
        bcc: mailboxes(message.bcc),
        reply_to: mailboxes(message.reply_to),
        in_reply_to: message.in_reply_to,
        references: message.references,
        headers: message
            .headers
            .into_iter()
            .map(|(name, value)| JsHeader { name, value })
            .collect(),
        text: message.text,
        html: message.html,
        unsanitized_html: message.unsanitized_html,
        attachments: message
            .attachments
            .into_iter()
            .map(|a| JsAttachment {
                file_name: a.file_name,
                original_name: a.original_name,
                content_type: a.content_type,
                content: Buffer::from(a.content),
                content_id: a.content_id,
                inline: a.inline,
            })
            .collect(),
    })
}
