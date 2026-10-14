//! NAPI bindings for goldstone-engine: one call per message — the raw bytes
//! in, the parsed message out.

use goldstone_engine::auth::{AuthOptions, Envelope, TxtCache, Verdict};
use goldstone_engine::{Limits, Mailbox, ParseError};
use mail_auth::MessageAuthenticator;
use napi::bindgen_prelude::Buffer;
use napi::{Error, Result, Status};
use napi_derive::napi;
use std::sync::OnceLock;
use std::time::Duration;

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

/// The envelope SPF checks, and the bounds on the whole check.
#[napi(object)]
pub struct JsAuthOptions {
    pub ip: Option<String>,
    pub helo: Option<String>,
    pub mail_from: Option<String>,
    pub max_dkim_signatures: Option<u32>,
    pub timeout_ms: Option<u32>,
    pub max_bytes: Option<u32>,
}

#[napi(object)]
pub struct JsDkimVerdict {
    pub result: String,
    pub domain: Option<String>,
    pub selector: Option<String>,
    pub reason: Option<String>,
}

#[napi(object)]
pub struct JsVerdict {
    pub dkim: Vec<JsDkimVerdict>,
    pub spf: String,
    pub dmarc: String,
    pub dmarc_policy: String,
    pub dmarc_domain: Option<String>,
    pub arc: String,
    pub summary: String,
}

/// One resolver and one cache for every check in the process: the system's
/// resolver configuration, a short per-query timeout, two attempts.
fn authenticator() -> Result<&'static MessageAuthenticator> {
    static AUTHENTICATOR: OnceLock<std::result::Result<MessageAuthenticator, String>> =
        OnceLock::new();
    AUTHENTICATOR
        .get_or_init(|| {
            let (config, mut options) =
                mail_auth::hickory_resolver::system_conf::read_system_conf()
                    .map_err(|e| e.to_string())?;
            options.timeout = Duration::from_secs(2);
            options.attempts = 2;
            options.cache_size = 4096;
            MessageAuthenticator::new(config, options).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("E_GOLDSTONE_DNS_UNAVAILABLE: {e}"),
            )
        })
}

fn cache() -> &'static TxtCache {
    static CACHE: OnceLock<TxtCache> = OnceLock::new();
    CACHE.get_or_init(|| TxtCache::new(4096))
}

fn auth_options(options: Option<JsAuthOptions>) -> Result<AuthOptions> {
    let mut out = AuthOptions::default();
    let Some(o) = options else { return Ok(out) };
    let ip = match o.ip {
        Some(ip) => Some(ip.parse().map_err(|_| {
            Error::new(
                Status::InvalidArg,
                format!("E_GOLDSTONE_INVALID_ENVELOPE: \"{ip}\" is not an IP address"),
            )
        })?),
        None => None,
    };
    out.envelope = Envelope {
        ip,
        helo: o.helo,
        mail_from: o.mail_from,
    };
    if let Some(v) = o.max_dkim_signatures {
        out.max_dkim_signatures = v as usize;
    }
    if let Some(v) = o.timeout_ms {
        out.timeout = Duration::from_millis(v.into());
    }
    if let Some(v) = o.max_bytes {
        out.max_bytes = v as usize;
    }
    Ok(out)
}

fn verdict(v: Verdict) -> JsVerdict {
    JsVerdict {
        dkim: v
            .dkim
            .into_iter()
            .map(|d| JsDkimVerdict {
                result: d.result.as_str().into(),
                domain: d.domain,
                selector: d.selector,
                reason: d.reason,
            })
            .collect(),
        spf: v.spf.as_str().into(),
        dmarc: v.dmarc.as_str().into(),
        dmarc_policy: v.dmarc_policy.into(),
        dmarc_domain: v.dmarc_domain,
        arc: v.arc.as_str().into(),
        summary: v.summary.as_str().into(),
    }
}

/// DKIM, SPF (when the envelope is given), DMARC and ARC for one received
/// message. Resolves with `temperror` verdicts when DNS cannot answer in
/// time — never with a pass.
#[napi]
pub async fn authenticate_message(
    raw: Buffer,
    options: Option<JsAuthOptions>,
) -> Result<JsVerdict> {
    let options = auth_options(options)?;
    let authenticator = authenticator()?;
    let result = goldstone_engine::auth::authenticate(&raw, &options, authenticator, cache())
        .await
        .map_err(engine_error)?;
    Ok(verdict(result))
}
