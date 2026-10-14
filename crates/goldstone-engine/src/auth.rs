//! Who really sent it: DKIM, SPF, DMARC and ARC on a received message.
//!
//! The From header is whatever the sender typed. What can be checked is
//! whether the domain in it vouches for the message: a DKIM signature by
//! that domain, an SPF record that lists the IP that delivered it, and the
//! domain's DMARC policy tying the two to the From. `summary` is `pass` only
//! when DMARC passes — anything that could not be checked is never a pass.
//!
//! Every check runs on DNS, so every check is bounded: a total deadline, a
//! cap on the DKIM signatures verified (each is a lookup), SPF's own lookup
//! limit, and a cache so the same key is not fetched for every message.

use mail_auth::common::parse::TxtRecordParser;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::dmarc::Policy;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{
    AuthenticatedMessage, DkimResult, DmarcResult, MessageAuthenticator, Parameters, ResolverCache,
    SpfOutput, SpfResult, Txt,
};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::ParseError;

/// How the message was delivered, when the caller knows: what SPF checks.
/// Read from IMAP, a message usually does not carry this reliably, and SPF
/// is then not evaluated.
#[derive(Clone, Debug, Default)]
pub struct Envelope {
    /// The IP of the server that handed the message over.
    pub ip: Option<IpAddr>,
    pub helo: Option<String>,
    /// The SMTP MAIL FROM (return path).
    pub mail_from: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthOptions {
    pub envelope: Envelope,
    /// DKIM signatures verified, at most; the rest are ignored. Each one is a
    /// DNS lookup, and a message can carry any number. Default 5.
    pub max_dkim_signatures: usize,
    /// For the whole check. Past it, the verdict is `temperror`. Default 10 s.
    pub timeout: Duration,
    /// Size of the raw message, checked first. Default 25 MiB.
    pub max_bytes: usize,
    /// The name this receiver goes by, for SPF macros. Default `goldstone`.
    pub receiver: String,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            envelope: Envelope::default(),
            max_dkim_signatures: 5,
            timeout: Duration::from_secs(10),
            max_bytes: 25 * 1024 * 1024,
            receiver: "goldstone".into(),
        }
    }
}

/// A check's outcome, in the words of RFC 8601.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DkimVerdict {
    pub result: Outcome,
    pub domain: Option<String>,
    pub selector: Option<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Verdict {
    pub dkim: Vec<DkimVerdict>,
    /// `none` when no envelope was given.
    pub spf: Outcome,
    pub dmarc: Outcome,
    /// `none`, `quarantine`, `reject`, or `unspecified` without a record.
    pub dmarc_policy: &'static str,
    /// The From domain DMARC was evaluated for.
    pub dmarc_domain: Option<String>,
    pub arc: Outcome,
    /// `pass` (DMARC passed), `fail` (DMARC failed), `temperror` (a check
    /// could not complete) or `none` (nothing to decide on).
    pub summary: Outcome,
}

impl Verdict {
    fn temperror() -> Self {
        Self {
            dkim: Vec::new(),
            spf: Outcome::TempError,
            dmarc: Outcome::TempError,
            dmarc_policy: "unspecified",
            dmarc_domain: None,
            arc: Outcome::TempError,
            summary: Outcome::TempError,
        }
    }
}

/// TXT records (DKIM keys, SPF and DMARC policies) kept until their TTL,
/// and at most `capacity` of them — a full cache drops what has expired, and
/// everything if that is not enough. Shared by every check.
pub struct TxtCache {
    capacity: usize,
    entries: Mutex<HashMap<Box<str>, (Txt, Instant)>>,
}

impl TxtCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Put a record in by hand — for tests, where there is no DNS.
    pub fn insert_record(&self, name: &str, record: Txt, ttl: Duration) {
        self.insert(name.into(), record, Instant::now() + ttl);
    }
}

impl ResolverCache<Box<str>, Txt> for TxtCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.entries.lock().ok()?;
        let (value, valid_until) = entries.get(name)?;
        (Instant::now() < *valid_until).then(|| value.clone())
    }

    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries
            .lock()
            .ok()?
            .remove(name)
            .map(|(value, _)| value)
    }

    fn insert(&self, key: Box<str>, value: Txt, valid_until: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= self.capacity {
            let now = Instant::now();
            entries.retain(|_, (_, until)| *until > now);
            if entries.len() >= self.capacity {
                entries.clear();
            }
        }
        entries.insert(key, (value, valid_until));
    }
}

/// Parse a TXT record the way the resolver would — for tests.
pub fn dkim_key_record(text: &str) -> Txt {
    Txt::from(mail_auth::common::verify::DomainKey::parse(text.as_bytes()))
}

pub fn spf_record(text: &str) -> Txt {
    Txt::from(mail_auth::spf::Spf::parse(text.as_bytes()))
}

pub fn dmarc_record(text: &str) -> Txt {
    Txt::from(mail_auth::dmarc::Dmarc::parse(text.as_bytes()))
}

/// A name that does not exist (NXDOMAIN), as the resolver would cache it —
/// for tests, where a missing name would otherwise be a DNS failure.
pub fn not_found_record() -> Txt {
    Txt::Error(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(
        mail_auth::hickory_resolver::proto::op::ResponseCode::NXDomain,
    )))
}

pub async fn authenticate(
    raw: &[u8],
    options: &AuthOptions,
    authenticator: &MessageAuthenticator,
    cache: &TxtCache,
) -> Result<Verdict, ParseError> {
    if raw.len() > options.max_bytes {
        return Err(ParseError::TooLarge {
            size: raw.len(),
            max: options.max_bytes,
        });
    }
    let mut message = AuthenticatedMessage::parse(raw).ok_or(ParseError::NotAMessage)?;
    message.dkim_headers.truncate(options.max_dkim_signatures);
    let checks = run(&message, options, authenticator, cache);
    Ok(tokio::time::timeout(options.timeout, checks)
        .await
        .unwrap_or_else(|_| Verdict::temperror()))
}

async fn run(
    message: &AuthenticatedMessage<'_>,
    options: &AuthOptions,
    authenticator: &MessageAuthenticator,
    cache: &TxtCache,
) -> Verdict {
    let dkim_output = authenticator
        .verify_dkim(Parameters::new(message).with_txt_cache(cache))
        .await;
    let arc_output = authenticator
        .verify_arc(Parameters::new(message).with_txt_cache(cache))
        .await;

    let envelope = &options.envelope;
    let mail_from = envelope.mail_from.as_deref().unwrap_or("");
    let spf_output = match (envelope.ip, envelope.helo.as_deref()) {
        (Some(ip), Some(helo)) if !mail_from.is_empty() => {
            authenticator
                .verify_spf(
                    Parameters::new(SpfParameters::verify_mail_from(
                        ip,
                        helo,
                        &options.receiver,
                        mail_from,
                    ))
                    .with_txt_cache(cache),
                )
                .await
        }
        _ => SpfOutput::new(String::new()),
    };
    let mail_from_domain = mail_from.rsplit_once('@').map_or("", |(_, domain)| domain);
    let dmarc_output = authenticator
        .verify_dmarc(
            Parameters::new(DmarcParameters::new(
                message,
                &dkim_output,
                mail_from_domain,
                &spf_output,
            ))
            .with_txt_cache(cache),
        )
        .await;

    let dkim: Vec<DkimVerdict> = dkim_output
        .iter()
        .map(|output| DkimVerdict {
            result: dkim_outcome(output.result()),
            domain: output.signature().map(|s| s.d.clone()),
            selector: output.signature().map(|s| s.s.clone()),
            reason: dkim_reason(output.result()),
        })
        .collect();
    let dmarc = dmarc_outcome(&dmarc_output.result());
    let summary = match dmarc {
        Outcome::Pass => Outcome::Pass,
        Outcome::Fail => Outcome::Fail,
        Outcome::TempError => Outcome::TempError,
        _ if dkim.iter().any(|d| d.result == Outcome::TempError) => Outcome::TempError,
        _ => Outcome::None,
    };
    Verdict {
        dkim,
        spf: spf_outcome(spf_output.result()),
        dmarc,
        dmarc_policy: match dmarc_output.policy() {
            Policy::None => "none",
            Policy::Quarantine => "quarantine",
            Policy::Reject => "reject",
            Policy::Unspecified => "unspecified",
        },
        dmarc_domain: Some(dmarc_output.domain().to_owned()).filter(|d| !d.is_empty()),
        arc: dkim_outcome(arc_output.result()),
        summary,
    }
}

fn dkim_outcome(result: &DkimResult) -> Outcome {
    match result {
        DkimResult::Pass => Outcome::Pass,
        DkimResult::Neutral(_) => Outcome::Neutral,
        DkimResult::Fail(_) => Outcome::Fail,
        DkimResult::PermError(_) => Outcome::PermError,
        DkimResult::TempError(_) => Outcome::TempError,
        DkimResult::None => Outcome::None,
    }
}

fn dkim_reason(result: &DkimResult) -> Option<String> {
    match result {
        DkimResult::Neutral(e)
        | DkimResult::Fail(e)
        | DkimResult::PermError(e)
        | DkimResult::TempError(e) => Some(e.to_string()),
        DkimResult::Pass | DkimResult::None => None,
    }
}

fn spf_outcome(result: SpfResult) -> Outcome {
    match result {
        SpfResult::Pass => Outcome::Pass,
        SpfResult::Fail => Outcome::Fail,
        SpfResult::SoftFail => Outcome::SoftFail,
        SpfResult::Neutral => Outcome::Neutral,
        SpfResult::TempError => Outcome::TempError,
        SpfResult::PermError => Outcome::PermError,
        SpfResult::None => Outcome::None,
    }
}

fn dmarc_outcome(result: &DmarcResult) -> Outcome {
    match result {
        DmarcResult::Pass => Outcome::Pass,
        DmarcResult::Fail(_) => Outcome::Fail,
        DmarcResult::TempError(_) => Outcome::TempError,
        DmarcResult::PermError(_) => Outcome::PermError,
        DmarcResult::None => Outcome::None,
    }
}
