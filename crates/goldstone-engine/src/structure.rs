//! Bounds on a message's structure: what the parser may build, and what the
//! application may be handed.
//!
//! mail-parser 1.0 bounds itself where a hostile message used to cost the
//! most: it stops at a number of parts and a nesting depth, searches for a
//! missing boundary without rescanning the message, and stores a parse in a
//! handful of flat vectors. What it does not bound is the number of header
//! fields: each costs about 40 bytes, so 25 MB of `a:b` lines is 200 MB
//! once parsed (measured on 1.0.1). That one is bounded before the parse, by
//! a count that needs no structure: every field the parser builds starts a
//! line and holds its colon on that line (it splits lines on LF only), so a
//! message never holds more fields than lines with a colon. Over
//! [`field_lines_allowed`] of them, the message is refused unread; under it,
//! the parse costs at most a few times the message's size. Encoded carried
//! messages are left as attachments (`max_encoded_nesting(0)`): parsing one
//! builds fields from decoded bytes this count never saw.
//!
//! Everything else is counted exactly, after the parse and before anything
//! is handed out: parts and nesting through the parts of carried messages
//! too, fields and bytes per header block, fields in all.

use crate::{Limits, ParseError};
use mail_parser::{Message, MessageParser};

/// Header fields per allowed part, on top of `max_headers` for the message's
/// own header.
const FIELDS_PER_PART: usize = 16;

/// Bytes of message per line with a colon the parse may meet: the parse
/// then builds at most one 40-byte field per 16 bytes of input.
const BYTES_PER_FIELD_LINE: usize = 16;

/// The parser goes this many levels past `max_depth`, so that a message
/// over it is seen to be over it rather than cut at it.
const DEPTH_MARGIN: usize = 2;

/// Header fields in all, through every part.
fn max_fields(limits: &Limits) -> usize {
    limits
        .max_parts
        .saturating_mul(FIELDS_PER_PART)
        .saturating_add(limits.max_headers)
}

/// Lines with a colon a message may hold: never fewer than the fields it may
/// carry, more when the message may be large, since a body's lines count too
/// (logs, CSV in the clear).
pub(crate) fn field_lines_allowed(limits: &Limits) -> usize {
    max_fields(limits).max(limits.max_bytes / BYTES_PER_FIELD_LINE)
}

/// The parser, bounded by `limits`.
pub(crate) fn parser(limits: &Limits) -> MessageParser {
    MessageParser::new()
        .max_parts(limits.max_parts.saturating_add(1))
        .max_depth(limits.max_depth.saturating_add(DEPTH_MARGIN))
        .max_encoded_nesting(0)
}

/// Before the parse: the lines that could each start a header field.
pub(crate) fn prescan(raw: &[u8], limits: &Limits) -> Result<(), ParseError> {
    let max = field_lines_allowed(limits);
    let mut lines = 0usize;
    for line in raw.split(|byte| *byte == b'\n') {
        if line.contains(&b':') {
            lines += 1;
            if lines > max {
                return Err(ParseError::TooManyFieldLines { max });
            }
        }
    }
    Ok(())
}

/// After the parse: the exact counts, through every carried message. A
/// carried message's root part is one level below the part that carries it.
pub(crate) fn check(message: &Message<'_>, limits: &Limits) -> Result<(), ParseError> {
    let parts = message.parts().len();
    if parts > limits.max_parts {
        return Err(ParseError::TooManyParts {
            count: parts,
            max: limits.max_parts,
        });
    }
    let max_fields = max_fields(limits);
    let mut fields = 0usize;
    // Part ids follow the document, so a part's container comes first.
    let mut depth_of = vec![0usize; parts];
    for part in message.parts() {
        let above = part.parent().or_else(|| part.message().container());
        let depth = above
            .and_then(|up| depth_of.get(up.id() as usize))
            .map_or(0, |depth| depth + 1);
        if let Some(slot) = depth_of.get_mut(part.id() as usize) {
            *slot = depth;
        }
        if depth > limits.max_depth {
            return Err(ParseError::TooDeep {
                depth,
                max: limits.max_depth,
            });
        }
        let headers = part.headers().len();
        if headers > limits.max_headers {
            return Err(ParseError::TooManyHeaders {
                count: headers,
                max: limits.max_headers,
            });
        }
        fields += headers;
        if fields > max_fields {
            return Err(ParseError::TooManyHeaderFields {
                count: fields,
                max: max_fields,
            });
        }
        let size = part.offset_body().saturating_sub(part.offset_header()) as usize;
        if size > limits.max_header_bytes {
            return Err(ParseError::HeadersTooLarge {
                size,
                max: limits.max_header_bytes,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fields the parse builds, through every part.
    fn built_fields(raw: &[u8]) -> Option<usize> {
        let message = parser(&Limits::default()).parse(raw)?;
        let fields = message.parts().map(|part| part.headers().len()).sum();
        Some(fields)
    }

    fn field_lines(raw: &[u8]) -> usize {
        raw.split(|byte| *byte == b'\n')
            .filter(|line| line.contains(&b':'))
            .count()
    }

    const HEAD: &str = "From: a@example.test\r\nTo: b@example.test\r\nSubject: s\r\n";

    /// Messages stitched from the pieces MIME structure is made of, in any
    /// order: the parse never builds more fields than there are lines with a
    /// colon, the count the prescan bounds.
    #[test]
    fn the_parse_never_builds_more_fields_than_lines_with_a_colon() {
        const PIECES: [&str; 30] = [
            "\r\n",
            "\n",
            "\r",
            " \r\n",
            "\t\r\n",
            "\r\r\n",
            "--a\r\n",
            "--b\r\n",
            "--a--\r\n",
            "--b-- \r\n",
            "x --a y: z\r\n",
            "--aContent-Type: message/rfc822\r\n",
            "Content-Type: multipart/mixed; boundary=a\r\n",
            "Content-Type: multipart/digest; boundary=\"b\"\r\n",
            "Content-Type: message/rfc822\r\n",
            ":Content-Type: message/rfc822\r\n",
            "content - type: multipart/alternative;\r\n boundary=b\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "RnJvbTogeEB5DQpYOiAxDQoNCmI=\r\n",
            "X=3A y\r\n",
            "From: a@b.test\r\n",
            "a:b\r\n",
            "a:b\rc:d\r\n",
            " folded: x\r\n",
            "::\r\n",
            "junk\r\n",
            "-- \r\n",
            "text\r\n",
            "To: g: a@b.test, c@d.test;\r\n",
        ];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut parsed = 0;
        for _ in 0..20_000 {
            let len = 1 + (next() % 40) as usize;
            let raw: String = (0..len)
                .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                .collect();
            let Some(built) = built_fields(raw.as_bytes()) else {
                continue;
            };
            parsed += 1;
            let lines = field_lines(raw.as_bytes());
            assert!(built <= lines, "{raw:?}: {built} fields, {lines} lines");
        }
        assert!(parsed > 10_000, "only {parsed} of the messages parsed");
    }

    #[test]
    fn an_encoded_carried_message_is_not_parsed() {
        // Its fields come from decoded bytes the prescan never sees: it stays
        // an attachment.
        let raw = format!("{HEAD}Content-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\nRnJvbTogeEB5LnRlc3QNClg6IDENCg0KYm9keQ0K\r\n--o\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nFrom: z@y.test\r\nA=3A b\r\n\r\nbody\r\n--o--\r\n");
        let message = parser(&Limits::default())
            .parse(raw.as_bytes())
            .expect("a message");
        assert_eq!(message.messages().len(), 1, "only the root message");
        assert_eq!(message.root().attachments().len(), 2);
    }

    #[test]
    fn body_lines_alone_stay_under_the_bound() {
        // A large log in the clear is read: it is the message size that sets
        // the bound, not the fields allowed.
        let log: String = (0..100_000)
            .map(|i| {
                format!(
                    "Nov 10 10:{:02}:00 host sshd[{i}]: Accepted publickey\r\n",
                    i % 60
                )
            })
            .collect();
        let raw = format!("{HEAD}Content-Type: text/plain\r\n\r\n{log}");
        assert!(prescan(raw.as_bytes(), &Limits::default()).is_ok());
    }

    #[test]
    fn the_bound_follows_the_message_size() {
        let limits = Limits::default();
        assert_eq!(field_lines_allowed(&limits), 25 * 1024 * 1024 / 16);
        let small = Limits {
            max_bytes: 64 * 1024,
            ..limits
        };
        assert_eq!(field_lines_allowed(&small), 1_000 * 16 + 1_000);
    }
}
