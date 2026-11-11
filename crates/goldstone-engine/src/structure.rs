//! Bounds on a message's structure, checked before it is parsed.
//!
//! mail-parser builds every part and every header it finds, and a part or a
//! header can cost a few bytes of input and a hundred of memory: 20 MB of
//! empty parts or of `a:b` lines is a gigabyte once parsed. Counting them
//! after the parse refuses the message once the memory is spent. So the
//! message is first walked the way mail-parser walks it, with mail-parser's
//! own primitives, keeping nothing but counts.
//!
//! A part starts where mail-parser starts one: after a delimiter of the
//! boundary the enclosing multipart declared (RFC 2046 section 5.1.1), after
//! the header block of a carried message/rfc822 part, or for a part of a
//! multipart/digest that names no type. Nothing else in a body opens a header
//! block: a `-- ` signature, a journalctl banner, the word "digest" or a file
//! named `messages.csv` are body text, as they are to the parser. A header
//! block is measured line by line (RFC 5322 section 2.2: a field is a line
//! holding a colon, a line starting with white space continues it, a line of
//! white space ends the block) before mail-parser reads it, so no block costs
//! more than the limits allow. A message/* body in base64 or
//! quoted-printable is decoded by mail-parser's decoder and walked the same
//! way, as many levels down as mail-parser parses it.
//!
//! The walk mirrors `MessageParser::parse` of the mail-parser release pinned
//! in Cargo.toml (src/parsers/message.rs): an upgrade has to be checked
//! against it, and the tests compare the walk's counts with what the parse
//! builds.

use crate::{Limits, ParseError};
use mail_parser::parsers::MessageStream;
use mail_parser::{ContentType, GetHeader, Header, HeaderName, HeaderValue, MessageParser};

/// mail-parser parses an encoded message/* part this many levels down
/// (its `MAX_NESTED_ENCODED`).
const ENCODED_LEVELS: usize = 3;

/// Header fields per allowed part, on top of `max_headers` for the message's
/// own header.
const FIELDS_PER_PART: usize = 16;

/// What the parse will build, counted through every carried message.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub parts: usize,
    pub fields: usize,
}

struct Budget {
    counts: Counts,
    max_parts: usize,
    max_fields: usize,
}

impl Budget {
    fn add_block(&mut self, fields: usize) -> Result<(), ParseError> {
        self.counts.parts += 1;
        if self.counts.parts > self.max_parts {
            return Err(ParseError::TooManyParts {
                count: self.counts.parts,
                max: self.max_parts,
            });
        }
        self.counts.fields += fields;
        if self.counts.fields > self.max_fields {
            return Err(ParseError::TooManyHeaderFields {
                count: self.counts.fields,
                max: self.max_fields,
            });
        }
        Ok(())
    }
}

/// The media types the walk tells apart: the ones that change where the next
/// part starts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mime {
    Digest,
    Message,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    None,
    Base64,
    QuotedPrintable,
}

/// A multipart being read, or a carried message being read.
struct State {
    mime: Mime,
    boundary: Option<Vec<u8>>,
    /// Its part, among the parts of the message it sits in.
    part_id: usize,
}

pub fn prescan(raw: &[u8], limits: &Limits) -> Result<(), ParseError> {
    count(raw, limits).map(|_| ())
}

pub(crate) fn count(raw: &[u8], limits: &Limits) -> Result<Counts, ParseError> {
    let mut budget = Budget {
        counts: Counts::default(),
        max_parts: limits.max_parts,
        max_fields: limits
            .max_parts
            .saturating_mul(FIELDS_PER_PART)
            .saturating_add(limits.max_headers),
    };
    walk(raw, ENCODED_LEVELS, 0, limits, &mut budget)?;
    Ok(budget.counts)
}

/// mail-parser's media type of a part, from its Content-Type and the
/// multipart it sits in; `true` for a multipart.
fn mime_of(content_type: Option<&ContentType<'_>>, parent: Mime) -> (bool, Mime) {
    match content_type {
        Some(content_type) => match content_type.ctype() {
            "multipart" => (
                true,
                if content_type.subtype() == Some("digest") {
                    Mime::Digest
                } else {
                    Mime::Other
                },
            ),
            "message" if matches!(content_type.subtype(), Some("rfc822" | "global")) => {
                (false, Mime::Message)
            }
            _ => (false, Mime::Other),
        },
        // RFC 2046 section 5.1.5: in a digest, a part without a type is a
        // message.
        None if parent == Mime::Digest => (false, Mime::Message),
        None => (false, Mime::Other),
    }
}

/// `levels`: how many encoded messages down mail-parser still parses;
/// `base`: the nesting of the message `data` is.
fn walk(
    data: &[u8],
    levels: usize,
    base: usize,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<(), ParseError> {
    let parser = MessageParser::default();
    let mut stream = MessageStream::new(data);
    let mut state = State {
        mime: Mime::Message,
        boundary: None,
        part_id: 0,
    };
    // The parts of the message being read: a carried message's are its own.
    let mut parts = 0usize;
    // The enclosing states; a carried message's keeps the number of parts
    // of the message around it.
    let mut stack: Vec<(State, Option<usize>)> = Vec::new();

    let mut first = true;
    'outer: while let Some(headers) =
        header_block(&parser, &mut stream, data, first, limits, budget)?
    {
        first = false;
        // Each multipart and carried message around a part is one level.
        let depth = base + stack.len();
        if depth > limits.max_depth {
            return Err(ParseError::TooDeep {
                depth,
                max: limits.max_depth,
            });
        }
        let content_type = headers
            .header_value(&HeaderName::ContentType)
            .and_then(|value| value.as_content_type());
        let (is_multipart, mut mime) = mime_of(content_type, state.mime);

        if is_multipart {
            if let Some(boundary) = content_type.and_then(|c| c.attribute("boundary")) {
                if stream.seek_next_part(boundary.as_bytes()) {
                    let inner = State {
                        mime,
                        boundary: Some(boundary.as_bytes().to_vec()),
                        part_id: parts,
                    };
                    parts += 1;
                    stack.push((state, None));
                    state = inner;
                    stream.skip_crlf();
                    continue;
                }
                // A boundary that never occurs: the body is text.
                mime = Mime::Other;
            }
        }

        let encoding = match headers.header_value(&HeaderName::ContentTransferEncoding) {
            Some(HeaderValue::Text(name)) if name.eq_ignore_ascii_case("base64") => {
                Encoding::Base64
            }
            Some(HeaderValue::Text(name)) if name.eq_ignore_ascii_case("quoted-printable") => {
                Encoding::QuotedPrintable
            }
            _ => Encoding::None,
        };

        if mime == Mime::Message && encoding == Encoding::None {
            // The carried message's header block follows at once, and its
            // parts end at the enclosing boundary.
            let carried = State {
                mime: Mime::Message,
                boundary: state.boundary.take(),
                part_id: parts,
            };
            stack.push((state, Some(parts + 1)));
            state = carried;
            parts = 0;
            continue;
        }

        let boundary = state.boundary.as_deref().unwrap_or_default();
        let (end, body) = match encoding {
            Encoding::Base64 => stream.decode_base64_mime(boundary),
            Encoding::QuotedPrintable => stream.decode_quoted_printable_mime(boundary),
            Encoding::None => stream.mime_part(boundary),
        };
        if end == usize::MAX {
            // Undecodable: mail-parser keeps the bytes as text up to the
            // boundary, and forgets the boundary when it never comes.
            let (_, found) = stream.seek_part_end(state.boundary.as_deref());
            if !found {
                state.boundary = None;
            }
        } else if mime == Mime::Message && levels != 0 {
            walk(&body, levels - 1, depth + 1, limits, budget)?;
        }
        drop(body);
        parts += 1;

        if state.boundary.is_some() {
            loop {
                if state.mime == Mime::Message {
                    // The end of a carried message: back to its multipart.
                    match stack.pop() {
                        Some((mut outer, Some(outer_parts))) => {
                            outer.boundary = state.boundary.take();
                            state = outer;
                            parts = outer_parts;
                        }
                        _ => break 'outer,
                    }
                }
                if !stream.is_multipart_end() {
                    // A delimiter: the next part's header block follows.
                    break;
                }
                // A close delimiter: on to the enclosing multipart's next
                // delimiter, if there is one. mail-parser stops when the
                // state it closes has no part in the message being read
                // (a carried message closed by its multipart's delimiter).
                if state.part_id >= parts {
                    break 'outer;
                }
                if let Some((outer, _)) = stack.pop() {
                    state = outer;
                    if let Some(boundary) = &state.boundary {
                        if stream.seek_next_part_offset(boundary).is_some() {
                            continue;
                        }
                    }
                }
                break 'outer;
            }
        } else if stream.offset() >= stream.len() {
            break;
        }
    }
    Ok(())
}

/// The header block at the stream's position, read by mail-parser once its
/// lines are known to fit the limits; `None` when the bytes end inside it,
/// where mail-parser stops too. `first`: the message's own header block.
fn header_block<'x>(
    parser: &MessageParser,
    stream: &mut MessageStream<'x>,
    data: &'x [u8],
    first: bool,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<Option<Vec<Header<'x>>>, ParseError> {
    let start = stream.offset();
    let end = block_end(data, start, limits)?;
    let mut block = MessageStream::new(&data[start..end]);
    let mut headers = Vec::new();
    let ended = block.parse_headers(parser, &mut headers);
    if !ended && end < data.len() {
        // mail-parser would read on past the line that ends the block for
        // RFC 5322, past what was measured.
        return Err(ParseError::UnendedHeaders);
    }
    stream.skip_bytes(block.offset());
    if !ended {
        // A message that is nothing but a header block is one part; a part
        // cut off by the end of the bytes is dropped.
        if first && !headers.is_empty() {
            budget.add_block(headers.len())?;
        }
        return Ok(None);
    }
    budget.add_block(headers.len())?;
    Ok(Some(headers))
}

/// Where the header block starting at `start` ends: after the first line of
/// white space where a field may start (an empty line, most of the time), or
/// at the end of the bytes. Its size and the lines that may hold a field are
/// bounded on the way.
fn block_end(data: &[u8], start: usize, limits: &Limits) -> Result<usize, ParseError> {
    let mut at = start;
    let mut colon_lines = 0usize;
    // A line may start a field: not right after a field's line, where a
    // line starting with white space continues it.
    let mut field_start = true;
    while at < data.len() {
        let next = data[at..]
            .iter()
            .position(|c| *c == b'\n')
            .map_or(data.len(), |n| at + n + 1);
        if next - start > limits.max_header_bytes {
            return Err(ParseError::HeadersTooLarge {
                size: next - start,
                max: limits.max_header_bytes,
            });
        }
        let line = data[at..next]
            .strip_suffix(b"\n")
            .unwrap_or(&data[at..next]);
        // A field's name and colon sit on one line, and a line holds at most
        // one name: the lines holding a colon bound the fields.
        if line.contains(&b':') {
            colon_lines += 1;
            if colon_lines > limits.max_headers {
                return Err(ParseError::TooManyHeaders {
                    count: colon_lines,
                    max: limits.max_headers,
                });
            }
        }
        at = next;
        if !field_start && matches!(line.first(), Some(b' ' | b'\t')) {
            continue;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(next);
        }
        field_start = !is_field(line);
    }
    Ok(data.len())
}

/// A line mail-parser reads as a field: a name, then a colon.
fn is_field(line: &[u8]) -> bool {
    line.iter()
        .position(|c| !c.is_ascii_whitespace() && *c != b':')
        .is_some_and(|name| line[name..].contains(&b':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_parser::{Message, PartType};

    /// What mail-parser builds: parts and header fields, through every
    /// carried message.
    fn built(raw: &[u8]) -> Counts {
        let message = MessageParser::default().parse(raw).expect("a message");
        let mut counts = Counts::default();
        let mut messages: Vec<&Message<'_>> = vec![&message];
        while let Some(message) = messages.pop() {
            counts.parts += message.parts.len();
            for part in &message.parts {
                counts.fields += part.headers.len();
                if let PartType::Message(carried) = &part.body {
                    messages.push(carried);
                }
            }
        }
        counts
    }

    fn walked(raw: &[u8]) -> Counts {
        count(raw, &Limits::default()).expect("within the limits")
    }

    fn assert_mirrors(raw: &str) {
        assert_eq!(walked(raw.as_bytes()), built(raw.as_bytes()), "{raw:?}");
    }

    const HEAD: &str = "From: a@example.test\r\nTo: b@example.test\r\nSubject: s\r\n";

    #[test]
    fn the_walk_counts_what_the_parse_builds() {
        let cases = [
            format!("{HEAD}\r\nplain body\r\n"),
            HEAD.to_string(),
            format!("{HEAD}Content-Type: multipart/mixed; boundary=b\r\n\r\npreamble\r\n--b\r\nContent-Type: text/plain\r\n\r\none\r\n--b\r\n\r\ntwo\r\n--b--\r\nepilogue\r\n"),
            // Nested multiparts, a carried message, a digest.
            format!("{HEAD}Content-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\nContent-Type: multipart/alternative; boundary=i\r\n\r\n--i\r\nContent-Type: text/plain\r\n\r\nt\r\n--i\r\nContent-Type: text/html\r\n\r\n<p>h</p>\r\n--i--\r\n--o\r\nContent-Type: message/rfc822\r\n\r\nFrom: c@example.test\r\nContent-Type: multipart/mixed; boundary=n\r\n\r\n--n\r\n\r\nx\r\n--n--\r\n--o--\r\n"),
            format!("{HEAD}Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nFrom: one@example.test\r\nSubject: 1\r\n\r\nbody 1\r\n--d\r\n\r\nFrom: two@example.test\r\n\r\nbody 2\r\n--d--\r\n"),
            // Encoded carried messages.
            format!("{HEAD}Content-Type: multipart/mixed; boundary=o\r\n\r\n--o\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\nRnJvbTogeEB5LnRlc3QNClg6IDENCg0KYm9keQ0K\r\n--o\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nFrom: z@y.test\r\nA=3A b\r\n\r\nbody\r\n--o--\r\n"),
            // A delimiter in the middle of a line, and padding after one.
            format!("{HEAD}Content-Type: multipart/mixed; boundary=b\r\n\r\n--b  \r\nX: 1\r\n\r\ntext --b\r\nY: 2\r\n\r\nz\r\n--b--\r\n"),
            // A boundary that never occurs, an undecodable part.
            format!("{HEAD}Content-Type: multipart/mixed; boundary=never\r\n\r\n--b\r\nX: 1\r\n\r\nz\r\n"),
            format!("{HEAD}Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n!!not base64!!\r\n--b\r\nX: 2\r\n\r\nz\r\n--b--\r\n"),
            // Folded fields, a field after a line that is not one.
            format!("{HEAD}X-Folded: a\r\n b: c\r\n\t\r\nnot a field\r\n Y: 1\r\n\r\nbody\r\n"),
        ];
        for case in &cases {
            assert_mirrors(case);
        }
    }

    /// Messages stitched from the pieces MIME structure is made of, in any
    /// order: the walk never counts less than the parse builds. It counts
    /// exactly, but for a carried message directly inside a carried message
    /// closed by a delimiter, whose part mail-parser builds and then leaves
    /// out of the tree.
    #[test]
    fn the_walk_agrees_with_the_parse_on_arbitrary_structure() {
        const PIECES: [&str; 26] = [
            "\r\n",
            "\n",
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
            " folded: x\r\n",
            "junk\r\n",
            "-- \r\n",
            "text\r\n",
        ];
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let len = 1 + (next() % 40) as usize;
            let raw: String = (0..len)
                .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                .collect();
            let Some(message) = MessageParser::default().parse(raw.as_bytes()) else {
                continue;
            };
            drop(message);
            let (walked, built) = (walked(raw.as_bytes()), built(raw.as_bytes()));
            assert!(
                walked.parts >= built.parts && walked.fields >= built.fields,
                "{raw:?}: {walked:?} {built:?}"
            );
        }
    }

    #[test]
    fn body_text_never_opens_a_header_block() {
        let log: String = (0..1_100)
            .map(|i| {
                format!(
                    "Nov 10 10:{:02}:00 host sshd[{i}]: Accepted publickey\r\n",
                    i % 60
                )
            })
            .collect();
        let plain = "line without a colon, long enough to add up quickly\r\n".repeat(25_000);
        for body in [
            format!("Cron output follows.\r\n-- \r\n{log}"),
            format!("-- Logs begin at Mon 2026-11-10 09:00:00 UTC. --\r\n{log}"),
            format!("-- \r\n{log}\r\n{log}"),
            format!("-- \r\n{plain}"),
            format!(
                "Here is your weekly digest.\r\n\r\n{}",
                "line\r\n\r\n".repeat(4_100)
            ),
        ] {
            let raw = format!("{HEAD}Content-Type: text/plain\r\n\r\n{body}");
            assert_eq!(
                walked(raw.as_bytes()),
                Counts {
                    parts: 1,
                    fields: 4
                }
            );
        }
    }

    #[test]
    fn a_large_attachment_is_body_whatever_the_message_says() {
        let base64 = format!("{}\r\n", "QUFB".repeat(19)).repeat(15_000);
        for (text, name, content_type) in [
            (
                "Your weekly digest, report attached.",
                "report.pdf",
                "application/pdf",
            ),
            ("Export attached.", "messages.csv", "text/csv"),
        ] {
            let raw = format!(
                "{HEAD}Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\n{text}\r\n--b1\r\nContent-Type: {content_type}; name=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{base64}--b1--\r\n"
            );
            assert_eq!(walked(raw.as_bytes()), built(raw.as_bytes()));
        }
    }

    /// Fields the parse would build where a looser reading of the header
    /// block saw none: each is counted before the parse.
    #[test]
    fn fields_hidden_from_a_line_reading_are_counted() {
        let fields = "a:b\r\n".repeat(2_000);
        let limits = Limits::default();
        for carrier in [
            // mail-parser skips a colon before the name, and white space in it.
            ":Content-Type: message/rfc822",
            "Content - Type: message/rfc822",
            // A line with no colon, then a field indented as if continued.
            "X-Junk\r\n Content-Type: message/rfc822",
        ] {
            let raw = format!(
                "{HEAD}Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n{carrier}\r\n\r\nFrom: x@y.test\r\n{fields}\r\nbody\r\n--b--\r\n"
            );
            assert_eq!(
                count(raw.as_bytes(), &limits),
                Err(ParseError::TooManyHeaders {
                    count: 1_001,
                    max: 1_000
                }),
                "{carrier}"
            );
        }
    }

    #[test]
    fn an_encoded_message_is_decoded_as_the_parser_decodes_it() {
        // mail-parser skips a lone `-` in base64 and restarts the quantum
        // after `=`: the fields after them are parsed, so they count.
        let inner = format!("From: x@y.test\r\n{}\r\nbody\r\n", "a:b\r\n".repeat(2_000));
        let encoded = base64(inner.as_bytes());
        let (head, tail) = encoded.split_at(8);
        for body in [format!("{head}-{tail}"), format!("QQ==\r\n{encoded}")] {
            let raw = format!(
                "{HEAD}Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n{body}\r\n--b--\r\n"
            );
            assert!(
                matches!(
                    count(raw.as_bytes(), &Limits::default()),
                    Err(ParseError::TooManyHeaders { .. })
                ),
                "{body:.40}"
            );
        }
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for k in 0..4 {
                if k <= chunk.len() {
                    out.push(char::from(ALPHABET[((n >> (18 - 6 * k)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
