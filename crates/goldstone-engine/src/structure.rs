//! Bounds on a message's structure, checked before it is parsed.
//!
//! mail-parser builds every part and every header it finds, and a part or a
//! header can cost a few bytes of input and a hundred of memory: 20 MB of
//! empty parts or of `a:b` lines is a gigabyte once parsed. Counting them
//! after the parse refuses the message once the memory is spent. So one
//! linear pass over the bytes bounds them first, from above: every part
//! begins after a line holding `--` (the delimiter, which mail-parser finds
//! anywhere on a line), every header field is a line holding `:`, and a
//! `message/*` part (or any part of a digest) is followed by the header
//! block of the message it carries. A message/* body encoded in base64 or
//! quoted-printable is decoded and scanned the same way, as mail-parser
//! parses it, at most three levels down.
//!
//! The pass errs towards counting too much: a body line holding `--` opens a
//! header block it does not really start. The bounds are set well above what
//! real mail reaches, and the exact counts are checked after the parse.

use crate::{Limits, ParseError};

/// mail-parser parses an encoded message/* part this many levels down.
const ENCODED_LEVELS: usize = 3;

/// Encoded message/* bodies decoded, at most. A quoted-printable one is
/// decoded to the end of the message, the delimiter being unknown here.
const MAX_ENCODED: usize = 8;

/// Header blocks per allowed part: a body line holding `--` counts as one.
const BLOCKS_PER_PART: usize = 4;

/// Header fields per allowed part, on top of `max_headers` for the message's
/// own header.
const FIELDS_PER_PART: usize = 16;

struct Budget {
    blocks: usize,
    fields: usize,
    encoded: usize,
    max_blocks: usize,
    max_fields: usize,
}

enum Encoding {
    Base64,
    QuotedPrintable,
}

/// The two fields of a header block that change how its body is read.
#[derive(Clone, Copy)]
enum Field {
    ContentType,
    TransferEncoding,
}

pub fn prescan(raw: &[u8], limits: &Limits) -> Result<(), ParseError> {
    let mut budget = Budget {
        blocks: 0,
        fields: 0,
        encoded: 0,
        max_blocks: limits.max_parts.saturating_mul(BLOCKS_PER_PART),
        max_fields: limits
            .max_parts
            .saturating_mul(FIELDS_PER_PART)
            .saturating_add(limits.max_headers),
    };
    scan(raw, limits, &mut budget, 0)
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The header field a line starts, by name, when it is one.
fn field_name(line: &[u8]) -> Option<&[u8]> {
    if line.first().is_some_and(|c| *c == b' ' || *c == b'\t') {
        return None;
    }
    let colon = line.iter().position(|c| *c == b':')?;
    Some(line[..colon].trim_ascii())
}

fn scan(
    bytes: &[u8],
    limits: &Limits,
    budget: &mut Budget,
    level: usize,
) -> Result<(), ParseError> {
    let digest = contains_ci(bytes, b"digest");
    let mut header = true;
    let mut block_fields = 0usize;
    let mut block_bytes = 0usize;
    let mut carries_message = false;
    let mut encoding: Option<Encoding> = None;
    // The field a continuation line belongs to, when it is one that matters.
    let mut current: Option<Field> = None;
    open_block(budget)?;

    let mut start = 0;
    while start < bytes.len() {
        let end = bytes[start..]
            .iter()
            .position(|c| *c == b'\n')
            .map_or(bytes.len(), |at| start + at + 1);
        let line = &bytes[start..end];
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if header {
            if content.is_empty() {
                // A message/* body holds a header block of its own, unless
                // it is encoded: then it is decoded and scanned apart, and
                // its bytes here are only the encoding.
                header = false;
                if carries_message || digest {
                    match encoding.take() {
                        Some(encoded) => {
                            scan_encoded(&bytes[end..], &encoded, limits, budget, level)?
                        }
                        None => {
                            header = true;
                            open_block(budget)?;
                        }
                    }
                }
                block_fields = 0;
                block_bytes = 0;
                carries_message = false;
                encoding = None;
                current = None;
            } else {
                block_bytes += line.len();
                if block_bytes > limits.max_header_bytes {
                    return Err(ParseError::HeadersTooLarge {
                        size: block_bytes,
                        max: limits.max_header_bytes,
                    });
                }
                if let Some(name) = field_name(content) {
                    block_fields += 1;
                    budget.fields += 1;
                    if block_fields > limits.max_headers {
                        return Err(ParseError::TooManyHeaders {
                            count: block_fields,
                            max: limits.max_headers,
                        });
                    }
                    if budget.fields > budget.max_fields {
                        return Err(ParseError::TooManyHeaderFields {
                            count: budget.fields,
                            max: budget.max_fields,
                        });
                    }
                    current = if name.eq_ignore_ascii_case(b"content-type") {
                        Some(Field::ContentType)
                    } else if name.eq_ignore_ascii_case(b"content-transfer-encoding") {
                        Some(Field::TransferEncoding)
                    } else {
                        None
                    };
                }
                match current {
                    Some(Field::ContentType) if contains_ci(content, b"message") => {
                        carries_message = true
                    }
                    Some(Field::TransferEncoding) if contains_ci(content, b"base64") => {
                        encoding = Some(Encoding::Base64)
                    }
                    Some(Field::TransferEncoding) if contains_ci(content, b"quoted-printable") => {
                        encoding = Some(Encoding::QuotedPrintable)
                    }
                    _ => {}
                }
                // A delimiter can sit on a header line too: the part after
                // it starts a block of its own.
                if contains(content, b"--") {
                    open_block(budget)?;
                }
            }
        } else if contains(content, b"--") {
            header = true;
            open_block(budget)?;
        }
        start = end;
    }
    Ok(())
}

fn open_block(budget: &mut Budget) -> Result<(), ParseError> {
    budget.blocks += 1;
    if budget.blocks > budget.max_blocks {
        return Err(ParseError::TooManyBoundaries {
            count: budget.blocks,
            max: budget.max_blocks,
        });
    }
    Ok(())
}

/// The body of an encoded message/* part, decoded as mail-parser decodes it
/// before parsing it, then scanned as a message. Base64 never holds `-`, so
/// its body ends at the first line that does; quoted-printable can, and is
/// decoded to the end of the bytes.
fn scan_encoded(
    body: &[u8],
    encoding: &Encoding,
    limits: &Limits,
    budget: &mut Budget,
    level: usize,
) -> Result<(), ParseError> {
    if level >= ENCODED_LEVELS {
        return Ok(());
    }
    budget.encoded += 1;
    if budget.encoded > MAX_ENCODED {
        return Err(ParseError::TooManyEncodedMessages { max: MAX_ENCODED });
    }
    let decoded = match encoding {
        Encoding::Base64 => {
            let end = body.iter().position(|c| *c == b'-').unwrap_or(body.len());
            base64(&body[..end])
        }
        Encoding::QuotedPrintable => quoted_printable(body),
    };
    scan(&decoded, limits, budget, level + 1)
}

/// Lenient, as mail-parser is: anything outside the alphabet is skipped.
fn base64(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in input {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn quoted_printable(input: &[u8]) -> Vec<u8> {
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'=' => match (input.get(i + 1), input.get(i + 2)) {
                (Some(b'\r'), Some(b'\n')) => i += 3,
                (Some(b'\n'), _) => i += 2,
                (Some(&h), Some(&l)) => match (hex(h), hex(l)) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b'=');
                        i += 1;
                    }
                },
                _ => {
                    out.push(b'=');
                    i += 1;
                }
            },
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}
