//! What the HTML has to satisfy before it reaches the sanitizer.
//!
//! html5ever, under ammonia, builds the tree the HTML standard describes,
//! and two of its rules cost more than linear time on hostile markup: every
//! insertion walks the open elements (quadratic in the nesting depth), and
//! every text run re-creates the formatting elements a closed ancestor left
//! behind (`<div><b id=1></div>` repeated, then `<p>x` repeated: each `<p>`
//! re-opens every `<b>`). The second one is a property of the tree, not of
//! the markup, so it is measured on the tree: the same parser runs first
//! with a sink that only counts the nodes it would build, fed a few bytes at
//! a time, and stops past a budget proportional to the markup. Over a bound,
//! the HTML is not sanitized at all; the message keeps its text and says
//! why it has no HTML.

use crate::ParseError;
use html5ever::interface::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::{local_name, ns, parse_fragment, Attribute, ParseOpts, QualName};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::OnceLock;

/// Deeper than this, the HTML is not sanitized. Real mail nests a few dozen
/// levels; the tree builder's cost grows with the square of the depth.
pub const MAX_DEPTH: usize = 1000;

/// Nodes the tree may have per `<` of markup, plus [`NODES_FLOOR`]. A tag
/// makes an element and the text after it a text node; what is left covers
/// the formatting elements a sloppy page legitimately re-opens.
const NODES_PER_TAG: usize = 3;
const NODES_FLOOR: usize = 4096;

/// Bytes handed to the counting parser at a time: the budget is checked
/// between two feeds, so this bounds how far past it one feed can go.
const FEED: usize = 64;

/// Attributes whose URL a browser loads on its own, without a click.
const FETCHED: [&str; 11] = [
    "src",
    "srcset",
    "background",
    "poster",
    "lowsrc",
    "dynsrc",
    "data",
    "longdesc",
    "action",
    "formaction",
    "xlink:href",
];

/// Sanitize HTML that passed [`check`]: ammonia's defaults, `cid:` URLs
/// allowed (the message's own parts), and unless `remote_content`, no URL a
/// browser would load by itself — a remote image is a read receipt the
/// reader never agreed to send.
pub fn sanitize(html: &str, remote_content: bool) -> String {
    static BLOCKING: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    static ALLOWING: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    let builder = if remote_content {
        ALLOWING.get_or_init(|| {
            let mut builder = ammonia::Builder::default();
            builder.add_url_schemes(["cid"]);
            builder
        })
    } else {
        BLOCKING.get_or_init(|| {
            let mut builder = ammonia::Builder::default();
            builder
                .add_url_schemes(["cid"])
                .attribute_filter(|_, attribute, value| {
                    let own_part = value
                        .trim_start()
                        .get(..4)
                        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("cid:"));
                    if FETCHED.contains(&attribute) && !own_part {
                        None
                    } else {
                        Some(value.into())
                    }
                });
            builder
        })
    };
    builder.clean(html).to_string()
}

/// Elements that never hold content: a start tag does not open a level.
const VOID: [&[u8]; 14] = [
    b"area", b"base", b"br", b"col", b"embed", b"hr", b"img", b"input", b"link", b"meta", b"param",
    b"source", b"track", b"wbr",
];

/// Closed implicitly when a sibling opens (li after li, td after td): an
/// unclosed run of them does not nest.
const IMPLIED_END: [&[u8]; 14] = [
    b"p",
    b"li",
    b"dt",
    b"dd",
    b"option",
    b"optgroup",
    b"tr",
    b"td",
    b"th",
    b"thead",
    b"tbody",
    b"tfoot",
    b"rt",
    b"rp",
];

fn is_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b':' | b'_')
}

fn find(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| from + at)
}

fn find_byte(haystack: &[u8], from: usize, byte: u8) -> Option<usize> {
    haystack
        .get(from..)?
        .iter()
        .position(|&c| c == byte)
        .map(|at| from + at)
}

/// Whether `html` may be handed to the sanitizer: under `max_bytes`, under
/// [`MAX_DEPTH`], and building a tree of a size in proportion to it.
pub fn check(html: &str, max_bytes: usize) -> Result<(), ParseError> {
    if html.len() > max_bytes {
        return Err(ParseError::HtmlTooLarge {
            size: html.len(),
            max: max_bytes,
        });
    }
    check_depth(html)?;
    let tags = html.bytes().filter(|&b| b == b'<').count();
    let budget = tags
        .saturating_mul(NODES_PER_TAG)
        .saturating_add(NODES_FLOOR);
    if nodes_within(html, budget) {
        Ok(())
    } else {
        Err(ParseError::HtmlTooComplex { max: budget })
    }
}

/// The nesting depth, in one linear pass that follows what the tree builder
/// does closely enough to bound it: a start tag opens an element, an end tag
/// closes down to the nearest open element of its name and is ignored
/// otherwise, comments are skipped.
fn check_depth(html: &str) -> Result<(), ParseError> {
    let bytes = html.as_bytes();
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut open: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut next = find_byte(bytes, 0, b'<');
    while let Some(at) = next {
        let mut pos = at + 1;
        if bytes.get(pos..pos + 3) == Some(b"!--") {
            next = find(bytes, pos + 3, b"-->").and_then(|end| find_byte(bytes, end + 3, b'<'));
            continue;
        }
        let closing = bytes.get(pos) == Some(&b'/');
        if closing {
            pos += 1;
        }
        let name_start = pos;
        while bytes.get(pos).copied().is_some_and(is_name_char) {
            pos += 1;
        }
        if pos == name_start {
            // Not a tag: "<" is text here.
            next = find_byte(bytes, pos, b'<');
            continue;
        }
        let Some(end) = find_byte(bytes, pos, b'>') else {
            break;
        };
        let name = bytes[name_start..pos].to_ascii_lowercase();
        let named = |list: &[&[u8]]| list.contains(&name.as_slice());

        if !named(&VOID) && !named(&IMPLIED_END) {
            if !closing {
                *open.entry(name.clone()).or_default() += 1;
                stack.push(name.clone());
                if stack.len() > MAX_DEPTH {
                    return Err(ParseError::HtmlTooDeep { max: MAX_DEPTH });
                }
            } else if open.get(&name).is_some_and(|&n| n > 0) {
                while let Some(popped) = stack.pop() {
                    if let Some(n) = open.get_mut(&popped) {
                        *n -= 1;
                    }
                    if popped == name {
                        break;
                    }
                }
            }
        }

        next = find_byte(bytes, end + 1, b'<');
    }
    Ok(())
}

/// Whether parsing `html` as the sanitizer does builds at most `budget`
/// nodes. Nothing is kept but each open element's name.
fn nodes_within(html: &str, budget: usize) -> bool {
    let nodes = Rc::new(Cell::new(0usize));
    let mut parser = parse_fragment(
        Counter {
            nodes: Rc::clone(&nodes),
            document: Rc::new(QualName::new(None, ns!(), local_name!(""))),
        },
        ParseOpts::default(),
        QualName::new(None, ns!(html), local_name!("div")),
        vec![],
        false,
    );
    let mut rest = html;
    while !rest.is_empty() {
        let mut cut = FEED.min(rest.len());
        while !rest.is_char_boundary(cut) {
            cut += 1;
        }
        let (feed, after) = rest.split_at(cut);
        parser.process(StrTendril::from_slice(feed));
        if nodes.get() > budget {
            return false;
        }
        rest = after;
    }
    parser.finish() <= budget
}

/// A tree sink that builds nothing: it counts the nodes and keeps the name
/// of each element only as long as the parser holds it.
struct Counter {
    nodes: Rc<Cell<usize>>,
    document: Rc<QualName>,
}

impl Counter {
    fn node(&self, name: QualName) -> Rc<QualName> {
        self.nodes.set(self.nodes.get() + 1);
        Rc::new(name)
    }

    fn anonymous(&self) -> Rc<QualName> {
        self.node(QualName::new(None, ns!(), local_name!("")))
    }
}

impl TreeSink for Counter {
    type Handle = Rc<QualName>;
    type Output = usize;
    type ElemName<'a> = &'a QualName;

    fn finish(self) -> usize {
        self.nodes.get()
    }

    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> Rc<QualName> {
        Rc::clone(&self.document)
    }

    fn elem_name<'a>(&'a self, target: &'a Rc<QualName>) -> &'a QualName {
        target
    }

    fn create_element(
        &self,
        name: QualName,
        _attrs: Vec<Attribute>,
        _flags: ElementFlags,
    ) -> Rc<QualName> {
        self.node(name)
    }

    fn create_comment(&self, _text: StrTendril) -> Rc<QualName> {
        self.anonymous()
    }

    fn create_pi(&self, _target: StrTendril, _data: StrTendril) -> Rc<QualName> {
        self.anonymous()
    }

    fn append(&self, _parent: &Rc<QualName>, child: NodeOrText<Rc<QualName>>) {
        if let NodeOrText::AppendText(_) = child {
            self.nodes.set(self.nodes.get() + 1);
        }
    }

    fn append_based_on_parent_node(
        &self,
        element: &Rc<QualName>,
        _prev_element: &Rc<QualName>,
        child: NodeOrText<Rc<QualName>>,
    ) {
        self.append(element, child);
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
    }

    fn get_template_contents(&self, _target: &Rc<QualName>) -> Rc<QualName> {
        self.anonymous()
    }

    fn same_node(&self, x: &Rc<QualName>, y: &Rc<QualName>) -> bool {
        Rc::ptr_eq(x, y)
    }

    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &Rc<QualName>, new_node: NodeOrText<Rc<QualName>>) {
        self.append(sibling, new_node);
    }

    fn add_attrs_if_missing(&self, _target: &Rc<QualName>, _attrs: Vec<Attribute>) {}

    fn remove_from_parent(&self, _target: &Rc<QualName>) {}

    fn reparent_children(&self, _node: &Rc<QualName>, _new_parent: &Rc<QualName>) {}
}
