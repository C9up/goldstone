//! What the HTML has to satisfy before it reaches the sanitizer.
//!
//! html5ever, under ammonia, builds the tree the HTML standard describes,
//! and three of its rules cost more than linear time on hostile markup:
//! every insertion walks the open elements (quadratic in the nesting depth),
//! every text run re-creates the formatting elements a closed ancestor left
//! behind (`<div><b id=1></div>` repeated, then `<p>x` repeated: each `<p>`
//! re-opens every `<b>`), and every node placed before a sibling (foster
//! parenting out of a `<table>`) or moved out of its parent is looked for
//! among its siblings. All three are properties of the tree, not of the
//! markup, so they are measured on the tree: the same parser runs first with
//! a sink that keeps only the shape of the tree, fed a few bytes at a time,
//! and stops at the first feed past a bound — the refusal costs no more than
//! the bound. Over a bound, the HTML is not sanitized at all; the message
//! keeps its text and says why it has no HTML.

use crate::ParseError;
use html5ever::interface::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::tendril::{StrTendril, TendrilSink};
use html5ever::{local_name, ns, parse_fragment, Attribute, ParseOpts, QualName};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::sync::OnceLock;

/// Deeper than this, the HTML is not sanitized. Real mail nests a few dozen
/// levels; the tree builder's cost grows with the square of the depth.
pub const MAX_DEPTH: usize = 1000;

/// Nodes the tree may have per `<` of markup, plus [`NODES_FLOOR`]. A tag
/// makes an element and the text after it a text node; what is left covers
/// the formatting elements a sloppy page legitimately re-opens.
const NODES_PER_TAG: usize = 3;
const NODES_FLOOR: usize = 4096;

/// Steps the measure may take per byte of markup, plus [`STEPS_FLOOR`]: the
/// siblings looked through to place a node before another or take one out
/// of its parent (a stray tag in a table costs a look through the table's
/// siblings, a page full of them the square of its size, in the sanitizer
/// too), and the ancestors walked to measure a depth again after a subtree
/// moved (misnested formatting closed deep in the tree).
const STEPS_PER_BYTE: usize = 16;
const STEPS_FLOOR: usize = 1 << 20;

/// Bytes handed to the measuring parser at a time: the bounds are checked
/// between two feeds, so this bounds how far past them one feed can go.
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
/// allowed (the message's own parts), no URL without a scheme, and unless
/// `remote_content`, no URL a browser would load by itself — a remote image
/// is a read receipt the reader never agreed to send.
///
/// A mail has no base URL in the page that displays it: a relative URL
/// (`/account/delete`, `../admin`, `//host/x`, `?q`, `#top`) would resolve
/// against the application showing the mail, on a path the sender chose, and
/// be requested with the reader's session. The attribute is removed, the
/// element kept.
pub fn sanitize(html: &str, remote_content: bool) -> String {
    static BLOCKING: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    static ALLOWING: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    let builder = if remote_content {
        ALLOWING.get_or_init(|| {
            let mut builder = ammonia::Builder::default();
            builder
                .add_url_schemes(["cid"])
                .url_relative(ammonia::UrlRelative::Deny);
            builder
        })
    } else {
        BLOCKING.get_or_init(|| {
            let mut builder = ammonia::Builder::default();
            builder
                .add_url_schemes(["cid"])
                .url_relative(ammonia::UrlRelative::Deny)
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

/// Whether `html` may be handed to the sanitizer: under `max_bytes`, under
/// [`MAX_DEPTH`], and building a tree of a size in proportion to it.
pub fn check(html: &str, max_bytes: usize) -> Result<(), ParseError> {
    if html.len() > max_bytes {
        return Err(ParseError::HtmlTooLarge {
            size: html.len(),
            max: max_bytes,
        });
    }
    let tags = html.bytes().filter(|&b| b == b'<').count();
    let state = Rc::new(State {
        nodes: Cell::new(0),
        max_nodes: tags
            .saturating_mul(NODES_PER_TAG)
            .saturating_add(NODES_FLOOR),
        steps: Cell::new(0),
        max_steps: html
            .len()
            .saturating_mul(STEPS_PER_BYTE)
            .saturating_add(STEPS_FLOOR),
        shape: Cell::new(0),
        refusal: RefCell::new(None),
    });
    // The context ammonia parses a fragment in: a `<div>`, scripting off.
    let mut parser = parse_fragment(
        Measure {
            document: Node::new(Kind::Other, empty_name(), false),
            state: Rc::clone(&state),
            path: RefCell::new(Vec::new()),
        },
        ParseOpts::default(),
        QualName::new(None, ns!(html), local_name!("div")),
        Vec::new(),
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
        if let Some(refusal) = state.refusal.take() {
            return Err(refusal);
        }
        rest = after;
    }
    parser.finish();
    match state.refusal.take() {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// What the parse has built so far, shared by the sink and [`check`].
struct State {
    nodes: Cell<usize>,
    max_nodes: usize,
    steps: Cell<usize>,
    max_steps: usize,
    /// Changes whenever a node that has children moves: the depths measured
    /// before may no longer hold.
    shape: Cell<u64>,
    refusal: RefCell<Option<ParseError>>,
}

impl State {
    fn refuse(&self, refusal: ParseError) {
        let mut slot = self.refusal.borrow_mut();
        if slot.is_none() {
            *slot = Some(refusal);
        }
    }

    fn add_node(&self) {
        self.nodes.set(self.nodes.get() + 1);
        if self.nodes.get() > self.max_nodes {
            self.refuse(ParseError::HtmlTooComplex {
                max: self.max_nodes,
            });
        }
    }

    fn step(&self, steps: usize) {
        self.steps.set(self.steps.get().saturating_add(steps));
        if self.steps.get() > self.max_steps {
            self.refuse(ParseError::HtmlTooTangled {
                max: self.max_steps,
            });
        }
    }

    fn reshaped(&self) {
        self.shape.set(self.shape.get().wrapping_add(1));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Element,
    Text,
    /// The document, a comment, a template's contents.
    Other,
}

/// The depth a node was measured at, valid while the tree keeps its
/// [`State::shape`]. Never measured yet: no shape.
const UNMEASURED: (usize, Option<u64>) = (0, None);

/// One node of the measured tree: what it is, and where it hangs.
struct Node {
    kind: Kind,
    /// An element's name; empty for any other node.
    name: QualName,
    mathml_annotation_xml_integration_point: bool,
    parent: RefCell<Weak<Node>>,
    children: RefCell<Vec<Rc<Node>>>,
    template_contents: RefCell<Option<Rc<Node>>>,
    depth: Cell<(usize, Option<u64>)>,
}

fn empty_name() -> QualName {
    QualName::new(None, ns!(), local_name!(""))
}

impl Node {
    fn new(kind: Kind, name: QualName, integration_point: bool) -> Rc<Self> {
        Rc::new(Self {
            kind,
            name,
            mathml_annotation_xml_integration_point: integration_point,
            parent: RefCell::new(Weak::new()),
            children: RefCell::new(Vec::new()),
            template_contents: RefCell::new(None),
            depth: Cell::new(UNMEASURED),
        })
    }

    fn parent(&self) -> Option<Rc<Node>> {
        self.parent.borrow().upgrade()
    }

    /// Whether a node hangs under this one whose depth is measured, or may
    /// hold one: anything but text.
    fn holds_nodes(&self) -> bool {
        self.template_contents.borrow().is_some()
            || self
                .children
                .borrow()
                .iter()
                .any(|child| child.kind != Kind::Text)
    }
}

impl Drop for Node {
    // Iterative: a deep tree dropped one level per call would overflow the
    // stack.
    fn drop(&mut self) {
        let mut nodes = std::mem::take(&mut *self.children.borrow_mut());
        nodes.extend(self.template_contents.borrow_mut().take());
        while let Some(node) = nodes.pop() {
            nodes.extend(std::mem::take(&mut *node.children.borrow_mut()));
            nodes.extend(node.template_contents.borrow_mut().take());
        }
    }
}

/// A [`TreeSink`] that keeps the shape of the tree, nothing else. It answers
/// the tree builder's questions (names, identity, template contents,
/// integration points) the way the sanitizer's DOM does, so the parse it
/// drives is the one the sanitizer runs; and it merges adjacent text the way
/// that DOM does, so a run of character references is one node.
struct Measure {
    document: Rc<Node>,
    state: Rc<State>,
    /// The nodes of one depth measure, reused from one measure to the next.
    path: RefCell<Vec<Rc<Node>>>,
}

impl Measure {
    /// The depth of `node` in elements: itself and its ancestors that are
    /// elements, the fragment's root `<html>` included; past
    /// `MAX_DEPTH + 1` the count stops. Measured from the nearest ancestor
    /// whose depth still holds, so a node appended where the tree did not
    /// move costs one step.
    fn depth_of(&self, node: &Rc<Node>) -> usize {
        let shape = Some(self.state.shape.get());
        let cap = MAX_DEPTH + 2;
        let level = |node: &Node| usize::from(node.kind == Kind::Element);
        let mut path = self.path.borrow_mut();
        path.clear();
        let mut elements = 0;
        let mut current = Rc::clone(node);
        let base = loop {
            self.state.step(1);
            let (depth, measured) = current.depth.get();
            if measured == shape {
                break depth;
            }
            match current.parent() {
                None => {
                    let depth = level(&current);
                    current.depth.set((depth, shape));
                    break depth;
                }
                Some(parent) => {
                    elements += level(&current);
                    path.push(current);
                    if elements > cap {
                        path.clear();
                        return elements;
                    }
                    current = parent;
                }
            }
        };
        let mut depth = base;
        while let Some(node) = path.pop() {
            depth += level(&node);
            node.depth.set((depth, shape));
        }
        depth
    }

    fn measure(&self, node: &Rc<Node>) {
        // The fragment's root `<html>` is the first element: the elements
        // of the HTML start at depth 2.
        if node.kind == Kind::Element && self.depth_of(node) > MAX_DEPTH + 1 {
            self.state
                .refuse(ParseError::HtmlTooDeep { max: MAX_DEPTH });
        }
    }

    /// Take `node` out of its parent, looking for it among its siblings.
    fn detach(&self, node: &Rc<Node>) {
        if let Some(parent) = node.parent() {
            let mut children = parent.children.borrow_mut();
            let at = children.iter().position(|child| Rc::ptr_eq(child, node));
            self.state.step(at.map_or(children.len(), |at| at + 1));
            if let Some(at) = at {
                children.remove(at);
            }
        }
        *node.parent.borrow_mut() = Weak::new();
    }

    /// Hang `child` under `parent`, at `index` or last, and measure it.
    fn attach(&self, parent: &Rc<Node>, child: NodeOrText<Rc<Node>>, index: Option<usize>) {
        let node = match child {
            NodeOrText::AppendText(_) => {
                let before = {
                    let children = parent.children.borrow();
                    match index {
                        Some(at) => at.checked_sub(1).and_then(|at| children.get(at).cloned()),
                        None => children.last().cloned(),
                    }
                };
                if before.is_some_and(|node| node.kind == Kind::Text) {
                    // The text joins the text node before it.
                    return;
                }
                self.state.add_node();
                Node::new(Kind::Text, empty_name(), false)
            }
            NodeOrText::AppendNode(node) => {
                self.detach(&node);
                if node.holds_nodes() {
                    // Its subtree moves with it: every depth measured may
                    // have changed. Text has no depth to keep.
                    self.state.reshaped();
                } else {
                    node.depth.set(UNMEASURED);
                }
                node
            }
        };
        *node.parent.borrow_mut() = Rc::downgrade(parent);
        {
            let mut children = parent.children.borrow_mut();
            match index {
                Some(at) if at <= children.len() => children.insert(at, Rc::clone(&node)),
                _ => children.push(Rc::clone(&node)),
            }
        }
        self.measure(&node);
    }

    fn contents_of(&self, template: &Rc<Node>) -> Rc<Node> {
        if let Some(contents) = template.template_contents.borrow().as_ref() {
            return Rc::clone(contents);
        }
        // The contents serialize inside the template: they hang under it.
        self.state.add_node();
        let contents = Node::new(Kind::Other, empty_name(), false);
        *contents.parent.borrow_mut() = Rc::downgrade(template);
        *template.template_contents.borrow_mut() = Some(Rc::clone(&contents));
        contents
    }
}

impl TreeSink for Measure {
    type Handle = Rc<Node>;
    type Output = ();
    type ElemName<'a> = &'a QualName;

    fn finish(self) {}

    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn get_document(&self) -> Rc<Node> {
        Rc::clone(&self.document)
    }

    fn elem_name<'a>(&'a self, target: &'a Rc<Node>) -> &'a QualName {
        &target.name
    }

    fn create_element(
        &self,
        name: QualName,
        _attrs: Vec<Attribute>,
        flags: ElementFlags,
    ) -> Rc<Node> {
        self.state.add_node();
        let node = Node::new(
            Kind::Element,
            name,
            flags.mathml_annotation_xml_integration_point,
        );
        if flags.template {
            self.contents_of(&node);
        }
        node
    }

    fn create_comment(&self, _text: StrTendril) -> Rc<Node> {
        self.state.add_node();
        Node::new(Kind::Other, empty_name(), false)
    }

    fn create_pi(&self, _target: StrTendril, _data: StrTendril) -> Rc<Node> {
        self.state.add_node();
        Node::new(Kind::Other, empty_name(), false)
    }

    fn append(&self, parent: &Rc<Node>, child: NodeOrText<Rc<Node>>) {
        self.attach(parent, child, None);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Rc<Node>,
        prev_element: &Rc<Node>,
        child: NodeOrText<Rc<Node>>,
    ) {
        if element.parent().is_some() {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
    }

    fn get_template_contents(&self, target: &Rc<Node>) -> Rc<Node> {
        self.contents_of(target)
    }

    fn same_node(&self, x: &Rc<Node>, y: &Rc<Node>) -> bool {
        Rc::ptr_eq(x, y)
    }

    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn append_before_sibling(&self, sibling: &Rc<Node>, new_node: NodeOrText<Rc<Node>>) {
        // The tree builder only places a node before one that has a parent.
        let Some(parent) = sibling.parent() else {
            return;
        };
        if let NodeOrText::AppendNode(ref node) = new_node {
            self.detach(node);
        }
        let index = {
            let children = parent.children.borrow();
            let at = children.iter().position(|child| Rc::ptr_eq(child, sibling));
            self.state.step(at.map_or(children.len(), |at| at + 1));
            at
        };
        self.attach(&parent, new_node, index);
    }

    fn add_attrs_if_missing(&self, _target: &Rc<Node>, _attrs: Vec<Attribute>) {}

    fn remove_from_parent(&self, target: &Rc<Node>) {
        self.detach(target);
        if target.holds_nodes() {
            self.state.reshaped();
        }
    }

    fn reparent_children(&self, node: &Rc<Node>, new_parent: &Rc<Node>) {
        let moved = std::mem::take(&mut *node.children.borrow_mut());
        if moved.is_empty() {
            return;
        }
        self.state.step(moved.len());
        let reshaped = moved.iter().any(|child| child.kind != Kind::Text);
        for child in &moved {
            *child.parent.borrow_mut() = Rc::downgrade(new_parent);
        }
        new_parent.children.borrow_mut().extend(moved);
        if reshaped {
            self.state.reshaped();
        }
        // The children now hang one level under `new_parent`: measuring one
        // element among them measures them all.
        let element = new_parent
            .children
            .borrow()
            .iter()
            .rev()
            .find(|child| child.kind == Kind::Element)
            .cloned();
        if let Some(child) = element {
            self.measure(&child);
        }
    }

    fn is_mathml_annotation_xml_integration_point(&self, handle: &Rc<Node>) -> bool {
        handle.mathml_annotation_xml_integration_point
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const MAX_BYTES: usize = 512 * 1024;

    fn divs(n: usize) -> String {
        "<div>".repeat(n)
    }

    /// `shape` grown to `bytes` by repeating its body after its prefix.
    fn grown(prefix: &str, body: &str, bytes: usize) -> String {
        let mut html = String::from(prefix);
        while html.len() + body.len() <= bytes {
            html.push_str(body);
        }
        html
    }

    #[test]
    fn depth_is_counted_in_elements_under_the_fragment() {
        assert_eq!(check(&format!("{}x", divs(MAX_DEPTH)), MAX_BYTES), Ok(()));
        // A template's contents are no element: they add no level.
        assert_eq!(
            check(&format!("{}x", "<template>".repeat(MAX_DEPTH)), MAX_BYTES),
            Ok(())
        );
        assert_eq!(
            check(&format!("{}x", divs(MAX_DEPTH + 1)), MAX_BYTES),
            Err(ParseError::HtmlTooDeep { max: MAX_DEPTH })
        );
    }

    /// Markup a reading of the bytes takes for something else than the tree
    /// builder does: the depth is the tree's.
    #[test]
    fn depth_is_measured_on_the_tree_the_parser_builds() {
        let deep = divs(MAX_DEPTH + 1);
        let shapes = [
            // Empty comments: complete for the tokenizer.
            format!("<!-->{deep}x"),
            format!("<!--->{deep}x"),
            // `<!--` is text inside RCDATA and RAWTEXT elements.
            format!("<textarea><!--</textarea>{deep}x"),
            format!("<title><!--</title>{deep}x"),
            format!("<style><!--</style>{deep}x"),
            // `</b>` over open blocks: the adoption agency keeps them open.
            format!("{}x", format!("<b>{}</b>", divs(900)).repeat(9)),
            // A template's contents hang under it.
            format!("{}x", "<template>".repeat(MAX_DEPTH + 1)),
            format!("{}x", "<template><div>".repeat(MAX_DEPTH / 2 + 1)),
        ];
        for html in &shapes {
            assert_eq!(
                check(html, MAX_BYTES),
                Err(ParseError::HtmlTooDeep { max: MAX_DEPTH }),
                "{:.40}",
                html
            );
        }
    }

    #[test]
    fn a_refusal_costs_no_more_than_the_bound() {
        // Each shape at the largest size the limits accept: the parse stops
        // at the first feed past the bound, wherever the rest of the bytes go.
        let shapes = [
            grown("<!-->", "<div>", MAX_BYTES),
            grown("<textarea><!--</textarea>", "<div>", MAX_BYTES),
            grown("", &format!("<b>{}</b>", divs(900)), MAX_BYTES),
            grown("<table>", "<br>", MAX_BYTES),
            grown(&divs(990), "<b><div><i></i></b></div>", MAX_BYTES),
        ];
        for html in &shapes {
            let started = Instant::now();
            assert!(check(html, MAX_BYTES).is_err(), "{:.40}", html);
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{:.40}: {:?}",
                html,
                started.elapsed()
            );
        }
    }

    #[test]
    fn adjacent_text_is_one_node() {
        // The tokenizer hands over each character reference on its own.
        assert_eq!(check(&"&nbsp;".repeat(5_000), MAX_BYTES), Ok(()));
        assert_eq!(
            check(
                &format!("<p>{}</p>", "&nbsp;".repeat(20)).repeat(500),
                MAX_BYTES
            ),
            Ok(())
        );
        assert_eq!(
            check(&format!("<table>{}", "&amp;x".repeat(5_000)), MAX_BYTES),
            Ok(())
        );
    }

    #[test]
    fn the_node_budget_still_refuses_a_tree_out_of_proportion() {
        let mut html: String = (0..2_000)
            .map(|i| format!("<div><b id={i}></div>"))
            .collect();
        html.push_str(&"<p>x".repeat(2_000));
        assert!(matches!(
            check(&html, MAX_BYTES),
            Err(ParseError::HtmlTooComplex { .. })
        ));
    }

    #[test]
    fn stray_tags_in_a_table_are_bounded_by_the_siblings_they_cost() {
        // Each `<br>` is placed before the table, looked for among the
        // siblings of all the ones before it.
        assert_eq!(
            check(&format!("<table>{}", "<br>".repeat(8_000)), MAX_BYTES).map_err(|e| e.code()),
            Err("E_GOLDSTONE_HTML_TOO_COMPLEX")
        );
        assert!(matches!(
            check(&format!("<table>{}", "<br>".repeat(8_000)), MAX_BYTES),
            Err(ParseError::HtmlTooTangled { .. })
        ));
        // A few stray tags, as broken tables have, are fine.
        assert_eq!(
            check(
                &format!(
                    "{}<table><tr><td>a{}</table>",
                    "<p>x</p>".repeat(200),
                    "<br>".repeat(200)
                ),
                MAX_BYTES
            ),
            Ok(())
        );
    }

    #[test]
    fn subtrees_moved_deep_in_the_tree_are_bounded_by_the_walks_they_cost() {
        // Each `</b>` moves a block that holds a node: the depths under it
        // are measured again, a walk of a thousand ancestors each time.
        let html = format!("{}{}", divs(990), "<b><div><i></i></b></div>".repeat(3_000));
        assert!(matches!(
            check(&html, MAX_BYTES),
            Err(ParseError::HtmlTooTangled { .. })
        ));
        // The same misnesting near the top of the tree costs a few steps.
        let html = format!("{}{}", divs(20), "<b><div><i></i></b></div>".repeat(3_000));
        assert_eq!(check(&html, MAX_BYTES), Ok(()));
        // Deep, a block that holds only text moves with nothing to measure.
        let html = format!("{}{}", divs(990), "<b><div>x</b></div>".repeat(3_000));
        assert_eq!(check(&html, MAX_BYTES), Ok(()));
    }

    #[test]
    fn ordinary_sloppy_html_passes() {
        let mut html = String::from("<font face=Arial><table><tr><td>");
        for i in 0..40 {
            html.push_str(&format!("<div><table><tr><td><b>cell {i}<i>x</b></i>"));
        }
        for i in 0..500 {
            html.push_str(&format!(
                "<p><font color=red>para {i}<li>item<td>cell&nbsp;&amp;"
            ));
        }
        html.push_str(
            "<template><p>t</p></template><svg><foreignObject><p>f</p></foreignObject></svg>",
        );
        html.push_str("<math><annotation-xml encoding=text/html><p>m</p></annotation-xml></math>");
        assert_eq!(check(&html, MAX_BYTES), Ok(()));
    }

    #[test]
    fn the_size_is_checked_before_parsing() {
        assert_eq!(
            check(&"<p>x".repeat(100), 10),
            Err(ParseError::HtmlTooLarge { size: 400, max: 10 })
        );
    }
}
