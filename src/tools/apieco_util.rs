//! Shared helpers for the API & ecosystem tools: the public-API surface walker
//! (used by `pubdeps` and `docscov`), target selection for local packages and
//! published crates, and small statistics helpers.
//!
//! The walker builds a model of a library crate from its source with the
//! project's own lexer (no compilation): the module tree (`mod x;` resolved to
//! `x.rs`, `x/mod.rs` or `#[path]`, inline `mod x { }`), every item with its
//! visibility, outer docs and attributes, `use` imports per module, impl blocks,
//! and reachability (an item is public API when it is `pub` and every enclosing
//! module is `pub`, or when a reachable module re-exports it with `pub use`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::cli::Args;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata};
use crate::registry::CrateSpec;
use crate::rustsrc::{self, Kind, Token, items};
use crate::tools::unsafe_hotspots::{matching_angle, split_top};
use crate::util;

// ------------------------------------------------------------------ model

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vis {
    Pub,
    /// `pub(crate)`, `pub(super)`, `pub(in path)`, `pub(self)`.
    Restricted,
    Private,
}

/// Documentation attached to an item.
#[derive(Debug, Clone, Default)]
pub struct Docs {
    /// Any doc comment or `#[doc = ...]`.
    pub present: bool,
    /// Concatenated doc text (Markdown).
    pub text: String,
    /// Line where the docs start.
    pub line: usize,
    /// Docs come (partly) from a non-literal source such as `include_str!` that could not be read.
    pub external: bool,
    /// `#[doc(hidden)]`.
    pub hidden: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemKind {
    Fn,
    Method,
    Struct,
    Enum,
    Union,
    Trait,
    TraitMethod,
    AssocType,
    AssocConst,
    TypeAlias,
    Const,
    Static,
    Mod,
    Macro,
    Field,
    Variant,
}

impl ItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ItemKind::Fn => "fn",
            ItemKind::Method => "method",
            ItemKind::Struct => "struct",
            ItemKind::Enum => "enum",
            ItemKind::Union => "union",
            ItemKind::Trait => "trait",
            ItemKind::TraitMethod => "trait method",
            ItemKind::AssocType => "assoc type",
            ItemKind::AssocConst => "assoc const",
            ItemKind::TypeAlias => "type",
            ItemKind::Const => "const",
            ItemKind::Static => "static",
            ItemKind::Mod => "mod",
            ItemKind::Macro => "macro",
            ItemKind::Field => "field",
            ItemKind::Variant => "variant",
        }
    }
    pub fn is_fn(&self) -> bool {
        matches!(self, ItemKind::Fn | ItemKind::Method | ItemKind::TraitMethod)
    }
    pub fn is_type(&self) -> bool {
        matches!(self, ItemKind::Struct | ItemKind::Enum | ItemKind::Union | ItemKind::TypeAlias)
    }
}

/// A token slice of an item that can mention other crates' types.
#[derive(Debug, Clone)]
pub struct Site {
    /// `signature`, `field`, `bound`, `type`.
    pub kind: &'static str,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone)]
pub struct Item {
    pub kind: ItemKind,
    pub name: String,
    /// Owning type or trait for methods, fields, variants and trait items.
    pub parent: Option<String>,
    pub module: usize,
    pub file: usize,
    pub line: usize,
    pub vis: Vis,
    pub reachable: bool,
    pub docs: Docs,
    pub is_unsafe: bool,
    pub returns_result: bool,
    /// Direct panic sites in the body: (line, what).
    pub panics: Vec<(usize, String)>,
    pub sites: Vec<Site>,
}

impl Item {
    /// `Type::method`, `Type.field`, `name`.
    pub fn display(&self) -> String {
        match (&self.parent, self.kind) {
            (Some(p), ItemKind::Field) => format!("{p}.{}", self.name),
            (Some(p), _) => format!("{p}::{}", self.name),
            (None, _) => self.name.clone(),
        }
    }
}

/// One name brought into scope by `use` or `extern crate`.
#[derive(Debug, Clone)]
pub struct UseEntry {
    /// Local name (`*` for globs, `_` for anonymous imports).
    pub alias: String,
    pub path: Vec<String>,
    pub glob: bool,
    pub vis: Vis,
    pub line: usize,
    pub file: usize,
    /// `extern crate` rather than `use`.
    pub extern_crate: bool,
}

#[derive(Debug, Clone)]
pub struct Module {
    /// `crate`, `crate::a::b`.
    pub path: String,
    pub name: String,
    pub parent: Option<usize>,
    pub vis: Vis,
    /// Reachable from outside the crate.
    pub reachable: bool,
    pub uses: Vec<UseEntry>,
    pub children: BTreeMap<String, usize>,
    /// Names of items defined directly in the module.
    pub defined: BTreeSet<String>,
    pub file: usize,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct ImplInfo {
    pub module: usize,
    pub file: usize,
    pub line: usize,
    /// Trait path tokens for `impl Trait for Type`.
    pub trait_toks: Option<Vec<Token>>,
    pub self_toks: Vec<Token>,
    /// Generic parameters and where clause tokens.
    pub bounds: Vec<Token>,
    pub negative: bool,
}

impl ImplInfo {
    pub fn header(&self) -> String {
        match &self.trait_toks {
            Some(t) => format!("impl {}{} for {}", if self.negative { "!" } else { "" }, items::join(t), items::join(&self.self_toks)),
            None => format!("impl {}", items::join(&self.self_toks)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SrcFile {
    pub path: PathBuf,
    pub rel: String,
    pub code: Vec<Token>,
    /// Doc comments: (byte offset, line, is outer, text without the comment markers).
    pub docs: Vec<(usize, usize, bool, String)>,
}

/// The modelled library crate.
#[derive(Debug, Clone, Default)]
pub struct Surface {
    pub root: PathBuf,
    pub files: Vec<SrcFile>,
    pub modules: Vec<Module>,
    pub items: Vec<Item>,
    pub impls: Vec<ImplInfo>,
    /// Files named by `mod x;` that could not be found.
    pub missing_modules: Vec<String>,
    /// Inner docs of the crate root (`//!`, `#![doc = ...]`).
    pub crate_docs: Docs,
    /// Extern crate names to treat as dependencies (for path resolution).
    pub dep_names: BTreeSet<String>,
}

// ------------------------------------------------------------------ building

struct Raw {
    kw: &'static str,
    name: String,
    vis: Vis,
    attrs: Vec<String>,
    docs: Docs,
    line: usize,
    kw_idx: usize,
    end: usize,
    body: Option<(usize, usize)>,
    is_unsafe: bool,
}

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "yield",
];

fn doc_strip(t: &Token) -> Option<(bool, String)> {
    if !t.doc {
        return None;
    }
    let s = t.text.as_str();
    if let Some(r) = s.strip_prefix("///") {
        return Some((true, r.strip_prefix(' ').unwrap_or(r).to_string()));
    }
    if let Some(r) = s.strip_prefix("//!") {
        return Some((false, r.strip_prefix(' ').unwrap_or(r).to_string()));
    }
    let (outer, inner) = if let Some(r) = s.strip_prefix("/**") {
        (true, r)
    } else if let Some(r) = s.strip_prefix("/*!") {
        (false, r)
    } else {
        return None;
    };
    let inner = inner.strip_suffix("*/").unwrap_or(inner);
    let lines: Vec<String> = inner
        .lines()
        .map(|l| {
            let t = l.trim_start();
            let t = t.strip_prefix("* ").or_else(|| t.strip_prefix('*')).unwrap_or(t);
            t.to_string()
        })
        .collect();
    Some((outer, lines.join("\n").trim().to_string()))
}

/// Unescape a Rust string literal token (`"..."` or `r#"..."#`); `None` for other tokens.
pub fn str_literal(t: &str) -> Option<String> {
    let t = t.trim();
    if let Some(r) = t.strip_prefix('r') {
        let hashes = r.chars().take_while(|c| *c == '#').count();
        let inner = r.get(hashes + 1..r.len().saturating_sub(hashes + 1))?;
        return Some(inner.to_string());
    }
    let inner = t.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => {}
            Some('0') => {}
            Some('\n') => {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
            }
            Some(o) => out.push(o),
            None => {}
        }
    }
    Some(out)
}

impl SrcFile {
    fn load(root: &Path, path: &Path) -> Option<SrcFile> {
        if std::fs::metadata(path).map(|m| m.len() > 8 * 1024 * 1024).unwrap_or(true) {
            return None;
        }
        let text = util::read_to_string_lossy(path).ok()?;
        let toks = rustsrc::lex(&text);
        let docs = toks.iter().filter_map(|t| doc_strip(t).map(|(o, s)| (t.start, t.line, o, s))).collect();
        let code = items::code_only(&toks);
        Some(SrcFile { path: path.to_path_buf(), rel: util::rel(root, path), code, docs })
    }

    /// Outer doc comments with byte offset in `(lo, hi)`.
    fn outer_docs(&self, lo: usize, hi: usize) -> Vec<&(usize, usize, bool, String)> {
        self.docs.iter().filter(|d| d.2 && d.0 >= lo && d.0 < hi).collect()
    }

    fn byte(&self, idx: usize) -> usize {
        self.code.get(idx).map(|t| t.start).unwrap_or(usize::MAX)
    }
}

fn attr_compact(a: &str) -> String {
    a.chars().filter(|c| !c.is_whitespace()).collect()
}

fn is_cfg_test(attrs: &[String]) -> bool {
    attrs.iter().any(|a| {
        let c = attr_compact(a);
        c == "cfg(test)" || c.starts_with("cfg(all(test") || c == "test" || c.ends_with("::test") || c == "bench"
    })
}

/// Merge doc comments and `#[doc]` attributes. `dir` resolves `include_str!` paths.
fn make_docs(comments: &[&(usize, usize, bool, String)], attr_toks: &[Vec<Token>], dir: &Path) -> Docs {
    let mut d = Docs::default();
    let mut parts: Vec<String> = Vec::new();
    for c in comments {
        if !d.present {
            d.line = c.1;
        }
        d.present = true;
        parts.push(c.3.clone());
    }
    for a in attr_toks {
        if !a.first().is_some_and(|t| t.ident("doc")) {
            continue;
        }
        match a.get(1).map(|t| t.text.as_str()) {
            Some("=") => {
                d.present = true;
                if d.line == 0 {
                    d.line = a[0].line;
                }
                let rest = &a[2..];
                if let Some(s) = rest.first().filter(|t| t.kind == Kind::Str).and_then(|t| str_literal(&t.text)) {
                    parts.push(s);
                } else if let Some(text) = include_str_text(rest, dir) {
                    parts.push(text);
                } else {
                    d.external = true;
                }
            }
            Some("(") => {
                let inner: String = a.iter().map(|t| t.text.as_str()).collect();
                if inner.starts_with("doc(hidden") {
                    d.hidden = true;
                }
            }
            _ => {}
        }
    }
    d.text = parts.join("\n");
    d
}

/// `include_str!("path")` or `include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))`.
fn include_str_text(toks: &[Token], dir: &Path) -> Option<String> {
    if !toks.first().is_some_and(|t| t.ident("include_str")) {
        return None;
    }
    let lits: Vec<String> = toks.iter().filter(|t| t.kind == Kind::Str).filter_map(|t| str_literal(&t.text)).collect();
    let uses_manifest_dir = toks.iter().any(|t| t.text.contains("CARGO_MANIFEST_DIR"));
    let rel: String = lits.concat();
    if rel.is_empty() {
        return None;
    }
    let mut candidates = vec![dir.join(&rel)];
    if uses_manifest_dir {
        // walk up to the directory with Cargo.toml
        let mut cur = Some(dir);
        while let Some(c) = cur {
            if c.join("Cargo.toml").is_file() {
                candidates.insert(0, c.join(rel.trim_start_matches('/')));
                break;
            }
            cur = c.parent();
        }
    }
    candidates.into_iter().find_map(|p| std::fs::read_to_string(p).ok())
}

/// Parse `#[...]` attribute token contents into (joined text, tokens).
fn attr_at(code: &[Token], i: usize) -> Option<(usize, Vec<Token>)> {
    if !code.get(i).is_some_and(|t| t.punct("#")) {
        return None;
    }
    let open = if code.get(i + 1).is_some_and(|t| t.punct("[")) {
        i + 1
    } else if code.get(i + 1).is_some_and(|t| t.punct("!")) && code.get(i + 2).is_some_and(|t| t.punct("[")) {
        i + 2
    } else {
        return None;
    };
    let close = items::matching(code, open)?;
    Some((close, code[open + 1..close].to_vec()))
}

/// Index after the item that starts scanning at `j`: the matching `}` of the first `{`
/// at bracket depth 0 or the first `;` at depth 0.
fn item_end(code: &[Token], mut j: usize, hi: usize, brace_ends: bool) -> (usize, Option<(usize, usize)>) {
    let mut depth = 0i32;
    while j < hi {
        match code[j].text.as_str() {
            "(" | "[" if code[j].kind == Kind::Punct => depth += 1,
            ")" | "]" if code[j].kind == Kind::Punct => depth -= 1,
            "{" if code[j].kind == Kind::Punct => {
                if depth == 0 && brace_ends {
                    let c = items::matching(code, j).unwrap_or(hi.saturating_sub(1)).min(hi.saturating_sub(1));
                    return (c, Some((j, c)));
                }
                let c = items::matching(code, j).unwrap_or(hi.saturating_sub(1));
                j = c;
            }
            ";" if depth == 0 => return (j, None),
            _ => {}
        }
        j += 1;
    }
    (hi.saturating_sub(1), None)
}

/// Split the items between token indices `lo..hi` of a file.
fn parse_items(f: &SrcFile, lo: usize, hi: usize, dir: &Path, inner_attrs: &mut Vec<Vec<Token>>) -> Vec<Raw> {
    let code = &f.code;
    let hi = hi.min(code.len());
    let mut out = Vec::new();
    let mut i = lo;
    let mut boundary = if lo > 0 { f.byte(lo - 1).saturating_add(1) } else { 0 };
    let mut attrs: Vec<Vec<Token>> = Vec::new();
    while i < hi {
        let t = &code[i];
        if t.punct("#") {
            if let Some((close, toks)) = attr_at(code, i) {
                if code[i + 1].punct("!") {
                    inner_attrs.push(toks);
                    boundary = f.byte(close).saturating_add(1);
                } else {
                    attrs.push(toks);
                }
                i = close + 1;
                continue;
            }
        }
        if t.punct(";") || t.punct(",") {
            boundary = f.byte(i).saturating_add(1);
            attrs.clear();
            i += 1;
            continue;
        }
        // visibility
        let mut vis = Vis::Private;
        let mut j = i;
        if code[j].ident("pub") {
            if code.get(j + 1).is_some_and(|t| t.punct("(")) {
                vis = Vis::Restricted;
                j = items::matching(code, j + 1).map(|c| c + 1).unwrap_or(j + 1);
            } else {
                vis = Vis::Pub;
                j += 1;
            }
        } else if code[j].ident("crate") && code.get(j + 1).is_some_and(|t| t.kind == Kind::Ident) {
            vis = Vis::Restricted;
            j += 1;
        }
        // qualifiers
        let mut is_unsafe = false;
        loop {
            let Some(q) = code.get(j) else { break };
            let next = code.get(j + 1);
            match q.text.as_str() {
                "default" | "async" | "auto" if q.kind == Kind::Ident && next.is_some_and(|n| n.kind == Kind::Ident) => j += 1,
                "safe" if q.kind == Kind::Ident && next.is_some_and(|n| n.kind == Kind::Ident) => j += 1,
                "unsafe" if q.kind == Kind::Ident && next.is_some_and(|n| !n.punct("{")) => {
                    is_unsafe = true;
                    j += 1
                }
                "const" if q.kind == Kind::Ident && next.is_some_and(|n| n.ident("fn") || n.ident("unsafe") || n.ident("async") || n.ident("extern")) => j += 1,
                "extern" if q.kind == Kind::Ident && next.is_some_and(|n| n.kind == Kind::Str) && code.get(j + 2).is_some_and(|n| n.ident("fn") || n.ident("unsafe")) => j += 2,
                "extern" if q.kind == Kind::Ident && next.is_some_and(|n| n.ident("fn")) => j += 1,
                _ => break,
            }
        }
        let Some(kwt) = code.get(j) else { break };
        let kw_idx = j;
        let kw: &'static str = match kwt.text.as_str() {
            "fn" => "fn",
            "struct" => "struct",
            "enum" => "enum",
            "union" if code.get(j + 1).is_some_and(|n| n.kind == Kind::Ident) => "union",
            "trait" => "trait",
            "type" => "type",
            "const" => "const",
            "static" => "static",
            "mod" => "mod",
            "use" => "use",
            "impl" => "impl",
            "extern" if code.get(j + 1).is_some_and(|n| n.ident("crate")) => "extern_crate",
            "macro_rules" if code.get(j + 1).is_some_and(|n| n.punct("!")) => "macro_rules",
            _ => "other",
        };
        if kwt.kind != Kind::Ident {
            // stray punctuation (e.g. a closing brace of malformed code)
            boundary = f.byte(i).saturating_add(1);
            attrs.clear();
            i += 1;
            continue;
        }
        let name = match kw {
            "fn" | "struct" | "enum" | "union" | "trait" | "type" | "mod" => code.get(j + 1).map(|t| t.text.clone()).unwrap_or_default(),
            "const" => code.get(j + 1).map(|t| t.text.clone()).unwrap_or_default(),
            "static" => {
                let k = if code.get(j + 1).is_some_and(|t| t.ident("mut")) { j + 2 } else { j + 1 };
                code.get(k).map(|t| t.text.clone()).unwrap_or_default()
            }
            "extern_crate" => code.get(j + 2).map(|t| t.text.clone()).unwrap_or_default(),
            "macro_rules" => code.get(j + 2).map(|t| t.text.clone()).unwrap_or_default(),
            _ => String::new(),
        };
        let (end, body) = match kw {
            "fn" => {
                // body: first `{` at paren/bracket depth 0 after the signature
                let mut k = j + 2;
                let mut depth = 0i32;
                let mut res = (hi.saturating_sub(1), None);
                while k < hi {
                    let x = &code[k];
                    match x.text.as_str() {
                        "(" | "[" if x.kind == Kind::Punct => depth += 1,
                        ")" | "]" if x.kind == Kind::Punct => depth -= 1,
                        "{" if depth == 0 && x.kind == Kind::Punct => {
                            let c = items::matching(code, k).unwrap_or(hi - 1);
                            res = (c, Some((k, c)));
                            break;
                        }
                        ";" if depth == 0 => {
                            res = (k, None);
                            break;
                        }
                        _ => {}
                    }
                    k += 1;
                }
                res
            }
            "struct" | "union" => {
                // `struct X;`, `struct X(..);`, `struct X<T> where .. { }`
                let mut k = j + 2;
                if code.get(k).is_some_and(|t| t.punct("<")) {
                    k = matching_angle(code, k).map(|c| c + 1).unwrap_or(k + 1);
                }
                if code.get(k).is_some_and(|t| t.punct("(")) {
                    let c = items::matching(code, k).unwrap_or(hi - 1);
                    let (e, _) = item_end(code, c + 1, hi, false);
                    (e, Some((k, c)))
                } else {
                    item_end(code, k, hi, true)
                }
            }
            "enum" | "trait" | "impl" | "mod" | "macro_rules" => {
                let (e, b) = item_end(code, j + 1, hi, true);
                if kw == "macro_rules" && b.is_some() {
                    // `macro_rules! m { }` has no trailing `;`
                    (e, b)
                } else {
                    (e, b)
                }
            }
            "other" => {
                // macro invocation `name! { }` / `name!(..);` or unknown syntax
                if code.get(j + 1).is_some_and(|t| t.punct("!")) {
                    let k = j + 2 + usize::from(code.get(j + 2).is_some_and(|t| t.kind == Kind::Ident));
                    match code.get(k).map(|t| t.text.as_str()) {
                        Some("{") => {
                            let c = items::matching(code, k).unwrap_or(hi - 1);
                            (c, Some((k, c)))
                        }
                        Some("(") | Some("[") => {
                            let c = items::matching(code, k).unwrap_or(hi - 1);
                            let e = if code.get(c + 1).is_some_and(|t| t.punct(";")) { c + 1 } else { c };
                            (e, None)
                        }
                        _ => item_end(code, j, hi, true),
                    }
                } else {
                    item_end(code, j, hi, true)
                }
            }
            _ => item_end(code, j, hi, false),
        };
        let comments = f.outer_docs(boundary, f.byte(kw_idx));
        let docs = make_docs(&comments, &attrs, dir);
        out.push(Raw {
            kw,
            name,
            vis,
            attrs: attrs.iter().map(|a| items::join(a)).collect(),
            docs,
            line: code[kw_idx].line,
            kw_idx,
            end,
            body,
            is_unsafe,
        });
        attrs.clear();
        boundary = f.byte(end).saturating_add(1);
        i = end + 1;
    }
    out
}

/// Parse a `use` tree (tokens between `use` and `;`).
pub fn parse_use_tree(toks: &[Token], prefix: Vec<String>, out: &mut Vec<(String, Vec<String>, bool)>) {
    let mut segs = prefix;
    let mut i = 0;
    if toks.first().is_some_and(|t| t.punct("::")) {
        i += 1;
    }
    while i < toks.len() {
        let t = &toks[i];
        if t.punct("*") {
            out.push(("*".into(), segs, true));
            return;
        }
        if t.punct("{") {
            let close = items::matching(toks, i).unwrap_or(toks.len());
            let inner = &toks[i + 1..close.min(toks.len())];
            for part in split_top(inner, ",") {
                if !part.is_empty() {
                    parse_use_tree(part, segs.clone(), out);
                }
            }
            return;
        }
        if t.kind == Kind::Ident {
            segs.push(t.text.clone());
            i += 1;
            match toks.get(i) {
                Some(n) if n.punct("::") => {
                    i += 1;
                    continue;
                }
                Some(n) if n.ident("as") => {
                    let alias = toks.get(i + 1).map(|a| a.text.clone()).unwrap_or_default();
                    if segs.last().is_some_and(|s| s == "self") {
                        segs.pop();
                    }
                    out.push((alias, segs, false));
                    return;
                }
                _ => {
                    if segs.last().is_some_and(|s| s == "self") && segs.len() > 1 {
                        segs.pop();
                    }
                    let alias = segs.last().cloned().unwrap_or_default();
                    out.push((alias, segs, false));
                    return;
                }
            }
        }
        i += 1;
    }
}

/// Byte-range doc lookup for fields and variants: docs between `lo_byte` and `hi_byte`.
fn member_docs(f: &SrcFile, lo_byte: usize, hi_byte: usize, attrs: &[Vec<Token>], dir: &Path) -> Docs {
    let comments = f.outer_docs(lo_byte, hi_byte);
    make_docs(&comments, attrs, dir)
}

/// Leading attributes of a member (field/variant) token slice; returns (attrs, rest).
fn split_member_attrs(toks: &[Token]) -> (Vec<Vec<Token>>, &[Token]) {
    let mut attrs = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        if toks[i].punct("#") && toks.get(i + 1).is_some_and(|t| t.punct("[")) {
            if let Some(c) = items::matching(toks, i + 1) {
                attrs.push(toks[i + 2..c].to_vec());
                i = c + 1;
                continue;
            }
        }
        break;
    }
    (attrs, &toks[i..])
}

fn member_vis(toks: &[Token]) -> (Vis, &[Token]) {
    if toks.first().is_some_and(|t| t.ident("pub")) {
        if toks.get(1).is_some_and(|t| t.punct("(")) {
            let c = items::matching(toks, 1).unwrap_or(1);
            return (Vis::Restricted, &toks[(c + 1).min(toks.len())..]);
        }
        return (Vis::Pub, &toks[1..]);
    }
    (Vis::Private, toks)
}

/// Generic parameters (`<...>` after the name) and a where clause of an item header.
fn header_bounds(code: &[Token], name_idx: usize, stop: usize) -> Vec<Token> {
    let mut out = Vec::new();
    let mut k = name_idx + 1;
    if code.get(k).is_some_and(|t| t.punct("<")) {
        if let Some(c) = matching_angle(code, k) {
            out.extend_from_slice(&code[k + 1..c]);
            k = c + 1;
        }
    }
    if let Some(w) = (k..stop.min(code.len())).find(|&x| code[x].ident("where")) {
        out.extend_from_slice(&code[w + 1..stop.min(code.len())]);
    }
    out
}

/// Panic sites in a function body.
pub fn panic_sites(code: &[Token], lo: usize, hi: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let hi = hi.min(code.len());
    let mut i = lo;
    while i < hi {
        let t = &code[i];
        if t.kind == Kind::Ident && code.get(i + 1).is_some_and(|n| n.punct("!")) {
            let prev_path = i > 0 && code[i - 1].punct("::");
            if matches!(t.text.as_str(), "panic" | "unreachable" | "todo" | "unimplemented" | "assert" | "assert_eq" | "assert_ne") && !prev_path
                || (prev_path && matches!(t.text.as_str(), "panic" | "unreachable"))
            {
                out.push((t.line, format!("{}!", t.text)));
            }
        } else if t.kind == Kind::Ident
            && matches!(t.text.as_str(), "unwrap" | "expect")
            && i > 0
            && code[i - 1].punct(".")
            && code.get(i + 1).is_some_and(|n| n.punct("("))
        {
            out.push((t.line, format!(".{}()", t.text)));
        } else if t.punct("[") && i > lo {
            let p = &code[i - 1];
            let indexing = (p.kind == Kind::Ident && !KEYWORDS.contains(&p.text.as_str()) && !(i >= 2 && code[i - 2].punct("#")))
                || (p.punct(")") || p.punct("]"));
            let is_attr = i >= 1 && (code[i - 1].punct("#") || (i >= 2 && code[i - 1].punct("!") && code[i - 2].punct("#")));
            let is_macro = p.punct("!");
            if indexing && !is_attr && !is_macro {
                // `x[..]` full-range slicing cannot panic
                let full = code.get(i + 1).is_some_and(|n| n.punct("..")) && code.get(i + 2).is_some_and(|n| n.punct("]"));
                if !full {
                    out.push((t.line, "indexing".into()));
                }
            }
        }
        i += 1;
    }
    out
}

fn returns_result(ret: &[Token]) -> bool {
    // first path in the return type: its last segment before `<`
    let mut last = None;
    for t in ret {
        if t.kind == Kind::Ident {
            last = Some(t.text.as_str());
        } else if t.punct("::") {
            continue;
        } else if last.is_some() {
            break;
        }
    }
    last.is_some_and(|l| l == "Result" || l.ends_with("Result"))
}

/// Signature sites of a fn whose `fn` keyword is at `kw`.
fn fn_sites(code: &[Token], kw: usize, body_open: usize) -> (Vec<Site>, bool) {
    let mut sites = Vec::new();
    let mut j = kw + 2;
    let stop = body_open.min(code.len());
    if code.get(j).is_some_and(|t| t.punct("<")) {
        if let Some(c) = matching_angle(code, j) {
            sites.push(Site { kind: "signature", tokens: code[j + 1..c].to_vec() });
            j = c + 1;
        }
    }
    if code.get(j).is_some_and(|t| t.punct("(")) {
        if let Some(c) = items::matching(code, j) {
            for p in split_top(&code[j + 1..c], ",") {
                if let Some(colon) = p.iter().position(|t| t.punct(":")) {
                    sites.push(Site { kind: "signature", tokens: p[colon + 1..].to_vec() });
                }
            }
            j = c + 1;
        }
    }
    let wh = (j..stop).find(|&k| code[k].ident("where"));
    let mut is_result = false;
    if code.get(j).is_some_and(|t| t.punct("->")) {
        let r = &code[j + 1..wh.unwrap_or(stop).max(j + 1)];
        is_result = returns_result(r);
        sites.push(Site { kind: "signature", tokens: r.to_vec() });
    }
    if let Some(w) = wh {
        sites.push(Site { kind: "signature", tokens: code[w + 1..stop].to_vec() });
    }
    (sites, is_result)
}

impl Surface {
    /// Model the library crate rooted at `root` with entry file `lib`.
    pub fn build(root: &Path, lib: &Path, dep_names: BTreeSet<String>) -> Surface {
        let mut s = Surface { root: root.to_path_buf(), dep_names, ..Default::default() };
        let Some(f) = SrcFile::load(root, lib) else { return s };
        s.files.push(f);
        s.modules.push(Module {
            path: "crate".into(),
            name: "crate".into(),
            parent: None,
            vis: Vis::Pub,
            reachable: true,
            uses: vec![],
            children: BTreeMap::new(),
            defined: BTreeSet::new(),
            file: 0,
            line: 1,
        });
        let dir = lib.parent().map(Path::to_path_buf).unwrap_or_default();
        let n = s.files[0].code.len();
        let mut visited = HashSet::new();
        visited.insert(lib.to_path_buf());
        let docs = s.walk(0, 0, n, 0, dir.clone(), dir, false, &mut visited, 0);
        s.crate_docs = docs;
        s.compute_reachability();
        s
    }

    #[allow(clippy::too_many_arguments)]
    fn walk(&mut self, file: usize, lo: usize, hi: usize, m: usize, child_dir: PathBuf, file_dir: PathBuf, inline: bool, visited: &mut HashSet<PathBuf>, depth: usize) -> Docs {
        let mut inner_attrs = Vec::new();
        let raws = parse_items(&self.files[file], lo, hi, &file_dir, &mut inner_attrs);
        // inner docs of this module: `//!` comments inside lo..hi before the first item
        let f = &self.files[file];
        let lo_b = if lo > 0 { f.byte(lo - 1) } else { 0 };
        let first_item_b = raws.first().map(|r| f.byte(r.kw_idx)).unwrap_or(usize::MAX);
        let hi_b = if hi < f.code.len() { f.byte(hi) } else { usize::MAX };
        let inner: Vec<&(usize, usize, bool, String)> =
            f.docs.iter().filter(|d| !d.2 && d.0 >= lo_b && d.0 < hi_b && (d.0 < first_item_b || lo == 0)).collect();
        let inner_docs = {
            let fake: Vec<(usize, usize, bool, String)> = inner.iter().map(|d| (d.0, d.1, true, d.3.clone())).collect();
            let refs: Vec<&(usize, usize, bool, String)> = fake.iter().collect();
            make_docs(&refs, &inner_attrs, &file_dir)
        };
        for r in raws {
            if is_cfg_test(&r.attrs) {
                continue;
            }
            if r.kw == "other" {
                // item-level macro invocation with a brace body (`cfg_if! { if #[cfg(x)] { .. } else { .. } }`,
                // `if_feature! { pub mod x; }`): model the items written inside it
                if let (Some((a, b)), true) = (r.body, depth < 40) {
                    let code = &self.files[file].code;
                    let groups: Vec<(usize, usize)> = if code.get(a + 1).is_some_and(|t| t.ident("if")) {
                        let mut g = Vec::new();
                        let mut k = a + 1;
                        while k < b {
                            if code[k].punct("{") {
                                let c = items::matching(code, k).unwrap_or(b).min(b);
                                g.push((k, c));
                                k = c;
                            } else if code[k].punct("[") || code[k].punct("(") {
                                k = items::matching(code, k).unwrap_or(b).min(b);
                            }
                            k += 1;
                        }
                        g
                    } else {
                        vec![(a, b)]
                    };
                    for (ga, gb) in groups {
                        self.walk(file, ga + 1, gb, m, child_dir.clone(), file_dir.clone(), inline, visited, depth + 1);
                    }
                }
                continue;
            }
            self.add_raw(file, m, r, &child_dir, &file_dir, inline, visited, depth);
        }
        inner_docs
    }

    #[allow(clippy::too_many_arguments)]
    fn add_raw(&mut self, file: usize, m: usize, r: Raw, child_dir: &Path, file_dir: &Path, inline: bool, visited: &mut HashSet<PathBuf>, depth: usize) {
        let code = self.files[file].code.clone();
        let mk = |kind: ItemKind, name: String, sites: Vec<Site>| Item {
            kind,
            name,
            parent: None,
            module: m,
            file,
            line: r.line,
            vis: r.vis,
            reachable: false,
            docs: r.docs.clone(),
            is_unsafe: r.is_unsafe,
            returns_result: false,
            panics: vec![],
            sites,
        };
        match r.kw {
            "fn" => {
                let stop = r.body.map(|b| b.0).unwrap_or(r.end);
                let (sites, res) = fn_sites(&code, r.kw_idx, stop);
                let mut it = mk(ItemKind::Fn, r.name.clone(), sites);
                it.returns_result = res;
                if let Some((a, b)) = r.body {
                    it.panics = panic_sites(&code, a + 1, b);
                }
                self.modules[m].defined.insert(r.name.clone());
                self.items.push(it);
            }
            "struct" | "union" => {
                let kind = if r.kw == "struct" { ItemKind::Struct } else { ItemKind::Union };
                let stop = r.body.map(|b| b.0).unwrap_or(r.end);
                let bounds = header_bounds(&code, r.kw_idx + 1, stop);
                let mut it = mk(kind, r.name.clone(), vec![Site { kind: "bound", tokens: bounds }]);
                it.sites.retain(|s| !s.tokens.is_empty());
                self.modules[m].defined.insert(r.name.clone());
                let parent_idx = self.items.len();
                self.items.push(it);
                if let Some((a, b)) = r.body {
                    let tuple = code[a].punct("(");
                    let mut prev_b = self.files[file].byte(a);
                    for (n, part) in split_top(&code[a + 1..b], ",").into_iter().enumerate() {
                        if part.is_empty() {
                            continue;
                        }
                        let (attrs, rest) = split_member_attrs(part);
                        if is_cfg_test(&attrs.iter().map(|a| items::join(a)).collect::<Vec<_>>()) {
                            continue;
                        }
                        let (vis, rest) = member_vis(rest);
                        let (fname, ty): (String, &[Token]) = if tuple {
                            (n.to_string(), rest)
                        } else {
                            let c = rest.iter().position(|t| t.punct(":")).unwrap_or(0);
                            (rest.first().map(|t| t.text.clone()).unwrap_or_default(), &rest[(c + 1).min(rest.len())..])
                        };
                        let Some(first) = rest.first() else { continue };
                        let docs = member_docs(&self.files[file], prev_b, first.start, &attrs, file_dir);
                        prev_b = part.last().map(|t| t.start).unwrap_or(prev_b);
                        self.items.push(Item {
                            kind: ItemKind::Field,
                            name: fname,
                            parent: Some(self.items[parent_idx].name.clone()),
                            module: m,
                            file,
                            line: first.line,
                            vis,
                            reachable: false,
                            docs,
                            is_unsafe: false,
                            returns_result: false,
                            panics: vec![],
                            sites: vec![Site { kind: "field", tokens: ty.to_vec() }],
                        });
                    }
                }
            }
            "enum" => {
                let Some((a, b)) = r.body else { return };
                let bounds = header_bounds(&code, r.kw_idx + 1, a);
                let mut it = mk(ItemKind::Enum, r.name.clone(), vec![Site { kind: "bound", tokens: bounds }]);
                it.sites.retain(|s| !s.tokens.is_empty());
                self.modules[m].defined.insert(r.name.clone());
                self.items.push(it);
                let mut prev_b = self.files[file].byte(a);
                for part in split_top(&code[a + 1..b], ",") {
                    if part.is_empty() {
                        continue;
                    }
                    let (attrs, rest) = split_member_attrs(part);
                    let Some(first) = rest.first() else { continue };
                    let docs = member_docs(&self.files[file], prev_b, first.start, &attrs, file_dir);
                    prev_b = part.last().map(|t| t.start).unwrap_or(prev_b);
                    // field types: everything inside (..) or {..} after the name, minus field names
                    let mut ty = Vec::new();
                    if let Some(open) = rest.get(1) {
                        if open.punct("(") || open.punct("{") {
                            let c = items::matching(rest, 1).unwrap_or(rest.len());
                            let inner = &rest[2..c.min(rest.len())];
                            for p in split_top(inner, ",") {
                                let (_, p) = split_member_attrs(p);
                                if open.punct("{") {
                                    if let Some(col) = p.iter().position(|t| t.punct(":")) {
                                        ty.extend_from_slice(&p[col + 1..]);
                                        ty.push(Token { kind: Kind::Punct, text: ",".into(), line: first.line, start: first.start, doc: false });
                                    }
                                } else {
                                    ty.extend_from_slice(p);
                                    ty.push(Token { kind: Kind::Punct, text: ",".into(), line: first.line, start: first.start, doc: false });
                                }
                            }
                        }
                    }
                    self.items.push(Item {
                        kind: ItemKind::Variant,
                        name: first.text.clone(),
                        parent: Some(r.name.clone()),
                        module: m,
                        file,
                        line: first.line,
                        vis: Vis::Pub,
                        reachable: false,
                        docs,
                        is_unsafe: false,
                        returns_result: false,
                        panics: vec![],
                        sites: vec![Site { kind: "field", tokens: ty }],
                    });
                }
            }
            "trait" => {
                let Some((a, b)) = r.body else { return };
                // header: generics, supertraits, where
                let header = code[r.kw_idx + 2..a].to_vec();
                let mut it = mk(ItemKind::Trait, r.name.clone(), vec![Site { kind: "bound", tokens: header }]);
                it.sites.retain(|s| !s.tokens.is_empty());
                self.modules[m].defined.insert(r.name.clone());
                self.items.push(it);
                let mut sink = Vec::new();
                let f = self.files[file].clone();
                for ti in parse_items(&f, a + 1, b, file_dir, &mut sink) {
                    if is_cfg_test(&ti.attrs) {
                        continue;
                    }
                    let (kind, sites, res, panics) = match ti.kw {
                        "fn" => {
                            let stop = ti.body.map(|x| x.0).unwrap_or(ti.end);
                            let (s, res) = fn_sites(&code, ti.kw_idx, stop);
                            let p = ti.body.map(|(x, y)| panic_sites(&code, x + 1, y)).unwrap_or_default();
                            (ItemKind::TraitMethod, s, res, p)
                        }
                        "type" => (ItemKind::AssocType, vec![Site { kind: "bound", tokens: code[ti.kw_idx + 2..ti.end].to_vec() }], false, vec![]),
                        "const" => (ItemKind::AssocConst, vec![Site { kind: "type", tokens: code[ti.kw_idx + 2..ti.end].to_vec() }], false, vec![]),
                        _ => continue,
                    };
                    self.items.push(Item {
                        kind,
                        name: ti.name,
                        parent: Some(r.name.clone()),
                        module: m,
                        file,
                        line: ti.line,
                        vis: Vis::Pub,
                        reachable: false,
                        docs: ti.docs,
                        is_unsafe: ti.is_unsafe,
                        returns_result: res,
                        panics,
                        sites,
                    });
                }
            }
            "type" => {
                let it = mk(ItemKind::TypeAlias, r.name.clone(), vec![Site { kind: "type", tokens: code[r.kw_idx + 2..r.end].to_vec() }]);
                self.modules[m].defined.insert(r.name.clone());
                self.items.push(it);
            }
            "const" | "static" => {
                if r.name == "_" {
                    return;
                }
                let kind = if r.kw == "const" { ItemKind::Const } else { ItemKind::Static };
                let col = (r.kw_idx..r.end).find(|&k| code[k].punct(":"));
                let eq = (r.kw_idx..r.end).find(|&k| code[k].punct("=")).unwrap_or(r.end);
                let ty = col.map(|c| code[c + 1..eq.max(c + 1)].to_vec()).unwrap_or_default();
                let it = mk(kind, r.name.clone(), vec![Site { kind: "type", tokens: ty }]);
                self.modules[m].defined.insert(r.name.clone());
                self.items.push(it);
            }
            "macro_rules" => {
                if r.attrs.iter().any(|a| attr_compact(a).starts_with("macro_export")) {
                    let mut it = mk(ItemKind::Macro, r.name.clone(), vec![]);
                    it.module = 0;
                    it.vis = Vis::Pub;
                    self.items.push(it);
                }
            }
            "use" => {
                let mut out = Vec::new();
                parse_use_tree(&code[r.kw_idx + 1..r.end], vec![], &mut out);
                for (alias, path, glob) in out {
                    self.modules[m].uses.push(UseEntry { alias, path, glob, vis: r.vis, line: r.line, file, extern_crate: false });
                }
            }
            "extern_crate" => {
                let alias = if code.get(r.kw_idx + 3).is_some_and(|t| t.ident("as")) {
                    code.get(r.kw_idx + 4).map(|t| t.text.clone()).unwrap_or_default()
                } else {
                    r.name.clone()
                };
                self.modules[m].uses.push(UseEntry { alias, path: vec![r.name.clone()], glob: false, vis: r.vis, line: r.line, file, extern_crate: true });
            }
            "impl" => {
                let Some((a, b)) = r.body else { return };
                let mut k = r.kw_idx + 1;
                let mut bounds = Vec::new();
                if code.get(k).is_some_and(|t| t.punct("<")) {
                    if let Some(c) = matching_angle(&code, k) {
                        bounds.extend_from_slice(&code[k + 1..c]);
                        k = c + 1;
                    }
                }
                let head = &code[k..a];
                let wh = head.iter().position(|t| t.ident("where"));
                if let Some(w) = wh {
                    bounds.extend_from_slice(&head[w + 1..]);
                }
                let main = &head[..wh.unwrap_or(head.len())];
                let mut angle = 0i32;
                let mut for_pos = None;
                for (x, t) in main.iter().enumerate() {
                    match t.text.as_str() {
                        "<" => angle += 1,
                        ">" => angle -= 1,
                        ">>" => angle -= 2,
                        "for" if angle == 0 && x > 0 => {
                            for_pos = Some(x);
                            break;
                        }
                        _ => {}
                    }
                }
                let (trait_toks, self_toks, negative) = match for_pos {
                    Some(p) => {
                        let mut tr = &main[..p];
                        let neg = tr.first().is_some_and(|t| t.punct("!"));
                        if neg {
                            tr = &tr[1..];
                        }
                        (Some(tr.to_vec()), main[p + 1..].to_vec(), neg)
                    }
                    None => (None, main.to_vec(), false),
                };
                let self_name = base_type_name(&self_toks);
                let is_trait_impl = trait_toks.is_some();
                self.impls.push(ImplInfo { module: m, file, line: r.line, trait_toks, self_toks, bounds, negative });
                if is_trait_impl {
                    return;
                }
                let mut sink = Vec::new();
                let f = self.files[file].clone();
                for ii in parse_items(&f, a + 1, b, file_dir, &mut sink) {
                    if is_cfg_test(&ii.attrs) {
                        continue;
                    }
                    let (kind, sites, res, panics) = match ii.kw {
                        "fn" => {
                            let stop = ii.body.map(|x| x.0).unwrap_or(ii.end);
                            let (s, res) = fn_sites(&code, ii.kw_idx, stop);
                            let p = ii.body.map(|(x, y)| panic_sites(&code, x + 1, y)).unwrap_or_default();
                            (ItemKind::Method, s, res, p)
                        }
                        "const" => {
                            let col = (ii.kw_idx..ii.end).find(|&k| code[k].punct(":"));
                            let eq = (ii.kw_idx..ii.end).find(|&k| code[k].punct("=")).unwrap_or(ii.end);
                            let ty = col.map(|c| code[c + 1..eq.max(c + 1)].to_vec()).unwrap_or_default();
                            (ItemKind::AssocConst, vec![Site { kind: "type", tokens: ty }], false, vec![])
                        }
                        _ => continue,
                    };
                    self.items.push(Item {
                        kind,
                        name: ii.name,
                        parent: Some(self_name.clone()),
                        module: m,
                        file,
                        line: ii.line,
                        vis: ii.vis,
                        reachable: false,
                        docs: ii.docs,
                        is_unsafe: ii.is_unsafe,
                        returns_result: res,
                        panics,
                        sites,
                    });
                }
            }
            "mod" => {
                if depth > 40 || r.name.is_empty() {
                    return;
                }
                let parent_path = self.modules[m].path.clone();
                let idx = self.modules.len();
                self.modules.push(Module {
                    path: format!("{parent_path}::{}", r.name),
                    name: r.name.clone(),
                    parent: Some(m),
                    vis: r.vis,
                    reachable: false,
                    uses: vec![],
                    children: BTreeMap::new(),
                    defined: BTreeSet::new(),
                    file,
                    line: r.line,
                });
                self.modules[m].children.insert(r.name.clone(), idx);
                let path_attr = r.attrs.iter().find_map(|a| {
                    let c = attr_compact(a);
                    c.strip_prefix("path=").and_then(str_literal)
                });
                let mut item = mk(ItemKind::Mod, r.name.clone(), vec![]);
                item.module = m;
                let item_idx = self.items.len();
                self.items.push(item);
                let inner_docs = if let Some((a, b)) = r.body {
                    let cd = match &path_attr {
                        Some(p) => child_dir.join(p),
                        None => child_dir.join(&r.name),
                    };
                    self.walk(file, a + 1, b, idx, cd, file_dir.to_path_buf(), true, visited, depth + 1)
                } else {
                    let candidates: Vec<PathBuf> = match &path_attr {
                        Some(p) => {
                            let base = if inline { child_dir.to_path_buf() } else { file_dir.to_path_buf() };
                            vec![base.join(p)]
                        }
                        None => vec![child_dir.join(format!("{}.rs", r.name)), child_dir.join(&r.name).join("mod.rs")],
                    };
                    match candidates.iter().find(|p| p.is_file()) {
                        Some(p) if visited.insert(p.clone()) => match SrcFile::load(&self.root, p) {
                            Some(sf) => {
                                let fidx = self.files.len();
                                let n = sf.code.len();
                                self.files.push(sf);
                                self.modules[idx].file = fidx;
                                let fdir = p.parent().map(Path::to_path_buf).unwrap_or_default();
                                let mod_rs = path_attr.is_some() || p.file_name().is_some_and(|f| f == "mod.rs");
                                let cd = if mod_rs { fdir.clone() } else { child_dir.join(&r.name) };
                                self.walk(fidx, 0, n, idx, cd, fdir, false, visited, depth + 1)
                            }
                            None => Docs::default(),
                        },
                        Some(_) => Docs::default(),
                        None => {
                            self.missing_modules.push(format!("{}::{}", parent_path, r.name));
                            Docs::default()
                        }
                    }
                };
                // module docs: outer docs on `mod x;` plus inner `//!` docs
                let d = &mut self.items[item_idx].docs;
                if inner_docs.present {
                    if !d.present {
                        d.line = inner_docs.line;
                    }
                    d.present = true;
                    d.text = format!("{}\n{}", d.text, inner_docs.text).trim().to_string();
                    d.external |= inner_docs.external;
                    d.hidden |= inner_docs.hidden;
                }
            }
            _ => {}
        }
    }

    fn compute_reachability(&mut self) {
        // fixpoint: module reachability through pub chains and `pub use` re-exports
        let mut reexported_items: HashSet<(usize, String)> = HashSet::new();
        let mut reexported_mods: HashSet<usize> = HashSet::new();
        for _ in 0..8 {
            let mut changed = false;
            for i in 1..self.modules.len() {
                let p = self.modules[i].parent.unwrap_or(0);
                let r = (self.modules[p].reachable && self.modules[i].vis == Vis::Pub) || reexported_mods.contains(&i);
                if r != self.modules[i].reachable {
                    self.modules[i].reachable = r;
                    changed = true;
                }
            }
            for mi in 0..self.modules.len() {
                if !self.modules[mi].reachable {
                    continue;
                }
                let uses: Vec<UseEntry> = self.modules[mi].uses.iter().filter(|u| u.vis == Vis::Pub).cloned().collect();
                for u in uses {
                    if let Some((tm, name)) = self.local_target(mi, &u.path, 0) {
                        if u.glob {
                            // all pub items and modules of the target module (or a module named `name`)
                            let target = match &name {
                                Some(n) => self.modules[tm].children.get(n).copied(),
                                None => Some(tm),
                            };
                            if let Some(t) = target {
                                let names: Vec<String> = self.modules[t].defined.iter().cloned().collect();
                                for n in names {
                                    changed |= reexported_items.insert((t, n));
                                }
                                let kids: Vec<usize> = self.modules[t].children.values().copied().collect();
                                for k in kids {
                                    if self.modules[k].vis == Vis::Pub {
                                        changed |= reexported_mods.insert(k);
                                    }
                                }
                            }
                        } else if let Some(n) = name {
                            if let Some(&child) = self.modules[tm].children.get(&n) {
                                changed |= reexported_mods.insert(child);
                            }
                            changed |= reexported_items.insert((tm, n));
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        // items
        for it in self.items.iter_mut() {
            if matches!(it.kind, ItemKind::Field | ItemKind::Variant | ItemKind::Method | ItemKind::TraitMethod | ItemKind::AssocType | ItemKind::AssocConst) {
                continue;
            }
            if it.kind == ItemKind::Macro {
                it.reachable = true;
                continue;
            }
            if it.kind == ItemKind::Mod {
                // the module item itself: reachable if the module is
                let mi = self.modules.iter().position(|m| m.parent == Some(it.module) && m.name == it.name);
                it.reachable = mi.is_some_and(|mi| self.modules[mi].reachable);
                continue;
            }
            it.reachable = it.vis == Vis::Pub && (self.modules[it.module].reachable || reexported_items.contains(&(it.module, it.name.clone())));
        }
        // members follow their parent type/trait; a parent is looked up in the member's own module
        // first, so a private type that shares a name with a public one does not leak its members
        let snapshot: Vec<(usize, String, ItemKind, bool)> = self.items.iter().map(|i| (i.module, i.name.clone(), i.kind, i.reachable)).collect();
        let parent_ok = |m: usize, name: &str, want: &dyn Fn(ItemKind) -> bool| -> bool {
            let mut local = snapshot.iter().filter(|(im, n, k, _)| *im == m && n == name && want(*k)).peekable();
            if local.peek().is_some() {
                return local.any(|x| x.3);
            }
            snapshot.iter().any(|(_, n, k, r)| *r && n == name && want(*k))
        };
        let is_type = |k: ItemKind| k.is_type() || k == ItemKind::Trait;
        let is_enum = |k: ItemKind| k == ItemKind::Enum;
        let is_trait = |k: ItemKind| k == ItemKind::Trait;
        for it in self.items.iter_mut() {
            let parent = it.parent.clone().unwrap_or_default();
            let parent = parent.as_str();
            match it.kind {
                ItemKind::Field => it.reachable = it.vis == Vis::Pub && parent_ok(it.module, parent, &is_type),
                ItemKind::Variant => it.reachable = parent_ok(it.module, parent, &is_enum),
                ItemKind::Method | ItemKind::AssocConst => it.reachable = it.vis == Vis::Pub && parent_ok(it.module, parent, &is_type),
                ItemKind::TraitMethod | ItemKind::AssocType => it.reachable = parent_ok(it.module, parent, &is_trait),
                _ => {}
            }
        }
    }

    /// Whether a type (or, with `traits_only`, a trait) named `name`, as seen from module `m`, is public API: an item of
    /// that name defined in `m` decides; otherwise any reachable item of that name counts.
    pub fn named_reachable(&self, m: usize, name: &str, traits_only: bool) -> bool {
        let want = |k: ItemKind| if traits_only { k == ItemKind::Trait } else { k.is_type() };
        let mut local = self.items.iter().filter(|i| i.module == m && i.name == name && want(i.kind)).peekable();
        if local.peek().is_some() {
            return local.any(|i| i.reachable);
        }
        self.items.iter().any(|i| i.reachable && i.name == name && want(i.kind))
    }

    /// Resolve a `use` path that points into this crate to (module, final name).
    /// `None` when it points outside the crate.
    fn local_target(&self, m: usize, path: &[String], depth: usize) -> Option<(usize, Option<String>)> {
        if depth > 8 || path.is_empty() {
            return None;
        }
        let (mut cur, rest): (usize, &[String]) = match path[0].as_str() {
            "crate" => (0, &path[1..]),
            "self" => (m, &path[1..]),
            "super" => (self.modules[m].parent.unwrap_or(0), &path[1..]),
            first => {
                if self.modules[m].children.contains_key(first) {
                    (m, path)
                } else if let Some(u) = self.modules[m].uses.iter().find(|u| !u.glob && u.alias == first && !u.extern_crate) {
                    let mut p = u.path.clone();
                    p.extend_from_slice(&path[1..]);
                    if p == path {
                        return None;
                    }
                    return self.local_target(m, &p, depth + 1);
                } else {
                    return None;
                }
            }
        };
        let mut i = 0;
        while i < rest.len() {
            let seg = rest[i].as_str();
            if seg == "super" {
                cur = self.modules[cur].parent.unwrap_or(0);
                i += 1;
                continue;
            }
            if i + 1 == rest.len() {
                // follow a re-export of the final name (`pub use self::body::Body;` in `cur`)
                let here = self.modules[cur].defined.contains(seg) || self.modules[cur].children.contains_key(seg);
                if !here {
                    if let Some(u) = self.modules[cur].uses.iter().find(|u| !u.glob && u.alias == seg && !u.extern_crate) {
                        if let Some(t) = self.local_target(cur, &u.path, depth + 1) {
                            return Some(t);
                        }
                    }
                }
                return Some((cur, Some(seg.to_string())));
            }
            if let Some(&c) = self.modules[cur].children.get(seg) {
                cur = c;
                i += 1;
                continue;
            }
            // through a re-export inside the crate
            if let Some(u) = self.modules[cur].uses.iter().find(|u| !u.glob && u.alias == seg && !u.extern_crate) {
                let mut p = u.path.clone();
                p.extend_from_slice(&rest[i + 1..]);
                return self.local_target(cur, &p, depth + 1);
            }
            return None;
        }
        Some((cur, None))
    }

    /// If a path written in module `m` refers to an item of a dependency, return
    /// (extern crate name, full path).
    pub fn resolve_dep(&self, m: usize, segs: &[String], depth: usize) -> Option<(String, Vec<String>)> {
        if depth > 10 || segs.is_empty() {
            return None;
        }
        let first = segs[0].as_str();
        match first {
            "crate" | "self" | "super" => {
                let (cur, rest) = self.descend_local(m, segs)?;
                return self.resolve_in_module(cur, &rest, depth + 1);
            }
            "Self" | "std" | "core" | "alloc" | "proc_macro" | "test" => return None,
            _ => {}
        }
        if let Some(u) = self.modules[m].uses.iter().find(|u| !u.glob && u.alias == first) {
            let mut p = u.path.clone();
            p.extend_from_slice(&segs[1..]);
            if u.extern_crate {
                return self.dep_names.contains(&u.path[0]).then(|| (u.path[0].clone(), p));
            }
            if p == segs {
                // `use dep;` (2018 style) or `use dep::X;` where the alias is the crate itself
                return self.dep_names.contains(first).then(|| (first.to_string(), segs.to_vec()));
            }
            return self.resolve_dep(m, &p, depth + 1);
        }
        if let Some(&child) = self.modules[m].children.get(first) {
            return self.resolve_in_module(child, &segs[1..], depth + 1);
        }
        if self.modules[m].defined.contains(first) {
            return None;
        }
        if self.dep_names.contains(first) {
            return Some((first.to_string(), segs.to_vec()));
        }
        // crate root `extern crate` aliases are visible everywhere (2015 prelude)
        if let Some(u) = self.modules[0].uses.iter().find(|u| u.extern_crate && u.alias == first) {
            let mut p = u.path.clone();
            p.extend_from_slice(&segs[1..]);
            return self.dep_names.contains(&u.path[0]).then(|| (u.path[0].clone(), p));
        }
        None
    }

    fn descend_local(&self, m: usize, segs: &[String]) -> Option<(usize, Vec<String>)> {
        let mut cur = m;
        let mut i = 0;
        while i < segs.len() {
            match segs[i].as_str() {
                "crate" if i == 0 => cur = 0,
                "self" if i == 0 => {}
                "super" => cur = self.modules[cur].parent.unwrap_or(0),
                _ => break,
            }
            i += 1;
        }
        Some((cur, segs[i..].to_vec()))
    }

    /// Resolve `rest` relative to module `cur` (no 2018 extern-crate lookup at the start).
    fn resolve_in_module(&self, cur: usize, rest: &[String], depth: usize) -> Option<(String, Vec<String>)> {
        if depth > 10 || rest.is_empty() {
            return None;
        }
        let first = rest[0].as_str();
        if let Some(&c) = self.modules[cur].children.get(first) {
            return self.resolve_in_module(c, &rest[1..], depth + 1);
        }
        if let Some(u) = self.modules[cur].uses.iter().find(|u| !u.glob && u.alias == first) {
            let mut p = u.path.clone();
            p.extend_from_slice(&rest[1..]);
            if u.extern_crate {
                return self.dep_names.contains(&u.path[0]).then(|| (u.path[0].clone(), p));
            }
            if p == rest {
                return self.dep_names.contains(first).then(|| (first.to_string(), rest.to_vec()));
            }
            return self.resolve_dep(cur, &p, depth + 1);
        }
        None
    }

    /// Paths (`a::b::C`) mentioned in a token slice: (segments, line, text).
    pub fn paths_in(toks: &[Token]) -> Vec<(Vec<String>, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < toks.len() {
            let t = &toks[i];
            let starts = t.kind == Kind::Ident && !(i > 0 && toks[i - 1].punct("::"));
            if !starts || (KEYWORDS.contains(&t.text.as_str()) && !matches!(t.text.as_str(), "crate" | "self" | "super")) {
                i += 1;
                continue;
            }
            let mut segs = vec![t.text.clone()];
            let line = t.line;
            let mut j = i + 1;
            while j + 1 < toks.len() && toks[j].punct("::") {
                if toks[j + 1].kind == Kind::Ident {
                    segs.push(toks[j + 1].text.clone());
                    j += 2;
                } else if toks[j + 1].punct("<") {
                    // turbofish: skip the generic args
                    j = matching_angle(toks, j + 1).map(|c| c + 1).unwrap_or(j + 2);
                } else {
                    break;
                }
            }
            // a lone ident followed by `:` in a bound list is a generic param name, not a path
            out.push((segs, line));
            i = j.max(i + 1);
        }
        out
    }

    /// What `#[doc(hidden)]` removes from the documented API: hidden items, the members of hidden
    /// types/traits, and everything inside a hidden module (`#[doc(hidden)] pub mod __private;`).
    pub fn hidden(&self) -> Hidden {
        let mut mods = vec![false; self.modules.len()];
        // parents are always created before their children
        for i in 1..self.modules.len() {
            let m = &self.modules[i];
            let p = m.parent.unwrap_or(0);
            let own = self.items.iter().any(|it| it.kind == ItemKind::Mod && it.module == p && it.name == m.name && it.docs.hidden);
            mods[i] = mods[p] || own;
        }
        let parents = self
            .items
            .iter()
            .filter(|i| i.docs.hidden && i.parent.is_none() && (i.kind.is_type() || i.kind == ItemKind::Trait))
            .map(|i| i.name.clone())
            .collect();
        Hidden { mods, parents }
    }

    pub fn reachable_items(&self) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(|i| i.reachable)
    }

    pub fn file_rel(&self, file: usize) -> &str {
        self.files.get(file).map(|f| f.rel.as_str()).unwrap_or("")
    }

    /// Every name defined anywhere in the crate (any visibility), for link resolution.
    pub fn all_names(&self) -> HashSet<String> {
        let mut s: HashSet<String> = self.items.iter().map(|i| i.name.clone()).collect();
        for m in &self.modules {
            s.insert(m.name.clone());
            for u in &m.uses {
                if !u.glob {
                    s.insert(u.alias.clone());
                }
            }
        }
        s
    }
}

/// Result of [`Surface::hidden`].
#[derive(Debug, Clone, Default)]
pub struct Hidden {
    /// Per module: hidden itself or inside a hidden module.
    pub mods: Vec<bool>,
    /// Names of hidden types and traits (their members are hidden too).
    pub parents: HashSet<String>,
}

impl Hidden {
    pub fn of(&self, it: &Item) -> bool {
        it.docs.hidden || self.mods.get(it.module).copied().unwrap_or(false) || it.parent.as_ref().is_some_and(|p| self.parents.contains(p))
    }
}

/// Last path segment before generic arguments in a type (`&mut a::B<T>` -> `B`).
pub fn base_type_name(toks: &[Token]) -> String {
    let mut last = String::new();
    for t in toks {
        if t.punct("<") || t.punct("(") || t.punct("[") {
            if !last.is_empty() {
                break;
            }
            continue;
        }
        if t.kind == Kind::Ident && !matches!(t.text.as_str(), "mut" | "dyn" | "const") {
            last = t.text.clone();
        }
    }
    last
}

// ------------------------------------------------------------------ targets

/// A dependency as declared by the analyzed crate.
#[derive(Debug, Clone)]
pub struct DepDecl {
    /// Name used in code (`extern crate` name, `-` replaced by `_`).
    pub extern_name: String,
    /// crates.io package name.
    pub package: String,
    pub req: String,
    /// Version in Cargo.lock (projects), or the newest version matching `req` (published crates).
    pub locked: Option<String>,
    pub optional: bool,
    pub registry: bool,
}

/// A library crate to analyze.
#[derive(Debug, Clone)]
pub struct LibTarget {
    pub name: String,
    pub version: String,
    pub dir: PathBuf,
    pub lib: PathBuf,
    pub deps: Vec<DepDecl>,
    pub local: bool,
}

/// Normal dependencies from a (normalized, published) Cargo.toml.
pub fn manifest_deps(root: &Path) -> Vec<DepDecl> {
    let Some(m) = rustsrc::manifest(root) else { return vec![] };
    let mut tables: Vec<&toml::Value> = Vec::new();
    if let Some(d) = m.get("dependencies") {
        tables.push(d);
    }
    if let Some(t) = m.get("target").and_then(|t| t.as_table()) {
        for v in t.values() {
            if let Some(d) = v.get("dependencies") {
                tables.push(d);
            }
        }
    }
    let mut out: Vec<DepDecl> = Vec::new();
    for tbl in tables {
        let Some(tbl) = tbl.as_table() else { continue };
        for (key, spec) in tbl {
            let (pkg, req, optional, registry) = match spec {
                toml::Value::String(s) => (key.clone(), s.clone(), false, true),
                toml::Value::Table(t) => (
                    t.get("package").and_then(|v| v.as_str()).unwrap_or(key).to_string(),
                    t.get("version").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                    t.get("optional").and_then(|v| v.as_bool()).unwrap_or(false),
                    t.get("path").is_none() && t.get("git").is_none() && t.get("registry").is_none(),
                ),
                _ => continue,
            };
            let ext = key.replace('-', "_");
            if out.iter().any(|d| d.extern_name == ext) {
                continue;
            }
            out.push(DepDecl { extern_name: ext, package: pkg, req, locked: None, optional, registry });
        }
    }
    out
}

/// Library crates named on the command line, or the project's library members
/// (`--package NAME` picks one).
pub fn lib_targets(ctx: &Ctx, args: &Args) -> Result<(String, Vec<LibTarget>)> {
    if !args.positional.is_empty() {
        let mut out = Vec::new();
        for p in &args.positional {
            let spec = CrateSpec::parse(p)?;
            let v = spec.resolve(ctx)?;
            let dir = crate::registry::download::unpacked(ctx, &v.name, &v.vers)?;
            let Some(lib) = rustsrc::lib_root(&dir) else {
                return Err(Error::Usage(format!("{}@{} has no library target", v.name, v.vers)));
            };
            let mut deps = manifest_deps(&dir);
            let names: Vec<String> = deps.iter().filter(|d| d.registry).map(|d| d.package.clone()).collect();
            let idx = crate::registry::index::versions_many(ctx, &names);
            for d in deps.iter_mut() {
                if let (Some(Some(vs)), Ok(req)) = (idx.get(&d.package), semver::VersionReq::parse(&d.req)) {
                    d.locked = crate::registry::index::best_match(vs, &req).map(|v| v.vers.clone());
                }
            }
            out.push(LibTarget { name: v.name.clone(), version: v.vers.clone(), dir, lib, deps, local: false });
        }
        let label = out.iter().map(|t| format!("{}@{}", t.name, t.version)).collect::<Vec<_>>().join(", ");
        return Ok((label, out));
    }
    let meta = Metadata::load(ctx, &MetaOpts::default())?;
    let want = args.value("package");
    let mut out = Vec::new();
    for p in meta.members() {
        if want.is_some_and(|w| util::normalize_crate_name(w) != util::normalize_crate_name(&p.name)) {
            continue;
        }
        let Some(lt) = p.targets.iter().find(|t| t.kind.iter().any(|k| matches!(k.as_str(), "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"))) else {
            continue;
        };
        let by_id = meta.by_id();
        let node = meta.node(&p.id);
        let mut deps = Vec::new();
        for d in &p.dependencies {
            if d.kind() != "normal" {
                continue;
            }
            let ext = d.rename.clone().unwrap_or_else(|| d.name.clone()).replace('-', "_");
            // the resolved edge gives the exact extern name and locked version
            let edge = node.and_then(|n| {
                n.deps.iter().find(|e| {
                    e.is_normal() && by_id.get(e.pkg.as_str()).is_some_and(|pk| pk.name == d.name) && (d.rename.is_none() || e.name == ext)
                })
            });
            let locked = edge.and_then(|e| by_id.get(e.pkg.as_str()).map(|pk| pk.version.clone()));
            let registry = edge.and_then(|e| by_id.get(e.pkg.as_str()).map(|pk| pk.is_crates_io())).unwrap_or(d.source.as_deref().is_some_and(|s| crate::registry::is_crates_io_source(Some(s))));
            let extern_name = edge.map(|e| e.name.clone()).unwrap_or(ext);
            if deps.iter().any(|x: &DepDecl| x.extern_name == extern_name) {
                continue;
            }
            deps.push(DepDecl { extern_name, package: d.name.clone(), req: d.req.clone(), locked, optional: d.optional, registry });
        }
        out.push(LibTarget { name: p.name.clone(), version: p.version.clone(), dir: p.dir(), lib: lt.src_path.clone(), deps, local: true });
    }
    if out.is_empty() {
        return Err(match want {
            Some(w) => Error::Usage(format!("no workspace member named `{w}` with a library target")),
            None => Error::Usage("the project has no library target to analyze (name a crate: NAME[@VERSION])".into()),
        });
    }
    let label = out.iter().map(|t| t.name.clone()).collect::<Vec<_>>().join(", ");
    Ok((format!("project {label}"), out))
}

// ------------------------------------------------------------------ stats

pub fn median(v: &[f64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 }
}

/// Median absolute deviation.
pub fn mad(v: &[f64]) -> f64 {
    let m = median(v);
    let d: Vec<f64> = v.iter().map(|x| (x - m).abs()).collect();
    median(&d)
}

/// `owner/repo` from a GitHub URL.
pub fn github_repo(url: &str) -> Option<String> {
    let u = url.trim().trim_end_matches('/').trim_end_matches(".git");
    let rest = u.split("github.com/").nth(1)?;
    let mut parts = rest.split('/');
    let o = parts.next()?;
    let r = parts.next()?;
    if o.is_empty() || r.is_empty() {
        return None;
    }
    Some(format!("{o}/{r}").to_ascii_lowercase())
}

/// Count crate occurrences by name.
pub fn count_by<K: Ord + Clone>(v: impl IntoIterator<Item = K>) -> BTreeMap<K, usize> {
    let mut m = BTreeMap::new();
    for k in v {
        *m.entry(k).or_insert(0) += 1;
    }
    m
}

/// Map from item name to items (for quick lookups).
pub fn by_name(s: &Surface) -> HashMap<&str, Vec<&Item>> {
    let mut m: HashMap<&str, Vec<&Item>> = HashMap::new();
    for i in &s.items {
        m.entry(i.name.as_str()).or_default().push(i);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(files: &[(&str, &str)], deps: &[&str]) -> Surface {
        let dir = util::temp_dir("surface").unwrap();
        for (p, c) in files {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        }
        let s = Surface::build(&dir, &dir.join("src/lib.rs"), deps.iter().map(|s| s.to_string()).collect());
        let _ = std::fs::remove_dir_all(&dir);
        s
    }

    fn item<'a>(s: &'a Surface, name: &str) -> &'a Item {
        s.items.iter().find(|i| i.name == name).unwrap_or_else(|| panic!("no item {name}"))
    }

    #[test]
    fn module_tree_and_reachability() {
        let s = build(
            &[
                ("src/lib.rs", "//! Crate docs\npub mod a;\nmod hidden;\n#[path = \"weird.rs\"]\npub mod w;\npub use hidden::Exported;\nmod inl { pub fn inner_pub() {} }\n#[cfg(test)]\nmod tests { pub fn t() {} }\n"),
                ("src/a.rs", "/// A docs\npub struct A { pub x: u8, y: u8 }\npub mod b;\npub(crate) fn restricted() {}\n"),
                ("src/a/b.rs", "pub enum E { One, Two(u8) }\n"),
                ("src/hidden/mod.rs", "pub struct Exported;\npub struct NotExported;\n"),
                ("src/weird.rs", "pub fn via_path() {}\n"),
            ],
            &[],
        );
        assert!(s.missing_modules.is_empty(), "{:?}", s.missing_modules);
        assert!(s.crate_docs.present && s.crate_docs.text.contains("Crate docs"));
        assert!(item(&s, "A").reachable && item(&s, "A").docs.present);
        assert!(item(&s, "x").reachable && !item(&s, "y").reachable);
        assert!(item(&s, "E").reachable && item(&s, "Two").reachable);
        assert!(item(&s, "Exported").reachable);
        assert!(!item(&s, "NotExported").reachable);
        assert!(item(&s, "via_path").reachable);
        assert!(!item(&s, "inner_pub").reachable);
        assert!(!item(&s, "restricted").reachable);
        assert!(!s.items.iter().any(|i| i.name == "t"), "cfg(test) skipped");
    }

    #[test]
    fn use_trees_and_dep_resolution() {
        let s = build(
            &[(
                "src/lib.rs",
                "use url::{Url as U, ParseError};\nuse serde_json as json;\nuse std::fmt;\npub use url;\nmod m { pub use super::U as Again; }\npub fn f(a: U, b: json::Value, c: fmt::Error, d: crate::m::Again) -> Result<(), ParseError> { todo!() }\n",
            )],
            &["url", "serde_json"],
        );
        let f = item(&s, "f");
        let mut deps = Vec::new();
        for site in &f.sites {
            for (p, _) in Surface::paths_in(&site.tokens) {
                if let Some((d, full)) = s.resolve_dep(f.module, &p, 0) {
                    deps.push(format!("{d}:{}", full.join("::")));
                }
            }
        }
        assert_eq!(deps, ["url:url::Url", "serde_json:serde_json::Value", "url:url::Url", "url:url::ParseError"]);
        assert!(f.returns_result);
        assert_eq!(f.panics.len(), 1);
    }

    #[test]
    fn panics_and_docs_attrs() {
        let s = build(
            &[(
                "src/lib.rs",
                "#![doc = \"Root\"]\n#[doc = \"Doc attr\"]\npub fn g(v: &[u8]) -> u8 { let a = vec![1]; let [x, y] = [1, 2]; v[0] + a.first().unwrap() + v[..].len() as u8 }\n#[doc(hidden)]\npub fn h() {}\npub trait T { /// m\n fn m(&self); type X: Clone; }\npub struct S;\nimpl S { pub fn new() -> Self { S } fn private() {} }\n",
            )],
            &[],
        );
        assert!(s.crate_docs.text.contains("Root"));
        let g = item(&s, "g");
        assert_eq!(g.docs.text, "Doc attr");
        let what: Vec<&str> = g.panics.iter().map(|p| p.1.as_str()).collect();
        assert_eq!(what, ["indexing", ".unwrap()"]);
        assert!(item(&s, "h").docs.hidden);
        assert!(item(&s, "m").reachable && item(&s, "m").docs.present);
        assert!(item(&s, "X").reachable);
        assert!(item(&s, "new").reachable && !item(&s, "private").reachable);
    }

    #[test]
    fn literals_and_stats() {
        assert_eq!(str_literal("\"a\\\"b\\n\"").unwrap(), "a\"b\n");
        assert_eq!(str_literal("r#\"x\"y\"#").unwrap(), "x\"y");
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(mad(&[1.0, 1.0, 2.0, 2.0, 4.0, 6.0, 9.0]), 1.0);
        assert_eq!(github_repo("https://github.com/Foo/bar.git").unwrap(), "foo/bar");
        assert_eq!(github_repo("https://gitlab.com/a/b"), None);
    }
}
