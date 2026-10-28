//! Doc Coverage & Link Check: Undocumented public items, missing rustdoc sections and broken intra-doc links.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::apieco_util::{self, Docs, ItemKind, LibTarget, Surface};
use crate::tools::{Group, Tool};
use crate::util;

pub struct DocsCov;

const OPTS: &[Opt] = &[
    Opt::value("package", "NAME", "Workspace member to analyze (default: every library member)"),
    Opt::value("min-coverage", "PCT", "High finding when documented public items are below PCT percent"),
    Opt::value("source", "WHERE", "Where the public API comes from: auto (default), nightly, docsrs, source"),
    Opt::value("rustdoc-json", "FILE", "Use this rustdoc JSON file (from `cargo +nightly rustdoc -- -Z unstable-options --output-format json`)"),
    Opt::flag("rustdoc", "Also run stable `cargo rustdoc` with missing_docs and intra-doc link lints (compiles the crate)"),
    Opt::value("max-items", "N", "Undocumented items listed in the table (default 25)"),
    Opt::value("max-findings", "N", "Findings reported per check before summarizing the rest (default 40)"),
];

/// Names that resolve in every crate without an import: std prelude items and primitives.
const PRELUDE: &[&str] = &[
    "Option", "Some", "None", "Result", "Ok", "Err", "Vec", "String", "Box", "ToString", "ToOwned", "Clone", "Copy", "Send", "Sync", "Sized", "Unpin",
    "Default", "Drop", "Fn", "FnMut", "FnOnce", "From", "Into", "TryFrom", "TryInto", "AsRef", "AsMut", "PartialEq", "Eq", "PartialOrd", "Ord",
    "Iterator", "IntoIterator", "DoubleEndedIterator", "ExactSizeIterator", "Extend", "FromIterator", "drop", "Debug", "Hash", "bool", "char",
    "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64", "slice", "array", "tuple", "unit",
    "pointer", "reference", "never", "fn", "self", "Self", "crate", "panic", "assert", "assert_eq", "assert_ne", "vec", "format", "println",
    "write", "writeln", "matches", "todo", "unimplemented", "unreachable", "include_str", "Future", "IntoFuture",
];

impl Tool for DocsCov {
    fn name(&self) -> &'static str {
        "docscov"
    }
    fn title(&self) -> &'static str {
        "Doc Coverage & Link Check"
    }
    fn group(&self) -> Group {
        Group::Api
    }
    fn summary(&self) -> &'static str {
        "Undocumented public items, missing # Safety/# Errors/# Panics sections and broken intra-doc links"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Measures documentation of a library's public API and checks it against rustdoc conventions, from
rustdoc's JSON output (the compiler's own view of the public API, after macro expansion and cfg):

  1. --rustdoc-json FILE, when given (output of `cargo +nightly rustdoc -- -Z unstable-options
     --output-format json`);
  2. a local nightly toolchain, when installed: `cargo +nightly rustdoc --lib -- -Z unstable-options
     --output-format json` in a temporary target directory (a published crate is first copied out
     of the download cache);
  3. docs.rs (named crates only): `https://docs.rs/crate/NAME/VERSION/json.gz`, the JSON docs.rs
     built for that release (available for releases built since 2025);
  4. otherwise the source model shared with `pubdeps` (module tree, `pub` chains and `pub use`
     re-exports, no macro expansion), and the report says so. --source picks one explicitly.

Public items are walked from the crate root through public modules, re-exports (including globs),
struct/union fields, enum variants and their fields, trait items and inherent impl items; trait impl
items are not counted (rustdoc's missing_docs does not require them), #[doc(hidden)] items are
excluded. Coverage is reported per module and per kind, with the undocumented items listed.

Intra-doc links: rustdoc JSON lists, for every item, the links it resolved. Every link-like target in
the item's docs (`[`Name`]`, `[Name::path]`, `[text](Name)`, `[text][label]`, `[label]: Name`) that
rustdoc did not resolve is a broken (or private) link, low docscov/broken-link. With the source model,
targets are resolved heuristically against names in the crate, the std prelude and dependencies.

Section checks (rustdoc/clippy conventions): pub `unsafe fn` and `unsafe trait` without a `# Safety`
heading (medium); documented pub fns returning a Result without `# Errors` (low); documented pub fns
whose own body can panic (panic!/assert!/unreachable!/todo!, .unwrap()/.expect(), indexing, found in
the source) without `# Panics` (low); crate docs without an `# Examples` heading or code example
(low), or no crate docs at all (low). --min-coverage PCT turns low coverage into a high finding, for
CI gates. --rustdoc additionally runs stable `cargo rustdoc` with -W missing_docs and the intra-doc
link lints and reports rustdoc's own diagnostics."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates docscov",
            "sm-crates docscov semver --min-coverage 90",
            "sm-crates docscov itoa --source docsrs",
            "sm-crates docscov itoa --rustdoc",
            "sm-crates docscov --rustdoc-json target/doc/my_lib.json",
            "sm-crates docscov --package core-lib --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crates.io; docs.rs for named crates); cargo for local projects; nightly toolchain optional"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let min_cov: Option<f64> = match args.value("min-coverage") {
            Some(v) => Some(v.trim_end_matches('%').parse().map_err(|_| Error::Usage(format!("invalid --min-coverage {v} (expected a percentage)")))?),
            None => None,
        };
        let source = Source::parse(args.value("source").unwrap_or("auto"))?;
        let json_file = args.value("rustdoc-json").map(std::path::PathBuf::from);
        let (subject, targets) = apieco_util::lib_targets(ctx, args)?;
        if json_file.is_some() && targets.len() > 1 {
            return Err(Error::Usage("--rustdoc-json applies to a single crate; pick one with --package or name one crate".into()));
        }
        let max_items: usize = args.parse_or("max-items", 25)?;
        let max_findings: usize = args.parse_or("max-findings", 40)?;
        let mut rep = Report::new("docscov", subject);
        let mut mod_table = Table::new("Coverage by module", &["Crate", "Module", "Items", "Documented", "Coverage"]);
        let mut kind_table = Table::new("Coverage by kind", &["Crate", "Kind", "Items", "Documented", "Coverage"]);
        let mut undoc_table = Table::new("Undocumented public items", &["Crate", "Item", "Kind", "Location"]);
        let mut data = Vec::new();
        let mut summary_parts = Vec::new();
        let mut findings: BTreeMap<&'static str, Vec<Finding>> = BTreeMap::new();
        let mut any_heuristic = false;
        for t in &targets {
            let dep_names = t.deps.iter().map(|d| d.extern_name.clone()).collect();
            let s = Surface::build(&t.dir, &t.lib, dep_names);
            let loc = |rel: &str| if t.local { util::rel(ctx.project_root(), &t.dir.join(rel)) } else { rel.to_string() };
            let model = match obtain_json(ctx, t, source, json_file.as_deref()) {
                Ok((doc, label)) => match from_rustdoc(&doc, &s, &label) {
                    Ok(m) => m,
                    Err(e) => {
                        rep.note(format!("{}: rustdoc JSON from {label} could not be used ({e}); using the source model", t.name));
                        from_surface(&s, &loc)
                    }
                },
                Err(why) => {
                    if source != Source::Heuristic {
                        rep.note(format!("{}: {why}; using the source model (heuristic)", t.name));
                    }
                    from_surface(&s, &loc)
                }
            };
            any_heuristic |= model.heuristic;
            if let Some(w) = &model.warning {
                rep.note(format!("{}: {w}", t.name));
            }
            let a = analyze(&model);
            for (path, (n, d)) in &a.by_module {
                mod_table.row([t.name.clone(), path.clone(), n.to_string(), d.to_string(), pct(*d, *n)]);
            }
            for (k, (n, d)) in &a.by_kind {
                kind_table.row([t.name.clone(), k.to_string(), n.to_string(), d.to_string(), pct(*d, *n)]);
            }
            for it in a.undocumented.iter().take(max_items) {
                undoc_table.row([t.name.clone(), it.path.clone(), it.kind.to_string(), it.location()]);
            }
            let cov = if a.total == 0 { 100.0 } else { 100.0 * a.documented as f64 / a.total as f64 };
            summary_parts.push(format!("{}@{}: {}/{} public items documented ({cov:.1}%, {})", t.name, t.version, a.documented, a.total, model.source));
            if let Some(min) = min_cov {
                if cov < min {
                    rep.finding(
                        Finding::new(Severity::High, "docscov/below-minimum", format!("doc coverage {cov:.1}% is below the required {min}% ({} of {} public items undocumented)", a.total - a.documented, a.total))
                            .krate(&t.name, Some(&t.version))
                            .fix("Document the items listed under 'Undocumented public items' (`#![warn(missing_docs)]` keeps it from regressing)"),
                    );
                }
            }
            let root = &model.items[0];
            if !root.documented {
                findings.entry("docscov/no-crate-docs").or_default().push(
                    Finding::new(Severity::Low, "docscov/no-crate-docs", "the crate root has no crate-level documentation (`//!`)")
                        .krate(&t.name, Some(&t.version))
                        .at(root.file.clone(), Some(1))
                        .fix("Add `//!` docs to the library root, or `#![doc = include_str!(\"../README.md\")]`"),
                );
            } else if !root.external_docs && !has_heading(&root.docs, &["example"]) && !has_code_block(&root.docs) {
                findings.entry("docscov/no-crate-examples").or_default().push(
                    Finding::new(Severity::Low, "docscov/no-crate-examples", "crate-level docs have no `# Examples` section or code example")
                        .krate(&t.name, Some(&t.version))
                        .at(root.file.clone(), Some(root.line.max(1)))
                        .fix("Add an `# Examples` section with a short doctest to the crate docs"),
                );
            }
            for (code, it, msg, fix) in a.section_issues {
                let sev = if code == "docscov/missing-safety" { Severity::Medium } else { Severity::Low };
                findings.entry(code).or_default().push(Finding::new(sev, code, msg).krate(&t.name, Some(&t.version)).at(it.file.clone(), Some(it.line)).fix(fix));
            }
            for l in &model.links {
                findings.entry("docscov/broken-link").or_default().push(
                    Finding::new(Severity::Low, "docscov/broken-link", format!("intra-doc link `{}` in the docs of {} does not resolve", l.target, l.owner))
                        .krate(&t.name, Some(&t.version))
                        .at(l.file.clone(), Some(l.line))
                        .detail(if model.heuristic {
                            "Heuristic check (source model); run with --rustdoc or a nightly toolchain for rustdoc's result".to_string()
                        } else {
                            "rustdoc did not resolve this link: the target does not exist, is private, or is ambiguous".to_string()
                        })
                        .fix("Fix the path (e.g. `crate::module::Item`), import the item, or escape the brackets (`\\[x\\]`)"),
                );
            }
            let mut rustdoc_json = Value::Null;
            if args.flag("rustdoc") {
                match run_rustdoc(ctx, t) {
                    Ok(r) => {
                        for f in r.findings(t) {
                            findings.entry(f.0).or_default().push(f.1);
                        }
                        rustdoc_json = r.to_json();
                    }
                    Err(e) => rep.note(format!("{}: --rustdoc could not run: {e}", t.name)),
                }
            }
            data.push(json!({
                "crate": t.name,
                "version": t.version,
                "source": model.source,
                "format_version": model.format_version,
                "items": a.total,
                "documented": a.documented,
                "coverage": (cov * 10.0).round() / 10.0,
                "crate_docs": root.documented,
                "by_kind": a.by_kind.iter().map(|(k, (n, d))| json!({"kind": k, "items": n, "documented": d})).collect::<Vec<_>>(),
                "by_module": a.by_module.iter().map(|(m, (n, d))| json!({"module": m, "items": n, "documented": d})).collect::<Vec<_>>(),
                "undocumented": a.undocumented.iter().map(|i| json!({"item": i.path, "kind": i.kind, "file": i.file, "line": i.line})).collect::<Vec<_>>(),
                "broken_links": model.links.iter().map(|l| json!({"target": l.target, "in": l.owner, "file": l.file, "line": l.line})).collect::<Vec<_>>(),
                "missing_modules": s.missing_modules,
                "rustdoc": rustdoc_json,
            }));
        }
        for (code, list) in findings {
            let n = list.len();
            for f in list.into_iter().take(max_findings) {
                rep.finding(f);
            }
            if n > max_findings {
                rep.note(format!("{code}: {} more finding(s) not shown (raise --max-findings)", n - max_findings));
            }
        }
        rep.summary(summary_parts.join("; "));
        rep.table(kind_table);
        rep.table(mod_table);
        rep.table(undoc_table);
        if any_heuristic {
            rep.note("Source model: heuristic (no macro expansion); install a nightly toolchain or use --rustdoc-json for rustdoc's own view.");
        }
        rep.note("# Errors / # Panics are only checked on documented items; undocumented items are counted in coverage instead.");
        rep.data = json!({"crates": data});
        Ok(rep)
    }
}

fn pct(d: usize, n: usize) -> String {
    if n == 0 { "-".into() } else { format!("{:.1}%", 100.0 * d as f64 / n as f64) }
}

/// Markdown headings (outside code fences), lowercased.
fn headings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fence = false;
    for l in text.lines() {
        let t = l.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fence = !fence;
            continue;
        }
        if !fence && t.starts_with('#') {
            out.push(t.trim_start_matches('#').trim().to_ascii_lowercase());
        }
    }
    out
}

fn has_heading(text: &str, words: &[&str]) -> bool {
    headings(text).iter().any(|h| words.iter().any(|w| h.contains(w)))
}

fn has_code_block(text: &str) -> bool {
    let mut open = false;
    for l in text.lines() {
        let t = l.trim_start();
        if !t.starts_with("```") {
            continue;
        }
        if !open && !["text", "sh", "bash", "toml", "console", "shell", "json", "yaml"].iter().any(|x| t[3..].trim().starts_with(x)) {
            return true;
        }
        open = !open;
    }
    false
}

// ------------------------------------------------------------------ common model

/// One public item, from rustdoc JSON or the source model.
#[derive(Debug, Clone, Default)]
pub struct DocItem {
    /// `crate`, `crate::a::Type`, `Type::method`, `Type.field`.
    pub path: String,
    pub kind: &'static str,
    /// Module the item is listed under.
    pub module: String,
    pub documented: bool,
    pub docs: String,
    pub external_docs: bool,
    pub file: String,
    pub line: usize,
    pub is_unsafe: bool,
    pub returns_result: bool,
    pub panics: Vec<(usize, String)>,
}

impl DocItem {
    fn location(&self) -> String {
        if self.file.is_empty() { "-".into() } else { format!("{}:{}", self.file, self.line) }
    }
    fn is_fn(&self) -> bool {
        matches!(self.kind, "fn" | "method" | "trait method")
    }
}

/// The documented surface of one crate. `items[0]` is the crate root.
#[derive(Debug, Clone, Default)]
pub struct DocModel {
    pub source: String,
    pub heuristic: bool,
    pub format_version: Option<u64>,
    pub items: Vec<DocItem>,
    pub links: Vec<BadLink>,
    /// Caveat about the data (e.g. a rustdoc JSON format newer than this tool knows).
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Auto,
    Nightly,
    DocsRs,
    Heuristic,
}

impl Source {
    fn parse(s: &str) -> Result<Source> {
        match s {
            "auto" => Ok(Source::Auto),
            "nightly" | "rustdoc" => Ok(Source::Nightly),
            "docsrs" | "docs.rs" => Ok(Source::DocsRs),
            "source" | "heuristic" => Ok(Source::Heuristic),
            _ => Err(Error::Usage(format!("invalid --source {s} (expected auto, nightly, docsrs or source)"))),
        }
    }
}

/// The source model as a [`DocModel`].
fn from_surface(s: &Surface, loc: &dyn Fn(&str) -> String) -> DocModel {
    let hidden = s.hidden();
    let mut items = vec![DocItem {
        path: "crate".into(),
        kind: "crate",
        module: "crate".into(),
        documented: s.crate_docs.present,
        docs: s.crate_docs.text.clone(),
        external_docs: s.crate_docs.external,
        file: loc(s.file_rel(0)),
        line: s.crate_docs.line,
        ..Default::default()
    }];
    for it in s.reachable_items() {
        if hidden.of(it) {
            continue;
        }
        let module = if it.kind == ItemKind::Mod { format!("{}::{}", s.modules[it.module].path, it.name) } else { s.modules[it.module].path.clone() };
        items.push(DocItem {
            path: it.display(),
            kind: it.kind.as_str(),
            module,
            documented: it.docs.present,
            docs: it.docs.text.clone(),
            external_docs: it.docs.external,
            file: loc(s.file_rel(it.file)),
            line: it.line,
            is_unsafe: it.is_unsafe,
            returns_result: it.returns_result,
            panics: it.panics.clone(),
        });
    }
    let links = check_links(s).into_iter().map(|mut l| {
        l.file = loc(&l.file);
        l
    });
    DocModel { source: "source model".into(), heuristic: true, format_version: None, items, links: links.collect(), warning: None }
}

#[derive(Default)]
struct Analysis<'s> {
    total: usize,
    documented: usize,
    by_kind: BTreeMap<&'static str, (usize, usize)>,
    by_module: BTreeMap<String, (usize, usize)>,
    undocumented: Vec<&'s DocItem>,
    section_issues: Vec<(&'static str, &'s DocItem, String, String)>,
}

fn analyze(m: &DocModel) -> Analysis<'_> {
    let mut a = Analysis::default();
    for it in &m.items {
        a.total += 1;
        a.documented += usize::from(it.documented);
        let e = a.by_kind.entry(it.kind).or_insert((0, 0));
        e.0 += 1;
        e.1 += usize::from(it.documented);
        let e = a.by_module.entry(it.module.clone()).or_insert((0, 0));
        e.0 += 1;
        e.1 += usize::from(it.documented);
        if !it.documented && it.kind != "crate" {
            a.undocumented.push(it);
        }
        section_checks(it, &mut a.section_issues);
    }
    a
}

fn section_checks<'s>(it: &'s DocItem, out: &mut Vec<(&'static str, &'s DocItem, String, String)>) {
    if it.external_docs {
        return;
    }
    let what = format!("{} `{}`", it.kind, it.path);
    if it.is_unsafe && (it.is_fn() || it.kind == "trait") && !has_heading(&it.docs, &["safety"]) {
        out.push((
            "docscov/missing-safety",
            it,
            format!("public unsafe {what} has no `# Safety` section"),
            "Add a `# Safety` section listing the invariants callers must uphold".into(),
        ));
    }
    if !it.documented || !it.is_fn() {
        return;
    }
    if it.returns_result && !has_heading(&it.docs, &["error"]) {
        out.push((
            "docscov/missing-errors",
            it,
            format!("{what} returns a Result but its docs have no `# Errors` section"),
            "Add an `# Errors` section describing when an error is returned".into(),
        ));
    }
    if !it.panics.is_empty() && !has_heading(&it.docs, &["panic"]) {
        let sites: Vec<String> = it.panics.iter().take(3).map(|(l, w)| format!("{w} at line {l}")).collect();
        out.push((
            "docscov/missing-panics",
            it,
            format!("{what} can panic ({}) but its docs have no `# Panics` section", sites.join(", ")),
            "Add a `# Panics` section, or return an error instead of panicking".into(),
        ));
    }
}

/// An intra-doc link that did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadLink {
    pub target: String,
    pub owner: String,
    pub file: String,
    pub line: usize,
}

/// Normalize a link target to path segments, or `None` if it is not path-like.
fn link_path(raw: &str) -> Option<Vec<String>> {
    let mut t = raw.trim().trim_matches('`').trim();
    if let Some((pre, rest)) = t.split_once('@') {
        if pre.chars().all(|c| c.is_ascii_lowercase()) {
            t = rest;
        }
    }
    let t = t.trim_end_matches("()").trim_end_matches('!');
    // strip generic arguments: Vec<T> -> Vec
    let t = match t.find('<') {
        Some(p) if t.ends_with('>') => &t[..p],
        _ => t,
    };
    let t = t.trim_start_matches("::");
    if t.is_empty() {
        return None;
    }
    let segs: Vec<String> = t.split("::").map(str::to_string).collect();
    let ok = segs.iter().all(|s| {
        let mut c = s.chars();
        c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
    });
    ok.then_some(segs)
}

/// Link targets in a doc text: (target text, line offset within the text).
fn link_targets(text: &str) -> Vec<(String, usize)> {
    let mut defs: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    let mut fence = false;
    let lines: Vec<&str> = text.lines().collect();
    // reference definitions first
    for l in &lines {
        let t = l.trim_start();
        if t.starts_with("```") {
            fence = !fence;
            continue;
        }
        if fence {
            continue;
        }
        if let Some(rest) = t.strip_prefix('[') {
            if let Some((label, after)) = rest.split_once("]:") {
                defs.insert(label.trim().to_ascii_lowercase());
                let dest = after.trim().split_whitespace().next().unwrap_or("");
                if !dest.contains("://") && !dest.starts_with('#') && !dest.contains('.') && !dest.contains('/') {
                    out.push((dest.to_string(), usize::MAX)); // line fixed below
                }
            }
        }
    }
    // fix def lines
    let mut fixed = Vec::new();
    for (dest, _) in out.drain(..) {
        let line = lines.iter().position(|l| l.contains(&format!("]: {dest}")) || l.contains(&format!("]:{dest}"))).unwrap_or(0);
        fixed.push((dest, line));
    }
    out = fixed;
    fence = false;
    for (n, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fence = !fence;
            continue;
        }
        if fence || (t.starts_with('[') && t.contains("]:")) {
            continue;
        }
        // drop inline code spans that are not inside brackets: replace `...` outside [] by spaces
        let b: Vec<char> = l.chars().collect();
        let mut i = 0;
        while i < b.len() {
            if b[i] == '\\' {
                i += 2;
                continue;
            }
            if b[i] == '`' && !(i > 0 && b[i - 1] == '[') {
                // skip a code span
                let mut j = i + 1;
                while j < b.len() && b[j] != '`' {
                    j += 1;
                }
                i = j + 1;
                continue;
            }
            if b[i] != '[' {
                i += 1;
                continue;
            }
            // find matching ]
            let mut depth = 0;
            let mut j = i;
            while j < b.len() {
                if b[j] == '[' {
                    depth += 1;
                } else if b[j] == ']' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j >= b.len() {
                break;
            }
            let label: String = b[i + 1..j].iter().collect();
            let next = b.get(j + 1).copied();
            match next {
                Some('(') => {
                    let close = b[j + 1..].iter().position(|&c| c == ')').map(|p| p + j + 1).unwrap_or(b.len());
                    let dest: String = b[j + 2..close.min(b.len())].iter().collect();
                    let dest = dest.trim().split_whitespace().next().unwrap_or("").to_string();
                    if !dest.is_empty() && !dest.contains("://") && !dest.starts_with('#') && !dest.contains('/') && !dest.contains('.') && !dest.starts_with("mailto:") {
                        out.push((dest, n));
                    }
                    i = close + 1;
                    continue;
                }
                Some('[') => {
                    let close = b[j + 1..].iter().position(|&c| c == ']').map(|p| p + j + 1).unwrap_or(b.len());
                    let lab: String = b[j + 2..close.min(b.len())].iter().collect();
                    let lab = if lab.is_empty() { label.clone() } else { lab };
                    if !defs.contains(&lab.to_ascii_lowercase()) {
                        out.push((lab, n));
                    }
                    i = close + 1;
                    continue;
                }
                _ => {
                    if !defs.contains(&label.to_ascii_lowercase()) {
                        let ticked = label.starts_with('`') && label.ends_with('`') && label.len() > 2;
                        let pathy = label.contains("::") || label.ends_with("()") || label.ends_with('!') || label.contains('@');
                        if (ticked || pathy) && !label.contains(' ') {
                            out.push((label, n));
                        }
                    }
                }
            }
            i = j + 1;
        }
    }
    out
}

/// Heuristic intra-doc link check over every documented item.
pub fn check_links(s: &Surface) -> Vec<BadLink> {
    let names = s.all_names();
    let deps: HashSet<&str> = s.dep_names.iter().map(|d| d.as_str()).collect();
    let known = |n: &str| names.contains(n) || PRELUDE.contains(&n);
    let resolves = |segs: &[String]| -> bool {
        let first = segs[0].as_str();
        let last = segs[segs.len() - 1].as_str();
        match first {
            "std" | "core" | "alloc" | "proc_macro" | "test" => true,
            "crate" | "self" | "super" | "Self" => segs.len() == 1 || known(last),
            _ if deps.contains(first) => true,
            _ if segs.len() == 1 => known(first),
            _ => {
                if names.contains(first) {
                    known(last) || deps.contains(first)
                } else {
                    PRELUDE.contains(&first)
                }
            }
        }
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut check = |docs: &Docs, owner: String, file: usize| {
        if !docs.present {
            return;
        }
        for (target, off) in link_targets(&docs.text) {
            let Some(segs) = link_path(&target) else { continue };
            if resolves(&segs) {
                continue;
            }
            let line = docs.line + off;
            if seen.insert((target.clone(), file, line)) {
                out.push(BadLink { target: target.trim_matches('`').to_string(), owner: owner.clone(), file: s.file_rel(file).to_string(), line });
            }
        }
    };
    check(&s.crate_docs, "the crate root".into(), 0);
    for it in &s.items {
        check(&it.docs, format!("{} `{}`", it.kind.as_str(), it.display()), it.file);
    }
    out
}

// ------------------------------------------------------------------ --rustdoc

#[derive(Debug, Default)]
struct RustdocResult {
    /// (lint, message, file, line)
    diags: Vec<(String, String, String, Option<usize>)>,
    ok: bool,
}

impl RustdocResult {
    fn to_json(&self) -> Value {
        let counts = apieco_util::count_by(self.diags.iter().map(|d| d.0.clone()));
        json!({
            "ok": self.ok,
            "counts": counts,
            "diagnostics": self.diags.iter().map(|(l, m, f, n)| json!({"lint": l, "message": m, "file": f, "line": n})).collect::<Vec<_>>(),
        })
    }

    fn findings(&self, t: &LibTarget) -> Vec<(&'static str, Finding)> {
        let mut out = Vec::new();
        let missing: Vec<&(String, String, String, Option<usize>)> = self.diags.iter().filter(|d| d.0 == "missing_docs").collect();
        if let Some(first) = missing.first() {
            out.push((
                "docscov/rustdoc-missing-docs",
                Finding::new(Severity::Info, "docscov/rustdoc-missing-docs", format!("rustdoc: {} public item(s) are missing documentation", missing.len()))
                    .krate(&t.name, Some(&t.version))
                    .at(first.2.clone(), first.3)
                    .detail(missing.iter().take(5).map(|d| format!("{}:{} {}", d.2, d.3.unwrap_or(0), d.1)).collect::<Vec<_>>().join("\n"))
                    .fix("Add `#![warn(missing_docs)]` to the crate root and document these items"),
            ));
        }
        for d in self.diags.iter().filter(|d| d.0 != "missing_docs") {
            let (code, sev): (&'static str, Severity) = match d.0.as_str() {
                "rustdoc::broken_intra_doc_links" => ("docscov/rustdoc-broken-link", Severity::Low),
                "rustdoc::private_intra_doc_links" => ("docscov/rustdoc-private-link", Severity::Low),
                _ => ("docscov/rustdoc-warning", Severity::Info),
            };
            out.push((
                code,
                Finding::new(sev, code, format!("rustdoc: {}", d.1))
                    .krate(&t.name, Some(&t.version))
                    .at(d.2.clone(), d.3)
                    .detail(format!("lint {}", d.0))
                    .fix("Fix the link target or make it point to a public item"),
            ));
        }
        out
    }
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    for f in util::walk_files(from) {
        let rel = f.strip_prefix(from).unwrap_or(&f);
        let dest = to.join(rel);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::copy(&f, &dest)?;
    }
    Ok(())
}

fn run_rustdoc(ctx: &Ctx, t: &LibTarget) -> Result<RustdocResult> {
    let tmp = util::temp_dir("docscov")?;
    let target_dir = tmp.join("target");
    let mut cmd = Command::new(&ctx.cargo);
    cmd.args(["rustdoc", "--lib", "--message-format", "json"]);
    let workdir = if t.local {
        cmd.arg("--manifest-path").arg(ctx.manifest_path()).args(["-p", &format!("{}@{}", t.name, t.version)]);
        ctx.project_root().to_path_buf()
    } else {
        // never let cargo write a Cargo.lock into the shared source cache
        let dir = tmp.join("src");
        copy_dir(&t.dir, &dir)?;
        dir
    };
    if ctx.offline {
        cmd.arg("--offline");
    }
    cmd.args(["--", "-W", "missing_docs", "-W", "rustdoc::broken_intra_doc_links", "-W", "rustdoc::private_intra_doc_links"]);
    cmd.current_dir(&workdir).env("CARGO_TARGET_DIR", &target_dir).env_remove("RUSTDOCFLAGS");
    let out = util::run(&mut cmd, Duration::from_secs(1200));
    let _ = std::fs::remove_dir_all(&tmp);
    let out = out?;
    if out.timed_out {
        return Err(Error::Env("cargo rustdoc timed out after 20 minutes".into()));
    }
    let mut r = RustdocResult { ok: out.success(), ..Default::default() };
    let lib_name = t.name.replace('-', "_");
    for line in out.stdout.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        if v["reason"] != "compiler-message" {
            continue;
        }
        if v["target"]["name"].as_str().is_some_and(|n| n.replace('-', "_") != lib_name) {
            continue;
        }
        let msg = &v["message"];
        let level = msg["level"].as_str().unwrap_or("");
        if level != "warning" && level != "error" {
            continue;
        }
        let Some(lint) = msg["code"]["code"].as_str() else { continue };
        let span = msg["spans"].as_array().and_then(|s| s.iter().find(|x| x["is_primary"] == true).or(s.first()));
        let file = span.and_then(|s| s["file_name"].as_str()).unwrap_or("").to_string();
        let file = if t.local { file } else { file.trim_start_matches(&format!("{}/", workdir.display())).to_string() };
        let line_no = span.and_then(|s| s["line_start"].as_u64()).map(|n| n as usize);
        r.diags.push((lint.to_string(), msg["message"].as_str().unwrap_or("").to_string(), file, line_no));
    }
    if !r.ok && r.diags.is_empty() {
        let tail: Vec<&str> = out.stderr.lines().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect();
        return Err(Error::Env(format!("cargo rustdoc failed:\n{}", tail.join("\n"))));
    }
    Ok(r)
}

// ------------------------------------------------------------------ rustdoc JSON

/// Whether `cargo +nightly` works (checked once per run).
fn nightly_available(ctx: &Ctx) -> bool {
    static NIGHTLY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *NIGHTLY.get_or_init(|| {
        util::run(Command::new(&ctx.cargo).args(["+nightly", "--version"]), Duration::from_secs(60)).is_ok_and(|o| o.success())
    })
}

/// rustdoc JSON for a target and a label of where it came from; `Err` explains why none is available.
fn obtain_json(ctx: &Ctx, t: &LibTarget, source: Source, file: Option<&Path>) -> std::result::Result<(Value, String), String> {
    if let Some(f) = file {
        let text = std::fs::read(f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        let v = serde_json::from_slice(&text).map_err(|e| format!("{} is not rustdoc JSON: {e}", f.display()))?;
        return Ok((v, f.display().to_string()));
    }
    match source {
        Source::Heuristic => Err("source model requested".into()),
        Source::Nightly => nightly_json(ctx, t).map(|v| (v, "local nightly rustdoc".into())),
        Source::DocsRs => docsrs_json(ctx, t).map(|v| (v, "docs.rs".into())),
        Source::Auto => {
            if nightly_available(ctx) {
                match nightly_json(ctx, t) {
                    Ok(v) => return Ok((v, "local nightly rustdoc".into())),
                    Err(e) if t.local => return Err(e),
                    Err(_) => {}
                }
            }
            if t.local {
                return Err("no nightly toolchain for rustdoc JSON (rustup toolchain install nightly)".into());
            }
            docsrs_json(ctx, t).map(|v| (v, "docs.rs".into()))
        }
    }
}

fn nightly_json(ctx: &Ctx, t: &LibTarget) -> std::result::Result<Value, String> {
    if !nightly_available(ctx) {
        return Err("no nightly toolchain for rustdoc JSON (rustup toolchain install nightly)".into());
    }
    let tmp = util::temp_dir("docscov-json").map_err(|e| e.to_string())?;
    let target_dir = tmp.join("target");
    let mut cmd = Command::new(&ctx.cargo);
    cmd.args(["+nightly", "rustdoc", "--lib", "-q"]);
    let workdir = if t.local {
        cmd.arg("--manifest-path").arg(ctx.manifest_path()).args(["-p", &format!("{}@{}", t.name, t.version)]);
        ctx.project_root().to_path_buf()
    } else {
        let dir = tmp.join("src");
        copy_dir(&t.dir, &dir).map_err(|e| e.to_string())?;
        dir
    };
    if ctx.offline {
        cmd.arg("--offline");
    }
    cmd.args(["--", "-Z", "unstable-options", "--output-format", "json"]);
    cmd.current_dir(&workdir).env("CARGO_TARGET_DIR", &target_dir).env_remove("RUSTDOCFLAGS");
    let out = util::run(&mut cmd, Duration::from_secs(1200));
    let result = (|| {
        let out = out.map_err(|e| e.to_string())?;
        if !out.success() {
            let tail: Vec<&str> = out.stderr.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
            return Err(format!("nightly rustdoc failed: {}", tail.join(" | ")));
        }
        let doc = target_dir.join("doc");
        let want = format!("{}.json", t.name.replace('-', "_"));
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&doc).map_err(|e| e.to_string())?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
        files.sort();
        let f = files.iter().find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == want)).or(files.first()).ok_or("nightly rustdoc wrote no JSON file")?;
        let data = std::fs::read(f).map_err(|e| e.to_string())?;
        serde_json::from_slice(&data).map_err(|e| format!("bad rustdoc JSON: {e}"))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

fn docsrs_json(ctx: &Ctx, t: &LibTarget) -> std::result::Result<Value, String> {
    if t.local {
        return Err("docs.rs has no JSON for local code".into());
    }
    let url = format!("{}/crate/{}/{}/json.gz", ctx.endpoints.docsrs, t.name, t.version);
    let r = ctx.http.get(&url, crate::http::Ttl::DAY).map_err(|e| format!("docs.rs is unreachable ({e})"))?;
    match r.status {
        200..=299 => {}
        404 | 410 => return Err(format!("docs.rs has no rustdoc JSON for {}@{} (built before docs.rs produced JSON, or the build failed)", t.name, t.version)),
        s => return Err(format!("docs.rs returned HTTP {s} for {url}")),
    }
    let body = if r.body.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&r.body[..]), &mut out).map_err(|e| format!("bad gzip from docs.rs: {e}"))?;
        out
    } else {
        r.body
    };
    serde_json::from_slice(&body).map_err(|e| format!("docs.rs JSON could not be parsed: {e}"))
}

fn id_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// `(variant, payload)` of an item's externally tagged `inner`.
fn inner_of(item: &Value) -> Option<(&str, &Value)> {
    match &item["inner"] {
        Value::Object(m) if m.len() == 1 => m.iter().next().map(|(k, v)| (k.as_str(), v)),
        Value::String(s) => Some((s.as_str(), &Value::Null)),
        _ => None,
    }
}

fn type_is_result(t: &Value) -> bool {
    let p = &t["resolved_path"];
    let name = p["path"].as_str().or_else(|| p["name"].as_str()).unwrap_or("");
    name == "Result" || name.ends_with("::Result")
}

fn canon_link(raw: &str) -> Option<String> {
    link_path(raw).map(|s| s.join("::"))
}

struct Walker<'a> {
    index: &'a serde_json::Map<String, Value>,
    local: Option<u64>,
    seen: HashSet<String>,
    /// Public names of re-exported items (`pub use a::B as C`).
    renamed: HashMap<String, String>,
    items: Vec<DocItem>,
    links: Vec<BadLink>,
    /// Source-model fns by name, for panic sites (rustdoc JSON has no bodies).
    fns: HashMap<&'a str, Vec<(&'a str, usize, &'a [(usize, String)])>>,
    /// Package directory, to place broken links on their real source line.
    root: &'a Path,
    sources: HashMap<String, Option<Vec<String>>>,
}

#[derive(Clone)]
enum Parent {
    None,
    Type(String),
    Trait(String),
}

impl<'a> Walker<'a> {
    fn get(&self, id: &str) -> Option<&'a Value> {
        let it = self.index.get(id)?;
        if self.local.is_some_and(|l| it["crate_id"].as_u64() != Some(l)) {
            return None;
        }
        Some(it)
    }

    fn ids(v: &Value) -> Vec<String> {
        v.as_array().map(|a| a.iter().filter_map(id_key).collect()).unwrap_or_default()
    }

    fn span(it: &Value) -> (String, usize) {
        let f = it["span"]["filename"].as_str().unwrap_or("");
        let f = f.rsplit_once("/workdir/").map(|x| x.1).unwrap_or(f).to_string();
        (f, it["span"]["begin"][0].as_u64().unwrap_or(0) as usize)
    }

    fn push(&mut self, it: &Value, path: String, kind: &'static str, module: &str) -> usize {
        let docs = it["docs"].as_str().unwrap_or("").to_string();
        let (file, line) = Self::span(it);
        // links rustdoc resolved, keyed by their normalized target
        let resolved: HashSet<String> = it["links"].as_object().map(|m| m.keys().filter_map(|k| canon_link(k)).collect()).unwrap_or_default();
        let mut seen = HashSet::new();
        for (target, off) in link_targets(&docs) {
            let Some(c) = canon_link(&target) else { continue };
            if resolved.contains(&c) || !seen.insert(c) {
                continue;
            }
            // the span starts at the item, not at its docs (and covers the whole file for a module):
            // find the doc line that holds the link, falling back to an estimate
            let estimate = line.saturating_sub(docs.lines().count()).max(1) + off.min(docs.lines().count());
            let at = self.doc_line(&file, &target, line).unwrap_or(estimate);
            self.links.push(BadLink { target: target.trim_matches('`').to_string(), owner: if kind == "crate" { "the crate root".into() } else { format!("{kind} `{path}`") }, file: file.clone(), line: at });
        }
        self.items.push(DocItem { path, kind, module: module.to_string(), documented: !docs.trim().is_empty(), docs, external_docs: false, file, line, ..Default::default() });
        self.items.len() - 1
    }

    /// 1-based line of the doc comment in `file` that contains `target`, nearest to `near`
    /// (preferring lines before it, where outer docs live).
    fn doc_line(&mut self, file: &str, target: &str, near: usize) -> Option<usize> {
        if file.is_empty() {
            return None;
        }
        let root = self.root;
        let lines = self.sources.entry(file.to_string()).or_insert_with(|| {
            let p = Path::new(file);
            let cand = if p.is_absolute() { p.to_path_buf() } else { root.join(p) };
            std::fs::read_to_string(cand).ok().map(|t| t.lines().map(str::to_string).collect())
        });
        let lines = lines.as_ref()?;
        let is_doc = |l: &str| {
            let t = l.trim_start();
            t.starts_with("///") || t.starts_with("//!") || t.starts_with("#[doc") || t.starts_with("#![doc") || t.starts_with('*') || t.starts_with("/**") || t.starts_with("/*!")
        };
        // the link syntax first (`[target]`, `(target)`, `]: target`), so a code span with the same
        // text elsewhere in the docs does not win
        let forms = [format!("[{target}]"), format!("({target})"), format!("]: {target}")];
        let pick = |strict: bool| {
            lines
                .iter()
                .enumerate()
                .filter(|(_, l)| is_doc(l) && if strict { forms.iter().any(|f| l.contains(f.as_str())) } else { l.contains(target) })
                .map(|(i, _)| i + 1)
                .min_by_key(|&n| if n <= near { (near - n) * 2 } else { (n - near) * 2 + 1 })
        };
        pick(true).or_else(|| pick(false))
    }

    fn walk(&mut self, id: &str, module: &str, parent: &Parent) {
        if !self.seen.insert(id.to_string()) {
            return;
        }
        let Some(it) = self.get(id) else { return };
        let Some((kind, inner)) = inner_of(it) else { return };
        let name = self.renamed.get(id).cloned().unwrap_or_else(|| it["name"].as_str().unwrap_or("").to_string());
        let qual = |sep: &str| match parent {
            Parent::Type(p) | Parent::Trait(p) => format!("{p}{sep}{name}"),
            Parent::None => if module == "crate" { name.clone() } else { format!("{}::{name}", module.trim_start_matches("crate::")) },
        };
        match kind {
            "module" => {
                if inner["is_stripped"].as_bool() == Some(true) {
                    return;
                }
                let root = inner["is_crate"].as_bool() == Some(true);
                let path = if root { "crate".to_string() } else { format!("{module}::{name}") };
                self.push(it, if root { "crate".into() } else { path.trim_start_matches("crate::").to_string() }, if root { "crate" } else { "mod" }, &path);
                for c in Self::ids(&inner["items"]) {
                    self.walk(&c, &path, &Parent::None);
                }
            }
            // `import` / `glob` before format 34
            "use" | "import" => {
                let Some(target) = id_key(&inner["id"]) else { return };
                if inner["is_glob"].as_bool().or_else(|| inner["glob"].as_bool()) == Some(true) {
                    let Some(t) = self.get(&target) else { return };
                    match inner_of(t) {
                        Some(("module", m)) => {
                            for c in Self::ids(&m["items"]) {
                                self.walk(&c, module, &Parent::None);
                            }
                        }
                        Some(("enum", e)) => {
                            for c in Self::ids(&e["variants"]) {
                                self.walk(&c, module, &Parent::None);
                            }
                        }
                        _ => {}
                    }
                } else {
                    if let Some(n) = inner["name"].as_str() {
                        self.renamed.entry(target.clone()).or_insert_with(|| n.to_string());
                    }
                    self.walk(&target, module, &Parent::None);
                }
            }
            "struct" | "union" | "enum" => {
                let path = qual("::");
                self.push(it, path.clone(), match kind { "struct" => "struct", "union" => "union", _ => "enum" }, module);
                let me = Parent::Type(name.clone());
                let fields = if kind == "union" { Self::ids(&inner["fields"]) } else { Self::ids(&inner["kind"]["plain"]["fields"]) };
                for f in fields {
                    self.walk(&f, module, &me);
                }
                for v in Self::ids(&inner["variants"]) {
                    self.walk(&v, module, &me);
                }
                for imp in Self::ids(&inner["impls"]) {
                    self.walk_impl(&imp, module, &name);
                }
            }
            "variant" => {
                let path = qual("::");
                self.push(it, path.clone(), "variant", module);
                let me = Parent::Type(path);
                for f in Self::ids(&inner["kind"]["struct"]["fields"]) {
                    self.walk(&f, module, &me);
                }
            }
            "struct_field" => {
                if name.chars().all(|c| c.is_ascii_digit()) {
                    return;
                }
                self.push(it, qual("."), "field", module);
            }
            "trait" => {
                let i = self.push(it, qual("::"), "trait", module);
                self.items[i].is_unsafe = inner["is_unsafe"].as_bool().unwrap_or(false);
                let me = Parent::Trait(name.clone());
                for c in Self::ids(&inner["items"]) {
                    self.walk(&c, module, &me);
                }
            }
            "function" => {
                let k = match parent {
                    Parent::None => "fn",
                    Parent::Type(_) => "method",
                    Parent::Trait(_) => "trait method",
                };
                let i = self.push(it, qual("::"), k, module);
                let h = &inner["header"];
                self.items[i].is_unsafe = h["is_unsafe"].as_bool().or_else(|| h["unsafe_"].as_bool()).unwrap_or(false);
                self.items[i].returns_result = type_is_result(&inner["sig"]["output"]) || type_is_result(&inner["decl"]["output"]);
                let (file, line) = (self.items[i].file.clone(), self.items[i].line);
                let best = self.fns.get(name.as_str()).and_then(|c| {
                    c.iter()
                        .filter(|(f, _, _)| !f.is_empty() && (file.ends_with(f) || f.ends_with(file.as_str())))
                        .min_by_key(|(_, l, _)| l.abs_diff(line))
                        .filter(|(_, l, _)| l.abs_diff(line) <= 50)
                        .map(|x| x.2.to_vec())
                });
                if let Some(p) = best {
                    self.items[i].panics = p;
                }
            }
            "type_alias" => {
                self.push(it, qual("::"), "type", module);
            }
            "constant" => {
                self.push(it, qual("::"), "const", module);
            }
            "static" => {
                self.push(it, qual("::"), "static", module);
            }
            "macro" | "proc_macro" => {
                self.push(it, qual("::"), "macro", module);
            }
            "assoc_const" => {
                self.push(it, qual("::"), "assoc const", module);
            }
            "assoc_type" => {
                self.push(it, qual("::"), "assoc type", module);
            }
            "trait_alias" => {
                self.push(it, qual("::"), "trait alias", module);
            }
            _ => {}
        }
    }

    /// Items of inherent impls (trait impl items are not required to have docs).
    fn walk_impl(&mut self, id: &str, module: &str, ty: &str) {
        let Some(it) = self.get(id) else { return };
        let Some(("impl", imp)) = inner_of(it) else { return };
        let synthetic = imp["is_synthetic"].as_bool().or_else(|| imp["synthetic"].as_bool()) == Some(true);
        if !imp["trait"].is_null() || synthetic || !imp["blanket_impl"].is_null() {
            return;
        }
        for c in Self::ids(&imp["items"]) {
            self.walk(&c, module, &Parent::Type(ty.to_string()));
        }
    }
}

/// Oldest rustdoc JSON format the walker reads (externally tagged `inner`, `import`/`use` both handled).
pub const MIN_FORMAT: u64 = 30;
/// Newest rustdoc JSON format checked against (rustdoc-types 0.61).
pub const MAX_KNOWN_FORMAT: u64 = 61;

/// Build the model from a rustdoc JSON document (`rustdoc_types::Crate`, format 30 or later).
pub fn from_rustdoc(doc: &Value, s: &Surface, label: &str) -> Result<DocModel> {
    let fv = doc["format_version"].as_u64();
    if let Some(v) = fv.filter(|v| *v < MIN_FORMAT) {
        return Err(Error::Parse(format!("rustdoc JSON format_version {v} is too old (need {MIN_FORMAT} or later; regenerate it with a current nightly)")));
    }
    let index = doc["index"].as_object().ok_or_else(|| Error::Parse("no `index` object".into()))?;
    let root = id_key(&doc["root"]).ok_or_else(|| Error::Parse("no `root` id".into()))?;
    let root_item = index.get(&root).ok_or_else(|| Error::Parse("root item missing from the index".into()))?;
    if inner_of(root_item).is_none_or(|(k, _)| k != "module") {
        return Err(Error::Parse(format!("unsupported rustdoc JSON format_version {} (need 30 or later)", fv.unwrap_or(0))));
    }
    let mut fns: HashMap<&str, Vec<(&str, usize, &[(usize, String)])>> = HashMap::new();
    for it in s.items.iter().filter(|i| i.kind.is_fn()) {
        fns.entry(it.name.as_str()).or_default().push((s.file_rel(it.file), it.line, &it.panics));
    }
    let mut w = Walker { index, local: root_item["crate_id"].as_u64(), seen: HashSet::new(), renamed: HashMap::new(), items: Vec::new(), links: Vec::new(), fns, root: &s.root, sources: HashMap::new() };
    w.walk(&root, "crate", &Parent::None);
    if w.items.is_empty() {
        return Err(Error::Parse("the crate root could not be read".into()));
    }
    let warning = match fv {
        Some(v) if v > MAX_KNOWN_FORMAT => {
            Some(format!("rustdoc JSON format_version {v} is newer than the newest format this tool was checked against ({MAX_KNOWN_FORMAT}); items whose JSON shape changed may be missing"))
        }
        None => Some("rustdoc JSON has no format_version; results may be incomplete".to_string()),
        _ => None,
    };
    Ok(DocModel { source: format!("rustdoc JSON from {label}"), heuristic: false, format_version: fv, items: w.items, links: w.links, warning })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_extraction() {
        let t = "See [`Foo`] and [Bar::baz()] and [text](crate::x::Y) and [a link](https://x.y)\n\
                 and [ref][`Q`] and [plain words] and [1] and `[`NotALink`]`\n```\n[`InCode`]\n```\n[`Def`]: crate::Real\n";
        let got: Vec<String> = link_targets(t).into_iter().map(|x| x.0).collect();
        assert_eq!(got, ["crate::Real", "`Foo`", "Bar::baz()", "crate::x::Y", "`Q`"]);
        assert_eq!(link_path("`struct@Foo<T>`").unwrap(), ["Foo"]);
        assert_eq!(link_path("std::vec::Vec::push()").unwrap().len(), 4);
        assert!(link_path("not a path").is_none());
    }

    fn surface(files: &[(&str, &str)]) -> (std::path::PathBuf, Surface) {
        let dir = util::temp_dir("docscov-t").unwrap();
        for (p, c) in files {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        }
        let s = Surface::build(&dir, &dir.join("src/lib.rs"), Default::default());
        (dir, s)
    }

    /// A rustdoc JSON crate: root module (span = whole file) with a re-export of `inner::Thing`
    /// and an unsafe fn, written in the pre-34 (`import`/`glob`/`unsafe_`) or current shape.
    fn json_doc(fv: u64, old: bool) -> Value {
        let (use_kind, glob_key, unsafe_key) = if old { ("import", "glob", "unsafe_") } else { ("use", "is_glob", "is_unsafe") };
        json!({
            "format_version": fv,
            "root": 0,
            "index": {
                "0": {"crate_id": 0, "name": "demo", "docs": "Licensed header above.\n\nSee [`Missing`] for details.", "links": {},
                      "span": {"filename": "src/lib.rs", "begin": [1, 0]},
                      "inner": {"module": {"is_crate": true, "items": [1, 3, 4], "is_stripped": false}}},
                "1": {"crate_id": 0, "name": null, "docs": null, "links": {}, "span": {"filename": "src/lib.rs", "begin": [9, 0]},
                      "inner": {use_kind: {"source": "inner::Thing", "name": "Thing", "id": 2, glob_key: false}}},
                "2": {"crate_id": 0, "name": "Thing", "docs": "A thing.", "links": {}, "span": {"filename": "src/inner.rs", "begin": [2, 0]},
                      "inner": {"struct": {"kind": {"plain": {"fields": []}}, "impls": []}}},
                "3": {"crate_id": 0, "name": "danger", "docs": "Does things.", "links": {}, "span": {"filename": "src/lib.rs", "begin": [12, 0]},
                      "inner": {"function": {"header": {unsafe_key: true}, "sig": {"output": null}}}},
                "4": {"crate_id": 0, "name": "inner", "docs": null, "links": {}, "span": {"filename": "src/inner.rs", "begin": [1, 0]},
                      "inner": {"module": {"is_crate": false, "items": [2], "is_stripped": true}}}
            }
        })
    }

    #[test]
    fn rustdoc_json_old_and_new_formats() {
        let lib = "// Copyright header\n// more header\n\n//! Licensed header above, `Missing` too.\n//!\n//! See [`Missing`] for details.\n\nmod inner;\npub use inner::Thing;\n\n/// Does things.\npub unsafe fn danger() {}\n";
        let (dir, s) = surface(&[("src/lib.rs", lib), ("src/inner.rs", "/// A thing.\npub struct Thing;\n")]);
        for (fv, old) in [(33, true), (57, false), (61, false)] {
            let m = from_rustdoc(&json_doc(fv, old), &s, "test").unwrap();
            let paths: Vec<&str> = m.items.iter().map(|i| i.path.as_str()).collect();
            assert_eq!(paths, ["crate", "Thing", "danger"], "format {fv}");
            assert!(m.items[2].is_unsafe, "format {fv}: unsafe fn not detected");
            assert!(m.warning.is_none());
            // the broken link sits on line 6 of lib.rs, not on line 1 + offset
            assert_eq!(m.links.len(), 1);
            assert_eq!((m.links[0].target.as_str(), m.links[0].line), ("Missing", 6));
        }
        assert!(from_rustdoc(&json_doc(62, false), &s, "test").unwrap().warning.is_some_and(|w| w.contains("62")));
        assert!(from_rustdoc(&json_doc(29, false), &s, "test").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn source_model_skips_doc_hidden_modules() {
        let (dir, s) = surface(&[
            ("src/lib.rs", "//! Docs\n#[doc(hidden)]\npub mod __private_api;\n/// Shown.\npub fn shown() {}\n"),
            ("src/__private_api.rs", "pub fn capture() {}\npub struct Helper { pub x: u8 }\n"),
        ]);
        let m = from_surface(&s, &|r: &str| r.to_string());
        let paths: Vec<&str> = m.items.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(paths, ["crate", "shown"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn heading_detection() {
        assert!(has_heading("Does x.\n\n# Safety\n\nCaller must...", &["safety"]));
        assert!(!has_heading("```\n# Safety\n```", &["safety"]));
        assert!(has_code_block("x\n```rust\nlet a = 1;\n```"));
        assert!(!has_code_block("x\n```toml\n[dependencies]\n```"));
    }
}
