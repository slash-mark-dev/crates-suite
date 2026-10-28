//! Panic Surface Map: Every unwrap, expect, index and panic! reachable from a crate's public API.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::items::{self, ImplBlock};
use crate::rustsrc::{self, Kind, SourceFile, Token};
use crate::tools::common::{self, CrateRef, Select};
use crate::tools::unsafe_hotspots::{fn_sig, library_files, macro_ranges, par_map};
use crate::tools::{Group, Tool};

pub struct Panics;

const OPTS: &[Opt] = &[
    Opt::flag("deps", "Analyze the project's crates.io dependencies instead of its workspace members"),
    Opt::value("only", "A,B", "Only analyze these crates (comma-separated names)"),
    Opt::value("max-findings", "N", "Maximum findings to print (default 50; the rest are summarized)"),
    Opt::value("top", "N", "Public functions to list per crate in the top table (default 5)"),
];

impl Tool for Panics {
    fn name(&self) -> &'static str {
        "panics"
    }
    fn title(&self) -> &'static str {
        "Panic Surface Map"
    }
    fn group(&self) -> Group {
        Group::Soundness
    }
    fn summary(&self) -> &'static str {
        "Every unwrap, expect, index and panic! reachable from a crate's public API"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Finds panic sites in library code (tests and #[cfg(test)] excluded): .unwrap(), .expect(),
panic!/unreachable!/todo!/unimplemented!, assert!/assert_eq!/assert_ne! (debug_ asserts excluded),
indexing `x[i]` (not `[..]`, attributes, array types or vec![]), and division/remainder by a
non-literal (low confidence: the divisor's type is unknown, floats never panic).
It then builds an intra-crate call graph BY NAME: a call `foo(`, `.foo(`, `Self::foo(` or
`path::foo(` links to every function named foo of the matching kind (free fn or method). This is
not type-resolved, so it over-approximates (a `.len()` call links to every `len` method in the
crate) and misses calls through closures stored in variables, trait objects and macros' generated
code. Entry points are `pub fn` items, `pub fn` methods of inherent impls, all methods of trait
impls and default methods of pub traits; `pub` inside a private module is still treated as public.
A panic site is reachable when its function is reachable from an entry point. Findings: reachable
todo!/unimplemented! (medium), unwrap/expect inside a public fn returning Result/Option that could
use `?` (low), and one aggregated info finding per other function with reachable sites.
Defaults to your workspace members; --deps analyzes crates.io dependencies instead."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates panics",
            "sm-crates panics itoa@1.0.11 smallvec",
            "sm-crates panics --deps --only serde_json,url",
            "sm-crates panics semver --max-findings 20 --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "network for published crates; none for your own project"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let max_findings: usize = args.parse_or("max-findings", 50)?;
        let top_n: usize = args.parse_or("top", 5)?;
        let deps = args.flag("deps");
        let (subject, crates, meta) = common::select(ctx, args, Select { members: true, dev: false, non_registry: false })?;
        let crates: Vec<CrateRef> = match &meta {
            Some(m) => crates
                .into_iter()
                .filter(|c| {
                    let member = c.id.as_ref().is_some_and(|id| m.is_member(id));
                    if deps { !member && c.is_registry() } else { member }
                })
                .collect(),
            None => crates,
        };
        let crates = common::only(args, crates);
        common::non_empty(&crates)?;
        let results = par_map(&crates, 4, |c| -> Result<CrateMap> {
            let dir = c.source_dir(ctx)?;
            let files = library_files(&dir);
            let mut m = analyze(&files);
            m.lints = lint_settings(&dir);
            Ok(m)
        });
        let mut rep = Report::new("panics", subject);
        let mut t = Table::new(
            "Panic sites per crate",
            &["Crate", "Version", "Sites", "Reachable", "unwrap/expect", "panic macros", "asserts", "indexing", "div (low conf.)", "Public fns"],
        );
        let mut top = Table::new("Public functions reaching the most panic sites", &["Crate", "Function", "Defined at", "Reachable sites", "Example chain"]);
        let mut all_findings: Vec<(usize, Finding)> = Vec::new();
        let mut data = Vec::new();
        let (mut tot_sites, mut tot_reach) = (0, 0);
        for (c, r) in crates.iter().zip(results) {
            let m = match r {
                Ok(m) => m,
                Err(e) => {
                    rep.note(format!("{}: could not analyze: {e}", c.spec()));
                    continue;
                }
            };
            let k = m.kind_counts(false);
            let kr = m.kind_counts(true);
            let sites: usize = k.values().sum::<usize>() - k.get("div").copied().unwrap_or(0);
            let reach: usize = kr.values().sum::<usize>() - kr.get("div").copied().unwrap_or(0);
            tot_sites += sites;
            tot_reach += reach;
            let g = |m: &BTreeMap<&str, usize>, ks: &[&str]| ks.iter().map(|x| m.get(x).copied().unwrap_or(0)).sum::<usize>();
            let pair = |ks: &[&str]| format!("{}/{}", g(&kr, ks), g(&k, ks));
            t.row([
                c.name.clone(),
                c.version.clone(),
                sites.to_string(),
                reach.to_string(),
                pair(&["unwrap", "expect"]),
                pair(&["panic", "unreachable", "todo", "unimplemented"]),
                pair(&["assert"]),
                pair(&["index"]),
                pair(&["div"]),
                m.entries().len().to_string(),
            ]);
            let tops = m.top_entries(top_n);
            for (e, n, chain) in &tops {
                top.row([c.name.clone(), m.fns[*e].display.clone(), format!("{}:{}", m.fns[*e].file, m.fns[*e].line), n.to_string(), chain.clone()]);
            }
            for f in m.findings(c) {
                all_findings.push(f);
            }
            for l in &m.lints {
                rep.note(format!("{}: sets {l}; sites under #[allow] are still counted here", c.spec()));
            }
            data.push(json!({
                "crate": c.name, "version": c.version, "functions": m.fns.len(), "public_entry_points": m.entries().len(),
                "sites": k, "reachable_sites": kr, "outside_functions": m.outside,
                "top_functions": tops.iter().map(|(e, n, chain)| json!({"function": m.fns[*e].display, "file": m.fns[*e].file, "line": m.fns[*e].line, "reachable_sites": n, "example_chain": chain})).collect::<Vec<_>>(),
                "lints": m.lints,
            }));
        }
        rep.table(t);
        rep.table(top);
        // severity first, then most sites
        all_findings.sort_by(|a, b| b.1.severity.cmp(&a.1.severity).then(b.0.cmp(&a.0)));
        let total = all_findings.len();
        for (_, f) in all_findings.into_iter().take(max_findings) {
            rep.finding(f);
        }
        if total > max_findings {
            rep.note(format!("{} more function-level finding(s) not shown (raise --max-findings or use --json data)", total - max_findings));
        }
        rep.note("Call graph is name-based (not type-resolved): reachability over-approximates; counts in the table are reachable/total.");
        rep.summary(format!("{tot_reach} of {tot_sites} panic site(s) are reachable from public functions (division sites counted separately)"));
        rep.data = json!({"crates": data});
        Ok(rep)
    }
}

/// Clippy lints about panics that a crate turns on (inner attributes of the lib root, `[lints.clippy]`).
fn lint_settings(dir: &std::path::Path) -> Vec<String> {
    const LINTS: &[&str] = &["unwrap_used", "expect_used", "panic", "indexing_slicing", "unreachable", "todo", "unimplemented", "panic_in_result_fn", "arithmetic_side_effects", "integer_division"];
    let mut out = Vec::new();
    if let Some(root) = rustsrc::lib_root(dir) {
        if let Ok(f) = SourceFile::load(dir, &root) {
            for a in items::inner_attrs(&f.code) {
                let compact: String = a.chars().filter(|c| !c.is_whitespace()).collect();
                for level in ["deny", "forbid", "warn"] {
                    if !compact.contains(&format!("{level}(")) {
                        continue;
                    }
                    for l in LINTS {
                        if compact.contains(&format!("clippy::{l}")) {
                            out.push(format!("#![{level}(clippy::{l})]"));
                        }
                    }
                }
            }
        }
    }
    if let Some(m) = rustsrc::manifest(dir) {
        if let Some(t) = m.get("lints").and_then(|l| l.get("clippy")).and_then(|c| c.as_table()) {
            for l in LINTS {
                if let Some(v) = t.get(*l) {
                    let level = v.as_str().map(String::from).or_else(|| v.get("level").and_then(|x| x.as_str()).map(String::from)).unwrap_or_default();
                    if level != "allow" {
                        out.push(format!("[lints.clippy] {l} = \"{level}\""));
                    }
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PKind {
    Unwrap,
    Expect,
    Panic,
    Unreachable,
    Todo,
    Unimplemented,
    Assert,
    Index,
    Div,
}

impl PKind {
    fn key(&self) -> &'static str {
        match self {
            PKind::Unwrap => "unwrap",
            PKind::Expect => "expect",
            PKind::Panic => "panic",
            PKind::Unreachable => "unreachable",
            PKind::Todo => "todo",
            PKind::Unimplemented => "unimplemented",
            PKind::Assert => "assert",
            PKind::Index => "index",
            PKind::Div => "div",
        }
    }
}

#[derive(Debug, Clone)]
struct Site {
    kind: PKind,
    file: String,
    line: usize,
    source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallKind {
    /// `foo(` or `module::foo(`
    Free,
    /// `.foo(`
    Method,
    /// `Self::foo(` / `Type::foo(`
    Assoc,
}

#[derive(Debug, Clone)]
struct FnNode {
    display: String,
    file: String,
    line: usize,
    is_method: bool,
    is_entry: bool,
    fallible: bool,
    /// Short name of the impl's self type for methods.
    self_ty: Option<String>,
    /// (kind, name, qualifying type: `Type::f` / `Self::f` / `self.f`).
    calls: Vec<(CallKind, String, Option<String>)>,
    sites: Vec<Site>,
    name: String,
}

#[derive(Debug, Default)]
struct CrateMap {
    fns: Vec<FnNode>,
    /// Adjacency (deduplicated).
    edges: Vec<Vec<usize>>,
    /// Multi-source BFS parent (for chains) and reachability.
    reachable: Vec<bool>,
    parent: Vec<Option<usize>>,
    /// Panic sites outside any function (consts, statics).
    outside: usize,
    lints: Vec<String>,
}

const NOT_INDEXABLE_BEFORE: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "static", "struct", "super", "trait", "type", "unsafe", "use", "where", "while", "async", "await",
    "dyn", "yield", "box", "Self",
];

/// Trait blocks: (open, close, is_pub).
fn trait_ranges(code: &[Token]) -> Vec<(usize, usize, bool)> {
    let mut out = Vec::new();
    for i in 0..code.len() {
        if !code[i].ident("trait") || !code.get(i + 1).is_some_and(|t| t.kind == Kind::Ident) {
            continue;
        }
        let prev_ok = i == 0 || matches!(code[i - 1].text.as_str(), "}" | ";" | "]" | "{" | "pub" | "unsafe" | "auto" | ")");
        if !prev_ok {
            continue;
        }
        let mut j = i + 2;
        let mut depth = 0i32;
        while j < code.len() {
            match code[j].text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                "{" if depth == 0 => break,
                ";" if depth == 0 => break,
                _ => {}
            }
            j += 1;
        }
        if code.get(j).is_some_and(|t| t.punct("{")) {
            if let Some(c) = items::matching(code, j) {
                let mut k = i;
                while k > 0 && (code[k - 1].ident("unsafe") || code[k - 1].ident("auto")) {
                    k -= 1;
                }
                let is_pub = k > 0 && code[k - 1].ident("pub");
                out.push((j, c, is_pub));
            }
        }
    }
    out
}

fn short_type(self_ty: &str) -> String {
    let base = self_ty.split('<').next().unwrap_or(self_ty).trim();
    let base = base.trim_start_matches('&').trim_start_matches("mut ").trim();
    base.rsplit("::").next().unwrap_or(base).to_string()
}

fn analyze(files: &[SourceFile]) -> CrateMap {
    let mut m = CrateMap::default();
    for f in files {
        analyze_file(f, &mut m);
    }
    // resolve calls by name
    let mut free: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut methods: HashMap<&str, Vec<usize>> = HashMap::new();
    for (k, n) in m.fns.iter().enumerate() {
        if n.is_method { methods.entry(&n.name).or_default().push(k) } else { free.entry(&n.name).or_default().push(k) }
    }
    let local_types: std::collections::HashSet<&str> = m.fns.iter().filter_map(|f| f.self_ty.as_deref()).collect();
    let mut edges = Vec::with_capacity(m.fns.len());
    for n in &m.fns {
        let mut e: Vec<usize> = Vec::new();
        for (kind, name, qual) in &n.calls {
            let c = match kind {
                CallKind::Free => free.get(name.as_str()),
                CallKind::Method | CallKind::Assoc => methods.get(name.as_str()),
            };
            let Some(c) = c else { continue };
            match qual {
                Some(t) => {
                    let same: Vec<usize> = c.iter().copied().filter(|&k| m.fns[k].self_ty.as_deref() == Some(t.as_str())).collect();
                    if !same.is_empty() {
                        e.extend(same);
                    } else if *kind == CallKind::Assoc && !local_types.contains(t.as_str()) && t != "Self" {
                        // `String::from(..)`: a method of a type this crate does not implement anything for
                    } else {
                        e.extend(c.iter().copied());
                    }
                }
                None => e.extend(c.iter().copied()),
            }
        }
        e.sort_unstable();
        e.dedup();
        edges.push(e);
    }
    m.edges = edges;
    // multi-source BFS from entry points
    let n = m.fns.len();
    m.reachable = vec![false; n];
    m.parent = vec![None; n];
    let mut q: VecDeque<usize> = VecDeque::new();
    for (k, f) in m.fns.iter().enumerate() {
        if f.is_entry {
            m.reachable[k] = true;
            q.push_back(k);
        }
    }
    while let Some(x) = q.pop_front() {
        for &y in &m.edges[x] {
            if !m.reachable[y] {
                m.reachable[y] = true;
                m.parent[y] = Some(x);
                q.push_back(y);
            }
        }
    }
    m
}

fn analyze_file(f: &SourceFile, m: &mut CrateMap) {
    let code = &f.code;
    let n = code.len();
    let tests = items::test_ranges(code);
    let macros = macro_ranges(code);
    let fns = items::fns(code);
    let impls: Vec<ImplBlock> = items::impls(code);
    let traits = trait_ranges(code);
    // owner[i]: innermost fn body containing token i (local index)
    let mut owner: Vec<Option<usize>> = vec![None; n];
    let mut order: Vec<usize> = (0..fns.len()).filter(|&k| fns[k].body.is_some()).collect();
    order.sort_by_key(|&k| std::cmp::Reverse(fns[k].body.map(|(a, b)| b - a).unwrap_or(0)));
    for &k in &order {
        let (a, b) = fns[k].body.expect("filtered");
        for o in owner.iter_mut().take(b).skip(a + 1) {
            *o = Some(k);
        }
    }
    // local fn index -> global node index
    let mut local: Vec<Option<usize>> = vec![None; fns.len()];
    for (k, func) in fns.iter().enumerate() {
        if func.body.is_none() || items::in_ranges(&tests, func.decl) || items::in_ranges(&macros, func.decl) {
            continue;
        }
        let nested = owner.get(func.decl).copied().flatten().is_some();
        let in_trait = traits.iter().find(|(a, b, _)| *a < func.decl && func.decl < *b);
        let imp: Option<&ImplBlock> = func.impl_idx.and_then(|x| impls.get(x)).filter(|_| !nested);
        let is_method = imp.is_some() || in_trait.is_some();
        let is_entry = !nested
            && match (imp, in_trait) {
                (Some(im), _) => im.trait_name.is_some() || func.is_pub,
                (None, Some((_, _, tpub))) => *tpub,
                (None, None) => func.is_pub,
            };
        let display = match imp {
            Some(im) => format!("{}::{}", short_type(&im.self_ty), func.name),
            None => func.name.clone(),
        };
        let sig = fn_sig(code, func);
        let fallible = sig.ret.is_some_and(|(a, b)| returns_fallible(&code[a..b]));
        local[k] = Some(m.fns.len());
        let self_ty = imp.map(|im| short_type(&im.self_ty));
        m.fns.push(FnNode { display, file: f.rel.clone(), line: func.line, is_method, is_entry, fallible, self_ty, calls: Vec::new(), sites: Vec::new(), name: func.name.clone() });
    }
    let node_of = |i: usize| owner[i].and_then(|k| local[k]);
    let mut i = 0;
    while i < n {
        if items::in_ranges(&tests, i) || items::in_ranges(&macros, i) {
            let end = tests.iter().chain(macros.iter()).filter(|(a, b)| *a <= i && i <= *b).map(|(_, b)| *b).max().unwrap_or(i);
            i = end + 1;
            continue;
        }
        let t = &code[i];
        let prev = if i > 0 { code.get(i - 1) } else { None };
        let next = code.get(i + 1);
        let mut site: Option<PKind> = None;
        if t.kind == Kind::Ident {
            // calls
            let call = next.is_some_and(|x| x.punct("("))
                || (next.is_some_and(|x| x.punct("::")) && code.get(i + 2).is_some_and(|x| x.punct("<")));
            let fn_value = prev.is_some_and(|p| p.punct("::")) && next.is_some_and(|x| x.punct(")") || x.punct(","));
            if (call || fn_value) && !prev.is_some_and(|p| p.ident("fn")) && t.text.chars().next().is_some_and(|c| c.is_lowercase() || c == '_') {
                let seg = if i >= 2 { code[i - 2].text.as_str() } else { "" };
                let (kind, qual) = match prev {
                    Some(p) if p.punct(".") => (CallKind::Method, (seg == "self").then(|| "Self".to_string())),
                    Some(p) if p.punct("::") => {
                        if seg == "Self" || seg.chars().next().is_some_and(|c| c.is_uppercase()) {
                            (CallKind::Assoc, Some(seg.to_string()))
                        } else if seg == ">" {
                            (CallKind::Assoc, None)
                        } else {
                            (CallKind::Free, None)
                        }
                    }
                    _ => (CallKind::Free, None),
                };
                if let Some(nd) = node_of(i) {
                    let qual = match qual.as_deref() {
                        Some("Self") => m.fns[nd].self_ty.clone().or(Some("Self".into())),
                        _ => qual,
                    };
                    m.fns[nd].calls.push((kind, t.text.clone(), qual));
                }
            }
            let is_macro = next.is_some_and(|x| x.punct("!")) && !prev.is_some_and(|p| p.punct("."));
            site = match t.text.as_str() {
                "unwrap" if prev.is_some_and(|p| p.punct(".")) && next.is_some_and(|x| x.punct("(")) && code.get(i + 2).is_some_and(|x| x.punct(")")) => Some(PKind::Unwrap),
                "expect" if prev.is_some_and(|p| p.punct(".")) && next.is_some_and(|x| x.punct("(")) => Some(PKind::Expect),
                "panic" if is_macro => Some(PKind::Panic),
                "unreachable" if is_macro => Some(PKind::Unreachable),
                "todo" if is_macro => Some(PKind::Todo),
                "unimplemented" if is_macro => Some(PKind::Unimplemented),
                "assert" | "assert_eq" | "assert_ne" if is_macro => Some(PKind::Assert),
                _ => None,
            };
        } else if t.punct("[") && is_index(code, i) {
            site = Some(PKind::Index);
        } else if (t.punct("/") || t.punct("%") || t.punct("/=") || t.punct("%=")) && is_runtime_div(code, i) {
            site = Some(PKind::Div);
        }
        if let Some(kind) = site {
            let mut source = f.line_text(t.line).trim().to_string();
            if source.chars().count() > 140 {
                source = source.chars().take(137).collect::<String>() + "...";
            }
            let s = Site { kind, file: f.rel.clone(), line: t.line, source };
            match node_of(i) {
                Some(nd) => m.fns[nd].sites.push(s),
                None => m.outside += 1,
            }
        }
        i += 1;
    }
}

fn is_index(code: &[Token], i: usize) -> bool {
    if i == 0 {
        return false;
    }
    let p = &code[i - 1];
    let ok_prev = match p.kind {
        Kind::Ident => !NOT_INDEXABLE_BEFORE.contains(&p.text.as_str()),
        Kind::Punct => matches!(p.text.as_str(), ")" | "]" | "?"),
        _ => false,
    };
    if !ok_prev {
        return false;
    }
    // `#[attr]` and `name![...]` never reach here (prev is `#` / `!`). Skip `[..]`.
    if code.get(i + 1).is_some_and(|t| t.punct("..")) && code.get(i + 2).is_some_and(|t| t.punct("]")) {
        return false;
    }
    // `]` before `[` that closes an attribute: `#[x] [..]` is not indexing
    if p.punct("]") {
        if let Some(open) = (0..i - 1).rev().find(|&k| items::matching(code, k) == Some(i - 1)) {
            if open > 0 && (code[open - 1].punct("#") || code[open - 1].punct("!")) {
                return false;
            }
        }
    }
    true
}

fn is_runtime_div(code: &[Token], i: usize) -> bool {
    let Some(n) = code.get(i + 1) else { return false };
    if n.kind == Kind::Num {
        return false;
    }
    // constants (SCREAMING_CASE) are almost always non-zero
    if n.kind == Kind::Ident && n.text.len() > 1 && n.text.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
        return false;
    }
    // `(2)` / `(8 * 4)` literal expressions
    if n.punct("(") {
        if let Some(c) = items::matching(code, i + 1) {
            if code[i + 2..c].iter().all(|t| t.kind == Kind::Num || t.kind == Kind::Punct) {
                return false;
            }
        }
    }
    true
}

/// Whether a return type's outermost type is `Result`/`Option` (any path, e.g. `io::Result`).
fn returns_fallible(ret: &[Token]) -> bool {
    let end = ret.iter().position(|t| t.punct("<")).unwrap_or(ret.len());
    ret[..end].iter().rev().find(|t| t.kind == Kind::Ident).is_some_and(|t| t.text == "Result" || t.text == "Option")
}

impl CrateMap {
    fn entries(&self) -> Vec<usize> {
        (0..self.fns.len()).filter(|&k| self.fns[k].is_entry).collect()
    }

    fn kind_counts(&self, reachable_only: bool) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for (k, f) in self.fns.iter().enumerate() {
            if reachable_only && !self.reachable[k] {
                continue;
            }
            for s in &f.sites {
                *out.entry(s.kind.key()).or_default() += 1;
            }
        }
        out
    }

    /// Chain of display names from an entry point to `k`.
    fn chain_to(&self, k: usize) -> Vec<String> {
        let mut v = vec![self.fns[k].display.clone()];
        let mut cur = k;
        let mut guard = 0;
        while let Some(p) = self.parent[cur] {
            v.push(self.fns[p].display.clone());
            cur = p;
            guard += 1;
            if guard > 64 {
                break;
            }
        }
        v.reverse();
        v
    }

    fn real_sites(f: &FnNode) -> usize {
        f.sites.iter().filter(|s| s.kind != PKind::Div).count()
    }

    /// Entry points with the most reachable (non-division) panic sites: (entry, count, example chain).
    fn top_entries(&self, n: usize) -> Vec<(usize, usize, String)> {
        let entries = self.entries();
        let mut counts: Vec<(usize, usize)> = Vec::new();
        let size = self.fns.len();
        let mut seen = vec![u32::MAX; size];
        let mut q: VecDeque<usize> = VecDeque::new();
        for (round, &e) in entries.iter().enumerate() {
            let round = round as u32;
            let mut total = 0;
            q.clear();
            q.push_back(e);
            seen[e] = round;
            while let Some(x) = q.pop_front() {
                total += Self::real_sites(&self.fns[x]);
                for &y in &self.edges[x] {
                    if seen[y] != round {
                        seen[y] = round;
                        q.push_back(y);
                    }
                }
            }
            if total > 0 {
                counts.push((e, total));
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(self.fns[a.0].display.cmp(&self.fns[b.0].display)));
        counts.truncate(n);
        counts.into_iter().map(|(e, c)| (e, c, self.example_chain(e))).collect()
    }

    /// Path from entry `e` to the nearest function with a panic site, ending with the site.
    fn example_chain(&self, e: usize) -> String {
        let mut parent: HashMap<usize, usize> = HashMap::new();
        let mut q = VecDeque::from([e]);
        let mut seen = vec![false; self.fns.len()];
        seen[e] = true;
        while let Some(x) = q.pop_front() {
            if let Some(s) = self.fns[x].sites.iter().find(|s| s.kind != PKind::Div) {
                let mut path = vec![self.fns[x].display.clone()];
                let mut cur = x;
                while let Some(&p) = parent.get(&cur) {
                    path.push(self.fns[p].display.clone());
                    cur = p;
                }
                path.reverse();
                return format!("{} ({} at {}:{})", path.join(" -> "), s.kind.key(), s.file, s.line);
            }
            for &y in &self.edges[x] {
                if !seen[y] {
                    seen[y] = true;
                    parent.insert(y, x);
                    q.push_back(y);
                }
            }
        }
        String::new()
    }

    /// Function-level findings, each with its site count for ranking.
    fn findings(&self, c: &CrateRef) -> Vec<(usize, Finding)> {
        let mut out = Vec::new();
        for (k, f) in self.fns.iter().enumerate() {
            if !self.reachable[k] || f.sites.is_empty() {
                continue;
            }
            let real: Vec<&Site> = f.sites.iter().filter(|s| s.kind != PKind::Div).collect();
            if real.is_empty() {
                continue;
            }
            let chain = self.chain_to(k).join(" -> ");
            let list = |sites: &[&Site]| sites.iter().take(6).map(|s| format!("{}:{} {}: {}", s.file, s.line, s.kind.key(), s.source)).collect::<Vec<_>>().join("\n");
            let todo: Vec<&Site> = real.iter().copied().filter(|s| matches!(s.kind, PKind::Todo | PKind::Unimplemented)).collect();
            let unwraps: Vec<&Site> = real.iter().copied().filter(|s| matches!(s.kind, PKind::Unwrap | PKind::Expect)).collect();
            let finding = if !todo.is_empty() {
                Finding::new(Severity::Medium, "panics/todo-in-api", format!("`{}` reaches {} todo!/unimplemented! from the public API", f.display, todo.len()))
                    .at(&todo[0].file, Some(todo[0].line))
                    .detail(format!("reached via: {chain}\n{}", list(&todo)))
                    .fix("Implement the missing branch or return an error instead of panicking")
            } else if f.is_entry && f.fallible && !unwraps.is_empty() {
                Finding::new(
                    Severity::Low,
                    "panics/unwrap-in-fallible-api",
                    format!("public `{}` returns Result/Option but panics via {} unwrap/expect", f.display, unwraps.len()),
                )
                .at(&unwraps[0].file, Some(unwraps[0].line))
                .detail(list(&unwraps))
                .fix("Propagate with `?` (or ok_or/map_err) instead of unwrap/expect")
            } else {
                let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
                for s in &real {
                    *kinds.entry(s.kind.key()).or_default() += 1;
                }
                let summary = kinds.iter().map(|(k, n)| format!("{n} {k}")).collect::<Vec<_>>().join(", ");
                Finding::new(Severity::Info, "panics/reachable-panic", format!("`{}` has {} reachable panic site(s): {summary}", f.display, real.len()))
                    .at(&real[0].file, Some(real[0].line))
                    .detail(format!("reached via: {chain}\n{}", list(&real)))
            };
            out.push((real.len(), finding.krate(&c.name, Some(&c.version))));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn map(src: &str) -> CrateMap {
        let f = SourceFile::from_text(Path::new("/x"), Path::new("/x/src/lib.rs"), src.to_string());
        analyze(&[f])
    }
    fn node<'a>(m: &'a CrateMap, name: &str) -> (usize, &'a FnNode) {
        m.fns.iter().enumerate().find(|(_, f)| f.display == name).unwrap_or_else(|| panic!("no fn {name}"))
    }

    const SRC: &str = r#"
#[derive(Debug)]
pub struct P { v: Vec<u8> }

pub fn parse(s: &str) -> Result<u8, ()> {
    let n = helper(s);
    Ok(s.parse::<u8>().unwrap() + n)
}

fn helper(s: &str) -> u8 {
    let b = s.as_bytes();
    let arr: [u8; 4] = [0; 4];
    let _ = &b[..];
    b[0] + arr[1]
}

fn unused() { panic!("never called") }

impl P {
    pub fn get(&self, i: usize) -> u8 { self.inner(i) }
    fn inner(&self, i: usize) -> u8 { self.v[i] / i as u8 % 2 }
    pub fn later(&self) { todo!() }
}

impl std::fmt::Display for P {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { assert!(!self.v.is_empty()); Ok(()) }
}

pub trait T { fn d(&self) -> u8 { deep() } }
fn deep() -> u8 { unreachable!() }

const X: usize = [1, 2][0];
macro_rules! m { ($e:expr) => { $e.unwrap() } }
#[cfg(test)]
mod tests { #[test] fn t() { None::<u8>.unwrap(); } }
"#;

    #[test]
    fn sites_and_kinds() {
        let m = map(SRC);
        let k = m.kind_counts(false);
        assert_eq!(k.get("unwrap"), Some(&1), "{k:?}");
        assert_eq!(k.get("index"), Some(&3), "{k:?}");
        assert_eq!(k.get("panic"), Some(&1));
        assert_eq!(k.get("todo"), Some(&1));
        assert_eq!(k.get("assert"), Some(&1));
        assert_eq!(k.get("unreachable"), Some(&1));
        assert_eq!(k.get("div"), Some(&1), "`/ i` counts, `% 2` does not: {k:?}");
        assert_eq!(m.outside, 1);
    }

    #[test]
    fn reachability_and_entries() {
        let m = map(SRC);
        let entries: Vec<&str> = m.entries().iter().map(|&k| m.fns[k].display.as_str()).collect();
        assert_eq!(entries, ["parse", "P::get", "P::later", "P::fmt", "d"]);
        let (h, _) = node(&m, "helper");
        assert!(m.reachable[h]);
        assert_eq!(m.chain_to(h), ["parse", "helper"]);
        let (u, _) = node(&m, "unused");
        assert!(!m.reachable[u]);
        let (inner, _) = node(&m, "P::inner");
        assert!(m.reachable[inner]);
        let (deep, _) = node(&m, "deep");
        assert!(m.reachable[deep], "trait default methods of pub traits are entries");
        let kr = m.kind_counts(true);
        assert_eq!(kr.get("panic"), None);
        assert!(node(&m, "parse").1.fallible);
        assert!(!node(&m, "helper").1.fallible);
    }

    #[test]
    fn top_and_findings() {
        let m = map(SRC);
        let top = m.top_entries(2);
        assert_eq!(m.fns[top[0].0].display, "parse");
        assert_eq!(top[0].1, 3);
        assert!(top[0].2.starts_with("parse (unwrap at src/lib.rs:"), "{}", top[0].2);
        let c = CrateRef { name: "x".into(), version: "1.0.0".into(), origin: common::Origin::Registry, via: vec![], id: None };
        let f = m.findings(&c);
        let codes: Vec<&str> = f.iter().map(|(_, f)| f.code.as_str()).collect();
        assert!(codes.contains(&"panics/todo-in-api"), "{codes:?}");
        assert!(codes.contains(&"panics/unwrap-in-fallible-api"), "{codes:?}");
        assert!(codes.contains(&"panics/reachable-panic"), "{codes:?}");
        assert!(!f.iter().any(|(_, f)| f.message.contains("unused")));
    }

    #[test]
    fn index_heuristics() {
        let m = map("pub fn f(x: &mut [u8], v: Vec<u8>) -> [u8; 2] { let [a, b] = [1u8, 2]; let w = vec![0; 3]; x[0] = v[1]; foo()[2]; #[allow(x)] let z = 1; for i in [1, 2] {} [a, b] }\nfn foo() -> Vec<u8> { Vec::new() }");
        assert_eq!(m.kind_counts(false).get("index"), Some(&3));
    }

    #[test]
    fn type_qualified_calls_prefer_their_type() {
        let m = map(
            "pub struct A; pub struct B;
             impl A { pub fn new() -> A { A::build() } fn build() -> A { A } pub fn run(&self) { self.go() } fn go(&self) {} }
             impl B { fn build() -> B { panic!() } fn go(&self) { panic!() } }
             pub fn f() -> String { String::from(\"x\") }
             impl From<u8> for B { fn from(_: u8) -> B { panic!() } }",
        );
        let (bb, _) = node(&m, "B::build");
        let (bg, _) = node(&m, "B::go");
        assert!(!m.reachable[bb], "A::build() must not link to B::build");
        assert!(!m.reachable[bg], "self.go() in A must not link to B::go");
        let (f, _) = node(&m, "f");
        assert!(m.edges[f].is_empty(), "String::from is external: {:?}", m.edges[f]);
    }

    #[test]
    fn fallible_return_types() {
        let t = |s: &str| returns_fallible(&items::code_only(&rustsrc::lex(s)));
        assert!(t("io::Result<()>"));
        assert!(t("Option<&str>"));
        assert!(!t("Poll<Option<u8>>"));
        assert!(!t("u8"));
    }
}
