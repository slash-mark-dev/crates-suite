//! Unsafe Soundness Hotspots: Known-unsound unsafe patterns and unsafe blocks without SAFETY comments, per dependency.
//!
//! The scanner here (`library_files`, `analyze`) is also used by `miri` (to pick crates with
//! unsafe code first) and `assurance` (unsafe block counts).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::registry::CrateSpec;
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::items::{self, FnItem, ImplBlock};
use crate::rustsrc::{self, Kind, LoadOpts, SourceFile, Token, lex};
use crate::tools::common::{self, CrateRef, Origin, Select};
use crate::tools::{Group, Tool};

pub struct UnsafeHotspots;

const OPTS: &[Opt] = &[
    Opt::flag("members", "Also scan workspace members (your own code), not only crates.io dependencies"),
    Opt::value("only", "A,B", "Only scan these crates (comma-separated names)"),
    Opt::value("diff", "OLD", "With one crate: report unsafe code and hotspots added between OLD and the given/latest version"),
    Opt::value("max-findings", "N", "Hotspot findings shown per crate and pattern (default 20; all are in --json data)"),
];

impl Tool for UnsafeHotspots {
    fn name(&self) -> &'static str {
        "unsafe"
    }
    fn title(&self) -> &'static str {
        "Unsafe Soundness Hotspots"
    }
    fn group(&self) -> Group {
        Group::Soundness
    }
    fn summary(&self) -> &'static str {
        "Known-unsound unsafe patterns and unsafe blocks without SAFETY comments, per dependency"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Lexes the library sources of each crate (src/, excluding tests, examples, benches, build.rs,
src/bin and #[cfg(test)] code) and counts unsafe blocks, unsafe fns, unsafe impls, unsafe traits,
extern blocks, #[no_mangle]/#[export_name] items and `static mut`. An unsafe block counts as
documented when a comment containing \"safety\" (any case) is on the same line, directly above
(through comment lines and up to 3 attribute/blank/continuation lines) or first inside the block.
It then flags patterns behind real RUSTSEC advisories: set_len before initialization,
mem::uninitialized, mem::zeroed of a generic type, transmute that extends lifetimes, unchecked
indexing without a bounds check, `unsafe impl Send/Sync` for a generic type without Send/Sync
bounds, `static mut`, writes through a *const-to-*mut cast, and Box/Vec::from_raw(_parts).
With --diff OLD it compares two versions of one crate and reports only what the upgrade adds.
Limits: the analysis is lexical and per function; it does not resolve types or follow calls, so
hotspots are leads for review, not proof of unsoundness. Sources come from verified .crate files
(or the local tree for --members)."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates unsafe",
            "sm-crates unsafe smallvec@1.13.2 bytes hashbrown",
            "sm-crates unsafe smallvec@1.15.1 --diff 1.11.0",
            "sm-crates unsafe --members --only mycrate --fail-on medium",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crate downloads)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let max_findings: usize = args.parse_or("max-findings", 20)?;
        if let Some(old) = args.value("diff") {
            return run_diff(ctx, args, old, max_findings);
        }
        let (subject, crates, _) = common::select(ctx, args, Select { members: args.flag("members"), dev: false, non_registry: false })?;
        let crates = common::only(args, crates);
        common::non_empty(&crates)?;
        let results = par_map(&crates, 4, |c| -> Result<CrateUnsafe> {
            let dir = c.source_dir(ctx)?;
            Ok(analyze(&library_files(&dir)))
        });
        let mut rep = Report::new("unsafe", subject);
        let mut rows: Vec<(&CrateRef, CrateUnsafe)> = Vec::new();
        for (c, r) in crates.iter().zip(results) {
            match r {
                Ok(u) => rows.push((c, u)),
                Err(e) => rep.note(format!("{}: could not scan: {e}", c.spec())),
            }
        }
        if rows.is_empty() {
            return Err(Error::Network("no crate could be downloaded and scanned".into()));
        }
        rows.sort_by(|a, b| b.1.hotspot_count().cmp(&a.1.hotspot_count()).then(b.1.blocks.cmp(&a.1.blocks)).then(a.0.name.cmp(&b.0.name)));
        let mut t = Table::new("Unsafe code per crate", &["Crate", "Version", "Unsafe blocks", "Without SAFETY", "Unsafe impls", "Hotspots"]);
        let mut data = Vec::new();
        for (c, u) in &rows {
            t.row([
                c.name.clone(),
                c.version.clone(),
                u.blocks.to_string(),
                u.undocumented.len().to_string(),
                u.unsafe_impls.to_string(),
                u.hotspot_count().to_string(),
            ]);
            emit_findings(&mut rep, c, u, max_findings, "");
            let mut d = u.to_json();
            d["crate"] = json!(c.name);
            d["version"] = json!(c.version);
            if !c.via.is_empty() {
                d["via"] = json!(c.via);
            }
            data.push(d);
        }
        rep.table(t);
        let with_unsafe = rows.iter().filter(|(_, u)| u.blocks + u.unsafe_fns + u.unsafe_impls > 0).count();
        let blocks: usize = rows.iter().map(|(_, u)| u.blocks).sum();
        let undoc: usize = rows.iter().map(|(_, u)| u.undocumented.len()).sum();
        let hot: usize = rows.iter().map(|(_, u)| u.hotspot_count()).sum();
        rep.summary(format!(
            "{} of {} crate(s) use unsafe: {blocks} unsafe block(s), {undoc} without a SAFETY comment, {hot} hotspot(s)",
            with_unsafe,
            rows.len()
        ));
        rep.note("Hotspots are lexical leads for review; each finding shows the source line. Use --json for every count and location.");
        rep.data = json!({ "crates": data });
        Ok(rep)
    }
}

fn emit_findings(rep: &mut Report, c: &CrateRef, u: &CrateUnsafe, max: usize, prefix: &str) {
    let mut per_code: HashMap<&str, usize> = HashMap::new();
    let mut omitted: BTreeMap<&str, usize> = BTreeMap::new();
    for h in &u.hotspots {
        let n = per_code.entry(h.code).or_default();
        *n += 1;
        if *n > max {
            *omitted.entry(h.code).or_default() += 1;
            continue;
        }
        rep.finding(h.finding(c, prefix));
    }
    for (code, n) in omitted {
        rep.note(format!("{}: {n} more `unsafe/{prefix}{code}` finding(s) not shown (raise --max-findings or use --json)", c.spec()));
    }
    if prefix.is_empty() && !u.undocumented.is_empty() {
        let list: Vec<String> = u.undocumented.iter().take(8).map(|(f, l)| format!("{f}:{l}")).collect();
        let more = if u.undocumented.len() > 8 { format!("\n... and {} more", u.undocumented.len() - 8) } else { String::new() };
        rep.finding(
            Finding::new(
                Severity::Info,
                "unsafe/undocumented-blocks",
                format!("{} of {} unsafe block(s) have no SAFETY comment", u.undocumented.len(), u.blocks),
            )
            .krate(&c.name, Some(&c.version))
            .at(&u.undocumented[0].0, Some(u.undocumented[0].1))
            .detail(format!("{}{more}", list.join("\n")))
            .fix("Document each block's invariants with a `// SAFETY:` comment (clippy::undocumented_unsafe_blocks enforces this)"),
        );
    }
}

// ------------------------------------------------------------------ --diff

fn run_diff(ctx: &Ctx, args: &Args, old: &str, max: usize) -> Result<Report> {
    if args.positional.len() != 1 {
        return Err(Error::Usage("--diff OLD needs exactly one crate: sm-crates unsafe NAME[@NEW] --diff OLD".into()));
    }
    let spec = CrateSpec::parse(&args.positional[0])?;
    let new_v = spec.resolve(ctx)?;
    let old_v = CrateSpec { name: spec.name.clone(), version: Some(old.to_string()) }.resolve(ctx)?;
    let mk = |v: &str| CrateRef { name: new_v.name.clone(), version: v.to_string(), origin: Origin::Registry, via: vec![], id: None };
    let (oc, nc) = (mk(&old_v.vers), mk(&new_v.vers));
    let ou = analyze(&library_files(&oc.source_dir(ctx)?));
    let nu = analyze(&library_files(&nc.source_dir(ctx)?));
    let mut rep = Report::new("unsafe", format!("{} {} -> {}", nc.name, oc.version, nc.version));
    let mut t = Table::new("Unsafe code, old vs new", &["Metric", &oc.version, &nc.version, "Change"]);
    let metrics: [(&str, usize, usize); 9] = [
        ("unsafe blocks", ou.blocks, nu.blocks),
        ("without SAFETY", ou.undocumented.len(), nu.undocumented.len()),
        ("unsafe fns", ou.unsafe_fns, nu.unsafe_fns),
        ("unsafe impls", ou.unsafe_impls, nu.unsafe_impls),
        ("unsafe traits", ou.unsafe_traits, nu.unsafe_traits),
        ("extern blocks", ou.extern_blocks, nu.extern_blocks),
        ("no_mangle/export_name", ou.no_mangle, nu.no_mangle),
        ("static mut", ou.static_mut, nu.static_mut),
        ("hotspots", ou.hotspot_count(), nu.hotspot_count()),
    ];
    for (m, a, b) in metrics {
        t.row([m.to_string(), a.to_string(), b.to_string(), format!("{:+}", b as i64 - a as i64)]);
    }
    rep.table(t);
    let added = new_hotspots(&ou, &nu);
    let mut added_u = CrateUnsafe { hotspots: added.into_iter().cloned().collect(), ..Default::default() };
    added_u.hotspots.sort_by_key(|h| std::cmp::Reverse(h.severity));
    emit_findings(&mut rep, &nc, &added_u, max, "new-");
    if nu.blocks > ou.blocks || nu.undocumented.len() > ou.undocumented.len() {
        let grown = file_growth(&ou, &nu);
        rep.finding(
            Finding::new(
                Severity::Info,
                "unsafe/new-unsafe-blocks",
                format!(
                    "{} adds {} unsafe block(s) ({} -> {}); undocumented {} -> {}",
                    nc.version,
                    nu.blocks.saturating_sub(ou.blocks),
                    ou.blocks,
                    nu.blocks,
                    ou.undocumented.len(),
                    nu.undocumented.len()
                ),
            )
            .krate(&nc.name, Some(&nc.version))
            .detail(grown.iter().take(10).map(|(f, a, b)| format!("{f}: {a} -> {b}")).collect::<Vec<_>>().join("\n"))
            .fix(format!("Review the new unsafe code before upgrading (e.g. a diff of {} between the two versions)", grown.first().map(|g| g.0.as_str()).unwrap_or("src/"))),
        );
    }
    rep.summary(format!(
        "{} {} -> {}: unsafe blocks {} -> {}, {} new hotspot(s)",
        nc.name,
        oc.version,
        nc.version,
        ou.blocks,
        nu.blocks,
        added_u.hotspots.iter().filter(|h| h.severity >= Severity::Low).count()
    ));
    rep.data = json!({
        "crate": nc.name, "old": {"version": oc.version, "stats": ou.to_json()}, "new": {"version": nc.version, "stats": nu.to_json()},
        "added_hotspots": added_u.hotspots.iter().map(|h| h.to_json()).collect::<Vec<_>>(),
    });
    Ok(rep)
}

/// Hotspots in `new` not present in `old`, matched by (code, file, normalized source line).
fn new_hotspots<'a>(old: &CrateUnsafe, new: &'a CrateUnsafe) -> Vec<&'a Hotspot> {
    let key = |h: &Hotspot| (h.code, h.file.clone(), h.source.split_whitespace().collect::<Vec<_>>().join(" "));
    let mut have: HashMap<(&str, String, String), usize> = HashMap::new();
    for h in &old.hotspots {
        *have.entry(key(h)).or_default() += 1;
    }
    let mut out = Vec::new();
    for h in &new.hotspots {
        match have.get_mut(&key(h)) {
            Some(n) if *n > 0 => *n -= 1,
            _ => out.push(h),
        }
    }
    out
}

fn file_growth(old: &CrateUnsafe, new: &CrateUnsafe) -> Vec<(String, usize, usize)> {
    let mut v: Vec<(String, usize, usize)> = new
        .blocks_per_file
        .iter()
        .map(|(f, n)| (f.clone(), old.blocks_per_file.get(f).copied().unwrap_or(0), *n))
        .filter(|(_, a, b)| b > a)
        .collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.2 - x.1));
    v
}

// ------------------------------------------------------------------ shared helpers

/// Run `f` over `items` on up to `threads` threads, keeping order.
pub fn par_map<T: Sync, R: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let out: std::sync::Mutex<Vec<Option<R>>> = std::sync::Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|s| {
        for _ in 0..threads.clamp(1, 16).min(items.len().max(1)) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if i >= items.len() {
                        break;
                    }
                    let r = f(&items[i]);
                    out.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(r);
                }
            });
        }
    });
    out.into_inner().unwrap_or_else(|e| e.into_inner()).into_iter().map(|r| r.expect("par_map item ran")).collect()
}

/// Library source files of a crate: files under the library root's directory, without
/// tests/examples/benches/build.rs/src/bin and without files of `#[cfg(test)] mod x;` modules.
pub fn library_files(root: &Path) -> Vec<SourceFile> {
    let files = rustsrc::load_crate(root, LoadOpts { auxiliary: false, build_script: false });
    let lib = rustsrc::lib_root(root);
    let has_lib = lib.is_some();
    let lib_dir = lib.and_then(|p| p.parent().map(|d| crate::util::rel(root, d))).unwrap_or_else(|| "src".to_string());
    let prefix = if lib_dir.is_empty() { String::new() } else { format!("{lib_dir}/") };
    // binary-only packages (workspace members) have no library: keep their src/ code
    let mut files: Vec<SourceFile> = files
        .into_iter()
        .filter(|f| f.rel.starts_with(&prefix) && (!has_lib || (!f.rel.starts_with("src/bin/") && f.rel != "src/main.rs")))
        .collect();
    // files of modules declared under #[cfg(test)]
    let mut excluded: Vec<String> = Vec::new();
    for f in &files {
        let ranges = items::test_ranges(&f.code);
        for (a, b) in &ranges {
            let (a, b) = (*a, *b);
            if b < f.code.len() && f.code[b].punct(";") && b >= 2 && f.code[b - 2].ident("mod") && (a..b).len() < 64 {
                let name = &f.code[b - 1].text;
                let dir = module_dir(&f.rel);
                excluded.push(format!("{dir}{name}.rs"));
                excluded.push(format!("{dir}{name}/"));
            }
        }
    }
    files.retain(|f| !excluded.iter().any(|e| if e.ends_with('/') { f.rel.starts_with(e.as_str()) } else { f.rel == *e }));
    files
}

/// Directory (with trailing slash) where child modules of the file at `rel` live.
fn module_dir(rel: &str) -> String {
    let (dir, file) = match rel.rsplit_once('/') {
        Some((d, f)) => (format!("{d}/"), f),
        None => (String::new(), rel),
    };
    if matches!(file, "lib.rs" | "main.rs" | "mod.rs") { dir } else { format!("{dir}{}/", file.trim_end_matches(".rs")) }
}

// ------------------------------------------------------------------ analysis

/// One hotspot pattern hit.
#[derive(Debug, Clone)]
pub struct Hotspot {
    /// Code without the `unsafe/` prefix.
    pub code: &'static str,
    pub severity: Severity,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub source: String,
    pub fix: &'static str,
}

impl Hotspot {
    fn finding(&self, c: &CrateRef, prefix: &str) -> Finding {
        Finding::new(self.severity, format!("unsafe/{prefix}{}", self.code), self.message.clone())
            .krate(&c.name, Some(&c.version))
            .at(&self.file, Some(self.line))
            .detail(format!("{}:{}: {}", self.file, self.line, self.source))
            .fix(self.fix)
    }
    fn to_json(&self) -> serde_json::Value {
        json!({"code": format!("unsafe/{}", self.code), "severity": self.severity.as_str(), "message": self.message,
               "file": self.file, "line": self.line, "source": self.source})
    }
}

/// Unsafe usage of one crate.
#[derive(Debug, Clone, Default)]
pub struct CrateUnsafe {
    pub files: usize,
    pub blocks: usize,
    pub blocks_in_unsafe_fn: usize,
    pub blocks_in_macros: usize,
    pub unsafe_fns: usize,
    pub unsafe_impls: usize,
    pub unsafe_traits: usize,
    pub extern_blocks: usize,
    pub no_mangle: usize,
    pub static_mut: usize,
    /// Unsafe blocks without a SAFETY comment: (file, line).
    pub undocumented: Vec<(String, usize)>,
    pub blocks_per_file: BTreeMap<String, usize>,
    pub hotspots: Vec<Hotspot>,
}

impl CrateUnsafe {
    /// Hotspots at low severity or above (info-level from_raw notes excluded).
    pub fn hotspot_count(&self) -> usize {
        self.hotspots.iter().filter(|h| h.severity >= Severity::Low).count()
    }
    pub fn uses_unsafe(&self) -> bool {
        self.blocks + self.unsafe_fns + self.unsafe_impls + self.extern_blocks > 0
    }
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "files": self.files, "unsafe_blocks": self.blocks, "without_safety_comment": self.undocumented.len(),
            "blocks_in_unsafe_fn": self.blocks_in_unsafe_fn, "blocks_in_macros": self.blocks_in_macros,
            "unsafe_fns": self.unsafe_fns, "unsafe_impls": self.unsafe_impls, "unsafe_traits": self.unsafe_traits,
            "extern_blocks": self.extern_blocks, "no_mangle_or_export_name": self.no_mangle,
            "static_mut": self.static_mut, "hotspot_count": self.hotspot_count(),
            "undocumented": self.undocumented.iter().map(|(f, l)| format!("{f}:{l}")).collect::<Vec<_>>(),
            "hotspots": self.hotspots.iter().map(|h| h.to_json()).collect::<Vec<_>>(),
        })
    }
}

/// Analyze a set of (library) files.
pub fn analyze(files: &[SourceFile]) -> CrateUnsafe {
    let mut u = CrateUnsafe { files: files.len(), ..Default::default() };
    let types = type_visibility(files);
    for f in files {
        analyze_file(f, &mut u, &types);
    }
    u
}

/// Struct/enum/union names declared in the crate, mapped to whether any declaration is plain `pub`.
fn type_visibility(files: &[SourceFile]) -> HashMap<String, bool> {
    let mut out: HashMap<String, bool> = HashMap::new();
    for f in files {
        let c = &f.code;
        for i in 0..c.len().saturating_sub(1) {
            if !(c[i].ident("struct") || c[i].ident("enum") || c[i].ident("union")) || c[i + 1].kind != Kind::Ident {
                continue;
            }
            let is_pub = i >= 1 && c[i - 1].ident("pub");
            *out.entry(c[i + 1].text.clone()).or_default() |= is_pub;
        }
    }
    out
}

/// Lines of a file: comment text per line and whether the line has code.
struct LineInfo<'a> {
    comments: HashMap<usize, Vec<&'a str>>,
    /// First and last code token per line.
    code: HashMap<usize, (&'a Token, &'a Token)>,
}

impl<'a> LineInfo<'a> {
    fn new(f: &'a SourceFile) -> LineInfo<'a> {
        let mut comments: HashMap<usize, Vec<&str>> = HashMap::new();
        let mut code: HashMap<usize, (&Token, &Token)> = HashMap::new();
        for t in &f.tokens {
            if t.is_comment() {
                let span = t.text.matches('\n').count();
                for l in t.line..=t.line + span {
                    comments.entry(l).or_default().push(&t.text);
                }
            } else {
                code.entry(t.line).and_modify(|e| e.1 = t).or_insert((t, t));
            }
        }
        LineInfo { comments, code }
    }
    fn safety_on(&self, line: usize) -> bool {
        self.comments.get(&line).is_some_and(|v| v.iter().any(|c| c.to_ascii_lowercase().contains("safety")))
    }
}

/// Whether the unsafe block whose `unsafe` keyword is on `line` (and whose `{` is the
/// all-tokens index `open_all`) has a SAFETY comment.
fn documented(f: &SourceFile, li: &LineInfo, line: usize, open_all: Option<usize>) -> bool {
    if li.safety_on(line) {
        return true;
    }
    // first thing inside the block
    if let Some(o) = open_all {
        if let Some(t) = f.tokens.get(o + 1) {
            if t.is_comment() && t.text.to_ascii_lowercase().contains("safety") {
                return true;
            }
            if li.safety_on(f.tokens[o].line) {
                return true;
            }
        }
    }
    // walk up through comments, attributes, blank and continuation lines
    let mut budget = 3i32;
    let mut l = line;
    let mut steps = 0;
    while l > 1 && steps < 80 {
        l -= 1;
        steps += 1;
        if li.safety_on(l) {
            return true;
        }
        match li.code.get(&l) {
            None => {
                if !li.comments.contains_key(&l) {
                    budget -= 1; // blank line
                }
            }
            Some((first, last)) => {
                let attr = first.punct("#");
                let continuation = !(last.punct(";") || last.punct("}") || last.punct("{") || last.punct(","));
                if attr || continuation {
                    budget -= 1;
                } else {
                    return false;
                }
            }
        }
        if budget < 0 {
            return false;
        }
    }
    false
}

/// Token ranges of `macro_rules!` bodies.
pub fn macro_ranges(code: &[Token]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..code.len().saturating_sub(3) {
        if code[i].ident("macro_rules") && code[i + 1].punct("!") && code[i + 2].kind == Kind::Ident {
            if let Some(c) = items::matching(code, i + 3) {
                out.push((i, c));
            }
        }
    }
    out
}

fn is_unsafe_block(code: &[Token], i: usize) -> bool {
    code[i].ident("unsafe") && code.get(i + 1).is_some_and(|t| t.punct("{"))
}

/// Index of the token in the all-tokens list with the same start offset.
fn all_index(f: &SourceFile, code_tok: &Token) -> Option<usize> {
    f.tokens.binary_search_by_key(&code_tok.start, |t| t.start).ok()
}

fn analyze_file(f: &SourceFile, u: &mut CrateUnsafe, types: &HashMap<String, bool>) {
    let code = &f.code;
    let tests = items::test_ranges(code);
    let macros = macro_ranges(code);
    let fns = items::fns(code);
    let impls = items::impls(code);
    let li = LineInfo::new(f);
    let mut ctx = FileCtx { f, code, fns: &fns, impls: &impls, types, blocks: Vec::new(), out: Vec::new() };
    let n = code.len();
    let mut i = 0;
    while i < n {
        if items::in_ranges(&tests, i) {
            // skip whole test region quickly
            let end = tests.iter().filter(|(a, b)| *a <= i && i <= *b).map(|(_, b)| *b).max().unwrap_or(i);
            i = end + 1;
            continue;
        }
        let t = &code[i];
        let in_macro = items::in_ranges(&macros, i);
        if t.kind == Kind::Ident {
            match t.text.as_str() {
                "unsafe" => {
                    if is_unsafe_block(code, i) {
                        u.blocks += 1;
                        *u.blocks_per_file.entry(f.rel.clone()).or_default() += 1;
                        if in_macro {
                            u.blocks_in_macros += 1;
                        }
                        if items::enclosing_fn(&fns, i).is_some_and(|e| e.is_unsafe) {
                            u.blocks_in_unsafe_fn += 1;
                        }
                        let open_all = all_index(f, &code[i + 1]);
                        let doc = documented(f, &li, t.line, open_all);
                        if !doc {
                            u.undocumented.push((f.rel.clone(), t.line));
                        }
                        if let Some(close) = items::matching(code, i + 1) {
                            ctx.blocks.push((i + 1, close, doc));
                        }
                    } else {
                        // unsafe fn / unsafe extern "C" fn / unsafe impl / unsafe trait / unsafe extern {
                        let mut j = i + 1;
                        while j < n && (code[j].ident("extern") || code[j].kind == Kind::Str || code[j].ident("auto")) {
                            j += 1;
                        }
                        match code.get(j) {
                            Some(x) if x.ident("fn") && code.get(j + 1).is_some_and(|y| y.kind == Kind::Ident) => u.unsafe_fns += 1,
                            Some(x) if x.ident("impl") => u.unsafe_impls += 1,
                            Some(x) if x.ident("trait") => u.unsafe_traits += 1,
                            _ => {}
                        }
                    }
                }
                "extern" => {
                    let mut j = i + 1;
                    if code.get(j).is_some_and(|x| x.kind == Kind::Str) {
                        j += 1;
                    }
                    if code.get(j).is_some_and(|x| x.punct("{")) {
                        u.extern_blocks += 1;
                    }
                }
                "no_mangle" | "export_name" => {
                    // #[no_mangle], #[unsafe(no_mangle)], #[export_name = ".."]
                    let attr = (i >= 2 && code[i - 1].punct("[") && code[i - 2].punct("#"))
                        || (i >= 4 && code[i - 1].punct("(") && code[i - 2].ident("unsafe") && code[i - 3].punct("[") && code[i - 4].punct("#"));
                    if attr {
                        u.no_mangle += 1;
                    }
                }
                "static" if code.get(i + 1).is_some_and(|x| x.ident("mut")) && !(i > 0 && code[i - 1].punct("&")) => {
                    u.static_mut += 1;
                    ctx.push(i, "static-mut", Severity::Medium, "`static mut` global: every access is unsafe and references to it are easy to alias".into(),
                        "Use an atomic, a Mutex/OnceLock, or UnsafeCell behind a Sync wrapper with documented invariants");
                }
                _ => {}
            }
            if !in_macro {
                ctx.patterns(i);
            }
        }
        i += 1;
    }
    for im in &impls {
        if items::in_ranges(&tests, im.start) {
            continue;
        }
        ctx.send_sync(im);
    }
    u.hotspots.extend(ctx.out);
}

struct FileCtx<'a> {
    f: &'a SourceFile,
    code: &'a [Token],
    fns: &'a [FnItem],
    impls: &'a [ImplBlock],
    types: &'a HashMap<String, bool>,
    /// Unsafe blocks seen so far: (open, close, has SAFETY comment).
    blocks: Vec<(usize, usize, bool)>,
    out: Vec<Hotspot>,
}

/// A generic parameter: name and its inline bounds text.
#[derive(Debug, Clone, PartialEq)]
pub struct GenericParam {
    pub name: String,
    pub bounds: String,
}

/// Parse the inside of `<...>` (without the angle brackets) into type parameters
/// (lifetimes and const generics are skipped).
pub fn parse_generics(toks: &[Token]) -> Vec<GenericParam> {
    let mut out = Vec::new();
    for part in split_top(toks, ",") {
        let Some(first) = part.first() else { continue };
        if first.kind == Kind::Lifetime || first.ident("const") || first.kind != Kind::Ident {
            continue;
        }
        let bounds = match part.iter().position(|t| t.punct(":")) {
            Some(c) => {
                let end = part.iter().position(|t| t.punct("=")).unwrap_or(part.len());
                items::join(&part[c + 1..end.max(c + 1)])
            }
            None => String::new(),
        };
        out.push(GenericParam { name: first.text.clone(), bounds });
    }
    out
}

/// Split a token slice on a separator at bracket/angle depth 0.
pub fn split_top<'t>(toks: &'t [Token], sep: &str) -> Vec<&'t [Token]> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (k, t) in toks.iter().enumerate() {
        if t.kind == Kind::Punct {
            match t.text.as_str() {
                "(" | "[" | "{" | "<" => depth += 1,
                ")" | "]" | "}" | ">" => depth -= 1,
                ">>" => depth -= 2,
                "<<" => depth += 2,
                s if s == sep && depth == 0 => {
                    out.push(&toks[start..k]);
                    start = k + 1;
                }
                _ => {}
            }
        }
    }
    if start < toks.len() {
        out.push(&toks[start..]);
    }
    out
}

/// Index of the `>` closing an angle bracket opened at `open` (handles `>>`).
pub fn matching_angle(code: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (k, t) in code.iter().enumerate().skip(open) {
        match t.text.as_str() {
            "<" => depth += 1,
            "<<" => depth += 2,
            ">" => depth -= 1,
            ">>" => depth -= 2,
            "(" | "[" if depth == 0 => return None,
            ";" | "{" => return None,
            _ => {}
        }
        if depth <= 0 && k > open {
            return Some(k);
        }
    }
    None
}

/// Signature pieces of a function, as token index ranges into the file's code tokens.
#[derive(Debug, Clone, Default)]
pub struct FnSig {
    /// Index of the `fn` keyword.
    pub fn_kw: usize,
    /// Tokens inside `<...>` after the name.
    pub generics: Option<(usize, usize)>,
    /// Parameter parentheses `(`..`)`.
    pub params: Option<(usize, usize)>,
    /// Return type tokens after `->` (exclusive end).
    pub ret: Option<(usize, usize)>,
    /// `where` clause tokens (exclusive end).
    pub where_clause: Option<(usize, usize)>,
}

pub fn fn_sig(code: &[Token], f: &FnItem) -> FnSig {
    let mut s = FnSig::default();
    let Some(kw) = (f.decl..code.len()).find(|&k| code[k].ident("fn")) else { return s };
    s.fn_kw = kw;
    let mut j = kw + 2;
    if code.get(j).is_some_and(|t| t.punct("<")) {
        if let Some(c) = matching_angle(code, j) {
            s.generics = Some((j + 1, c));
            j = c + 1;
        }
    }
    if code.get(j).is_some_and(|t| t.punct("(")) {
        if let Some(c) = items::matching(code, j) {
            s.params = Some((j, c));
            j = c + 1;
        }
    }
    let end = f.body.map(|b| b.0).unwrap_or_else(|| (j..code.len()).find(|&k| code[k].punct(";")).unwrap_or(code.len()));
    let wh = (j..end).find(|&k| code[k].ident("where"));
    if code.get(j).is_some_and(|t| t.punct("->")) {
        s.ret = Some((j + 1, wh.unwrap_or(end)));
    }
    if let Some(w) = wh {
        s.where_clause = Some((w + 1, end));
    }
    s
}

fn relex_inner(text: &str) -> Vec<Token> {
    // `<T: Send>` -> tokens of `T: Send`
    let mut t = items::code_only(&lex(text));
    if t.first().is_some_and(|x| x.punct("<")) {
        t.remove(0);
        if t.last().is_some_and(|x| x.punct(">")) {
            t.pop();
        }
    }
    t
}

/// Where-clause predicates as (lhs tokens text, bounds text).
fn where_preds(toks: &[Token]) -> Vec<(Vec<String>, String)> {
    split_top(toks, ",")
        .into_iter()
        .filter_map(|p| {
            let c = p.iter().position(|t| t.punct(":"))?;
            Some((p[..c].iter().map(|t| t.text.clone()).collect(), items::join(&p[c + 1..])))
        })
        .collect()
}

fn mentions_auto(bounds: &str) -> bool {
    bounds.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| w == "Send" || w == "Sync")
}

impl FileCtx<'_> {
    fn push(&mut self, idx: usize, code: &'static str, sev: Severity, msg: String, fix: &'static str) {
        let line = self.code[idx].line;
        let mut src: String = self.f.line_text(line).trim().to_string();
        if src.chars().count() > 160 {
            src = src.chars().take(157).collect::<String>() + "...";
        }
        self.out.push(Hotspot { code, severity: sev, message: msg, file: self.f.rel.clone(), line, source: src, fix });
    }

    fn enclosing(&self, i: usize) -> Option<&FnItem> {
        items::enclosing_fn(self.fns, i)
    }

    fn in_unsafe_fn(&self, i: usize) -> bool {
        self.enclosing(i).is_some_and(|f| f.is_unsafe)
    }

    /// Whether the innermost unsafe block around `i` carries a SAFETY comment.
    fn documented_at(&self, i: usize) -> bool {
        self.blocks.iter().filter(|(a, b, _)| *a < i && i < *b).min_by_key(|(a, b, _)| b - a).is_some_and(|x| x.2)
    }

    /// Parameter names of the enclosing fn.
    fn param_names(&self, i: usize) -> Vec<String> {
        let Some(f) = self.enclosing(i) else { return vec![] };
        let Some((a, b)) = fn_sig(self.code, f).params else { return vec![] };
        split_top(&self.code[a + 1..b], ",")
            .into_iter()
            .filter_map(|p| {
                let c = p.iter().position(|t| t.punct(":"))?;
                p[..c].iter().rev().find(|t| t.kind == Kind::Ident && t.text != "mut").map(|t| t.text.clone())
            })
            .collect()
    }

    /// Tokens of the enclosing fn body before `i` (or the 200 tokens before when outside a fn).
    fn before(&self, i: usize) -> &[Token] {
        match self.enclosing(i).and_then(|f| f.body) {
            Some((a, _)) => &self.code[a..i],
            None => &self.code[i.saturating_sub(200)..i],
        }
    }

    /// Statement around `i`: back to `;`/`}`/a `{` not opened by `unsafe`, forward to `;`.
    fn statement(&self, i: usize) -> (usize, usize) {
        let c = self.code;
        let mut a = i;
        while a > 0 {
            let p = &c[a - 1];
            if p.punct(";") || p.punct("}") || (p.punct("{") && !(a >= 2 && c[a - 2].ident("unsafe"))) {
                break;
            }
            a -= 1;
        }
        let mut b = i;
        let mut depth = 0i32;
        while b < c.len() {
            match c[b].text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                ";" if depth <= 0 => break,
                _ => {}
            }
            b += 1;
        }
        (a, b)
    }

    /// Generic type parameters in scope at `i` (enclosing fn and its impl block).
    fn generics_at(&self, i: usize) -> Vec<GenericParam> {
        let mut out = Vec::new();
        if let Some(f) = self.enclosing(i) {
            let s = fn_sig(self.code, f);
            if let Some((a, b)) = s.generics {
                out.extend(parse_generics(&self.code[a..b]));
            }
            if let Some((a, b)) = s.where_clause {
                for (lhs, bounds) in where_preds(&self.code[a..b]) {
                    if lhs.len() == 1 {
                        if let Some(p) = out.iter_mut().find(|p| p.name == lhs[0]) {
                            p.bounds = format!("{} + {bounds}", p.bounds);
                        }
                    }
                }
            }
            if let Some(im) = f.impl_idx.and_then(|k| self.impls.get(k)) {
                out.extend(parse_generics(&relex_inner(&im.generics)));
            }
        }
        out
    }

    fn patterns(&mut self, i: usize) {
        let c = self.code;
        let t = &c[i];
        let prev = |k: usize| if i >= k { c.get(i - k) } else { None };
        let next = |k: usize| c.get(i + k);
        let after_dot = prev(1).is_some_and(|p| p.punct("."));
        let call = next(1).is_some_and(|x| x.punct("("));
        match t.text.as_str() {
            "set_len" if after_dot && call => self.set_len(i),
            "uninitialized" if prev(1).is_some_and(|p| p.punct("::")) && prev(2).is_some_and(|p| p.ident("mem")) => {
                self.push(i, "mem-uninitialized", Severity::High,
                    "`mem::uninitialized` is deprecated and instantly undefined behavior for most types".into(),
                    "Use MaybeUninit<T> and only assume_init() after every byte is written");
            }
            "zeroed" if prev(1).is_some_and(|p| p.punct("::")) && prev(2).is_some_and(|p| p.ident("mem")) => self.zeroed(i),
            "transmute" if prev(1).is_none_or(|p| !p.punct(".")) && (call || next(1).is_some_and(|x| x.punct("::"))) => self.transmute(i),
            "from_raw_parts" | "from_raw_parts_mut" if call || next(1).is_some_and(|x| x.punct("::")) => {
                let owner = if prev(1).is_some_and(|p| p.punct("::")) { prev(2).map(|p| p.text.as_str()) } else { None };
                match owner {
                    Some("slice") => self.check_from_raw_parts(i),
                    None if !after_dot => self.check_from_raw_parts(i),
                    Some("Vec") | Some("String") => self.check_from_raw(i, "Vec::from_raw_parts"),
                    _ => {}
                }
            }
            "from_raw" if call && prev(1).is_some_and(|p| p.punct("::")) && prev(2).is_some_and(|p| matches!(p.text.as_str(), "Box" | "Rc" | "Arc")) => {
                let name = format!("{}::from_raw", c[i - 2].text);
                self.check_from_raw(i, &name);
            }
            "get_unchecked" | "get_unchecked_mut" if after_dot && call => self.get_unchecked(i),
            "as" if next(1).is_some_and(|x| x.punct("*")) && next(2).is_some_and(|x| x.ident("const")) => self.const_to_mut(i),
            _ => {}
        }
    }

    fn call_args(&self, i: usize) -> Option<Vec<&[Token]>> {
        // i = function name; skip turbofish
        let mut j = i + 1;
        if self.code.get(j).is_some_and(|t| t.punct("::")) && self.code.get(j + 1).is_some_and(|t| t.punct("<")) {
            j = matching_angle(self.code, j + 1)? + 1;
        }
        if !self.code.get(j)?.punct("(") {
            return None;
        }
        let close = items::matching(self.code, j)?;
        Some(split_top(&self.code[j + 1..close], ","))
    }

    fn set_len(&mut self, i: usize) {
        let Some(args) = self.call_args(i) else { return };
        let arg = args.first().map(|a| items::join(a)).unwrap_or_default();
        // shrinking (`set_len(0)`, `set_len(len - n)`) never exposes uninitialized memory
        if arg == "0" || arg.contains(" - ") || arg.contains("saturating_sub") || arg.contains("checked_sub") {
            return;
        }
        let before = self.before(i);
        // guarded shrink: `if len <= self.len() { set_len(len) }`
        let arg_toks = &args[0];
        if arg_toks.len() == 1 && arg_toks[0].kind == Kind::Ident {
            let name = &arg_toks[0].text;
            let guarded = before.windows(2).any(|w| {
                (w[0].ident(name) && (w[1].punct("<=") || w[1].punct("<"))) || ((w[0].punct(">=") || w[0].punct(">")) && w[1].ident(name))
            });
            if guarded {
                return;
            }
        }
        let init = before.iter().any(|t| {
            t.kind == Kind::Ident && {
                let s = t.text.to_ascii_lowercase();
                ["write", "copy", "fill", "init", "as_mut_ptr", "extend", "push", "read", "clone_from", "spare_capacity", "set_len", "zero", "insert", "add"]
                    .iter()
                    .any(|k| s.contains(k))
            }
        });
        let contract = self.in_unsafe_fn(i);
        if init || contract {
            let sev = if self.documented_at(i) { Severity::Low } else { Severity::Medium };
            let why = if contract && !init { " (inside an unsafe fn: the caller must have initialized it)" } else { "" };
            self.push(i, "set-len-verify", sev,
                format!("`set_len({arg})`: verify every element up to the new length is initialized{why}"),
                "Prefer spare_capacity_mut()/MaybeUninit writes followed by set_len, or extend/resize");
        } else {
            self.push(i, "set-len-before-init", Severity::High,
                format!("`set_len({arg})` before any write to the buffer in this function exposes uninitialized memory"),
                "Initialize the elements first (ptr::write, copy_nonoverlapping, spare_capacity_mut) and call set_len after");
        }
    }

    fn zeroed(&mut self, i: usize) {
        let c = self.code;
        let generics = self.generics_at(i);
        let ty: Option<String> = if c.get(i + 1).is_some_and(|t| t.punct("::")) && c.get(i + 2).is_some_and(|t| t.punct("<")) {
            matching_angle(c, i + 2).map(|e| items::join(&c[i + 3..e]))
        } else {
            // `let x: T = mem::zeroed()`
            let (a, _) = self.statement(i);
            let st = &c[a..i];
            match (st.iter().position(|t| t.ident("let")), st.iter().position(|t| t.punct(":")), st.iter().rposition(|t| t.punct("="))) {
                (Some(_), Some(colon), Some(eq)) if colon < eq => Some(items::join(&st[colon + 1..eq])),
                _ => {
                    // tail expression of a fn returning a generic
                    self.enclosing(i).and_then(|f| {
                        let s = fn_sig(c, f);
                        let body_end = f.body?.1;
                        let tail = c[i..body_end].iter().all(|t| !t.punct(";"));
                        if tail { s.ret.map(|(a, b)| items::join(&c[a..b])) } else { None }
                    })
                }
            }
        };
        let Some(ty) = ty else { return };
        let Some(p) = generics.iter().find(|g| g.name == ty.trim()) else { return };
        let zero_safe = ["Zeroable", "Pod", "FromZeroes", "FromZeros", "Zeroed", "AnyBitPattern", "Zero"];
        if zero_safe.iter().any(|z| p.bounds.contains(z)) {
            return;
        }
        let in_unsafe_fn = self.enclosing(i).is_some_and(|f| f.is_unsafe);
        let sev = if in_unsafe_fn { Severity::Medium } else { Severity::High };
        self.push(i, "zeroed-generic", sev,
            format!("`mem::zeroed` for generic `{ty}`: undefined behavior when `{ty}` is a reference, NonNull, enum or other type without a valid all-zero value{}",
                if in_unsafe_fn { " (inside an unsafe fn: callers must uphold it)" } else { "" }),
            "Bound the parameter by a zero-safe trait (bytemuck::Zeroable, zerocopy::FromZeros) or use MaybeUninit::zeroed() without assume_init");
    }

    fn transmute(&mut self, i: usize) {
        let c = self.code;
        let turbofish = if c.get(i + 1).is_some_and(|t| t.punct("::")) && c.get(i + 2).is_some_and(|t| t.punct("<")) {
            matching_angle(c, i + 2).map(|e| &c[i + 3..e])
        } else {
            None
        };
        let hit = match turbofish {
            Some(tf) => {
                let parts = split_top(tf, ",");
                let lifetimes: Vec<&str> = tf.iter().filter(|t| t.kind == Kind::Lifetime && t.text != "'_").map(|t| t.text.as_str()).collect();
                let to = parts.get(1).map(|p| items::join(p)).unwrap_or_default();
                to.contains("'static")
                    || (parts.len() == 2 && lifetimes.len() >= 2 && {
                        let a: HashSet<&str> = parts[0].iter().filter(|t| t.kind == Kind::Lifetime).map(|t| t.text.as_str()).collect();
                        let b: HashSet<&str> = parts[1].iter().filter(|t| t.kind == Kind::Lifetime).map(|t| t.text.as_str()).collect();
                        !a.is_empty() && !b.is_empty() && a != b
                    })
            }
            None => {
                let (a, _) = self.statement(i);
                c[a..i].iter().any(|t| t.kind == Kind::Lifetime && t.text == "'static") && c[a..i].iter().any(|t| t.punct("&") || t.ident("str"))
            }
        };
        if hit {
            self.push(i, "transmute-lifetime", Severity::High,
                "`transmute` that changes or extends a lifetime (to `'static` or between named lifetimes) can create dangling references".into(),
                "Avoid lifetime transmutes; restructure ownership (Arc, owned data) or prove the referent truly lives long enough and document it");
        }
    }

    fn check_from_raw_parts(&mut self, i: usize) {
        let Some(args) = self.call_args(i) else { return };
        if args.len() != 2 {
            return;
        }
        let ptr = items::join(args[0]);
        let len = items::join(args[1]);
        let literal = args[1].len() == 1 && args[1][0].kind == Kind::Num;
        let base = |s: &str| -> Option<String> {
            for suffix in [".as_ptr()", ".as_mut_ptr()", ".as_ptr().cast()", ".as_mut_ptr().cast()"] {
                if let Some(b) = s.strip_suffix(suffix) {
                    return Some(b.trim_start_matches("&mut ").trim_start_matches('&').to_string());
                }
            }
            None
        };
        let strip_field = |s: &str, fields: &[&str]| -> String {
            let mut s = s.to_string();
            for f in fields {
                if let Some(b) = s.strip_suffix(f) {
                    s = b.to_string();
                }
            }
            s
        };
        let pbase = strip_field(&base(&ptr).unwrap_or_else(|| ptr.clone()), &[".cast()", ".ptr", ".data", ".buf"]);
        let lbase = strip_field(&len, &[".len()", ".len"]);
        let same_source = (len != lbase && pbase == lbase) || base(&ptr).is_some_and(|b| len == format!("{b}.len()"));
        // `let (ptr, len, ..) = x.triple();`
        let before = self.before(i);
        let pident = args[0].iter().find(|t| t.kind == Kind::Ident).map(|t| t.text.as_str());
        let tuple = args[1].len() == 1
            && pident.is_some_and(|p| {
                before.windows(2).enumerate().any(|(k, w)| {
                    w[0].ident("let") && w[1].punct("(") && {
                        let e = (k + 1..before.len()).find(|&m| before[m].punct(")")).unwrap_or(k + 1);
                        let pat = &before[k + 1..e];
                        pat.iter().any(|t| t.ident(p)) && pat.iter().any(|t| t.ident(&args[1][0].text))
                    }
                })
            });
        let params = self.param_names(i);
        let contract = self.in_unsafe_fn(i) && pident.is_some_and(|p| params.iter().any(|x| x == p)) && params.contains(&len);
        let documented = self.documented_at(i);
        let sev = if literal || same_source || tuple || contract || documented { Severity::Low } else { Severity::Medium };
        let why = if literal || same_source || tuple {
            "pointer and length come from the same source"
        } else if contract {
            "pointer and length are parameters of this unsafe fn (caller contract)"
        } else if documented {
            "documented with a SAFETY comment; verify it covers validity, alignment and initialization"
        } else {
            "undocumented: verify the pointer is valid, aligned and initialized for `len` elements"
        };
        self.push(i, "from-raw-parts", sev,
            format!("`{}({ptr}, {len})`: {why}", self.code[i].text),
            "Keep pointer and length from the same allocation; prefer safe slicing where possible");
    }

    fn check_from_raw(&mut self, i: usize, what: &str) {
        let Some(args) = self.call_args(i) else { return };
        let ptr = args.first().map(|a| items::join(a)).unwrap_or_default();
        let all_args = args.iter().map(|a| items::join(a)).collect::<Vec<_>>().join(", ");
        // double use: the same pointer handed to another from_raw in this function
        let body = match self.enclosing(i).and_then(|f| f.body) {
            Some((a, b)) => (a, b),
            None => (i, i),
        };
        let mut uses = 0;
        for k in body.0..body.1 {
            let t = &self.code[k];
            if (t.ident("from_raw") || t.ident("from_raw_parts")) && k >= 2 && self.code[k - 1].punct("::") && matches!(self.code[k - 2].text.as_str(), "Box" | "Rc" | "Arc" | "Vec" | "String") {
                if let Some(a) = self.call_args(k) {
                    if a.first().map(|x| items::join(x)).as_deref() == Some(ptr.as_str()) {
                        uses += 1;
                    }
                }
            }
        }
        if uses > 1 && !ptr.is_empty() {
            self.push(i, "double-from-raw", Severity::Medium,
                format!("`{what}({ptr})` appears {uses} times in this function: if more than one runs, the allocation is freed twice"),
                "Make sure only one owner is reconstructed from a raw pointer (branches are fine; sequential uses are a double free)");
        } else {
            self.push(i, "from-raw", Severity::Info,
                format!("`{what}({all_args})` takes ownership of a raw pointer"),
                "Verify the pointer came from the matching into_raw and is reconstructed exactly once");
        }
    }

    fn get_unchecked(&mut self, i: usize) {
        let before = self.before(i);
        let checked = before.iter().enumerate().any(|(k, t)| {
            if t.kind != Kind::Ident {
                return t.punct("%") || (t.punct("..") && before[..k].iter().rev().take(8).any(|x| x.ident("in")));
            }
            let s = t.text.as_str();
            if s.starts_with("assert") || s.starts_with("debug_assert") || s == "min" || s == "clamp" || s == "checked_sub" {
                return true;
            }
            if s == "if" || s == "while" {
                // condition up to `{`
                let rest = &before[k + 1..];
                let cond = &rest[..rest.iter().position(|x| x.punct("{")).unwrap_or(rest.len())];
                return cond.iter().any(|x| matches!(x.text.as_str(), "<" | "<=" | ">" | ">=" | "len" | "is_empty" | "get"));
            }
            false
        });
        if checked {
            return;
        }
        let in_unsafe_fn = self.in_unsafe_fn(i);
        let documented = self.documented_at(i);
        let sev = if in_unsafe_fn || documented { Severity::Low } else { Severity::Medium };
        let m = &self.code[i].text;
        self.push(i, "get-unchecked-unchecked", sev,
            format!("`.{m}()` with no assert, bounds condition or bounded loop earlier in this function{}",
                if in_unsafe_fn { " (unsafe fn: callers must guarantee the index)" } else if documented { " (a SAFETY comment states the bound)" } else { "" }),
            "Add a debug_assert!(idx < len) and make sure the index is bounded on every path");
    }

    fn const_to_mut(&mut self, i: usize) {
        let c = self.code;
        // as *const T [...] as *mut U
        let end = (i + 3..(i + 16).min(c.len())).find(|&k| c[k].ident("as") && c.get(k + 1).is_some_and(|t| t.punct("*")) && c.get(k + 2).is_some_and(|t| t.ident("mut")));
        let Some(_end) = end else { return };
        let (a, b) = self.statement(i);
        let st = &c[a..b];
        let writes_through = st.windows(3).any(|w| w[0].punct("&") && w[1].ident("mut") && w[2].punct("*"));
        if !writes_through {
            return;
        }
        self.push(i, "const-to-mut", Severity::Medium,
            "`&mut *` through a `*const` -> `*mut` cast: writing through a pointer derived from a shared reference is undefined behavior".into(),
            "Derive the pointer from a &mut or an UnsafeCell (e.g. UnsafeCell::get), not from a shared reference");
    }

    fn send_sync(&mut self, im: &ImplBlock) {
        if !im.is_unsafe {
            return;
        }
        let Some(tr) = im.trait_name.as_deref() else { return };
        if tr != "Send" && tr != "Sync" {
            return;
        }
        let params = parse_generics(&relex_inner(&im.generics));
        if params.is_empty() {
            return;
        }
        let self_toks = items::code_only(&lex(&im.self_ty));
        let wheres = where_preds(&items::code_only(&lex(&im.where_clause)));
        let unbounded: Vec<&str> = params
            .iter()
            .filter(|p| self_toks.iter().any(|t| t.ident(&p.name)))
            .filter(|p| !mentions_auto(&p.bounds))
            .filter(|p| !wheres.iter().any(|(lhs, b)| lhs.contains(&p.name) && mentions_auto(b)))
            .map(|p| p.name.as_str())
            .collect();
        if unbounded.is_empty() {
            return;
        }
        let names = unbounded.join("`, `");
        let ty_name = self_toks.iter().find(|t| t.kind == Kind::Ident).map(|t| t.text.as_str()).unwrap_or("");
        let public = self.types.get(ty_name).copied().unwrap_or(true);
        let (sev, note) = if public {
            (Severity::High, "")
        } else {
            (Severity::Medium, " (the type is not `pub`: check that every public wrapper adds the bounds)")
        };
        self.push(im.start, "send-sync-unbounded", sev,
            format!("`unsafe impl{} {tr} for {}` without a Send/Sync bound on `{names}`: lets non-thread-safe `{names}` cross threads{note}",
                im.generics, im.self_ty),
            "Add `T: Send` (for Send) or `T: Sync`/`T: Send + Sync` (for Sync) bounds, unless the type never stores or hands out T (then document why)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(src: &str) -> CrateUnsafe {
        let f = SourceFile::from_text(Path::new("/x"), Path::new("/x/src/lib.rs"), src.to_string());
        analyze(&[f])
    }
    fn codes(u: &CrateUnsafe) -> Vec<&str> {
        u.hotspots.iter().map(|h| h.code).collect()
    }

    #[test]
    fn counts_and_safety_comments() {
        let u = scan(
            r#"
pub unsafe fn a() {
    unsafe { x() } // SAFETY: fine
}
fn b() {
    // Safety: the pointer is valid
    // and aligned.
    #[allow(unused)]
    let v = unsafe { *p };
    let w = unsafe { *p };
    let z = unsafe {
        // SAFETY: inside
        *p
    };
    let q =
        unsafe { *p };
}
unsafe impl Send for X {}
pub unsafe trait T {}
extern "C" { fn f(); }
#[no_mangle]
pub extern "C" fn g() {}
static mut COUNTER: u32 = 0;
type F = unsafe fn(u8);
macro_rules! m { () => { unsafe { 1 } } }
#[cfg(test)]
mod tests { fn t() { unsafe { 1 }; } }
"#,
        );
        assert_eq!(u.blocks, 6, "{u:?}");
        assert_eq!(u.blocks_in_unsafe_fn, 1);
        assert_eq!(u.blocks_in_macros, 1);
        assert_eq!(u.unsafe_fns, 1);
        assert_eq!(u.unsafe_impls, 1);
        assert_eq!(u.unsafe_traits, 1);
        assert_eq!(u.extern_blocks, 1);
        assert_eq!(u.no_mangle, 1);
        assert_eq!(u.static_mut, 1);
        let lines: Vec<usize> = u.undocumented.iter().map(|x| x.1).collect();
        assert_eq!(lines, [10, 16, 25], "{:?}", u.undocumented);
    }

    #[test]
    fn set_len_patterns() {
        let u = scan(
            "fn a(v: &mut Vec<u8>, n: usize) { unsafe { v.set_len(n); } }
             fn b(v: &mut Vec<u8>, n: usize) { unsafe { ptr::write(v.as_mut_ptr(), 1); v.set_len(n); } }
             fn c(v: &mut Vec<u8>) { unsafe { v.set_len(0); v.set_len(len - 1); } }",
        );
        assert_eq!(codes(&u), ["set-len-before-init", "set-len-verify"]);
        assert_eq!(u.hotspots[0].severity, Severity::High);
        assert_eq!(u.hotspots[0].line, 1);
        assert!(u.hotspots[0].source.contains("v.set_len(n)"));
    }

    #[test]
    fn uninit_zeroed_transmute() {
        let u = scan(
            "fn a<T>() -> T { unsafe { mem::uninitialized() } }
             fn b<T>() -> T { unsafe { std::mem::zeroed::<T>() } }
             fn c<T: bytemuck::Zeroable>() -> T { unsafe { mem::zeroed::<T>() } }
             fn d() -> u32 { unsafe { mem::zeroed() } }
             fn e<T>() { let x: T = unsafe { mem::zeroed() }; }
             fn f<'a>(x: &'a str) -> &'static str { unsafe { mem::transmute::<&'a str, &'static str>(x) } }
             fn g(x: u32) -> f32 { unsafe { mem::transmute(x) } }
             fn h<'a>(x: &'a str) { let s: &'static str = unsafe { transmute(x) }; }",
        );
        assert_eq!(codes(&u), ["mem-uninitialized", "zeroed-generic", "zeroed-generic", "transmute-lifetime", "transmute-lifetime"]);
        assert_eq!(u.hotspots[4].line, 8);
    }

    #[test]
    fn raw_parts_and_unchecked() {
        let u = scan(
            "fn a(s: &[u8]) -> &[u8] { unsafe { slice::from_raw_parts(s.as_ptr(), s.len()) } }
             fn b(p: *const u8, n: usize) -> &'static [u8] { unsafe { core::slice::from_raw_parts(p, n) } }
             fn c(v: &[u8], i: usize) -> u8 { unsafe { *v.get_unchecked(i) } }
             fn d(v: &[u8], i: usize) -> u8 { debug_assert!(i < v.len()); unsafe { *v.get_unchecked(i) } }
             fn e(v: &[u8]) { for i in 0..v.len() { unsafe { v.get_unchecked(i); } } }
             fn f(p: *mut u8) { unsafe { drop(Box::from_raw(p)); } }
             fn g(p: *mut u8) { unsafe { drop(Box::from_raw(p)); drop(Box::from_raw(p)); } }
             fn h(p: *mut u8, n: usize) { unsafe { Vec::from_raw_parts(p, n, n); } }",
        );
        let got: Vec<(&str, Severity)> = u.hotspots.iter().map(|h| (h.code, h.severity)).collect();
        assert_eq!(
            got,
            [
                ("from-raw-parts", Severity::Low),
                ("from-raw-parts", Severity::Medium),
                ("get-unchecked-unchecked", Severity::Medium),
                ("from-raw", Severity::Info),
                ("double-from-raw", Severity::Medium),
                ("double-from-raw", Severity::Medium),
                ("from-raw", Severity::Info),
            ]
        );
    }

    #[test]
    fn send_sync_bounds() {
        let u = scan(
            "unsafe impl<T> Send for A<T> {}
             unsafe impl<T: Send> Send for B<T> {}
             unsafe impl<T> Sync for C<T> where T: Sync + Send {}
             unsafe impl<T: ?Sized> Sync for D<T> {}
             unsafe impl Send for E {}
             unsafe impl<'a> Send for F<'a> {}
             unsafe impl<T, U: Send> Send for G<T, U> where T: Send {}
             unsafe impl<T> Send for H {}",
        );
        let lines: Vec<usize> = u.hotspots.iter().map(|h| h.line).collect();
        assert_eq!(codes(&u), ["send-sync-unbounded", "send-sync-unbounded"]);
        assert_eq!(lines, [1, 4]);
    }

    #[test]
    fn const_to_mut_write() {
        let u = scan(
            "fn a(x: &u8) { unsafe { let r = &mut *(x as *const u8 as *mut u8); *r = 1; } }
             fn b(x: &u8) -> *mut u8 { x as *const u8 as *mut u8 }",
        );
        assert_eq!(codes(&u), ["const-to-mut"]);
    }

    #[test]
    fn diff_matches_by_line_text() {
        let old = scan("fn a(v: &mut Vec<u8>, n: usize) { unsafe { v.set_len(n); } }");
        let new = scan("\n\nfn a(v: &mut Vec<u8>, n: usize) { unsafe { v.set_len(n); } }\nfn b<T>() -> T { unsafe { mem::uninitialized() } }");
        let added = new_hotspots(&old, &new);
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].code, "mem-uninitialized");
    }

    #[test]
    fn module_dirs() {
        assert_eq!(module_dir("src/lib.rs"), "src/");
        assert_eq!(module_dir("src/foo.rs"), "src/foo/");
        assert_eq!(module_dir("src/foo/mod.rs"), "src/foo/");
    }

    #[test]
    fn generics_parse() {
        let t = items::code_only(&lex("'a, T: Send + 'a, const N: usize, U = u8"));
        let g = parse_generics(&t);
        assert_eq!(g, [GenericParam { name: "T".into(), bounds: "Send + 'a".into() }, GenericParam { name: "U".into(), bounds: String::new() }]);
    }
}
