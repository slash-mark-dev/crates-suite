//! Shared machinery for the Features & targets tools: a `cfg(...)` parser and
//! three-valued evaluator, target cfg from `rustc --print cfg`, cfg-scoped
//! source spans (from the lexer), the crate module tree, `cargo tree` and
//! `cargo check --message-format json` parsing, feature closures, "who enables
//! feature F of package P", and no_std detection.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata, Package};
use crate::rustsrc::items::{inner_attrs, matching};
use crate::rustsrc::{Kind, SourceFile, Token, lex};
use crate::util;

// ====================================================================== cfg

/// A parsed `cfg` predicate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cfg {
    Name(String),
    KeyValue(String, String),
    All(Vec<Cfg>),
    Any(Vec<Cfg>),
    Not(Box<Cfg>),
}

impl Cfg {
    /// Parse a predicate written as `cfg(...)` or bare (`unix`, `all(...)`).
    pub fn parse(s: &str) -> Option<Cfg> {
        let toks: Vec<Token> = lex(s).into_iter().filter(|t| !t.is_comment()).collect();
        let toks = strip_cfg_wrapper(&toks);
        let mut i = 0;
        let c = parse_pred(toks, &mut i)?;
        (i == toks.len()).then_some(c)
    }

    /// Parse the predicate from the tokens between `cfg(` and `)`.
    pub fn from_tokens(toks: &[Token]) -> Option<Cfg> {
        let mut i = 0;
        let c = parse_pred(toks, &mut i)?;
        (i == toks.len()).then_some(c)
    }

    /// Feature names this predicate mentions.
    pub fn features(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.walk(&mut |c| {
            if let Cfg::KeyValue(k, v) = c {
                if k == "feature" {
                    out.insert(v.clone());
                }
            }
        });
        out
    }

    /// Whether a feature appears under a `not(...)`.
    pub fn has_negated_feature(&self) -> Vec<String> {
        let mut out = Vec::new();
        fn go(c: &Cfg, neg: bool, out: &mut Vec<String>) {
            match c {
                Cfg::KeyValue(k, v) if k == "feature" && neg => out.push(v.clone()),
                Cfg::All(v) | Cfg::Any(v) => v.iter().for_each(|x| go(x, neg, out)),
                Cfg::Not(b) => go(b, !neg, out),
                _ => {}
            }
        }
        go(self, false, &mut out);
        out.sort();
        out.dedup();
        out
    }

    fn walk(&self, f: &mut dyn FnMut(&Cfg)) {
        f(self);
        match self {
            Cfg::All(v) | Cfg::Any(v) => v.iter().for_each(|x| x.walk(f)),
            Cfg::Not(b) => b.walk(f),
            _ => {}
        }
    }

    /// Evaluate with three-valued logic: `None` means "depends on something unknown".
    pub fn eval(&self, env: &Env) -> Option<bool> {
        match self {
            Cfg::Name(n) => env.name(n),
            Cfg::KeyValue(k, v) => env.key_value(k, v),
            Cfg::All(v) => {
                let mut unknown = false;
                for c in v {
                    match c.eval(env) {
                        Some(false) => return Some(false),
                        None => unknown = true,
                        Some(true) => {}
                    }
                }
                if unknown { None } else { Some(true) }
            }
            Cfg::Any(v) => {
                let mut unknown = false;
                for c in v {
                    match c.eval(env) {
                        Some(true) => return Some(true),
                        None => unknown = true,
                        Some(false) => {}
                    }
                }
                if unknown { None } else { Some(false) }
            }
            Cfg::Not(b) => b.eval(env).map(|x| !x),
        }
    }
}

impl std::fmt::Display for Cfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cfg::Name(n) => write!(f, "{n}"),
            Cfg::KeyValue(k, v) => write!(f, "{k} = \"{v}\""),
            Cfg::All(v) => write!(f, "all({})", v.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")),
            Cfg::Any(v) => write!(f, "any({})", v.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")),
            Cfg::Not(b) => write!(f, "not({b})"),
        }
    }
}

fn strip_cfg_wrapper(toks: &[Token]) -> &[Token] {
    if toks.len() >= 3 && toks[0].ident("cfg") && toks[1].punct("(") && toks[toks.len() - 1].punct(")") {
        &toks[2..toks.len() - 1]
    } else {
        toks
    }
}

fn unquote(s: &str) -> String {
    let s = s.strip_prefix('r').unwrap_or(s).trim_matches('#');
    s.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(s).to_string()
}

fn parse_pred(t: &[Token], i: &mut usize) -> Option<Cfg> {
    let tok = t.get(*i)?;
    if tok.kind != Kind::Ident {
        return None;
    }
    let name = tok.text.trim_start_matches("r#").to_string();
    *i += 1;
    match t.get(*i) {
        Some(p) if p.punct("=") => {
            *i += 1;
            let v = t.get(*i)?;
            if v.kind != Kind::Str {
                return None;
            }
            *i += 1;
            Some(Cfg::KeyValue(name, unquote(&v.text)))
        }
        Some(p) if p.punct("(") && matches!(name.as_str(), "all" | "any" | "not") => {
            *i += 1;
            let mut items = Vec::new();
            loop {
                if t.get(*i).is_some_and(|x| x.punct(")")) {
                    *i += 1;
                    break;
                }
                items.push(parse_pred(t, i)?);
                match t.get(*i) {
                    Some(x) if x.punct(",") => *i += 1,
                    Some(x) if x.punct(")") => {
                        *i += 1;
                        break;
                    }
                    _ => return None,
                }
            }
            match name.as_str() {
                "all" => Some(Cfg::All(items)),
                "any" => Some(Cfg::Any(items)),
                _ => {
                    if items.len() != 1 {
                        return None;
                    }
                    Some(Cfg::Not(Box::new(items.pop()?)))
                }
            }
        }
        _ => Some(Cfg::Name(name)),
    }
}

/// What is known when evaluating a cfg.
#[derive(Debug, Clone, Default)]
pub struct Env<'a> {
    /// Enabled features of the crate (`None` = unknown).
    pub features: Option<&'a BTreeSet<String>>,
    /// Target cfg (`None` = any target).
    pub target: Option<&'a TargetCfg>,
}

/// cfg names and keys rustc sets from the target or compiler flags.
fn is_target_name(n: &str) -> bool {
    matches!(n, "unix" | "windows" | "debug_assertions" | "target_thread_local" | "overflow_checks" | "ub_checks" | "panic" | "relocation_model" | "sanitize" | "fmt_debug" | "contract_checks" | "emscripten_wasm_eh")
        || n.starts_with("target_")
}

impl Env<'_> {
    fn name(&self, n: &str) -> Option<bool> {
        match n {
            "true" => Some(true),
            "false" => Some(false),
            _ if is_target_name(n) => self.target.map(|t| t.names.contains(n)),
            // test, doc, docsrs, miri, loom, custom --cfg flags: not set in a normal build
            _ => Some(false),
        }
    }
    fn key_value(&self, k: &str, v: &str) -> Option<bool> {
        if k == "feature" {
            return self.features.map(|f| f.contains(v));
        }
        if is_target_name(k) {
            return self.target.map(|t| t.kv.contains(&(k.to_string(), v.to_string())));
        }
        Some(false)
    }
}

// ====================================================================== targets

/// `rustc --print cfg --target T` output.
#[derive(Debug, Clone, Default)]
pub struct TargetCfg {
    pub triple: String,
    pub names: BTreeSet<String>,
    pub kv: BTreeSet<(String, String)>,
}

impl TargetCfg {
    pub fn parse(triple: &str, out: &str) -> TargetCfg {
        let mut t = TargetCfg { triple: triple.to_string(), ..Default::default() };
        for l in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
            match l.split_once('=') {
                Some((k, v)) => {
                    t.kv.insert((k.to_string(), v.trim_matches('"').to_string()));
                }
                None => {
                    t.names.insert(l.to_string());
                }
            }
        }
        t
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
    /// Whether the target ships the `std` crate at all.
    pub fn has_std(&self) -> bool {
        let os = self.get("target_os").unwrap_or("");
        !(os == "none" || self.triple.contains("-none"))
    }
    pub fn is_wasm_unknown(&self) -> bool {
        self.get("target_arch") == Some("wasm32") && self.get("target_os") == Some("unknown")
    }
    pub fn env(&self) -> Env<'_> {
        Env { features: None, target: Some(self) }
    }
}

fn rustc() -> String {
    std::env::var("RUSTC").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "rustc".into())
}

/// Target cfg for a triple, cached per process.
pub fn target_cfg(triple: &str) -> Result<TargetCfg> {
    static CACHE: OnceLock<Mutex<HashMap<String, TargetCfg>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(t) = cache.lock().ok().and_then(|c| c.get(triple).cloned()) {
        return Ok(t);
    }
    let o = util::run(Command::new(rustc()).args(["--print", "cfg", "--target", triple]), Duration::from_secs(60))?;
    if !o.success() {
        let msg = o.stderr.lines().find(|l| l.contains("error")).unwrap_or("").trim().to_string();
        return Err(Error::Usage(format!("unknown target `{triple}` ({msg}); list targets with `rustc --print target-list`")));
    }
    let t = TargetCfg::parse(triple, &o.stdout);
    if let Ok(mut c) = cache.lock() {
        c.insert(triple.to_string(), t.clone());
    }
    Ok(t)
}

/// The host triple from `rustc -vV`.
pub fn host_triple() -> Result<String> {
    static HOST: OnceLock<Option<String>> = OnceLock::new();
    HOST.get_or_init(|| {
        let o = util::run(Command::new(rustc()).arg("-vV"), Duration::from_secs(60)).ok()?;
        o.stdout.lines().find_map(|l| l.strip_prefix("host: ")).map(|s| s.trim().to_string())
    })
    .clone()
    .ok_or_else(|| Error::Env("could not determine the host target (`rustc -vV` failed); is Rust installed?".into()))
}

/// Whether the standard library for `triple` is installed in the active toolchain's sysroot.
pub fn target_installed(triple: &str) -> bool {
    let Ok(o) = util::run(Command::new(rustc()).args(["--print", "sysroot"]), Duration::from_secs(60)) else { return false };
    let root = PathBuf::from(o.stdout.trim());
    root.join("lib").join("rustlib").join(triple).join("lib").is_dir()
}

/// Evaluate a Cargo dependency `target` string (`cfg(...)` or a triple) for a target.
pub fn dep_target_applies(spec: Option<&str>, t: &TargetCfg) -> Option<bool> {
    let Some(s) = spec else { return Some(true) };
    let s = s.trim();
    if s.starts_with("cfg(") {
        Cfg::parse(s).and_then(|c| c.eval(&t.env()))
    } else {
        Some(s == t.triple)
    }
}

// ====================================================================== cfg-scoped spans

/// A source region gated by a `#[cfg(...)]` attribute: token indices `[start, end]`
/// in the comment-free token list (from the attribute's `#` to the item's end).
#[derive(Debug, Clone)]
pub struct CfgSpan {
    pub start: usize,
    pub end: usize,
    pub cfg: Cfg,
    pub line: usize,
    /// A branch body of a `cfg_if!` invocation (not an attribute on an item).
    pub branch: bool,
}

const ITEM_KW: &[&str] =
    &["fn", "impl", "struct", "enum", "trait", "type", "mod", "use", "const", "static", "union", "extern", "unsafe", "async", "let", "macro_rules", "pub"];

/// Every `#[cfg(...)]` attribute and the item/statement/field it gates.
pub fn cfg_spans(code: &[Token]) -> Vec<CfgSpan> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < code.len() {
        if !(code[i].punct("#") && code[i + 1].punct("[")) {
            i += 1;
            continue;
        }
        let Some(close) = matching(code, i + 1) else { break };
        let inner = &code[i + 2..close];
        // `if #[cfg(..)] {` inside cfg_if!: handled as a branch below
        let cfg_if_arm = i > 0 && code[i - 1].ident("if");
        if !cfg_if_arm && inner.len() >= 3 && inner[0].ident("cfg") && inner[1].punct("(") && inner[inner.len() - 1].punct(")") {
            if let Some(cfg) = Cfg::from_tokens(&inner[2..inner.len() - 1]) {
                let end = item_end(code, close + 1);
                out.push(CfgSpan { start: i, end, cfg, line: code[i].line, branch: false });
            }
        }
        i += 2;
    }
    for b in cfg_if_invocations(code) {
        for (open, close, cfg) in b.branches {
            out.push(CfgSpan { start: open, end: close, cfg, line: code[open].line, branch: true });
        }
    }
    out
}

/// One `cfg_if! { if #[cfg(A)] { .. } else if #[cfg(B)] { .. } else { .. } }` invocation.
#[derive(Debug, Clone)]
pub struct CfgIf {
    /// Delimiters of the macro body.
    pub open: usize,
    pub close: usize,
    /// Branch bodies (`{` and `}` indices) with the cfg under which each is compiled:
    /// `all(not(A), B)` for the second branch, `all(not(A), not(B))` for `else`.
    /// Empty when the body could not be parsed.
    pub branches: Vec<(usize, usize, Cfg)>,
}

/// Every `cfg_if!` / `cfg_if::cfg_if!` invocation in a token list.
pub fn cfg_if_invocations(code: &[Token]) -> Vec<CfgIf> {
    let mut out = Vec::new();
    for i in 0..code.len() {
        if !(code[i].ident("cfg_if") && code.get(i + 1).is_some_and(|t| t.punct("!"))) {
            continue;
        }
        let open = i + 2;
        if !code.get(open).is_some_and(|t| t.punct("{") || t.punct("(") || t.punct("[")) {
            continue;
        }
        let Some(close) = matching(code, open) else { continue };
        let branches = parse_cfg_if(code, open + 1, close).unwrap_or_default();
        out.push(CfgIf { open, close, branches });
    }
    out
}

fn parse_cfg_if(code: &[Token], mut p: usize, end: usize) -> Option<Vec<(usize, usize, Cfg)>> {
    let mut out = Vec::new();
    // `#[cfg(PRED)]` starting at `p`; returns the predicate and the index after `]`
    let attr = |p: usize| -> Option<(Cfg, usize)> {
        if !(code.get(p)?.punct("#") && code.get(p + 1)?.punct("[")) {
            return None;
        }
        let close = matching(code, p + 1)?;
        let inner = &code[p + 2..close];
        if inner.len() < 3 || !inner[0].ident("cfg") || !inner[1].punct("(") || !inner[inner.len() - 1].punct(")") {
            return None;
        }
        Some((Cfg::from_tokens(&inner[2..inner.len() - 1])?, close + 1))
    };
    while p < end {
        // one chain: if #[cfg(A)] {..} (else if #[cfg(B)] {..})* (else {..})?
        if !code[p].ident("if") {
            return None;
        }
        let mut prior: Vec<Cfg> = Vec::new();
        p += 1;
        loop {
            let (pred, after) = attr(p)?;
            if !code.get(after)?.punct("{") {
                return None;
            }
            let body_end = matching(code, after)?;
            let mut all: Vec<Cfg> = prior.iter().map(|c| Cfg::Not(Box::new(c.clone()))).collect();
            all.push(pred.clone());
            out.push((after, body_end, Cfg::All(all)));
            prior.push(pred);
            p = body_end + 1;
            if p < end && code[p].ident("else") {
                if code.get(p + 1).is_some_and(|t| t.ident("if")) {
                    p += 2;
                    continue;
                }
                if !code.get(p + 1)?.punct("{") {
                    return None;
                }
                let body_end = matching(code, p + 1)?;
                out.push((p + 1, body_end, Cfg::All(prior.iter().map(|c| Cfg::Not(Box::new(c.clone()))).collect())));
                p = body_end + 1;
            }
            break;
        }
    }
    Some(out)
}

/// `(open, close)` of every macro invocation body (`name! { .. }`, `name!( .. )`), except
/// `macro_rules!` definitions.
fn macro_bodies(code: &[Token]) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for i in 0..code.len().saturating_sub(2) {
        if code[i].kind == Kind::Ident && code[i + 1].punct("!") && code[i].text != "macro_rules" {
            let open = i + 2;
            if code[open].punct("{") || code[open].punct("(") || code[open].punct("[") {
                if let Some(c) = matching(code, open) {
                    out.push((open, c, code[i].text.clone()));
                }
            }
        }
    }
    out
}

/// End of the item starting at `from` (skipping further attributes).
fn item_end(code: &[Token], from: usize) -> usize {
    let mut j = from;
    // skip other attributes
    while j + 1 < code.len() && code[j].punct("#") && code[j + 1].punct("[") {
        match matching(code, j + 1) {
            Some(c) => j = c + 1,
            None => return code.len().saturating_sub(1),
        }
    }
    // look past the visibility to classify the item: fields and enum variants end at `,`
    let mut k = j;
    if code.get(k).is_some_and(|t| t.ident("pub")) {
        k += 1;
        if code.get(k).is_some_and(|t| t.punct("(")) {
            k = matching(code, k).map(|c| c + 1).unwrap_or(k);
        }
    }
    let first = code.get(k).map(|t| t.text.as_str()).unwrap_or("");
    let comma_ends = !ITEM_KW.contains(&first);
    let mut depth = 0i32;
    while j < code.len() {
        let t = &code[j];
        if t.kind == Kind::Punct {
            match t.text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => {
                    if depth == 0 {
                        return j.saturating_sub(1);
                    }
                    depth -= 1
                }
                "{" if depth == 0 => {
                    let c = matching(code, j).unwrap_or(code.len() - 1);
                    if code.get(c + 1).is_some_and(|t| t.punct(";")) {
                        return c + 1;
                    }
                    return c;
                }
                "}" if depth == 0 => return j.saturating_sub(1),
                ";" if depth == 0 => return j,
                "," if depth == 0 && comma_ends => return j,
                _ => {}
            }
        }
        j += 1;
    }
    code.len().saturating_sub(1)
}

/// The cfgs gating token `idx` (outermost first).
pub fn cfgs_at(spans: &[CfgSpan], idx: usize) -> Vec<&Cfg> {
    spans.iter().filter(|s| s.start <= idx && idx <= s.end).map(|s| &s.cfg).collect()
}

/// Conjunction of a file-level cfg list and a token's cfgs.
pub fn all_of(cfgs: &[&Cfg]) -> Cfg {
    Cfg::All(cfgs.iter().map(|c| (*c).clone()).collect())
}

// ====================================================================== module tree

/// A library source file reachable from the crate root through `mod` declarations,
/// with the cfgs that gate the whole file.
#[derive(Debug, Clone)]
pub struct ModFile {
    pub file: SourceFile,
    pub cfg: Vec<Cfg>,
    pub spans: Vec<CfgSpan>,
}

impl ModFile {
    /// Combined cfg for token `idx` of this file.
    pub fn cfg_at(&self, idx: usize) -> Cfg {
        let mut v: Vec<&Cfg> = self.cfg.iter().collect();
        v.extend(cfgs_at(&self.spans, idx));
        all_of(&v)
    }
}

/// The crate root file: `[lib] path`, `src/lib.rs`, else `src/main.rs`.
pub fn crate_root(dir: &Path) -> Option<PathBuf> {
    crate::rustsrc::lib_root(dir).or_else(|| {
        let p = dir.join("src/main.rs");
        p.is_file().then_some(p)
    })
}

/// Load the module tree starting at `root_file` (follows `mod x;` and `#[path]`).
pub fn module_tree(crate_dir: &Path, root_file: &Path) -> Vec<ModFile> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut q: VecDeque<(PathBuf, Vec<Cfg>, bool)> = VecDeque::new();
    q.push_back((root_file.to_path_buf(), vec![], true));
    while let Some((path, cfg, is_root)) = q.pop_front() {
        if out.len() > 5000 || !seen.insert(path.clone()) {
            continue;
        }
        if std::fs::metadata(&path).map(|m| m.len() > 4 * 1024 * 1024).unwrap_or(true) {
            continue;
        }
        let Ok(file) = SourceFile::load(crate_dir, &path) else { continue };
        let code = &file.code;
        let spans = cfg_spans(code);
        let mut file_cfg = cfg.clone();
        for a in inner_attrs(code) {
            if a.starts_with("cfg(") || a.starts_with("cfg (") {
                if let Some(c) = Cfg::parse(&a) {
                    file_cfg.push(c);
                }
            }
        }
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let mod_dir = if is_root || stem == "mod" || stem == "lib" || stem == "main" { dir.clone() } else { dir.join(stem) };
        let module_level = module_level_mask(code);
        for i in 0..code.len() {
            if !code[i].ident("mod") || !module_level[i] {
                continue;
            }
            let (Some(name), Some(semi)) = (code.get(i + 1), code.get(i + 2)) else { continue };
            if name.kind != Kind::Ident || !semi.punct(";") {
                continue;
            }
            let name = name.text.trim_start_matches("r#");
            let attrs = crate::rustsrc::items::attrs_before(code, i);
            let explicit = attrs.iter().find_map(|a| {
                let a = a.trim();
                a.strip_prefix("path").map(|r| r.trim_start().trim_start_matches('=').trim()).map(unquote)
            });
            let mut c = file_cfg.clone();
            c.extend(cfgs_at(&spans, i).into_iter().cloned());
            // `#[cfg_attr(PRED, path = "x.rs")]`: each alternative under PRED, the default path otherwise
            let alternatives: Vec<(Cfg, String)> = attrs.iter().filter_map(|a| cfg_attr_path(a)).collect();
            for (pred, p) in &alternatives {
                if explicit.is_none() && dir.join(p).is_file() {
                    let mut ca = c.clone();
                    ca.push(pred.clone());
                    q.push_back((dir.join(p), ca, false));
                }
            }
            if explicit.is_none() && !alternatives.is_empty() {
                c.push(Cfg::Not(Box::new(Cfg::Any(alternatives.iter().map(|(p, _)| p.clone()).collect()))));
            }
            let cands = match explicit {
                Some(p) => vec![dir.join(p)],
                None => vec![mod_dir.join(format!("{name}.rs")), mod_dir.join(name).join("mod.rs")],
            };
            let Some(target) = cands.into_iter().find(|p| p.is_file()) else { continue };
            q.push_back((target, c, false));
        }
        out.push(ModFile { file, cfg: file_cfg, spans });
    }
    out
}

/// `cfg_attr(PRED, path = "file.rs")` -> (PRED, file).
fn cfg_attr_path(attr: &str) -> Option<(Cfg, String)> {
    let toks: Vec<Token> = lex(attr.trim()).into_iter().filter(|t| !t.is_comment()).collect();
    if toks.len() < 6 || !toks[0].ident("cfg_attr") || !toks[1].punct("(") || !toks[toks.len() - 1].punct(")") {
        return None;
    }
    let inner = &toks[2..toks.len() - 1];
    let comma = top_level_comma(inner)?;
    let pred = Cfg::from_tokens(&inner[..comma])?;
    let rest = &inner[comma + 1..];
    if rest.len() == 3 && rest[0].ident("path") && rest[1].punct("=") && rest[2].kind == Kind::Str {
        return Some((pred, unquote(&rest[2].text)));
    }
    None
}

/// For each token: whether it is at module level (not inside a fn body, impl, trait, struct...).
pub fn module_level_mask(code: &[Token]) -> Vec<bool> {
    // braces of cfg_if! invocations at module level hold items too
    let mut item_braces: BTreeSet<usize> = BTreeSet::new();
    for c in cfg_if_invocations(code) {
        if !c.branches.is_empty() {
            item_braces.insert(c.open);
            item_braces.extend(c.branches.iter().map(|b| b.0));
        }
    }
    let mut mask = vec![true; code.len()];
    let mut stack: Vec<bool> = Vec::new(); // true = module brace
    for i in 0..code.len() {
        let t = &code[i];
        let level = stack.iter().all(|m| *m);
        mask[i] = level;
        if t.punct("{") {
            let is_mod = (i >= 2 && code[i - 1].kind == Kind::Ident && code[i - 2].ident("mod")) || item_braces.contains(&i);
            stack.push(is_mod);
        } else if t.punct("}") {
            stack.pop();
        }
    }
    mask
}

/// A public item: `pub fn/struct/enum/trait/type/const/static/mod/union NAME` at module level.
#[derive(Debug, Clone)]
pub struct PubItem {
    pub kind: String,
    pub name: String,
    pub file: String,
    pub line: usize,
    pub cfg: Cfg,
}

pub fn pub_items(files: &[ModFile]) -> Vec<PubItem> {
    let mut out = Vec::new();
    for mf in files {
        let code = &mf.file.code;
        let mask = module_level_mask(code);
        for i in 0..code.len() {
            if !code[i].ident("pub") || !mask[i] || code.get(i + 1).is_some_and(|t| t.punct("(")) {
                continue;
            }
            let mut j = i + 1;
            while code.get(j).is_some_and(|t| t.ident("unsafe") || t.ident("async") || t.ident("extern") || t.kind == Kind::Str)
                || (code.get(j).is_some_and(|t| t.ident("const")) && code.get(j + 1).is_some_and(|t| t.ident("fn") || t.ident("unsafe")))
            {
                j += 1;
            }
            let Some(kw) = code.get(j) else { continue };
            if !matches!(kw.text.as_str(), "fn" | "struct" | "enum" | "trait" | "type" | "const" | "static" | "mod" | "union") || kw.kind != Kind::Ident {
                continue;
            }
            let mut n = j + 1;
            if kw.text == "static" && code.get(n).is_some_and(|t| t.ident("mut")) {
                n += 1;
            }
            let Some(name) = code.get(n).filter(|t| t.kind == Kind::Ident) else { continue };
            out.push(PubItem { kind: kw.text.clone(), name: name.text.clone(), file: mf.file.rel.clone(), line: kw.line, cfg: mf.cfg_at(i) });
        }
    }
    out
}

/// Every name a module-level item or `use` declaration defines (any visibility), with its cfg:
/// `fn/struct/enum/trait/type/const/static/mod/union NAME` and the leaves of `use` trees
/// (`use a::{B, c::D as E}` defines `B` and `E`). Used to tell an implementation swap
/// (`#[cfg(f)] pub use x::T; #[cfg(not(f))] pub struct T;`) from a removal.
pub fn named_items(files: &[ModFile]) -> Vec<PubItem> {
    const KINDS: &[&str] = &["fn", "struct", "enum", "trait", "type", "const", "static", "mod", "union"];
    let mut out = Vec::new();
    for mf in files {
        let code = &mf.file.code;
        let mask = module_level_mask(code);
        for i in 0..code.len() {
            if !mask[i] || code[i].kind != Kind::Ident {
                continue;
            }
            if code[i].text == "use" {
                let end = (i + 1..code.len()).find(|&j| code[j].punct(";")).unwrap_or(code.len());
                for j in i + 1..end {
                    let t = &code[j];
                    if t.kind != Kind::Ident || code.get(j + 1).is_some_and(|n| n.punct("::") || n.ident("as")) || matches!(t.text.as_str(), "as" | "self" | "crate" | "super") {
                        continue;
                    }
                    out.push(PubItem { kind: "use".into(), name: t.text.clone(), file: mf.file.rel.clone(), line: t.line, cfg: mf.cfg_at(i) });
                }
                continue;
            }
            if !KINDS.contains(&code[i].text.as_str()) || (code[i].text == "const" && code.get(i + 1).is_some_and(|t| t.ident("fn") || t.ident("unsafe"))) {
                continue;
            }
            let mut n = i + 1;
            if code[i].text == "static" && code.get(n).is_some_and(|t| t.ident("mut")) {
                n += 1;
            }
            let Some(name) = code.get(n).filter(|t| t.kind == Kind::Ident) else { continue };
            out.push(PubItem { kind: code[i].text.clone(), name: name.text.clone(), file: mf.file.rel.clone(), line: code[i].line, cfg: mf.cfg_at(i) });
        }
    }
    out
}

/// A `compile_error!` invocation and the cfg under which it is compiled.
#[derive(Debug, Clone)]
pub struct CompileError {
    pub message: String,
    pub file: String,
    pub line: usize,
    pub cfg: Cfg,
}

pub fn compile_errors(files: &[ModFile]) -> Vec<CompileError> {
    let mut out = Vec::new();
    for mf in files {
        let code = &mf.file.code;
        let bodies = macro_bodies(code);
        for i in 0..code.len() {
            if !(code[i].ident("compile_error") && code.get(i + 1).is_some_and(|t| t.punct("!"))) {
                continue;
            }
            // skip macro_rules! bodies: compile_error inside a macro definition fires only when expanded
            if inside_macro_rules(code, i) {
                continue;
            }
            // inside another macro's input its condition is unknown, unless it is a cfg_if! branch
            let in_branch = mf.spans.iter().any(|s| s.branch && s.start < i && i < s.end);
            if !in_branch && bodies.iter().any(|(o, c, name)| *o < i && i < *c && name != "compile_error") {
                continue;
            }
            // `compile_error!("..")`, or the first literal of `compile_error!(concat!("..", ..))`
            let message = code
                .get(i + 2)
                .and_then(|_| matching(code, i + 2))
                .and_then(|close| code[i + 3..close].iter().find(|t| t.kind == Kind::Str))
                .map(|t| unquote(&t.text))
                .unwrap_or_default();
            out.push(CompileError { message, file: mf.file.rel.clone(), line: code[i].line, cfg: mf.cfg_at(i) });
        }
    }
    out
}

/// `(open, close)` token indices of every `macro_rules!` definition body.
pub fn macro_rules_ranges(code: &[Token]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..code.len() {
        if code[i].ident("macro_rules") && code.get(i + 1).is_some_and(|t| t.punct("!")) {
            let mut j = i + 2;
            while j < code.len() && !(code[j].punct("{") || code[j].punct("(") || code[j].punct("[")) {
                j += 1;
            }
            if let Some(c) = matching(code, j) {
                out.push((j, c));
            }
        }
    }
    out
}

fn inside_macro_rules(code: &[Token], idx: usize) -> bool {
    for i in 0..idx {
        if code[i].ident("macro_rules") && code.get(i + 1).is_some_and(|t| t.punct("!")) {
            let mut j = i + 2;
            while j < code.len() && !(code[j].punct("{") || code[j].punct("(") || code[j].punct("[")) {
                j += 1;
            }
            if let Some(c) = matching(code, j) {
                if j < idx && idx < c {
                    return true;
                }
            }
        }
    }
    false
}

// ====================================================================== features

/// Expand requested features through a package's `[features]` table (own features only).
pub fn feature_closure(table: &BTreeMap<String, Vec<String>>, start: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut q: Vec<String> = start.to_vec();
    while let Some(f) = q.pop() {
        if !table.contains_key(&f) {
            continue;
        }
        if !out.insert(f.clone()) {
            continue;
        }
        for e in table.get(&f).into_iter().flatten() {
            if e.starts_with("dep:") {
                continue;
            }
            match e.split_once('/') {
                Some((dep, _)) => {
                    // `dep/feat` also enables the implicit feature `dep` (not for `dep?/feat`)
                    if !dep.ends_with('?') && table.contains_key(dep) {
                        q.push(dep.to_string());
                    }
                }
                None => q.push(e.clone()),
            }
        }
    }
    out
}

/// Whether a feature is just the implicit feature of an optional dependency.
pub fn is_dep_feature(p: &Package, f: &str) -> bool {
    let v = p.features.get(f);
    let is_opt = p.dependencies.iter().any(|d| d.optional && d.rename.as_deref().unwrap_or(&d.name) == f);
    is_opt && v.is_some_and(|v| v.len() == 1 && v[0] == format!("dep:{f}"))
}

/// The name a dependency is referred to by in its declaring manifest.
pub fn dep_key(d: &crate::project::Dependency) -> &str {
    d.rename.as_deref().unwrap_or(&d.name)
}

/// A `Cargo.toml` dependency line with default features off: `key = { version = "..", default-features = false, .. }`,
/// keeping `package = ".."` for a renamed dependency.
pub fn dep_line_without_defaults(d: &crate::project::Dependency, keep: &[String]) -> String {
    let package = if d.rename.is_some() { format!(", package = \"{}\"", d.name) } else { String::new() };
    let feats = if keep.is_empty() { String::new() } else { format!(", features = [{}]", keep.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ")) };
    format!("{} = {{ version = \"{}\"{package}, default-features = false{feats} }}", dep_key(d), d.req.trim_start_matches('^'))
}

/// One reason a feature of a package is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enabler {
    /// Package id of the declaring package (`== target` for the package's own feature table).
    pub by: String,
    pub by_spec: String,
    /// normal, dev, build, or "self" for the target's own feature table, or "cli" for members.
    pub kind: String,
    /// The dependency declaration's `target` cfg, if any.
    pub target: Option<String>,
    /// Human description, e.g. `features = ["std"]`, `default-features`, `feature "full": tokio/rt`.
    pub how: String,
    /// Feature of the declaring package that must be on for this to apply.
    pub via_feature: Option<String>,
}

/// Activated features per package id.
pub type Active = BTreeMap<String, BTreeSet<String>>;

/// Every declaration that enables `feature` on package `pkg_id`, given the active features of
/// every package. Includes the package's own feature table (`kind == "self"`).
pub fn enablers(meta: &Metadata, active: &Active, pkg_id: &str, feature: &str) -> Vec<Enabler> {
    let mut out = Vec::new();
    let Some(target) = meta.package(pkg_id) else { return out };
    let empty = BTreeSet::new();
    // own feature table
    for (h, entries) in &target.features {
        if h == feature || !active.get(pkg_id).unwrap_or(&empty).contains(h) {
            continue;
        }
        // `feature`, or `feature/x` which also turns on the implicit feature of optional dep `feature`
        if let Some(e) = entries.iter().find(|e| *e == feature || e.split_once('/').is_some_and(|(x, _)| x == feature)) {
            out.push(Enabler {
                by: pkg_id.to_string(),
                by_spec: target.spec(),
                kind: "self".into(),
                target: None,
                how: format!("its feature \"{h}\" includes \"{e}\""),
                via_feature: Some(h.clone()),
            });
        }
    }
    let Some(res) = &meta.resolve else { return out };
    for node in &res.nodes {
        let Some(q) = meta.package(&node.id) else { continue };
        let q_active = active.get(&node.id);
        for d in &q.dependencies {
            let ext = util::normalize_crate_name(dep_key(d));
            let want_kind = d.kind.clone();
            let edge = node.deps.iter().find(|e| {
                e.pkg == pkg_id
                    && util::normalize_crate_name(&e.name) == ext
                    && (e.dep_kinds.is_empty() || e.dep_kinds.iter().any(|k| k.kind == want_kind && k.target == d.target))
            });
            if edge.is_none() {
                continue;
            }
            let kind = d.kind().to_string();
            let mk = |how: String, via: Option<String>| Enabler {
                by: node.id.clone(),
                by_spec: q.spec(),
                kind: kind.clone(),
                target: d.target.clone(),
                how,
                via_feature: via,
            };
            let key = dep_key(d);
            // optional declarations only count when the optional dependency is activated
            if d.optional {
                let on = q_active.is_some_and(|a| {
                    a.contains(key)
                        || a.iter().any(|g| {
                            q.features.get(g).is_some_and(|es| {
                                es.iter().any(|e| e == &format!("dep:{key}") || e.split_once('/').is_some_and(|(x, _)| x == key))
                            })
                        })
                });
                if !on {
                    continue;
                }
            }
            if d.features.iter().any(|f| f == feature) {
                out.push(mk(format!("declares `{key} = {{ features = [\"{feature}\"] }}`"), None));
            }
            if feature == "default" && d.uses_default_features {
                out.push(mk(format!("depends on `{key}` with default features"), None));
            }
            if let Some(qa) = q_active {
                for g in qa {
                    for e in q.features.get(g).into_iter().flatten() {
                        if let Some((x, f)) = e.split_once('/') {
                            if x.trim_end_matches('?') == key && f == feature {
                                out.push(mk(format!("its feature \"{g}\" includes \"{e}\""), Some(g.clone())));
                            }
                        }
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.by_spec.cmp(&b.by_spec).then(a.how.cmp(&b.how)));
    out.dedup();
    out
}

/// Active features from `cargo metadata`'s resolve (unified over every target and dev-deps).
pub fn metadata_active(meta: &Metadata) -> Active {
    meta.resolve
        .as_ref()
        .map(|r| r.nodes.iter().map(|n| (n.id.clone(), n.features.iter().cloned().collect())).collect())
        .unwrap_or_default()
}

// ====================================================================== cargo helpers

/// `cargo metadata` for an arbitrary manifest (the core loader only knows the project).
pub fn load_metadata_at(ctx: &Ctx, manifest: &Path, opts: &MetaOpts) -> Result<Metadata> {
    let mut cmd = Command::new(&ctx.cargo);
    cmd.args(["metadata", "--format-version", "1", "--manifest-path"]).arg(manifest);
    if ctx.offline {
        cmd.arg("--offline");
    }
    if opts.all_features {
        cmd.arg("--all-features");
    }
    if opts.no_default_features {
        cmd.arg("--no-default-features");
    }
    if !opts.features.is_empty() {
        cmd.arg("--features").arg(opts.features.join(","));
    }
    if let Some(p) = &opts.filter_platform {
        cmd.arg("--filter-platform").arg(p);
    }
    let out = util::run(&mut cmd, Duration::from_secs(600))?;
    if !out.success() {
        return Err(Error::Env(format!("cargo metadata failed:\n{}", out.stderr.trim())));
    }
    serde_json::from_str(&out.stdout).map_err(|e| Error::Parse(format!("cargo metadata output: {e}")))
}

/// One line of `cargo tree --prefix depth -f "{p}|{f}"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeLine {
    pub depth: usize,
    pub name: String,
    pub version: String,
    pub proc_macro: bool,
    pub features: BTreeSet<String>,
}

pub fn parse_tree(out: &str) -> Vec<TreeLine> {
    let mut v = Vec::new();
    for l in out.lines() {
        let digits: String = l.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(depth) = digits.parse::<usize>() else { continue };
        let rest = &l[digits.len()..];
        let (p, f) = rest.rsplit_once('|').unwrap_or((rest, ""));
        let mut parts = p.split_whitespace();
        let (Some(name), Some(ver)) = (parts.next(), parts.next()) else { continue };
        let features = f.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
        v.push(TreeLine {
            depth,
            name: name.to_string(),
            version: ver.trim_start_matches('v').to_string(),
            proc_macro: p.contains("(proc-macro)"),
            features,
        });
    }
    v
}

/// Run `cargo tree` for the workspace; `edges` like `normal` or `normal,build,dev`,
/// `target` a triple or `all`.
pub fn cargo_tree(ctx: &Ctx, manifest: &Path, edges: &str, target: &str, extra: &[String]) -> Result<Vec<TreeLine>> {
    let mut cmd = Command::new(&ctx.cargo);
    cmd.arg("tree").arg("--manifest-path").arg(manifest);
    if !extra.iter().any(|a| a == "-p" || a == "--package") {
        cmd.arg("--workspace");
    }
    cmd.args(["-e", edges, "--target", target, "-f", "{p}|{f}", "--prefix", "depth", "--no-dedupe", "--charset", "ascii"]);
    cmd.args(extra);
    if ctx.offline {
        cmd.arg("--offline");
    }
    let o = util::run(&mut cmd, Duration::from_secs(600))?;
    if !o.success() {
        return Err(Error::Env(format!("cargo tree failed:\n{}", o.stderr.trim())));
    }
    Ok(parse_tree(&o.stdout))
}

/// Features per `(name, version)` from tree lines; proc-macro subtrees (host code) are skipped
/// when `skip_host` is set.
pub fn tree_features(lines: &[TreeLine], skip_host: bool) -> BTreeMap<(String, String), BTreeSet<String>> {
    let mut out: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut skip_below: Option<usize> = None;
    for l in lines {
        if let Some(d) = skip_below {
            if l.depth > d {
                continue;
            }
            skip_below = None;
        }
        if skip_host && l.proc_macro {
            skip_below = Some(l.depth);
            continue;
        }
        out.entry((l.name.clone(), l.version.clone())).or_default().extend(l.features.iter().cloned());
    }
    out
}

/// Map tree features to package ids.
pub fn active_from_tree(meta: &Metadata, tf: &BTreeMap<(String, String), BTreeSet<String>>) -> Active {
    let mut out = Active::new();
    for p in &meta.packages {
        if let Some(f) = tf.get(&(p.name.clone(), p.version.clone())) {
            out.insert(p.id.clone(), f.clone());
        }
    }
    out
}

/// `(name, version)` from a cargo package id (both the old `name ver (source)` and the new
/// `source#name@ver` / `path+file:///dir/name#ver` forms).
pub fn pkg_from_id(id: &str) -> (String, String) {
    if let Some((src, frag)) = id.rsplit_once('#') {
        if let Some((n, v)) = frag.split_once('@') {
            return (n.to_string(), v.to_string());
        }
        let name = src.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
        return (name, frag.to_string());
    }
    let mut p = id.split_whitespace();
    (p.next().unwrap_or("").to_string(), p.next().unwrap_or("").to_string())
}

/// One error from `cargo check --message-format json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckError {
    pub package_id: String,
    pub package: String,
    pub version: String,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<usize>,
}

/// Parsed result of a `cargo check --message-format json` run.
#[derive(Debug, Clone, Default)]
pub struct CheckResult {
    pub success: bool,
    pub errors: Vec<CheckError>,
    pub timed_out: bool,
    pub secs: f64,
    /// Non-JSON error text (e.g. dependency resolution failures).
    pub stderr_error: Option<String>,
}

pub fn parse_check(stdout: &str) -> (Vec<CheckError>, Option<bool>) {
    let mut errors = Vec::new();
    let mut finished = None;
    for l in stdout.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else { continue };
        match v["reason"].as_str() {
            Some("build-finished") => finished = v["success"].as_bool(),
            Some("compiler-message") if v["message"]["level"].as_str() == Some("error") => {
                let msg = v["message"]["message"].as_str().unwrap_or("").to_string();
                if msg.starts_with("aborting due to") {
                    continue;
                }
                let id = v["package_id"].as_str().unwrap_or("").to_string();
                let (package, version) = pkg_from_id(&id);
                let spans = v["message"]["spans"].as_array().cloned().unwrap_or_default();
                let span = spans.iter().find(|s| s["is_primary"].as_bool() == Some(true)).or(spans.first());
                errors.push(CheckError {
                    package_id: id,
                    package,
                    version,
                    message: msg,
                    file: span.and_then(|s| s["file_name"].as_str()).map(String::from),
                    line: span.and_then(|s| s["line_start"].as_u64()).map(|n| n as usize),
                });
            }
            _ => {}
        }
    }
    (errors, finished)
}

/// Run `cargo check --message-format json` with extra args.
pub fn cargo_check(ctx: &Ctx, manifest: &Path, args: &[String], target_dir: &Path, timeout: Duration) -> Result<CheckResult> {
    let mut cmd = Command::new(&ctx.cargo);
    cmd.arg("check").arg("--manifest-path").arg(manifest).args(["--message-format", "json"]).args(args);
    if ctx.offline {
        cmd.arg("--offline");
    }
    cmd.env("CARGO_TARGET_DIR", target_dir).env("CARGO_TERM_COLOR", "never");
    let o = util::run(&mut cmd, timeout)?;
    let (errors, finished) = parse_check(&o.stdout);
    let success = o.success() && finished != Some(false);
    let stderr_error = if !success && errors.is_empty() {
        o.stderr.lines().find(|l| l.trim_start().starts_with("error")).map(|l| {
            let idx = o.stderr.find(l).unwrap_or(0);
            o.stderr[idx..].lines().take(4).collect::<Vec<_>>().join(" ").trim().to_string()
        })
    } else {
        None
    };
    Ok(CheckResult { success, errors, timed_out: o.timed_out, secs: o.elapsed.as_secs_f64(), stderr_error })
}

// ====================================================================== the package to analyze

/// The package a tool works on: a workspace member, or a crate from crates.io unpacked
/// into a scratch workspace.
pub struct Subject {
    pub label: String,
    pub manifest: PathBuf,
    pub meta: Metadata,
    pub pkg_id: String,
    /// Scratch directory to delete afterwards (downloaded crates).
    pub scratch: Option<PathBuf>,
}

impl Subject {
    pub fn package(&self) -> Option<&Package> {
        self.meta.package(&self.pkg_id)
    }
}

impl Drop for Subject {
    fn drop(&mut self) {
        if let Some(s) = &self.scratch {
            let _ = std::fs::remove_dir_all(s);
        }
    }
}

/// Resolve the package to analyze: positional `CRATE[@VERSION]` (downloaded) or the local
/// package (`--package NAME` in a workspace).
pub fn subject(ctx: &Ctx, args: &crate::cli::Args, label: &str) -> Result<Subject> {
    if let Some(spec) = args.positional.first() {
        if args.positional.len() > 1 {
            return Err(Error::Usage("name one crate at a time".into()));
        }
        let spec = crate::registry::CrateSpec::parse(spec)?;
        let v = spec.resolve(ctx)?;
        let src = crate::registry::download::unpacked(ctx, &v.name, &v.vers)?;
        let (tmp, dir) = crate::tools::miri::scratch_copy(&src, label)?;
        let manifest = dir.join("Cargo.toml");
        let meta = match load_metadata_at(ctx, &manifest, &MetaOpts::default()) {
            Ok(m) => m,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(e);
            }
        };
        let pkg_id = meta.workspace_members.first().cloned().unwrap_or_default();
        return Ok(Subject { label: format!("{}@{}", v.name, v.vers), manifest, meta, pkg_id, scratch: Some(tmp) });
    }
    let manifest = ctx.manifest_path();
    if !manifest.is_file() {
        return Err(Error::Env(format!(
            "no Cargo.toml at {} (run inside a Cargo project, pass --project DIR, or name a crate)",
            manifest.display()
        )));
    }
    let meta = load_metadata_at(ctx, &manifest, &MetaOpts::default())?;
    let members = meta.members();
    let pick = match args.value("package") {
        Some(name) => members.iter().find(|p| p.name == name).map(|p| p.id.clone()).ok_or_else(|| {
            Error::Usage(format!(
                "no workspace member named `{name}` (members: {})",
                members.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
            ))
        })?,
        None => match (meta.resolve.as_ref().and_then(|r| r.root.clone()), members.len()) {
            (Some(r), _) => r,
            (None, 1) => members[0].id.clone(),
            _ => {
                return Err(Error::Usage(format!(
                    "this is a workspace; choose a member with --package NAME ({})",
                    members.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
                )));
            }
        },
    };
    let label = meta.package(&pick).map(|p| p.spec()).unwrap_or_default();
    Ok(Subject { label, manifest, meta, pkg_id: pick, scratch: None })
}

// ====================================================================== no_std detection

/// How a library relates to `std`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdKind {
    /// `#![no_std]` unconditionally.
    NoStd,
    /// `#![cfg_attr(PRED, no_std)]`: no_std while PRED holds.
    NoStdIf(Cfg),
    /// No `no_std` attribute: always links std.
    Std,
    /// No library source found (e.g. binary-only).
    Unknown,
}

/// Static facts about a library's std usage.
#[derive(Debug, Clone)]
pub struct StdInfo {
    pub kind: StdKind,
    pub proc_macro: bool,
    /// `extern crate std` items and their cfg.
    pub extern_std: Vec<(Cfg, String, usize)>,
    /// `extern crate alloc` items and their cfg.
    pub extern_alloc: Vec<(Cfg, String, usize)>,
    pub root_file: Option<String>,
}

/// The verdict for one set of features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdVerdict {
    NoStd,
    /// Would be no_std, but these active features turn std on.
    StdViaFeatures(Vec<String>),
    AlwaysStd,
    Unknown,
}

impl StdInfo {
    pub fn analyze(dir: &Path) -> StdInfo {
        let files = crate::rustsrc::lib_root(dir).map(|root| module_tree(dir, &root)).unwrap_or_default();
        StdInfo::from_files(dir, &files)
    }

    /// Analyze an already loaded library module tree (first file = crate root).
    pub fn from_files(dir: &Path, files: &[ModFile]) -> StdInfo {
        let proc_macro = crate::rustsrc::is_proc_macro(dir);
        let Some(root) = crate::rustsrc::lib_root(dir).filter(|_| !files.is_empty()) else {
            return StdInfo { kind: StdKind::Unknown, proc_macro, extern_std: vec![], extern_alloc: vec![], root_file: None };
        };
        let mut kind = StdKind::Std;
        let mut extern_std = Vec::new();
        let mut extern_alloc = Vec::new();
        if let Some(rf) = files.first() {
            for a in inner_attrs(&rf.file.code) {
                let compact: String = a.chars().filter(|c| !c.is_whitespace()).collect();
                if compact == "no_std" {
                    kind = StdKind::NoStd;
                } else if compact.starts_with("cfg_attr(") && compact.ends_with(",no_std)") {
                    let toks: Vec<Token> = lex(&a).into_iter().filter(|t| !t.is_comment()).collect();
                    // cfg_attr ( PRED , no_std )
                    if toks.len() > 4 {
                        let inner = &toks[2..toks.len() - 1];
                        let comma = top_level_comma(inner);
                        if let Some(c) = comma.and_then(|k| Cfg::from_tokens(&inner[..k])) {
                            kind = StdKind::NoStdIf(c);
                        }
                    }
                }
            }
        }
        for mf in files {
            let code = &mf.file.code;
            for i in 0..code.len().saturating_sub(2) {
                if code[i].ident("extern") && code[i + 1].ident("crate") {
                    let which = &code[i + 2].text;
                    if which == "std" || which == "alloc" {
                        let entry = (mf.cfg_at(i), mf.file.rel.clone(), code[i].line);
                        if which == "std" { extern_std.push(entry) } else { extern_alloc.push(entry) }
                    }
                }
            }
        }
        StdInfo { kind, proc_macro, extern_std, extern_alloc, root_file: Some(util::rel(dir, &root)) }
    }

    /// Verdict with the given active features (and optional target).
    pub fn verdict(&self, features: &BTreeSet<String>, target: Option<&TargetCfg>) -> StdVerdict {
        let env = Env { features: Some(features), target };
        let base = match &self.kind {
            StdKind::Unknown => return StdVerdict::Unknown,
            StdKind::Std => return StdVerdict::AlwaysStd,
            StdKind::NoStd => true,
            StdKind::NoStdIf(c) => c.eval(&env) != Some(false),
        };
        let std_extern: Vec<&(Cfg, String, usize)> = self.extern_std.iter().filter(|(c, _, _)| c.eval(&env) != Some(false)).collect();
        if base && std_extern.is_empty() {
            return StdVerdict::NoStd;
        }
        // which active features flip it
        let mut culprits: BTreeSet<String> = BTreeSet::new();
        if let StdKind::NoStdIf(c) = &self.kind {
            if !base {
                for f in c.features() {
                    if features.contains(&f) {
                        culprits.insert(f);
                    }
                }
            }
        }
        for (c, _, _) in std_extern {
            for f in c.features() {
                if features.contains(&f) {
                    culprits.insert(f);
                }
            }
        }
        if culprits.is_empty() { StdVerdict::AlwaysStd } else { StdVerdict::StdViaFeatures(culprits.into_iter().collect()) }
    }

    pub fn needs_alloc(&self, features: &BTreeSet<String>, target: Option<&TargetCfg>) -> bool {
        let env = Env { features: Some(features), target };
        self.extern_alloc.iter().any(|(c, _, _)| c.eval(&env) != Some(false))
    }
}

fn top_level_comma(t: &[Token]) -> Option<usize> {
    let mut depth = 0i32;
    for (i, x) in t.iter().enumerate() {
        match x.text.as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            "," if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

// ====================================================================== tests

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_and_evaluates_cfg() {
        let c = Cfg::parse(r#"cfg(all(unix, not(feature = "std")), target_os = "linux")"#);
        assert!(c.is_none(), "cfg() takes exactly one predicate");
        let c = Cfg::parse(r#"cfg(all(unix, not(feature = "std"), target_os = "linux"))"#).unwrap();
        assert_eq!(c.to_string(), r#"all(unix, not(feature = "std"), target_os = "linux")"#);
        let linux = TargetCfg::parse("x86_64-unknown-linux-gnu", "unix\ntarget_os=\"linux\"\ntarget_family=\"unix\"\n");
        let f = set(&[]);
        let fs = set(&["std"]);
        assert_eq!(c.eval(&Env { features: Some(&f), target: Some(&linux) }), Some(true));
        assert_eq!(c.eval(&Env { features: Some(&fs), target: Some(&linux) }), Some(false));
        // unknown target: depends
        assert_eq!(c.eval(&Env { features: Some(&f), target: None }), None);
        // but a false conjunct decides it anyway
        assert_eq!(c.eval(&Env { features: Some(&fs), target: None }), Some(false));
        let any = Cfg::parse("any(windows, feature = \"x\")").unwrap();
        assert_eq!(any.eval(&Env { features: Some(&set(&["x"])), target: None }), Some(true));
        assert_eq!(Cfg::parse("test").unwrap().eval(&Env::default()), Some(false));
        assert_eq!(Cfg::parse("docsrs").unwrap().eval(&Env::default()), Some(false));
        assert_eq!(Cfg::parse("not(test)").unwrap().eval(&Env::default()), Some(true));
        assert_eq!(c.has_negated_feature(), ["std"]);
        assert!(Cfg::parse("all(unix").is_none());
        assert!(Cfg::parse("not(a, b)").is_none());
    }

    #[test]
    fn target_specs() {
        let w = TargetCfg::parse("wasm32-unknown-unknown", "target_arch=\"wasm32\"\ntarget_os=\"unknown\"\ntarget_family=\"wasm\"\n");
        assert!(w.is_wasm_unknown() && w.has_std());
        assert_eq!(dep_target_applies(Some("cfg(target_arch = \"wasm32\")"), &w), Some(true));
        assert_eq!(dep_target_applies(Some("cfg(unix)"), &w), Some(false));
        assert_eq!(dep_target_applies(Some("x86_64-pc-windows-msvc"), &w), Some(false));
        assert_eq!(dep_target_applies(None, &w), Some(true));
        let t = TargetCfg::parse("thumbv7em-none-eabihf", "target_os=\"none\"\ntarget_arch=\"arm\"\n");
        assert!(!t.has_std());
    }

    #[test]
    fn spans_and_items() {
        let src = r#"
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "a")]
pub fn only_a() {}
#[cfg(not(feature = "fast"))]
pub fn slow_path() -> u8 { 1 }
#[cfg(all(feature = "a", feature = "b"))]
compile_error!("a and b are exclusive");
pub struct S { #[cfg(feature = "x")] pub x: u8, pub y: u8 }
#[cfg(target_arch = "wasm32")]
mod wasm { pub fn inside() {} }
impl S { pub fn method(&self) {} }
pub(crate) fn hidden() {}
#[cfg(feature = "std")]
extern crate std;
extern crate alloc;
"#;
        let dir = std::env::temp_dir();
        let f = SourceFile::from_text(&dir, &dir.join("lib.rs"), src.to_string());
        let spans = cfg_spans(&f.code);
        let mf = ModFile { cfg: vec![], spans, file: f };
        let items = pub_items(std::slice::from_ref(&mf));
        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["only_a", "slow_path", "S", "inside"]);
        let slow = &items[1];
        assert_eq!(slow.cfg.has_negated_feature(), ["fast"]);
        let inside = &items[3];
        assert_eq!(inside.cfg.to_string(), "all(target_arch = \"wasm32\")");
        let ce = compile_errors(std::slice::from_ref(&mf));
        assert_eq!(ce.len(), 1);
        assert_eq!(ce[0].message, "a and b are exclusive");
        let ab = set(&["a", "b"]);
        assert_eq!(ce[0].cfg.eval(&Env { features: Some(&ab), target: None }), Some(true));
        assert_eq!(ce[0].cfg.eval(&Env { features: Some(&set(&["a"])), target: None }), Some(false));
        // field cfg does not swallow the next field
        let y_idx = mf.file.code.iter().position(|t| t.ident("y")).unwrap();
        assert!(cfgs_at(&mf.spans, y_idx).is_empty());
    }

    #[test]
    fn cfg_if_branches() {
        let src = r#"
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    } else if #[cfg(feature = "js")] {
        pub fn js() {}
    } else {
        compile_error!("unsupported");
    }
}
some_macro! { compile_error!("never seen"); }
"#;
        let dir = std::env::temp_dir();
        let f = SourceFile::from_text(&dir, &dir.join("lib.rs"), src.to_string());
        let spans = cfg_spans(&f.code);
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[1].cfg.to_string(), "all(not(unix), feature = \"js\")");
        assert_eq!(spans[2].cfg.to_string(), "all(not(unix), not(feature = \"js\"))");
        let mf = ModFile { cfg: vec![], spans, file: f };
        let items = pub_items(std::slice::from_ref(&mf));
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].cfg.to_string(), "all(all(not(unix), feature = \"js\"))");
        let ce = compile_errors(std::slice::from_ref(&mf));
        assert_eq!(ce.len(), 1, "{ce:?}");
        let linux = TargetCfg::parse("x86_64-unknown-linux-gnu", "unix\ntarget_os=\"linux\"\n");
        let none = BTreeSet::new();
        assert_eq!(ce[0].cfg.eval(&Env { features: Some(&none), target: Some(&linux) }), Some(false));
        let wasm = TargetCfg::parse("wasm32-unknown-unknown", "target_os=\"unknown\"\n");
        assert_eq!(ce[0].cfg.eval(&Env { features: Some(&none), target: Some(&wasm) }), Some(true));
        assert!(cfg_if_invocations(&lex("cfg_if! { if #[cfg(x)] }")).iter().all(|c| c.branches.is_empty()));
    }

    #[test]
    fn cfg_attr_module_paths() {
        let d = std::env::temp_dir().join(format!("smc-fu-attr-{}", std::process::id()));
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("Cargo.toml"), "[package]\nname=\"x\"\nversion=\"0.1.0\"\n").unwrap();
        std::fs::write(d.join("src/lib.rs"), "#[cfg_attr(unix, path = \"unix.rs\")]\n#[cfg_attr(windows, path = \"windows.rs\")]\nmod sys;\n").unwrap();
        std::fs::write(d.join("src/unix.rs"), "pub fn u() {}\n").unwrap();
        std::fs::write(d.join("src/windows.rs"), "pub fn w() {}\n").unwrap();
        std::fs::write(d.join("src/sys.rs"), "compile_error!(\"unsupported\");\n").unwrap();
        let files = module_tree(&d, &d.join("src/lib.rs"));
        assert_eq!(files.len(), 4);
        let ce = compile_errors(&files);
        assert_eq!(ce.len(), 1);
        let linux = TargetCfg::parse("x86_64-unknown-linux-gnu", "unix\n");
        let none = TargetCfg::parse("thumbv7em-none-eabihf", "target_os=\"none\"\n");
        let f = BTreeSet::new();
        assert_eq!(ce[0].cfg.eval(&Env { features: Some(&f), target: Some(&linux) }), Some(false));
        assert_eq!(ce[0].cfg.eval(&Env { features: Some(&f), target: Some(&none) }), Some(true));
        let unix_file = files.iter().find(|m| m.file.rel.ends_with("unix.rs")).unwrap();
        assert_eq!(unix_file.cfg, vec![Cfg::Name("unix".into())]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn std_detection() {
        let d = std::env::temp_dir().join(format!("smc-fu-{}", std::process::id()));
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("Cargo.toml"), "[package]\nname=\"x\"\nversion=\"0.1.0\"\n").unwrap();
        std::fs::write(d.join("src/lib.rs"), "#![cfg_attr(not(feature = \"std\"), no_std)]\nextern crate alloc;\n#[cfg(feature = \"io\")]\nmod io;\n").unwrap();
        std::fs::write(d.join("src/io.rs"), "extern crate std;\n").unwrap();
        let info = StdInfo::analyze(&d);
        assert!(matches!(info.kind, StdKind::NoStdIf(_)));
        assert_eq!(info.verdict(&set(&[]), None), StdVerdict::NoStd);
        assert_eq!(info.verdict(&set(&["std", "default"]), None), StdVerdict::StdViaFeatures(vec!["std".into()]));
        assert_eq!(info.verdict(&set(&["io"]), None), StdVerdict::StdViaFeatures(vec!["io".into()]));
        assert!(info.needs_alloc(&set(&[]), None));
        std::fs::write(d.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        assert_eq!(StdInfo::analyze(&d).verdict(&set(&[]), None), StdVerdict::AlwaysStd);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn renamed_dep_line_and_concat_compile_error() {
        let d: crate::project::Dependency = serde_json::from_value(serde_json::json!({
            "name": "reqwest", "req": "^0.12", "kind": null, "optional": false, "uses_default_features": true,
            "features": [], "target": null, "rename": "http"
        }))
        .unwrap();
        assert_eq!(dep_line_without_defaults(&d, &["json".into()]), "http = { version = \"0.12\", package = \"reqwest\", default-features = false, features = [\"json\"] }");
        let dir = std::env::temp_dir();
        let f = SourceFile::from_text(&dir, &dir.join("lib.rs"), "#[cfg(unix)]\ncompile_error!(concat!(\"not on \", env!(\"X\")));\n".to_string());
        let spans = cfg_spans(&f.code);
        let ce = compile_errors(&[ModFile { cfg: vec![], spans, file: f }]);
        assert_eq!(ce[0].message, "not on ");
    }

    #[test]
    fn closures_and_ids() {
        let mut t = BTreeMap::new();
        t.insert("default".to_string(), vec!["std".to_string()]);
        t.insert("std".to_string(), vec!["alloc".to_string(), "serde?/std".to_string()]);
        t.insert("alloc".to_string(), vec![]);
        t.insert("serde".to_string(), vec!["dep:serde".to_string()]);
        t.insert("derive".to_string(), vec!["serde/derive".to_string()]);
        assert_eq!(feature_closure(&t, &["default".into()]), set(&["default", "std", "alloc"]));
        assert_eq!(feature_closure(&t, &["derive".into()]), set(&["derive", "serde"]));
        assert_eq!(pkg_from_id("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.1"), ("serde".into(), "1.0.1".into()));
        assert_eq!(pkg_from_id("path+file:///tmp/app#0.1.0"), ("app".into(), "0.1.0".into()));
        assert_eq!(pkg_from_id("path+file:///tmp/dir#app@0.1.0"), ("app".into(), "0.1.0".into()));
        assert_eq!(pkg_from_id("serde 1.0.1 (registry+https://x)"), ("serde".into(), "1.0.1".into()));
    }

    #[test]
    fn tree_and_check_parsing() {
        let out = "0app v0.1.0 (/x)|default,std\n1derive v1.0.0 (proc-macro)|\n2syn v2.0.0|full\n1serde v1.0.0|std\n2syn v2.0.0|parsing\n";
        let l = parse_tree(out);
        assert_eq!(l.len(), 5);
        assert!(l[1].proc_macro);
        let tf = tree_features(&l, true);
        assert_eq!(tf[&("syn".to_string(), "2.0.0".to_string())], set(&["parsing"]));
        assert!(tf.get(&("derive".to_string(), "1.0.0".to_string())).is_none());
        let json = r#"{"reason":"compiler-message","package_id":"path+file:///p#fx@0.1.0","target":{},"message":{"level":"error","message":"cannot find function `a_only` in this scope","spans":[{"file_name":"src/lib.rs","line_start":3,"is_primary":true}]}}
{"reason":"compiler-message","package_id":"path+file:///p#fx@0.1.0","message":{"level":"error","message":"aborting due to 1 previous error","spans":[]}}
{"reason":"build-finished","success":false}"#;
        let (e, fin) = parse_check(json);
        assert_eq!(fin, Some(false));
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].package, "fx");
        assert_eq!(e[0].line, Some(3));
    }
}
