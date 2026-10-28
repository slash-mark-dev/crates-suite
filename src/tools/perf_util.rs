//! Helpers shared by the tools that drive cargo on the user's project
//! (timings, mono, profile, futurecompat, edition): spawning cargo with a
//! timeout, parsing cargo's JSON message stream, private target directories
//! under the cache, and scratch copies of a workspace.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use crate::cli::Args;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::util;

/// A `cargo` command that runs in the project root (add [`offline_flag`] after the subcommand).
pub fn cargo(ctx: &Ctx) -> Command {
    let mut c = Command::new(&ctx.cargo);
    c.current_dir(ctx.project_root());
    // Never let rustup download a toolchain as a side effect.
    c.env("RUSTUP_AUTO_INSTALL", "0");
    c
}

/// Add `--offline` (cargo subcommands that resolve dependencies) when the run is offline.
pub fn offline_flag(ctx: &Ctx, cmd: &mut Command) {
    if ctx.offline {
        cmd.arg("--offline");
    }
}

/// The `--timeout SECS` option (default given), as a Duration.
pub fn timeout(args: &Args, default_secs: u64) -> Result<Duration> {
    let s: u64 = args.parse_or("timeout", default_secs)?;
    Ok(Duration::from_secs(s.max(1)))
}

/// Feature selection options shared by the cargo-driving tools.
pub fn feature_args(args: &Args) -> Vec<String> {
    let mut v = Vec::new();
    let f = args.list("features");
    if !f.is_empty() {
        v.push("--features".to_string());
        v.push(f.join(","));
    }
    if args.flag("all-features") {
        v.push("--all-features".into());
    }
    if args.flag("no-default-features") {
        v.push("--no-default-features".into());
    }
    v
}

/// The first meaningful error line of cargo's stderr (for messages).
pub fn first_error(stderr: &str) -> String {
    let clean = strip_ansi(stderr);
    clean
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("error"))
        .or_else(|| clean.lines().map(str::trim).rev().find(|l| !l.is_empty()))
        .unwrap_or("cargo failed without output")
        .to_string()
}

/// A stable short key for a path (used to name per-project cache directories).
pub fn path_key(p: &Path) -> String {
    let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let name = canon.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "root".into());
    let name: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(40).collect();
    let h = util::sha256_hex(canon.to_string_lossy().as_bytes());
    format!("{name}-{}", &h[..12])
}

/// A private target directory under the cache: `<cache>/<tool>-target/<project-key>[/<variant>]`.
/// Reused across runs so dependencies are only built once per project and variant,
/// and never invalidates the user's own `target/`.
pub fn target_dir(ctx: &Ctx, tool: &str, variant: Option<&str>) -> Result<PathBuf> {
    let mut p = ctx.cache_subdir(&format!("{tool}-target"))?.join(path_key(ctx.project_root()));
    if let Some(v) = variant {
        p = p.join(v);
    }
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Copy the project's workspace into a fresh temp dir (skipping `target/` and `.git/`).
/// Returns (temp root to delete afterwards, copied workspace root).
pub fn copy_project(root: &Path, label: &str) -> Result<(PathBuf, PathBuf)> {
    let tmp = util::temp_dir(label)?;
    let dir = tmp.join("ws");
    crate::tools::miri::copy_tree(root, &dir)?;
    Ok((tmp, dir))
}

/// Remove ANSI escape sequences.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Parse cargo's `--message-format json` stdout into JSON objects (non-JSON lines are skipped).
pub fn messages(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("reason").is_some())
        .collect()
}

/// One compiler diagnostic from the JSON stream.
#[derive(Debug, Clone, PartialEq)]
pub struct Diag {
    /// Lint name or error code (`static_mut_refs`, `E0308`), empty if none.
    pub code: String,
    /// `error`, `warning`, ...
    pub level: String,
    pub message: String,
    pub package_id: String,
    /// Target kinds (`lib`, `bin`, `test`, ...).
    pub target_kind: Vec<String>,
    /// Primary span file (as rustc printed it) and line/column.
    pub file: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    /// Some suggestion is `MachineApplicable` (what `cargo fix` applies).
    pub machine_applicable: bool,
    /// Child messages (`level: message`).
    pub children: Vec<String>,
    pub rendered: String,
}

impl Diag {
    /// Whether rustc says this is a future-incompatibility warning.
    pub fn is_future_incompat(&self) -> bool {
        self.children.iter().any(|c| c.contains("previously accepted by the compiler but is being phased out"))
    }
    /// Deduplication key (the same diagnostic repeats for lib and lib-test targets).
    pub fn key(&self) -> (String, Option<String>, Option<usize>, Option<usize>, String) {
        (self.code.clone(), self.file.clone(), self.line, self.column, self.message.clone())
    }
    pub fn location(&self) -> String {
        match (&self.file, self.line) {
            (Some(f), Some(l)) => format!("{f}:{l}"),
            (Some(f), None) => f.clone(),
            _ => String::new(),
        }
    }
}

fn walk_applicability(m: &Value, found: &mut bool) {
    if let Some(spans) = m.get("spans").and_then(Value::as_array) {
        for s in spans {
            if s.get("suggestion_applicability").and_then(Value::as_str) == Some("MachineApplicable") {
                *found = true;
            }
        }
    }
    if let Some(ch) = m.get("children").and_then(Value::as_array) {
        for c in ch {
            walk_applicability(c, found);
        }
    }
}

/// Compiler diagnostics in a message stream, deduplicated, in order.
pub fn diagnostics(msgs: &[Value]) -> Vec<Diag> {
    let mut out: Vec<Diag> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for v in msgs {
        if v.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(m) = v.get("message") else { continue };
        let level = m.get("level").and_then(Value::as_str).unwrap_or("").to_string();
        if level == "failure-note" || level == "note" || level == "help" {
            continue;
        }
        let message = m.get("message").and_then(Value::as_str).unwrap_or("").to_string();
        if message.starts_with("aborting due to") || (message.contains("warning") && message.contains("emitted")) {
            continue;
        }
        let code = m.get("code").and_then(|c| c.get("code")).and_then(Value::as_str).unwrap_or("").to_string();
        let spans = m.get("spans").and_then(Value::as_array).cloned().unwrap_or_default();
        let primary = spans.iter().find(|s| s.get("is_primary").and_then(Value::as_bool) == Some(true)).or(spans.first());
        let file = primary.and_then(|s| s.get("file_name")).and_then(Value::as_str).map(String::from);
        let line = primary.and_then(|s| s.get("line_start")).and_then(Value::as_u64).map(|n| n as usize);
        let column = primary.and_then(|s| s.get("column_start")).and_then(Value::as_u64).map(|n| n as usize);
        let mut ma = false;
        walk_applicability(m, &mut ma);
        let children = m
            .get("children")
            .and_then(Value::as_array)
            .map(|cs| {
                cs.iter()
                    .map(|c| format!("{}: {}", c.get("level").and_then(Value::as_str).unwrap_or(""), c.get("message").and_then(Value::as_str).unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default();
        let d = Diag {
            code,
            level,
            message,
            package_id: v.get("package_id").and_then(Value::as_str).unwrap_or("").to_string(),
            target_kind: v
                .get("target")
                .and_then(|t| t.get("kind"))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            file,
            line,
            column,
            machine_applicable: ma,
            children,
            rendered: m.get("rendered").and_then(Value::as_str).unwrap_or("").to_string(),
        };
        let key = (d.package_id.clone(), d.key());
        if seen.insert(key) {
            out.push(d);
        }
    }
    out
}

/// Whether the message stream ends with `build-finished` success.
pub fn build_succeeded(msgs: &[Value]) -> Option<bool> {
    msgs.iter()
        .rev()
        .find(|v| v.get("reason").and_then(Value::as_str) == Some("build-finished"))
        .and_then(|v| v.get("success").and_then(Value::as_bool))
}

/// Name and version from a cargo package id (`registry+...#name@1.2.3`,
/// `path+file:///x/foo#0.1.0`, or the old `name 1.2.3 (source)` form).
pub fn package_id_name_version(id: &str) -> (String, String) {
    if let Some((src, frag)) = id.rsplit_once('#') {
        if let Some((n, v)) = frag.split_once('@') {
            return (n.to_string(), v.to_string());
        }
        // `path+file:///dir/name#0.1.0`: name is the last path segment
        let name = src.trim_end_matches('/').rsplit('/').next().unwrap_or(src).to_string();
        return (name, frag.to_string());
    }
    let mut it = id.split_whitespace();
    (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string())
}

/// Installed rustup toolchains (`rustup toolchain list`); `None` without rustup.
pub fn rustup_toolchains() -> Option<Vec<String>> {
    let rustup = util::which("rustup")?;
    let o = util::run(Command::new(rustup).args(["toolchain", "list"]), Duration::from_secs(30)).ok()?;
    if !o.success() {
        return None;
    }
    Some(o.stdout.lines().filter_map(|l| l.split_whitespace().next()).map(String::from).collect())
}

/// Whether `channel` (`beta`, `nightly`) is installed for rustup.
pub fn has_toolchain(channel: &str) -> bool {
    rustup_toolchains().is_some_and(|ts| ts.iter().any(|t| t == channel || t.starts_with(&format!("{channel}-"))))
}

/// Split a command line into words (double/single quotes, backslash escapes outside single quotes).
pub fn split_words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut it = s.chars();
    let mut quote: Option<char> = None;
    while let Some(c) = it.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('\''), c) => cur.push(c),
            (Some(_), '\\') => {
                if let Some(n) = it.next() {
                    cur.push(n);
                }
            }
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => {
                quote = Some(c);
                has = true;
            }
            (None, '\\') => {
                if let Some(n) = it.next() {
                    cur.push(n);
                    has = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            (None, c) => {
                cur.push(c);
                has = true;
            }
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Median of a non-empty slice.
pub fn median(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    Some(if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 })
}

/// Round to `d` decimals (for JSON output).
pub fn round(x: f64, d: i32) -> f64 {
    let p = 10f64.powi(d);
    (x * p).round() / p
}

/// Percent with sign, e.g. `+12.3%`, `-4.0%`.
pub fn pct_delta(new: f64, base: f64) -> String {
    if base <= 0.0 {
        return "-".into();
    }
    let d = (new - base) / base * 100.0;
    if d.abs() < 0.05 { "±0%".into() } else { format!("{d:+.1}%") }
}

/// Progress line on stderr (stdout carries the report); suppressed by --quiet.
pub fn progress(args: &Args, msg: &str) {
    if !args.flag("quiet") {
        eprintln!("sm-crates: {msg}");
    }
}

/// Fail with a clear message when there is no project to run cargo on.
pub fn require_manifest(ctx: &Ctx) -> Result<()> {
    if ctx.manifest_path().is_file() {
        Ok(())
    } else {
        Err(Error::Env(format!(
            "no Cargo.toml at {} (run inside a Cargo project or pass --project DIR)",
            ctx.manifest_path().display()
        )))
    }
}

/// Content hashes of the `.rs` files and manifests under a directory, keyed by relative path (for change detection).
pub fn file_hashes(root: &Path) -> BTreeMap<String, String> {
    util::walk_files(root)
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("rs") || p.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml"))
        .filter_map(|p| std::fs::read(&p).ok().map(|b| (util::rel(root, &p), util::sha256_hex(&b))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_and_words() {
        assert_eq!(strip_ansi("\x1b[1m\x1b[33mwarning\x1b[0m: x"), "warning: x");
        assert_eq!(split_words(r#"{bin} --n 3 "a b" 'c d' e\ f"#), ["{bin}", "--n", "3", "a b", "c d", "e f"]);
        assert_eq!(split_words("  "), Vec::<String>::new());
        assert_eq!(split_words(r#"x """#), ["x", ""]);
    }

    #[test]
    fn ids() {
        assert_eq!(package_id_name_version("registry+https://github.com/rust-lang/crates.io-index#fcdep@1.0.0"), ("fcdep".into(), "1.0.0".into()));
        assert_eq!(package_id_name_version("path+file:///tmp/x/fcapp#0.1.0"), ("fcapp".into(), "0.1.0".into()));
        assert_eq!(package_id_name_version("path+file:///tmp/x/dir#other@0.2.0"), ("other".into(), "0.2.0".into()));
        assert_eq!(package_id_name_version("serde 1.0.0 (registry+https://x)"), ("serde".into(), "1.0.0".into()));
    }

    #[test]
    fn diags_dedupe_and_applicability() {
        let line = r#"{"reason":"compiler-message","package_id":"path+file:///p#0.1.0","target":{"kind":["lib"]},"message":{"code":{"code":"keyword_idents_2024"},"level":"warning","message":"`gen` is a keyword","spans":[{"file_name":"src/lib.rs","line_start":2,"column_start":8,"is_primary":true,"suggestion_applicability":null}],"children":[{"level":"help","message":"use r#gen","spans":[{"file_name":"src/lib.rs","line_start":2,"column_start":8,"is_primary":true,"suggestion_applicability":"MachineApplicable"}],"children":[]}],"rendered":"warning: ..."}}"#;
        let fin = r#"{"reason":"build-finished","success":true}"#;
        let msgs = messages(&format!("{line}\n{line}\nnot json\n{fin}\n"));
        let d = diagnostics(&msgs);
        assert_eq!(d.len(), 1);
        assert!(d[0].machine_applicable);
        assert_eq!(d[0].location(), "src/lib.rs:2");
        assert_eq!(build_succeeded(&msgs), Some(true));
    }

    #[test]
    fn numbers() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[4.0, 1.0]), Some(2.5));
        assert_eq!(pct_delta(110.0, 100.0), "+10.0%");
        assert_eq!(pct_delta(1.0, 0.0), "-");
        assert!(path_key(Path::new("/nonexistent/abc def")).starts_with("abc_def-"));
    }
}
