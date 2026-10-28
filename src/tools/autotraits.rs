//! Auto-Trait Leak Detector: Catch a new version silently dropping Send, Sync, Unpin or UnwindSafe on a public type.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::registry::{CrateSpec, index};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::miri::scratch_copy;
use crate::tools::{Group, Tool};
use crate::util;

pub struct AutoTraits;

const OPTS: &[Opt] = &[
    Opt::flag("local", "Build rustdoc JSON locally with `cargo +nightly rustdoc` instead of downloading it from docs.rs"),
    Opt::flag("all-features", "With --local: document with --all-features"),
    Opt::value("timeout", "SECS", "With --local: time limit per rustdoc build (default 600)"),
];

const AUTO: [&str; 5] = ["Send", "Sync", "Unpin", "UnwindSafe", "RefUnwindSafe"];

impl Tool for AutoTraits {
    fn name(&self) -> &'static str {
        "autotraits"
    }
    fn title(&self) -> &'static str {
        "Auto-Trait Leak Detector"
    }
    fn group(&self) -> Group {
        Group::Soundness
    }
    fn summary(&self) -> &'static str {
        "Catch a new version silently dropping Send, Sync, Unpin or UnwindSafe on a public type"
    }
    fn usage(&self) -> &'static str {
        "CRATE [OLD [NEW]] | CRATE@OLD [NEW] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Auto traits (Send, Sync, Unpin, UnwindSafe, RefUnwindSafe) are inferred from a type's private
fields, so adding an Rc or a raw pointer field silently removes them: a semver break that compiles
fine for the author but breaks users who send the type across threads or hold it across an .await.
This tool reads the rustdoc JSON of two versions, where rustdoc records the inferred (synthetic)
auto-trait impls, and compares every public struct, enum and union by full path: positive or
conditional -> negative/missing is high for Send/Sync/Unpin and medium for the UnwindSafe pair;
unconditional -> conditional (new `where T: Send` style bounds) is medium; changed bounds are low;
removed or moved types are info. With only CRATE it compares the previous release with the latest.
Data source: docs.rs rustdoc JSON ({docsrs}/crate/NAME/VERSION/json.gz), which docs.rs only builds
for releases since 2025; for older versions use --local, which unpacks each verified .crate into a
temporary directory and runs `cargo +nightly rustdoc --lib -- -Zunstable-options --output-format
json`. Limits: only types rustdoc documents (public, not #[doc(hidden)]) are covered; private types
and types re-exported from other crates are not; rustdoc JSON differs by target and features."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates autotraits tokio 1.44.0 1.45.0",
            "sm-crates autotraits bytes",
            "sm-crates autotraits smallvec@1.13.2 1.15.1 --local",
            "sm-crates autotraits regex 1.10.6 1.11.1 --local --all-features --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (docs.rs rustdoc JSON), or nightly with --local"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let (name, old, new) = resolve_versions(ctx, &args.positional)?;
        let local = args.flag("local");
        let timeout: u64 = args.parse_or("timeout", 600)?;
        let fetch = |v: &str| -> Result<Value> {
            if local { build_local(ctx, &name, v, args.flag("all-features"), Duration::from_secs(timeout)) } else { fetch_docsrs(ctx, &name, v) }
        };
        let old_doc = fetch(&old)?;
        let new_doc = fetch(&new)?;
        let old_t = auto_traits(&old_doc)?;
        let new_t = auto_traits(&new_doc)?;
        let mut rep = Report::new("autotraits", format!("{name} {old} -> {new}"));
        let changes = compare(&old_t, &new_t);
        let mut t = Table::new("Auto-trait changes", &["Type", "Trait", &old, &new, "Change"]);
        for c in &changes {
            t.row([c.path.clone(), c.tr.unwrap_or("-").to_string(), c.old.clone(), c.new.clone(), c.code.trim_start_matches("autotraits/").to_string()]);
            let mut f = Finding::new(c.severity, c.code.clone(), c.message.clone()).krate(&name, Some(&new)).detail(format!("{old}: {}\n{new}: {}", c.old, c.new));
            if let Some(fx) = &c.fix {
                f = f.fix(fx.clone());
            }
            rep.finding(f);
        }
        rep.table(t);
        let lost = changes.iter().filter(|c| c.code.starts_with("autotraits/lost-")).count();
        rep.summary(format!(
            "{name} {old} -> {new}: {} public type(s) compared, {lost} lost auto trait(s), {} other change(s)",
            old_t.len().min(new_t.len()),
            changes.len() - lost
        ));
        rep.note(format!("source: {}; only public types documented by rustdoc are covered", if local { "rustdoc JSON built locally" } else { "docs.rs rustdoc JSON" }));
        rep.data = json!({
            "crate": name, "old": old, "new": new, "source": if local { "local" } else { "docs.rs" },
            "format_version": {"old": old_doc.get("format_version"), "new": new_doc.get("format_version")},
            "types": {"old": old_t.len(), "new": new_t.len()},
            "changes": changes.iter().map(|c| json!({"type": c.path, "trait": c.tr, "old": c.old, "new": c.new, "code": c.code, "severity": c.severity.as_str()})).collect::<Vec<_>>(),
        });
        Ok(rep)
    }
}

/// `(crate, old, new)` from `CRATE OLD NEW`, `CRATE@OLD NEW`, `CRATE@OLD`, `CRATE OLD` or `CRATE`.
fn resolve_versions(ctx: &Ctx, pos: &[String]) -> Result<(String, String, String)> {
    let usage = || Error::Usage("usage: sm-crates autotraits CRATE [OLD [NEW]] (or CRATE@OLD [NEW])".into());
    let first = pos.first().ok_or_else(usage)?;
    if pos.len() > 3 {
        return Err(usage());
    }
    let spec = CrateSpec::parse(first)?;
    // Accept `tokio@1.40.0 tokio@1.41.0` as well as `tokio@1.40.0 1.41.0`.
    let mut pos = pos.to_vec();
    for p in pos.iter_mut().skip(1) {
        if let Some((n, v)) = p.split_once('@') {
            if !n.replace('_', "-").eq_ignore_ascii_case(&spec.name.replace('_', "-")) {
                return Err(Error::Usage(format!("`{p}` names a different crate than `{}`; compare two versions of one crate", spec.name)));
            }
            *p = v.to_string();
        }
    }
    let pos = &pos[..];
    let (old_req, new_req): (Option<String>, Option<String>) = match (spec.version.clone(), pos.len()) {
        (Some(o), 1) => (Some(o), None),
        (Some(o), 2) => (Some(o), Some(pos[1].clone())),
        (None, 1) => (None, None),
        (None, 2) => (Some(pos[1].clone()), None),
        (None, 3) => (Some(pos[1].clone()), Some(pos[2].clone())),
        _ => return Err(usage()),
    };
    let vs = index::versions(ctx, &spec.name)?;
    let name = vs[0].name.clone();
    let pick = |req: &str| -> Result<String> {
        CrateSpec { name: name.clone(), version: Some(req.to_string()) }.resolve(ctx).map(|v| v.vers)
    };
    let new = match &new_req {
        Some(r) => pick(r)?,
        None => index::latest(&vs).map(|v| v.vers.clone()).ok_or_else(|| Error::NotFound(format!("{name} has no releases")))?,
    };
    let old = match &old_req {
        Some(r) => pick(r)?,
        None => {
            let newv = semver::Version::parse(&new).map_err(|e| Error::Parse(e.to_string()))?;
            vs.iter()
                .filter(|v| !v.yanked && !v.is_prerelease())
                .filter_map(|v| v.version().map(|x| (x, v)))
                .filter(|(x, _)| *x < newv)
                .max_by(|a, b| a.0.cmp(&b.0))
                .map(|(_, v)| v.vers.clone())
                .ok_or_else(|| Error::NotFound(format!("{name} has no release before {new} to compare with")))?
        }
    };
    if old == new {
        return Err(Error::Usage(format!("both versions resolve to {old}; name two different versions")));
    }
    Ok((name, old, new))
}

fn fetch_docsrs(ctx: &Ctx, name: &str, version: &str) -> Result<Value> {
    let url = format!("{}/crate/{name}/{version}/json.gz", ctx.endpoints.docsrs);
    let r = ctx.http.get(&url, Ttl::Forever)?;
    match r.status {
        200..=299 => {}
        404 | 410 => {
            return Err(Error::NotFound(format!(
                "docs.rs has no rustdoc JSON for {name}@{version} (docs.rs only builds JSON for releases published since 2025, \
                 and not when the docs build failed). Run with --local to build it with a nightly toolchain"
            )));
        }
        s => return Err(Error::Network(format!("{url} returned HTTP {s}"))),
    }
    parse_json_body(&r.body).map_err(|e| Error::Parse(format!("rustdoc JSON for {name}@{version}: {e}")))
}

/// Decode a possibly gzip-compressed JSON body.
fn parse_json_body(body: &[u8]) -> std::result::Result<Value, String> {
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut s = Vec::new();
        flate2::read::GzDecoder::new(body).read_to_end(&mut s).map_err(|e| format!("gzip: {e}"))?;
        serde_json::from_slice(&s).map_err(|e| e.to_string())
    } else {
        serde_json::from_slice(body).map_err(|e| e.to_string())
    }
}

fn build_local(ctx: &Ctx, name: &str, version: &str, all_features: bool, timeout: Duration) -> Result<Value> {
    let src = crate::registry::download::unpacked(ctx, name, version)?;
    let (tmp, dir) = scratch_copy(&src, &format!("autotraits-{name}"))?;
    let target = tmp.join("target");
    let mut cmd = Command::new(&ctx.cargo);
    cmd.args(["+nightly", "rustdoc", "--lib"]);
    if all_features {
        cmd.arg("--all-features");
    }
    if ctx.offline {
        cmd.arg("--offline");
    }
    cmd.args(["--", "-Zunstable-options", "--output-format", "json"]).current_dir(&dir).env("CARGO_TARGET_DIR", &target).env("RUSTUP_AUTO_INSTALL", "0");
    let out = util::run(&mut cmd, timeout);
    let result = (|| {
        let out = out?;
        if out.timed_out {
            return Err(Error::Env(format!("rustdoc for {name}@{version} did not finish within {}s (raise --timeout)", timeout.as_secs())));
        }
        if !out.success() {
            let tail: Vec<&str> = out.stderr.lines().filter(|l| !l.trim().is_empty()).collect();
            let hint = if out.stderr.contains("toolchain") || out.stderr.contains("nightly") {
                "rustdoc JSON needs a nightly toolchain: rustup toolchain install nightly"
            } else {
                "the published crate did not build here (dependency resolution or compile error); try another version or --all-features"
            };
            let tail = tail[tail.len().saturating_sub(6)..].join("\n");
            return Err(Error::Env(format!(
                "`cargo +nightly rustdoc --lib -- -Zunstable-options --output-format json` failed for {name}@{version}:\n{tail}\n{hint}"
            )));
        }
        let lib = crate::rustsrc::manifest(&dir)
            .and_then(|m| m.get("lib").and_then(|l| l.get("name")).and_then(|n| n.as_str()).map(String::from))
            .unwrap_or_else(|| name.to_string())
            .replace('-', "_");
        let path = target.join("doc").join(format!("{lib}.json"));
        let body = std::fs::read(&path).map_err(|e| Error::Env(format!("rustdoc did not write {}: {e}", path.display())))?;
        parse_json_body(&body).map_err(|e| Error::Parse(format!("{}: {e}", path.display())))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

// ------------------------------------------------------------------ rustdoc JSON

/// Auto-trait status of one type.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Yes,
    Conditional(String),
    No,
    Missing,
}

impl Status {
    fn positive(&self) -> bool {
        matches!(self, Status::Yes | Status::Conditional(_))
    }
    fn text(&self) -> String {
        match self {
            Status::Yes => "yes".into(),
            Status::Conditional(c) => format!("if {c}"),
            Status::No => "no".into(),
            Status::Missing => "unknown".into(),
        }
    }
}

type TypeTraits = BTreeMap<String, BTreeMap<&'static str, Status>>;

fn id_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// `(kind, inner)` for an item in both the current (`inner: {struct: {...}}`) and the old
/// (`kind: "struct", inner: {...}`) formats.
fn item_kind(item: &Value) -> Option<(String, &Value)> {
    if let Some(k) = item.get("kind").and_then(|k| k.as_str()) {
        return Some((k.to_string(), item.get("inner")?));
    }
    let obj = item.get("inner")?.as_object()?;
    let (k, v) = obj.iter().next()?;
    Some((k.clone(), v))
}

/// Normalize an old-style `{kind, inner}` type into `{kind: inner}`.
fn norm(v: &Value) -> std::borrow::Cow<'_, Value> {
    if let (Some(k), Some(i)) = (v.get("kind").and_then(|k| k.as_str()), v.get("inner")) {
        if v.as_object().is_some_and(|o| o.len() == 2) {
            return std::borrow::Cow::Owned(json!({ k: i }));
        }
    }
    std::borrow::Cow::Borrowed(v)
}

fn path_name(p: &Value) -> String {
    p.get("path").or_else(|| p.get("name")).and_then(|x| x.as_str()).unwrap_or("?").to_string()
}

fn render_args(a: &Value) -> String {
    let Some(ab) = a.get("angle_bracketed") else { return String::new() };
    let mut parts: Vec<String> = Vec::new();
    for x in ab.get("args").and_then(|x| x.as_array()).into_iter().flatten() {
        if let Some(t) = x.get("type") {
            parts.push(render_type(t));
        } else if let Some(l) = x.get("lifetime").and_then(|l| l.as_str()) {
            parts.push(l.to_string());
        } else if let Some(c) = x.get("const") {
            parts.push(c.get("expr").and_then(|e| e.as_str()).unwrap_or("_").to_string());
        }
    }
    if parts.is_empty() { String::new() } else { format!("<{}>", parts.join(", ")) }
}

fn render_type(t: &Value) -> String {
    let t = norm(t);
    let Some(obj) = t.as_object() else { return "_".into() };
    let Some((k, v)) = obj.iter().next() else { return "_".into() };
    match k.as_str() {
        "generic" | "primitive" => v.as_str().unwrap_or("_").to_string(),
        "resolved_path" => format!("{}{}", path_name(v), v.get("args").map(render_args).unwrap_or_default()),
        "borrowed_ref" => {
            let lt = v.get("lifetime").and_then(|l| l.as_str()).map(|l| format!("{l} ")).unwrap_or_default();
            let m = if v.get("is_mutable").or_else(|| v.get("mutable")).and_then(|m| m.as_bool()).unwrap_or(false) { "mut " } else { "" };
            format!("&{lt}{m}{}", v.get("type").map(render_type).unwrap_or_default())
        }
        "raw_pointer" => {
            let m = if v.get("is_mutable").or_else(|| v.get("mutable")).and_then(|m| m.as_bool()).unwrap_or(false) { "mut" } else { "const" };
            format!("*{m} {}", v.get("type").map(render_type).unwrap_or_default())
        }
        "slice" => format!("[{}]", render_type(v)),
        "array" => format!("[{}; {}]", v.get("type").map(render_type).unwrap_or_default(), v.get("len").and_then(|l| l.as_str()).unwrap_or("_")),
        "tuple" => format!("({})", v.as_array().into_iter().flatten().map(render_type).collect::<Vec<_>>().join(", ")),
        "qualified_path" => format!(
            "<{} as {}>::{}",
            v.get("self_type").map(render_type).unwrap_or_default(),
            v.get("trait").map(|t| if t.get("path").is_some() || t.get("name").is_some() { path_name(t) } else { render_type(t) }).unwrap_or_default(),
            v.get("name").and_then(|n| n.as_str()).unwrap_or("_")
        ),
        _ => "_".into(),
    }
}

fn render_bound(b: &Value) -> String {
    if let Some(tb) = b.get("trait_bound") {
        let tr = tb.get("trait").map(|t| if t.get("path").is_some() || t.get("name").is_some() { path_name(t) + &t.get("args").map(render_args).unwrap_or_default() } else { render_type(t) }).unwrap_or_default();
        let maybe = if tb.get("modifier").and_then(|m| m.as_str()) == Some("maybe") { "?" } else { "" };
        return format!("{maybe}{tr}");
    }
    if let Some(o) = b.get("outlives").and_then(|o| o.as_str()) {
        return o.to_string();
    }
    "_".into()
}

fn render_bounds(v: Option<&Value>) -> String {
    v.and_then(|b| b.as_array()).map(|a| a.iter().map(render_bound).collect::<Vec<_>>().join(" + ")).unwrap_or_default()
}

/// Conditions of an impl: param bounds and where predicates, as text.
fn impl_conditions(generics: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(g) = generics else { return out };
    for p in g.get("params").and_then(|p| p.as_array()).into_iter().flatten() {
        let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("_");
        let bounds = p.get("kind").and_then(|k| k.get("type")).map(|t| render_bounds(t.get("bounds"))).unwrap_or_default();
        if !bounds.is_empty() {
            out.push(format!("{name}: {bounds}"));
        }
    }
    for w in g.get("where_predicates").and_then(|w| w.as_array()).into_iter().flatten() {
        if let Some(bp) = w.get("bound_predicate") {
            let ty = bp.get("type").map(render_type).unwrap_or_default();
            out.push(format!("{ty}: {}", render_bounds(bp.get("bounds"))));
        } else if let Some(rp) = w.get("region_predicate").or_else(|| w.get("lifetime_predicate")) {
            out.push(format!("{}: {}", rp.get("lifetime").and_then(|l| l.as_str()).unwrap_or("'_"), render_bounds(rp.get("bounds").or_else(|| rp.get("outlives")))));
        } else if let Some(ep) = w.get("eq_predicate") {
            out.push(format!("{} = {}", ep.get("lhs").map(render_type).unwrap_or_default(), ep.get("rhs").map(|r| r.get("type").map(render_type).unwrap_or_else(|| render_type(r))).unwrap_or_default()));
        }
    }
    out
}

/// Auto-trait status of every public struct/enum/union in the local crate, keyed by full path.
fn auto_traits(doc: &Value) -> Result<TypeTraits> {
    let index = doc.get("index").and_then(|i| i.as_object()).ok_or_else(|| Error::Parse("rustdoc JSON has no `index`".into()))?;
    let paths = doc.get("paths").and_then(|p| p.as_object()).ok_or_else(|| Error::Parse("rustdoc JSON has no `paths`".into()))?;
    let mut out: TypeTraits = BTreeMap::new();
    for (id, p) in paths {
        if p.get("crate_id").and_then(|c| c.as_u64()) != Some(0) {
            continue;
        }
        let kind = p.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        if !matches!(kind, "struct" | "enum" | "union") {
            continue;
        }
        let Some(item) = index.get(id) else { continue };
        if item.get("visibility").and_then(|v| v.as_str()) != Some("public") {
            continue;
        }
        let full: Vec<&str> = p.get("path").and_then(|x| x.as_array()).into_iter().flatten().filter_map(|s| s.as_str()).collect();
        let Some((_, inner)) = item_kind(item) else { continue };
        let mut st: BTreeMap<&'static str, Status> = AUTO.iter().map(|t| (*t, Status::Missing)).collect();
        for iid in inner.get("impls").and_then(|i| i.as_array()).into_iter().flatten() {
            let Some(imp) = id_key(iid).and_then(|k| index.get(&k)) else { continue };
            let Some((ik, im)) = item_kind(imp) else { continue };
            if ik != "impl" {
                continue;
            }
            let Some(tr) = im.get("trait").filter(|t| !t.is_null()) else { continue };
            let tname = path_name(tr);
            let tname = tname.rsplit("::").next().unwrap_or("");
            let Some(auto) = AUTO.iter().find(|a| **a == tname) else { continue };
            let negative = im.get("is_negative").or_else(|| im.get("negative")).and_then(|n| n.as_bool()).unwrap_or(false);
            let status = if negative {
                Status::No
            } else {
                let mut c = impl_conditions(im.get("generics"));
                c.sort();
                c.dedup();
                if c.is_empty() { Status::Yes } else { Status::Conditional(c.join(", ")) }
            };
            st.insert(auto, status);
        }
        out.insert(full.join("::"), st);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct Change {
    path: String,
    tr: Option<&'static str>,
    old: String,
    new: String,
    code: String,
    severity: Severity,
    message: String,
    fix: Option<String>,
}

fn compare(old: &TypeTraits, new: &TypeTraits) -> Vec<Change> {
    let mut out = Vec::new();
    for (path, os) in old {
        let short = path.rsplit("::").next().unwrap_or(path);
        let Some(ns) = new.get(path) else {
            let moved: Vec<&String> = new.keys().filter(|k| k.rsplit("::").next() == Some(short) && !old.contains_key(*k)).collect();
            let (code, msg) = match moved.first() {
                Some(m) => ("autotraits/type-moved", format!("`{path}` is now `{m}`; auto traits are compared only by full path")),
                None => ("autotraits/type-removed", format!("public type `{path}` is gone (removed, renamed or hidden)")),
            };
            out.push(Change { path: path.clone(), tr: None, old: "present".into(), new: moved.first().map(|m| m.to_string()).unwrap_or("absent".into()), code: code.into(), severity: Severity::Info, message: msg, fix: None });
            continue;
        };
        for tr in AUTO {
            let (a, b) = (&os[tr], &ns[tr]);
            if a == b {
                continue;
            }
            let lower = tr.to_ascii_lowercase();
            let (code, sev, msg, fix) = if a.positive() && !b.positive() {
                let sev = if matches!(tr, "Send" | "Sync" | "Unpin") { Severity::High } else { Severity::Medium };
                let why = match tr {
                    "Send" => "it can no longer be moved to another thread (thread::spawn, tokio::spawn, Send futures)",
                    "Sync" => "&T can no longer be shared across threads (Arc<T>, static, scoped threads)",
                    "Unpin" => "it now needs pinning (Box::pin) before polling or moving out of Pin",
                    _ => "it can no longer cross catch_unwind without AssertUnwindSafe",
                };
                (
                    format!("autotraits/lost-{lower}"),
                    sev,
                    format!("`{path}` is no longer {tr}: {why}"),
                    Some(format!("A private field change removed {tr}; check the diff of `{short}`'s fields (Rc, Cell, raw pointers, dyn Trait without + {tr}) or pin the older version")),
                )
            } else if *a == Status::Yes && matches!(b, Status::Conditional(_)) {
                (format!("autotraits/conditional-{lower}"), Severity::Medium, format!("`{path}` is now {tr} only {}", b.text()), Some(format!("Callers using `{short}` with types that do not meet the new bound lose {tr}")))
            } else if matches!(a, Status::Conditional(_)) && matches!(b, Status::Conditional(_)) {
                (format!("autotraits/bounds-changed-{lower}"), Severity::Low, format!("`{path}`: {tr} bounds changed"), None)
            } else if !a.positive() && b.positive() {
                (format!("autotraits/gained-{lower}"), Severity::Info, format!("`{path}` is now {tr}"), None)
            } else {
                continue;
            };
            out.push(Change { path: path.clone(), tr: Some(tr), old: a.text(), new: b.text(), code, severity: sev, message: msg, fix });
        }
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.path.cmp(&b.path)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(types: Value) -> Value {
        // types: [(id, path, impls: [(trait, negative, where_predicates)])]
        let mut index = serde_json::Map::new();
        let mut paths = serde_json::Map::new();
        let mut next = 1000;
        for t in types.as_array().unwrap() {
            let id = t[0].as_u64().unwrap();
            let mut impl_ids = Vec::new();
            for im in t[2].as_array().unwrap() {
                next += 1;
                impl_ids.push(next);
                index.insert(
                    next.to_string(),
                    json!({"id": next, "crate_id": 0, "visibility": "default", "inner": {"impl": {
                        "trait": {"path": im[0], "id": 1, "args": null}, "is_negative": im[1], "is_synthetic": true,
                        "generics": {"params": [], "where_predicates": im[2]}}}}),
                );
            }
            index.insert(id.to_string(), json!({"id": id, "crate_id": 0, "visibility": "public", "inner": {"struct": {"impls": impl_ids}}}));
            paths.insert(id.to_string(), json!({"crate_id": 0, "path": t[1], "kind": "struct"}));
        }
        json!({"index": index, "paths": paths, "format_version": 57})
    }

    fn send_bound() -> Value {
        json!([{"bound_predicate": {"type": {"generic": "T"}, "bounds": [{"trait_bound": {"trait": {"path": "Send", "id": 4}, "modifier": "none"}}]}}])
    }

    #[test]
    fn statuses_and_rendering() {
        let d = doc(json!([[1, ["c", "A"], [["Send", false, []], ["Sync", true, []], ["Unpin", false, send_bound()]]]]));
        let t = auto_traits(&d).unwrap();
        let a = &t["c::A"];
        assert_eq!(a["Send"], Status::Yes);
        assert_eq!(a["Sync"], Status::No);
        assert_eq!(a["Unpin"], Status::Conditional("T: Send".into()));
        assert_eq!(a["UnwindSafe"], Status::Missing);
    }

    #[test]
    fn compares_versions() {
        let old = auto_traits(&doc(json!([
            [1, ["c", "A"], [["Send", false, []], ["Sync", false, []], ["UnwindSafe", false, []]]],
            [2, ["c", "B"], [["Send", false, []]]],
            [3, ["c", "Gone"], []],
            [4, ["c", "old", "Moved"], []]
        ])))
        .unwrap();
        let new = auto_traits(&doc(json!([
            [1, ["c", "A"], [["Send", true, []], ["Sync", true, []], ["UnwindSafe", true, []]]],
            [2, ["c", "B"], [["Send", false, send_bound()]]],
            [4, ["c", "new", "Moved"], []]
        ])))
        .unwrap();
        let ch = compare(&old, &new);
        let codes: Vec<(&str, Severity)> = ch.iter().map(|c| (c.code.as_str(), c.severity)).collect();
        assert_eq!(
            codes,
            [
                ("autotraits/lost-send", Severity::High),
                ("autotraits/lost-sync", Severity::High),
                ("autotraits/lost-unwindsafe", Severity::Medium),
                ("autotraits/conditional-send", Severity::Medium),
                ("autotraits/type-removed", Severity::Info),
                ("autotraits/type-moved", Severity::Info),
            ]
        );
    }

    #[test]
    fn old_format_items_and_types() {
        let item = json!({"kind": "struct", "inner": {"impls": ["0:5"]}});
        let (k, inner) = item_kind(&item).unwrap();
        assert_eq!(k, "struct");
        assert_eq!(id_key(&inner["impls"][0]).unwrap(), "0:5");
        assert_eq!(render_type(&json!({"kind": "generic", "inner": "T"})), "T");
        assert_eq!(render_type(&json!({"borrowed_ref": {"lifetime": "'a", "is_mutable": true, "type": {"primitive": "u8"}}})), "&'a mut u8");
        assert_eq!(render_type(&json!({"resolved_path": {"path": "Vec", "args": {"angle_bracketed": {"args": [{"type": {"generic": "T"}}]}}}})), "Vec<T>");
    }

    #[test]
    fn gzip_and_plain_bodies() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, b"{\"a\":1}").unwrap();
        assert_eq!(parse_json_body(&gz.finish().unwrap()).unwrap()["a"], 1);
        assert_eq!(parse_json_body(b"{\"a\":2}").unwrap()["a"], 2);
        assert!(parse_json_body(b"<html>").is_err());
    }
}
