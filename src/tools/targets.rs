//! Target Compatibility Matrix: Which dependencies build for wasm32, WASI, embedded, Android and iOS targets.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::project::{MetaOpts, Package};
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::Kind;
use crate::tools::features_util::{self as fu, Env, ModFile, StdInfo, StdVerdict, TargetCfg};
use crate::tools::{Group, Tool};
use crate::util;

pub struct Targets;

pub const DEFAULT_TARGETS: &[&str] = &[
    "wasm32-unknown-unknown",
    "wasm32-wasip1",
    "thumbv7em-none-eabihf",
    "aarch64-linux-android",
    "aarch64-apple-ios",
    "x86_64-pc-windows-msvc",
    "aarch64-unknown-linux-gnu",
];

const OPTS: &[Opt] = &[
    Opt::value("target", "TRIPLE", "Target(s) to check (repeatable or comma-separated; default: wasm32, WASI, thumbv7em, Android, iOS, Windows, aarch64 Linux)"),
    Opt::flag("all", "Show every dependency in the matrix, not only problematic ones"),
    Opt::flag("check", "Run cargo check for every target, even when its standard library does not look installed"),
    Opt::flag("no-check", "Static analysis only; never run cargo check"),
    Opt::value("timeout", "SECS", "Time limit per cargo check (default 900)"),
    Opt::flag("no-docsrs", "Do not look up docs.rs build results"),
];

impl Tool for Targets {
    fn name(&self) -> &'static str {
        "targets"
    }
    fn title(&self) -> &'static str {
        "Target Compatibility Matrix"
    }
    fn group(&self) -> Group {
        Group::Features
    }
    fn summary(&self) -> &'static str {
        "Which dependencies build for wasm32, WASI, embedded, Android and iOS targets"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Builds a dependency x target compatibility matrix for the project.
Targets: --target (repeatable, comma lists), default wasm32-unknown-unknown, wasm32-wasip1,
thumbv7em-none-eabihf, aarch64-linux-android, aarch64-apple-ios, x86_64-pc-windows-msvc and
aarch64-unknown-linux-gnu. Each target's cfg comes from `rustc --print cfg --target T`, which works
for every built-in target without installing it. The packages and features built for T come from
`cargo tree -e normal --target T` (target-specific dependencies evaluated by cargo; proc-macro and
build-script code runs on the host and is skipped).
Static checks per package at its active features: a `compile_error!` under a #[cfg(...)] that holds
for T (high); a native C build (a build-dependency on cc, cmake, pkg-config or autotools) on
wasm32-unknown-unknown (medium, likely fails); a library that is not no_std on a target without
std, such as thumbv*/*-none-* (high; same detection as `sm-crates nostd`); known pitfalls on
wasm32-unknown-unknown: getrandom 0.2 without feature `js`, getrandom 0.3/0.4 without `wasm_js`
(0.3.0-0.3.3 also need RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"'), ring older than 0.17 (high/
medium), and std::thread/std::fs use, which compiles but panics at run time (low).
docs.rs evidence: for every crates.io dependency version, https://docs.rs/crate/NAME/VERSION/status.json
and the platform list (/crate/NAME/VERSION/menus/platforms/) give the targets docs.rs built
it for. A target in that list is shown as 'ok (docs.rs)'. When the crate's
package.metadata.docs.rs asks for T (`targets` or `default-target`) but docs.rs has no build for
T, that is a low finding (`targets/docsrs-missing`, '?'). docs.rs only builds the targets a crate
asks for (since May 2026 only x86_64-unknown-linux-gnu by default; earlier releases got five tier-1
targets), so a missing wasm/embedded/mobile entry is not a failure. If docs.rs is unreachable the matrix uses the other checks and a note says so.
Real compile: when T's standard library is installed (sysroot check), or with --check, `cargo check
--workspace --target T --message-format json` runs and errors are attributed to the package that
failed; static and real results are shown separately. Matrix cells: ok, x (fails) or ? (risky),
'-' when the package is not built for T; only problematic packages are listed unless --all.
Limits: cfgs inside macros other than cfg_if! are not evaluated; C toolchains for cross targets are not checked."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates targets",
            "sm-crates targets --target wasm32-unknown-unknown,thumbv7em-none-eabihf",
            "sm-crates targets --target x86_64-unknown-linux-gnu --all",
            "sm-crates targets --no-docsrs --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo; rustup targets for real cross-checks"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let timeout: u64 = args.parse_or("timeout", 900)?;
        let manifest = ctx.manifest_path();
        if !manifest.is_file() {
            return Err(Error::Env(format!("no Cargo.toml at {} (run inside a Cargo project or pass --project DIR)", manifest.display())));
        }
        let mut triples = args.list("target");
        if triples.is_empty() {
            triples = DEFAULT_TARGETS.iter().map(|s| s.to_string()).collect();
        }
        let mut seen_t = BTreeSet::new();
        triples.retain(|t| seen_t.insert(t.clone()));
        let tcfgs: Vec<TargetCfg> = triples.iter().map(|t| fu::target_cfg(t)).collect::<Result<_>>()?;
        let meta = fu::load_metadata_at(ctx, &manifest, &MetaOpts::default())?;
        let label = meta.members().iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
        let mut rep = Report::new("targets", format!("project {label}"));
        let host = fu::host_triple()?;

        // ---- per-target package sets
        let mut per_target: Vec<fu::Active> = Vec::new();
        for t in &triples {
            let lines = fu::cargo_tree(ctx, &manifest, "normal", t, &[])?;
            per_target.push(fu::active_from_tree(&meta, &fu::tree_features(&lines, true)));
        }
        let mut ids: BTreeSet<String> = BTreeSet::new();
        for a in &per_target {
            ids.extend(a.keys().cloned());
        }

        // ---- static analysis
        let mut sources: BTreeMap<String, Src> = BTreeMap::new();
        for id in &ids {
            let Some(p) = meta.package(id) else { continue };
            let dir = p.dir();
            let files = fu::crate_root(&dir).map(|r| fu::module_tree(&dir, &r)).unwrap_or_default();
            let std = StdInfo::from_files(&dir, &files);
            sources.insert(id.clone(), Src { files, std, docs_targets: docs_rs_targets(&dir) });
        }
        // ---- docs.rs build results
        let mut docsrs: BTreeMap<String, DocsRs> = BTreeMap::new();
        let mut docsrs_status = json!({"used": false});
        if !args.flag("no-docsrs") {
            let pkgs: Vec<&Package> = ids.iter().filter_map(|id| meta.package(id)).filter(|p| p.is_crates_io() && !meta.is_member(&p.id)).collect();
            match docsrs_results(ctx, &pkgs) {
                Ok(m) => {
                    let built = m.values().filter(|d| matches!(d, DocsRs::Built(_))).count();
                    docsrs_status = json!({"used": true, "crates": pkgs.len(), "with_build": built});
                    docsrs = m;
                }
                Err(e) => {
                    rep.note(format!("docs.rs build results unavailable ({e}); the matrix uses static checks and cargo check only"));
                    docsrs_status = json!({"used": false, "error": e});
                }
            }
        }
        let mut cells: BTreeMap<(String, usize), Cell> = BTreeMap::new();
        for (ti, t) in tcfgs.iter().enumerate() {
            for (id, feats) in &per_target[ti] {
                let (Some(p), Some(src)) = (meta.package(id), sources.get(id)) else { continue };
                let mut cell = check_static(p, src, feats, t);
                let (label, issue) = docsrs_evidence(p, src, docsrs.get(id), &t.triple);
                cell.docsrs = label;
                cell.issues.extend(issue);
                cells.insert((id.clone(), ti), cell);
            }
        }

        // ---- real checks
        let target_dir = ctx.cache_subdir("targets-target")?;
        let mut real: Vec<(String, String, Vec<fu::CheckError>)> = Vec::new();
        let mut not_installed = Vec::new();
        for t in &triples {
            let installed = *t == host || fu::target_installed(t);
            if args.flag("no-check") || !(installed || args.flag("check")) {
                if !installed {
                    not_installed.push(t.clone());
                }
                continue;
            }
            let r = fu::cargo_check(ctx, &manifest, &["--workspace".into(), "--target".into(), t.clone()], &target_dir, Duration::from_secs(timeout))?;
            let missing_target = r.errors.iter().any(|e| e.message.contains("can't find crate for `core`") || e.message.contains("can't find crate for `std`") && !installed)
                || r.stderr_error.as_deref().is_some_and(|s| s.contains("target may not be installed"));
            if !installed && missing_target {
                not_installed.push(t.clone());
                real.push((t.clone(), "target not installed".into(), vec![]));
                continue;
            }
            let res = if r.timed_out {
                "timed out".to_string()
            } else if r.success {
                "ok".to_string()
            } else {
                format!("failed ({} error(s))", r.errors.len().max(1))
            };
            real.push((t.clone(), res, r.errors.clone()));
            if !r.success && r.errors.is_empty() {
                if let Some(e) = &r.stderr_error {
                    rep.note(format!("cargo check --target {t}: {e}"));
                }
            }
        }
        if !not_installed.is_empty() {
            rep.note(format!(
                "static analysis only for {} (standard library not installed); for a real check: {}",
                not_installed.join(", "),
                not_installed.iter().map(|t| format!("rustup target add {t}")).collect::<Vec<_>>().join("; ")
            ));
        }

        // ---- findings: one per (package, code, reason) listing targets
        let mut grouped: BTreeMap<(String, &'static str, String), (Severity, Vec<String>, Option<(String, usize)>, String)> = BTreeMap::new();
        for ((id, ti), c) in &cells {
            for i in &c.issues {
                let e = grouped.entry((id.clone(), i.code, i.message.clone())).or_insert((i.severity, vec![], i.location.clone(), i.fix.clone()));
                e.1.push(triples[*ti].clone());
            }
        }
        for ((id, code, msg), (sev, ts, loc, fix)) in grouped {
            let Some(p) = meta.package(&id) else { continue };
            let mut f = Finding::new(sev, code, format!("{msg} on {}", ts.join(", "))).krate(p.name.clone(), Some(p.version.clone())).fix(fix);
            if let Some((file, line)) = loc {
                f = f.at(format!("{}/{}", p.spec(), file), Some(line));
            }
            let chain = meta.path_to(&id);
            if chain.len() > 1 {
                f = f.detail(format!("path: {}", chain.join(" -> ")));
            }
            rep.finding(f);
        }
        let mut real_json = Vec::new();
        for (t, res, errs) in &real {
            let mut by_pkg: BTreeMap<(String, String), Vec<&fu::CheckError>> = BTreeMap::new();
            for e in errs {
                by_pkg.entry((e.package.clone(), e.version.clone())).or_default().push(e);
            }
            for ((n, v), es) in &by_pkg {
                let e = es[0];
                let mut f = Finding::new(Severity::High, "targets/build-fails", format!("does not compile for {t}: {}", e.message)).krate(n.clone(), Some(v.clone()));
                if let (Some(file), Some(line)) = (&e.file, e.line) {
                    f = f.at(file.clone(), Some(line));
                }
                rep.finding(f.detail(format!("{} error(s) from `cargo check --target {t}`", es.len())).fix(format!("reproduce with `cargo check --workspace --target {t}`")));
            }
            real_json.push(json!({"target": t, "result": res, "errors": errs.iter().map(|e| json!({"package": e.package, "version": e.version, "message": e.message, "file": e.file, "line": e.line})).collect::<Vec<_>>()}));
        }

        // ---- matrix
        let mut headers: Vec<&str> = vec!["Package"];
        headers.extend(triples.iter().map(|s| s.as_str()));
        let mut t = Table::new("Static compatibility (ok / x fails / ? risky / - not built for that target)", &headers);
        let mut matrix_json = Vec::new();
        let mut problem_pkgs = 0;
        for id in &ids {
            let Some(p) = meta.package(id) else { continue };
            let mut row = vec![if meta.is_member(id) { format!("{} (member)", p.spec()) } else { p.spec() }];
            let mut bad = false;
            for ti in 0..triples.len() {
                match cells.get(&(id.clone(), ti)) {
                    None => row.push("-".into()),
                    Some(c) => {
                        let s = c.status();
                        if s != "ok" {
                            bad = true;
                        }
                        row.push(c.label());
                        matrix_json.push(json!({"crate": p.name, "version": p.version, "target": triples[ti], "status": s, "docsrs": c.docsrs, "reasons": c.issues.iter().map(|i| i.short.clone()).chain(c.notes.iter().cloned()).collect::<Vec<_>>()}));
                    }
                }
            }
            if bad {
                problem_pkgs += 1;
            }
            if bad || args.flag("all") {
                t.row(row);
            }
        }
        rep.table(t);
        if !real.is_empty() {
            let mut rt = Table::new("Real cargo check", &["Target", "Result", "Failing packages"]);
            for (tr, res, errs) in &real {
                let pk: BTreeSet<String> = errs.iter().map(|e| format!("{}@{}", e.package, e.version)).collect();
                rt.row([tr.clone(), res.clone(), pk.into_iter().collect::<Vec<_>>().join(", ")]);
            }
            rep.table(rt);
        }
        let fails: BTreeSet<usize> = cells.iter().filter(|(_, c)| c.status() == "x").map(|((_, ti), _)| *ti).collect();
        rep.summary(format!(
            "{} package(s) x {} target(s): {problem_pkgs} package(s) with problems; static failures on {} target(s){}",
            ids.len(),
            triples.len(),
            fails.len(),
            if real.is_empty() { String::new() } else { format!("; real check ran for {}", real.iter().map(|r| r.0.as_str()).collect::<Vec<_>>().join(", ")) }
        ));
        rep.data = json!({
            "targets": triples,
            "host": host,
            "matrix": matrix_json,
            "real": real_json,
            "docsrs": docsrs_status,
            "target_cfg": tcfgs.iter().map(|t| json!({"target": t.triple, "os": t.get("target_os"), "arch": t.get("target_arch"), "family": t.get("target_family"), "env": t.get("target_env"), "pointer_width": t.get("target_pointer_width"), "has_std": t.has_std()})).collect::<Vec<_>>(),
        });
        Ok(rep)
    }
}

struct Src {
    files: Vec<ModFile>,
    std: StdInfo,
    /// Targets the crate asks docs.rs to build (`targets` plus `default-target`), if configured.
    docs_targets: Option<Vec<String>>,
}

/// What docs.rs knows about one crate version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DocsRs {
    /// Docs built; these are the targets docs.rs has documentation for.
    Built(Vec<String>),
    /// docs.rs has the version but its build failed (or is not finished).
    BuildFailed,
    /// docs.rs does not know the version.
    Unknown,
}

#[derive(Debug, Clone)]
struct Issue {
    severity: Severity,
    code: &'static str,
    /// Finding message (without the target list).
    message: String,
    /// Short matrix label.
    short: String,
    fix: String,
    location: Option<(String, usize)>,
}

#[derive(Debug, Clone, Default)]
struct Cell {
    issues: Vec<Issue>,
    notes: Vec<String>,
    /// docs.rs result for this package and target (`built`, `missing`, ...).
    docsrs: &'static str,
}

impl Cell {
    fn status(&self) -> &'static str {
        if self.issues.iter().any(|i| i.severity >= Severity::Medium) {
            "x"
        } else if !self.issues.is_empty() || !self.notes.is_empty() {
            "?"
        } else {
            "ok"
        }
    }
    fn label(&self) -> String {
        let s = self.status();
        let reasons: Vec<&str> = self.issues.iter().map(|i| i.short.as_str()).chain(self.notes.iter().map(|s| s.as_str())).collect();
        if reasons.is_empty() {
            if self.docsrs == "built" { format!("{s} (docs.rs)") } else { s.to_string() }
        } else {
            format!("{s} {}", reasons.join("; "))
        }
    }
}

fn docs_rs_targets(dir: &std::path::Path) -> Option<Vec<String>> {
    let m = crate::rustsrc::manifest(dir)?;
    let d = m.get("package")?.get("metadata")?.get("docs")?.get("rs")?;
    let mut out: Vec<String> = d.get("targets").and_then(|t| t.as_array()).map(|t| t.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    if let Some(dt) = d.get("default-target").and_then(|v| v.as_str()) {
        out.push(dt.to_string());
    }
    (!out.is_empty()).then_some(out)
}

/// Target triples listed in a docs.rs platform menu (`<a class="pure-menu-link" ...>TRIPLE</a>`).
fn parse_platforms(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for chunk in html.split("<a ").skip(1) {
        let Some(gt) = chunk.find('>') else { continue };
        if !chunk[..gt].contains("pure-menu-link") {
            continue;
        }
        let rest = &chunk[gt + 1..];
        let text = rest.split("</a>").next().unwrap_or("").trim();
        let triple_like = text.split('-').count() >= 2
            && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            && !text.starts_with(|c: char| c.is_ascii_digit());
        if triple_like && !out.iter().any(|t| t == text) {
            out.push(text.to_string());
        }
    }
    out
}

/// docs.rs results per package id. Returns `Err(reason)` when docs.rs cannot be reached.
fn docsrs_results(ctx: &Ctx, pkgs: &[&Package]) -> std::result::Result<BTreeMap<String, DocsRs>, String> {
    let mut out = BTreeMap::new();
    let Some(first) = pkgs.first() else { return Ok(out) };
    let base = &ctx.endpoints.docsrs;
    let status_url = |p: &Package| format!("{base}/crate/{}/{}/status.json", p.name, p.version);
    // probe once so an unreachable docs.rs costs one request, not one per crate
    match ctx.http.get(&status_url(first), Ttl::DAY) {
        Ok(r) if r.ok() || r.status == 404 || r.status == 410 => {}
        Ok(r) => return Err(format!("{} returned HTTP {}", status_url(first), r.status)),
        Err(e) => return Err(e.to_string()),
    }
    let urls: Vec<String> = pkgs.iter().map(|p| status_url(p)).collect();
    let statuses = ctx.http.get_many(&urls, Ttl::DAY, 6);
    let mut built: Vec<&Package> = Vec::new();
    for (p, r) in pkgs.iter().zip(statuses) {
        let state = match r {
            Ok(r) if r.ok() => match r.json().ok().and_then(|v| v["doc_status"].as_bool()) {
                Some(true) => {
                    built.push(p);
                    continue;
                }
                Some(false) => DocsRs::BuildFailed,
                None => DocsRs::Unknown,
            },
            _ => DocsRs::Unknown,
        };
        out.insert(p.id.clone(), state);
    }
    let urls: Vec<String> = built.iter().map(|p| format!("{base}/crate/{}/{}/menus/platforms/", p.name, p.version)).collect();
    for (p, r) in built.iter().zip(ctx.http.get_many(&urls, Ttl::DAY, 6)) {
        let state = match r {
            Ok(r) if r.ok() => {
                let list = parse_platforms(&r.text());
                if list.is_empty() { DocsRs::Unknown } else { DocsRs::Built(list) }
            }
            _ => DocsRs::Unknown,
        };
        out.insert(p.id.clone(), state);
    }
    Ok(out)
}

/// docs.rs evidence for one package and target: (label for the JSON, issue).
fn docsrs_evidence(p: &Package, src: &Src, d: Option<&DocsRs>, triple: &str) -> (&'static str, Option<Issue>) {
    match d {
        Some(DocsRs::Built(list)) if list.iter().any(|t| t == triple) => ("built", None),
        Some(DocsRs::Built(_)) if src.docs_targets.as_ref().is_some_and(|t| t.iter().any(|x| x == triple)) => (
            "missing",
            Some(Issue {
                severity: Severity::Low,
                code: "targets/docsrs-missing",
                message: format!("{}@{} asks docs.rs to build for this target, but docs.rs has no build for it", p.name, p.version),
                short: "docs.rs build missing".into(),
                fix: format!("check the docs.rs build log for {}@{} (https://docs.rs/crate/{}/{}/builds) or run `cargo check --target {triple}`", p.name, p.version, p.name, p.version),
                location: None,
            }),
        ),
        Some(DocsRs::Built(_)) => ("not-requested", None),
        Some(DocsRs::BuildFailed) => ("build-failed", None),
        Some(DocsRs::Unknown) => ("unknown", None),
        None => ("not-checked", None),
    }
}

fn check_static(p: &Package, src: &Src, feats: &BTreeSet<String>, t: &TargetCfg) -> Cell {
    let mut c = Cell::default();
    let env = Env { features: Some(feats), target: Some(t) };
    // (2) compile_error!
    for ce in fu::compile_errors(&src.files) {
        if ce.cfg.eval(&env) == Some(true) {
            c.issues.push(Issue {
                severity: Severity::High,
                code: "targets/compile-error",
                message: format!("compile_error!(\"{}\") is active", ce.message),
                short: "compile_error!".into(),
                fix: "pick a different target or the feature combination the crate supports for it (see the cfg above the compile_error!)".into(),
                location: Some((ce.file.clone(), ce.line)),
            });
        }
    }
    // (3) native C build on wasm32-unknown-unknown
    if t.is_wasm_unknown() {
        let c_dep = p
            .dependencies
            .iter()
            .find(|d| d.kind() == "build" && matches!(d.name.as_str(), "cc" | "cmake" | "pkg-config" | "autotools") && fu::dep_target_applies(d.target.as_deref(), t) != Some(false));
        // a `links` key alone is not evidence of C code (wasm-bindgen-shared uses it for uniqueness)
        if let Some(d) = c_dep {
            let why = match &p.links {
                Some(l) => format!("build script compiles native code with `{}` (links `{l}`)", d.name),
                None => format!("build script compiles native code with `{}`", d.name),
            };
            c.issues.push(Issue {
                severity: Severity::Medium,
                code: "targets/native-build",
                message: format!("{why}; there is no C toolchain or system library"),
                short: "native C build".into(),
                fix: "use a pure-Rust alternative or a feature that disables the C backend for wasm".into(),
                location: None,
            });
        }
    }
    // (4) std on a target without std
    if !t.has_std() && !src.std.proc_macro {
        match src.std.verdict(feats, Some(t)) {
            StdVerdict::AlwaysStd => c.issues.push(Issue {
                severity: Severity::High,
                code: "targets/needs-std",
                message: "needs std, which the target does not have".into(),
                short: "needs std".into(),
                fix: "replace it with a no_std crate, or make it optional behind your own `std` feature".into(),
                location: src.std.root_file.clone().map(|f| (f, 1)),
            }),
            StdVerdict::StdViaFeatures(fs) => c.issues.push(Issue {
                severity: Severity::High,
                code: "targets/needs-std",
                message: format!("links std through feature {}, which the target does not have", fs.join(", ")),
                short: format!("std via {}", fs.join(",")),
                fix: format!("depend on {} with default-features = false and without {} (see `sm-crates nostd --target {}`)", p.name, fs.join(", "), t.triple),
                location: None,
            }),
            _ => {}
        }
    }
    // (5) pitfalls
    if t.is_wasm_unknown() {
        let ver = util::parse_version(&p.version);
        if p.name == "getrandom" {
            if let Some(v) = &ver {
                if v.major == 0 && v.minor == 2 && !feats.contains("js") {
                    c.issues.push(Issue {
                        severity: Severity::High,
                        code: "targets/getrandom-wasm",
                        message: "getrandom 0.2 without the `js` feature does not compile".into(),
                        short: "getrandom needs `js`".into(),
                        fix: "add `getrandom = { version = \"0.2\", features = [\"js\"] }` under [target.'cfg(target_arch = \"wasm32\")'.dependencies]".into(),
                        location: None,
                    });
                } else if (v.major == 0 && v.minor >= 3 || v.major > 0) && !feats.contains("wasm_js") {
                    let cfg_too = v.major == 0 && v.minor == 3 && v.patch < 4;
                    c.issues.push(Issue {
                        severity: Severity::High,
                        code: "targets/getrandom-wasm",
                        message: format!("getrandom {} without the `wasm_js` feature does not compile", v),
                        short: "getrandom needs `wasm_js`".into(),
                        fix: format!(
                            "add `getrandom = {{ version = \"{}.{}\", features = [\"wasm_js\"] }}` for wasm32{}",
                            v.major,
                            v.minor,
                            if cfg_too { " and set RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"' (or upgrade to 0.3.4+, which needs only the feature)" } else { "" }
                        ),
                        location: None,
                    });
                } else if v.major == 0 && v.minor == 3 && v.patch < 4 {
                    c.issues.push(Issue {
                        severity: Severity::Low,
                        code: "targets/getrandom-wasm",
                        message: format!("getrandom {v} also needs RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"'"),
                        short: "getrandom needs --cfg".into(),
                        fix: "set the cfg in .cargo/config.toml (target.wasm32-unknown-unknown.rustflags), or upgrade getrandom to 0.3.4+".into(),
                        location: None,
                    });
                }
            }
        }
        if p.name == "ring" && ver.as_ref().is_some_and(|v| v.major == 0 && v.minor < 17) {
            c.issues.push(Issue {
                severity: Severity::Medium,
                code: "targets/ring-wasm",
                message: format!("ring {} does not build", p.version),
                short: "ring < 0.17".into(),
                fix: "upgrade to ring 0.17 (needs clang for wasm) or use a pure-Rust crypto backend".into(),
                location: None,
            });
        }
        // std::thread / std::fs compile on wasm32-unknown-unknown but panic at run time
        if let Some((what, file, line)) = runtime_panics(&src.files, &env) {
            c.issues.push(Issue {
                severity: Severity::Low,
                code: "targets/wasm-runtime-panic",
                message: format!("uses {what}, which compiles but panics or errors at run time"),
                short: format!("{what} panics"),
                fix: "gate the code with #[cfg(not(target_arch = \"wasm32\"))] or use a wasm-aware alternative".into(),
                location: Some((file, line)),
            });
        }
    }
    c
}

/// First active use of `std::thread::spawn/sleep` or `std::fs::` in library code.
fn runtime_panics(files: &[ModFile], env: &Env) -> Option<(String, String, usize)> {
    for mf in files {
        let code = &mf.file.code;
        let tests = crate::rustsrc::items::test_ranges(code);
        for i in 0..code.len().saturating_sub(4) {
            if !(code[i].ident("std") && code[i + 1].punct("::")) {
                continue;
            }
            let m = &code[i + 2];
            let what = match (m.text.as_str(), code[i + 4].text.as_str()) {
                ("thread", "spawn") | ("thread", "sleep") if code[i + 3].punct("::") => format!("std::thread::{}", code[i + 4].text),
                ("fs", _) if code[i + 3].punct("::") && code[i + 4].kind == Kind::Ident => "std::fs".to_string(),
                _ => continue,
            };
            if crate::rustsrc::items::in_ranges(&tests, i) || mf.cfg_at(i).eval(env) == Some(false) {
                continue;
            }
            return Some((what, mf.file.rel.clone(), code[i].line));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_status() {
        let mut c = Cell::default();
        assert_eq!(c.label(), "ok");
        c.notes.push("not in docs.rs targets".into());
        assert_eq!(c.status(), "?");
        c.issues.push(Issue { severity: Severity::High, code: "targets/needs-std", message: String::new(), short: "needs std".into(), fix: String::new(), location: None });
        assert_eq!(c.label(), "x needs std; not in docs.rs targets");
    }

    #[test]
    fn platform_menu() {
        let html = r#"<li class="pure-menu-item"><a href="/crate/x/1.0.0/target-redirect/i686-pc-windows-msvc/x/" class="pure-menu-link" data-fragment="retain" rel="nofollow">i686-pc-windows-msvc</a></li>
<li class="pure-menu-item"><a href="/x/1.0.0/x/" class="pure-menu-link current" rel="">
    x86_64-unknown-linux-gnu
</a></li><a href="/about" class="pure-menu-link">About docs.rs</a>"#;
        assert_eq!(parse_platforms(html), ["i686-pc-windows-msvc", "x86_64-unknown-linux-gnu"]);
        assert!(parse_platforms("").is_empty());
    }

    #[test]
    fn wasm_runtime_panics() {
        let dir = std::env::temp_dir();
        let src = "#[cfg(not(target_arch = \"wasm32\"))]\nfn a() { std::thread::spawn(|| ()); }\npub fn b() { let _ = std::fs::read(\"x\"); }\n";
        let file = crate::rustsrc::SourceFile::from_text(&dir, &dir.join("src/lib.rs"), src.into());
        let spans = fu::cfg_spans(&file.code);
        let files = vec![ModFile { file, cfg: vec![], spans }];
        let w = TargetCfg::parse("wasm32-unknown-unknown", "target_arch=\"wasm32\"\ntarget_os=\"unknown\"\n");
        let f = BTreeSet::new();
        let r = runtime_panics(&files, &Env { features: Some(&f), target: Some(&w) }).unwrap();
        assert_eq!((r.0.as_str(), r.2), ("std::fs", 3));
    }
}
