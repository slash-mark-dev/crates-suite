//! Compile Critical Path: The chain of crates that sets your build time, from cargo --timings data.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::perf_util as pu;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Timings;

const OPTS: &[Opt] = &[
    Opt::value("file", "HTML", "Analyze an existing cargo-timing.html instead of building"),
    Opt::flag("clean", "Build from an empty private target directory so every unit is measured"),
    Opt::flag("release", "Build with the release profile"),
    Opt::value("package", "NAME", "Build only this workspace package (cargo -p)"),
    Opt::value("features", "LIST", "Features to enable (comma-separated)"),
    Opt::flag("all-features", "Enable all features"),
    Opt::flag("no-default-features", "Disable default features"),
    Opt::value("top", "N", "Rows in the longest-units table (default 10)"),
    Opt::value("timeout", "SECS", "Time limit for the build (default 3600)"),
];

impl Tool for Timings {
    fn name(&self) -> &'static str {
        "timings"
    }
    fn title(&self) -> &'static str {
        "Compile Critical Path"
    }
    fn group(&self) -> Group {
        Group::Performance
    }
    fn summary(&self) -> &'static str {
        "The chain of crates that sets your build time, from cargo --timings data"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Runs `cargo build --timings` on the project (or reads an existing report with --file) and
reconstructs the build's critical path: the chain of compilation units where each one could only
start because the previous one finished (or, with pipelining, emitted its metadata). The data comes
from the UNIT_DATA table cargo embeds in target/cargo-timings/cargo-timing.html: per unit start,
duration, the frontend/codegen split (rmeta time) and which units it unblocked. Both the current
(`unblocked_units`, `sections`) and older (`unlocked_units`, `rmeta_time`) layouts are read.
Reports the wall time, how much of it the critical path covers, average parallelism, the path
itself and the longest units, with findings for your own crates that dominate the path (split
candidates: what to break into smaller crates that compile in parallel), proc-macro chains
(syn/quote/derive crates) and build scripts on the path, a dependency taking over 30% of the wall
time, codegen-heavy units and low parallelism. Without --clean only units cargo actually rebuilt are measured; --clean builds in
a private target directory under the cache (the project's own target/ is left alone). Timing
varies with machine load; compare runs on the same machine."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates timings --clean",
            "sm-crates timings --file target/cargo-timings/cargo-timing.html",
            "sm-crates timings --clean --release --top 5 --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo (no network unless dependencies must be downloaded)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let top: usize = args.parse_or("top", 10)?;
        let (html_path, subject, built) = match args.value("file") {
            Some(f) => (PathBuf::from(f), format!("timing report {f}"), None),
            None => {
                let (p, n) = build(ctx, args)?;
                (p, format!("project {}", ctx.project_root().display()), Some(n))
            }
        };
        let text = util::read_to_string_lossy(&html_path)
            .map_err(|e| Error::Env(format!("cannot read timing report {}: {e}", html_path.display())))?;
        let data = parse_html(&text)?;
        let mut rep = Report::new("timings", subject);
        let pkgs = project_packages(ctx);
        analyze(&data, &pkgs, top, &mut rep);
        if built.is_some() && !args.flag("clean") {
            rep.note("Only units cargo rebuilt in this run are measured; use --clean for a from-scratch build.");
        }
        rep.note(format!("Timing report: {}", html_path.display()));
        Ok(rep)
    }
}

/// Run `cargo build --timings` and return the report path and the cargo command shown.
fn build(ctx: &Ctx, args: &Args) -> Result<(PathBuf, String)> {
    pu::require_manifest(ctx)?;
    let timeout = pu::timeout(args, 3600)?;
    let mut cmd = pu::cargo(ctx);
    cmd.args(["build", "--timings"]);
    let mut shown = String::from("cargo build --timings");
    if args.flag("release") {
        cmd.arg("--release");
        shown.push_str(" --release");
    }
    if let Some(p) = args.value("package") {
        cmd.args(["-p", p]);
        shown.push_str(&format!(" -p {p}"));
    }
    for a in pu::feature_args(args) {
        shown.push(' ');
        shown.push_str(&a);
        cmd.arg(a);
    }
    pu::offline_flag(ctx, &mut cmd);
    let mut target: Option<PathBuf> = None;
    if args.flag("clean") {
        let t = pu::target_dir(ctx, "timings", Some("clean"))?;
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t)?;
        cmd.env("CARGO_TARGET_DIR", &t);
        target = Some(t);
    }
    pu::progress(args, &format!("running {shown}{}", if target.is_some() { " (fresh target dir)" } else { "" }));
    let out = util::run(&mut cmd, timeout)?;
    if out.timed_out {
        return Err(Error::Env(format!("{shown} did not finish within {}s (raise --timeout)", timeout.as_secs())));
    }
    let saved = pu::strip_ansi(&out.stderr)
        .lines()
        .find_map(|l| l.trim().strip_prefix("Timing report saved to ").map(|p| PathBuf::from(p.trim())));
    let path = match saved {
        Some(p) if p.is_file() => p,
        _ => {
            let dir = match &target {
                Some(t) => t.join("cargo-timings"),
                None => std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from).unwrap_or_else(|| ctx.project_root().join("target")).join("cargo-timings"),
            };
            newest_report(&dir).ok_or_else(|| {
                if out.success() {
                    Error::Env(format!("{shown} finished but wrote no timing report in {}", dir.display()))
                } else {
                    Error::Env(format!("{shown} failed: {}", pu::first_error(&out.stderr)))
                }
            })?
        }
    };
    if !out.success() {
        eprintln!("sm-crates: warning: the build failed ({}); analyzing the partial timing report", pu::first_error(&out.stderr));
    }
    Ok((path, shown))
}

/// The newest `cargo-timing-*.html` in a directory (falls back to `cargo-timing.html`).
fn newest_report(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("cargo-timing") && name.ends_with(".html")) {
            continue;
        }
        let t = e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(bt, _)| t > *bt) {
            best = Some((t, p));
        }
    }
    best.map(|(_, p)| p)
}

/// What the project's metadata says about package names (empty when there is no project).
#[derive(Debug, Clone, Default)]
pub struct Pkgs {
    /// Proc-macro packages.
    pub macros: BTreeSet<String>,
    /// Workspace members (your crates, which you can split).
    pub members: BTreeSet<String>,
}

fn project_packages(ctx: &Ctx) -> Pkgs {
    if !ctx.manifest_path().is_file() {
        return Pkgs::default();
    }
    let opts = crate::project::MetaOpts::default();
    match crate::project::Metadata::load(ctx, &opts) {
        Ok(m) => Pkgs {
            macros: m.packages.iter().filter(|p| p.is_proc_macro()).map(|p| p.name.clone()).collect(),
            members: m.members().iter().map(|p| p.name.clone()).collect(),
        },
        Err(_) => Pkgs::default(),
    }
}

/// One compilation unit from UNIT_DATA.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    pub i: u64,
    pub name: String,
    pub version: String,
    pub mode: String,
    /// cargo's target label: "" (lib), " build-script", " build-script (run)", ` app "bin"`...
    pub target: String,
    pub start: f64,
    pub duration: f64,
    /// Seconds after start when metadata (rmeta) was ready, if known.
    pub rmeta: Option<f64>,
    pub unblocked: Vec<u64>,
    pub unblocked_rmeta: Vec<u64>,
}

impl Unit {
    pub fn end(&self) -> f64 {
        self.start + self.duration
    }
    pub fn label(&self) -> String {
        format!("{} v{}{}", self.name, self.version, self.target.trim_end())
    }
    pub fn is_build_script_run(&self) -> bool {
        self.mode == "run-custom-build" || self.target.contains("build-script (run)")
    }
    pub fn is_build_script(&self) -> bool {
        self.is_build_script_run() || self.target.contains("build-script")
    }
    /// Codegen part (after metadata) in seconds.
    pub fn codegen(&self) -> f64 {
        match self.rmeta {
            Some(r) if r <= self.duration => self.duration - r,
            _ => 0.0,
        }
    }
}

/// Parsed timing report.
#[derive(Debug, Clone)]
pub struct TimingData {
    pub units: Vec<Unit>,
    /// Average number of active units over the build, from CONCURRENCY_DATA.
    pub avg_concurrency: Option<f64>,
    /// Units cargo found fresh (listed with zero duration by cargo 1.9x; not compiled).
    pub fresh: usize,
}

/// Find `const NAME = <json>;` in the HTML and parse the JSON value.
fn embedded_json(html: &str, name: &str) -> Option<Value> {
    let marker = format!("const {name} =");
    let pos = html.find(&marker)? + marker.len();
    let rest = &html[pos..];
    let mut it = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
    it.next()?.ok()
}

fn num(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

fn ids(v: &Value, keys: &[&str]) -> Vec<u64> {
    for k in keys {
        if let Some(a) = v.get(*k).and_then(Value::as_array) {
            return a.iter().filter_map(Value::as_u64).collect();
        }
    }
    Vec::new()
}

/// Parse a cargo-timing.html file.
pub fn parse_html(html: &str) -> Result<TimingData> {
    let units_v = embedded_json(html, "UNIT_DATA")
        .ok_or_else(|| Error::Parse("no UNIT_DATA table in the timing report (is this a cargo --timings HTML file?)".into()))?;
    let arr = units_v.as_array().ok_or_else(|| Error::Parse("UNIT_DATA is not an array".into()))?;
    let mut units = Vec::new();
    let mut fresh = 0;
    for (k, u) in arr.iter().enumerate() {
        let (Some(start), Some(duration)) = (num(u, "start"), num(u, "duration")) else { continue };
        if duration <= 0.0 && start <= 0.0 {
            // newer cargo lists fresh (up-to-date) units too, at t=0 with a zero duration
            // (a unit that really ran starts after cargo's own startup)
            fresh += 1;
            continue;
        }
        // rmeta: newer cargo records `sections` ([name, {start, end}]); older ones `rmeta_time`.
        let mut rmeta = num(u, "rmeta_time");
        if let Some(secs) = u.get("sections").and_then(Value::as_array) {
            for s in secs {
                let name = s.get(0).and_then(Value::as_str).unwrap_or("");
                if name == "frontend" {
                    if let Some(e) = s.get(1).and_then(|x| x.get("end")).and_then(Value::as_f64) {
                        rmeta = Some(e);
                    }
                }
            }
        }
        units.push(Unit {
            i: u.get("i").and_then(Value::as_u64).unwrap_or(k as u64),
            name: u.get("name").and_then(Value::as_str).unwrap_or("?").to_string(),
            version: u.get("version").and_then(Value::as_str).unwrap_or("").to_string(),
            mode: u.get("mode").and_then(Value::as_str).unwrap_or("").to_string(),
            target: u.get("target").and_then(Value::as_str).unwrap_or("").to_string(),
            start: start.max(0.0),
            duration: duration.max(0.0),
            rmeta,
            unblocked: ids(u, &["unblocked_units", "unlocked_units"]),
            unblocked_rmeta: ids(u, &["unblocked_rmeta_units", "unlocked_rmeta_units"]),
        });
    }
    let avg_concurrency = embedded_json(html, "CONCURRENCY_DATA").and_then(|c| avg_active(&c));
    Ok(TimingData { units, avg_concurrency, fresh })
}

/// Time-weighted average of `active` in CONCURRENCY_DATA (a step function over `t`).
fn avg_active(c: &Value) -> Option<f64> {
    let pts: Vec<(f64, f64)> = c.as_array()?.iter().filter_map(|p| Some((num(p, "t")?, num(p, "active")?))).collect();
    if pts.len() < 2 {
        return None;
    }
    let (t0, tn) = (pts[0].0, pts[pts.len() - 1].0);
    if tn <= t0 {
        return None;
    }
    let mut area = 0.0;
    for w in pts.windows(2) {
        area += w[0].1 * (w[1].0 - w[0].0).max(0.0);
    }
    Some(area / (tn - t0))
}

/// One step of the critical path.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    /// Index into `TimingData::units`.
    pub unit: usize,
    /// Only the unit's metadata (rmeta) was needed by the next step (pipelining).
    pub rmeta_only: bool,
    /// Time on the path: start .. end (end = rmeta time when rmeta_only).
    pub start: f64,
    pub end: f64,
    /// Idle time between the previous step's end and this unit's start (waiting for a job slot).
    pub wait: f64,
}

/// Walk back from the unit that finished last: each unit's blocker is the unit that
/// listed it in `unblocked_units` (needed the full unit) or `unblocked_rmeta_units`
/// (needed only its metadata). Returned in build order.
pub fn critical_path(units: &[Unit]) -> Vec<Step> {
    if units.is_empty() {
        return Vec::new();
    }
    let pos: HashMap<u64, usize> = units.iter().enumerate().map(|(k, u)| (u.i, k)).collect();
    // blocker[u] = (unit index, rmeta_only, time when it released u)
    let mut blocker: HashMap<usize, (usize, bool, f64)> = HashMap::new();
    for (k, x) in units.iter().enumerate() {
        let full_end = x.end();
        let rmeta_end = x.start + x.rmeta.unwrap_or(x.duration).min(x.duration);
        for (list, rmeta_only, t) in [(&x.unblocked, false, full_end), (&x.unblocked_rmeta, true, rmeta_end)] {
            for id in list {
                if let Some(&u) = pos.get(id) {
                    let replace = blocker.get(&u).is_none_or(|b| t > b.2);
                    if replace {
                        blocker.insert(u, (k, rmeta_only, t));
                    }
                }
            }
        }
    }
    let last = (0..units.len()).max_by(|&a, &b| units[a].end().partial_cmp(&units[b].end()).unwrap_or(std::cmp::Ordering::Equal)).unwrap_or(0);
    let mut steps = vec![Step { unit: last, rmeta_only: false, start: units[last].start, end: units[last].end(), wait: 0.0 }];
    let mut seen = BTreeSet::from([last]);
    let mut cur = last;
    while let Some(&(b, rmeta_only, released)) = blocker.get(&cur) {
        if !seen.insert(b) {
            break; // malformed data: cycle
        }
        if let Some(s) = steps.last_mut() {
            s.wait = (s.start - released).max(0.0);
        }
        let u = &units[b];
        steps.push(Step { unit: b, rmeta_only, start: u.start, end: released, wait: 0.0 });
        cur = b;
    }
    // the first unit's start is cargo's own startup (resolution, fingerprints), not a job-slot wait
    if let Some(s) = steps.last_mut() {
        s.wait = 0.0;
    }
    steps.reverse();
    steps
}

/// Crates that exist to implement proc macros (always on the path before a derive).
const MACRO_INFRA: &[&str] = &["syn", "quote", "proc-macro2", "synstructure", "darling", "darling_core", "darling_macro", "proc-macro-error", "proc-macro-error2", "proc-macro-error-attr", "proc-macro-error-attr2", "venial", "unsynn"];

fn is_macro_crate(name: &str, known: &BTreeSet<String>) -> bool {
    known.contains(name)
        || MACRO_INFRA.contains(&name)
        || ["_derive", "-derive", "_macros", "-macros", "_macro", "-macro", "-derive-internals", "_codegen", "-codegen"].iter().any(|s| name.ends_with(s))
}

fn secs(x: f64) -> String {
    format!("{x:.2}s")
}

fn analyze(data: &TimingData, pkgs: &Pkgs, top: usize, rep: &mut Report) {
    let known_macros = &pkgs.macros;
    let units = &data.units;
    if units.is_empty() {
        rep.summary("nothing was compiled (all units were fresh); run with --clean to measure a full build");
        rep.data = json!({"wall_secs": 0.0, "units": 0, "fresh_units": data.fresh, "critical_path": []});
        return;
    }
    // cargo measures every unit from the start of the build (t = 0)
    let wall = units.iter().map(Unit::end).fold(0.0, f64::max);
    let cpu: f64 = units.iter().map(|u| u.duration).sum();
    let parallelism = data.avg_concurrency.unwrap_or(if wall > 0.0 { cpu / wall } else { 0.0 });
    let path = critical_path(units);
    let on_path: f64 = path.iter().map(|s| s.end - s.start).sum();
    let waits: f64 = path.iter().map(|s| s.wait).sum();
    let share = |x: f64| if wall > 0.0 { x / wall * 100.0 } else { 0.0 };

    let mut t = Table::new("Critical path", &["#", "Unit", "Start", "End", "On path", "Share", "Note"]);
    for (k, s) in path.iter().enumerate() {
        let u = &units[s.unit];
        let mut note = Vec::new();
        if s.rmeta_only {
            note.push("metadata only (pipelined)".to_string());
        }
        if !u.is_build_script() {
            if MACRO_INFRA.contains(&u.name.as_str()) {
                note.push("proc-macro infrastructure".into());
            } else if is_macro_crate(&u.name, known_macros) {
                note.push("proc-macro".into());
            }
        }
        if u.is_build_script_run() {
            note.push("runs build script".into());
        } else if u.is_build_script() {
            note.push("compiles build script".into());
        }
        if s.wait > 0.05 {
            note.push(format!("waited {} for a job slot", secs(s.wait)));
        }
        t.row([
            (k + 1).to_string(),
            u.label(),
            secs(s.start),
            secs(s.end),
            secs(s.end - s.start),
            format!("{:.0}%", share(s.end - s.start)),
            note.join("; "),
        ]);
    }
    rep.table(t);
    let mut longest: Vec<&Unit> = units.iter().collect();
    longest.sort_by(|a, b| b.duration.partial_cmp(&a.duration).unwrap_or(std::cmp::Ordering::Equal));
    let mut t2 = Table::new(format!("Longest units (top {})", top.min(longest.len())), &["Unit", "Duration", "Frontend", "Codegen", "Share of wall", "On path"]);
    let path_units: BTreeSet<usize> = path.iter().map(|s| s.unit).collect();
    for u in longest.iter().take(top) {
        let k = units.iter().position(|x| std::ptr::eq(x, *u)).unwrap_or(0);
        t2.row([
            u.label(),
            secs(u.duration),
            u.rmeta.map(secs).unwrap_or_else(|| "-".into()),
            if u.rmeta.is_some() { secs(u.codegen()) } else { "-".into() },
            format!("{:.0}%", share(u.duration)),
            if path_units.contains(&k) { "yes".into() } else { String::new() },
        ]);
    }
    rep.table(t2);

    // ---- findings
    let path_secs = |pred: &dyn Fn(&Unit) -> bool| -> (f64, Vec<String>) {
        let mut total = 0.0;
        let mut names = Vec::new();
        for s in &path {
            let u = &units[s.unit];
            if pred(u) {
                total += s.end - s.start;
                if !names.contains(&u.name) {
                    names.push(u.name.clone());
                }
            }
        }
        (total, names)
    };
    let (macro_t, macro_names) = path_secs(&|u: &Unit| !u.is_build_script() && is_macro_crate(&u.name, known_macros));
    if macro_t > 0.0 && share(macro_t) >= 5.0 {
        let sev = if share(macro_t) >= 15.0 { Severity::Medium } else { Severity::Low };
        rep.finding(
            Finding::new(sev, "timings/proc-macro-on-path", format!("Proc-macro chain on the critical path: {} ({}, {:.0}% of the build)", macro_names.join(" → "), secs(macro_t), share(macro_t)))
                .detail("Every crate that uses a derive waits until syn/quote and the macro crate are fully compiled; nothing downstream can overlap with them.")
                .fix("Enable derive features only in the crates that need them (e.g. `serde = { version = \"1\", default-features = false }` plus `features = [\"derive\"]` in one crate), keep derive-heavy types in their own crate so the rest of the workspace compiles in parallel, check with `cargo tree -e features -i syn` which crate pulls in syn's \"full\" feature, and consider hand-written impls for a few types instead of a derive dependency"),
        );
    }
    let (bs_t, bs_names) = path_secs(&|u: &Unit| u.is_build_script());
    if bs_t > 0.0 && share(bs_t) >= 2.0 {
        let sev = if share(bs_t) >= 5.0 { Severity::Medium } else { Severity::Low };
        rep.finding(
            Finding::new(sev, "timings/build-script-on-path", format!("Build scripts on the critical path: {} ({}, {:.0}% of the build)", bs_names.join(", "), secs(bs_t), share(bs_t)))
                .detail("A build script must be compiled and run before its crate can start.")
                .fix("Check `cargo tree -i <crate>` for who needs it and whether a feature avoids the build step (prebuilt/system libraries instead of vendored C builds, `pkg-config`), make sure the script has `cargo:rerun-if-changed` lines so it does not rerun, and use sccache for C/C++ compilation"),
        );
    }
    // your own crates on the critical path: the ones worth splitting
    let mut split: Vec<&Step> = path
        .iter()
        .filter(|s| {
            let u = &units[s.unit];
            pkgs.members.contains(&u.name) && !u.is_build_script() && share(s.end - s.start) >= 15.0 && s.end - s.start >= 0.5
        })
        .collect();
    split.sort_by(|a, b| (b.end - b.start).partial_cmp(&(a.end - a.start)).unwrap_or(std::cmp::Ordering::Equal));
    let mut split_names = BTreeSet::new();
    for s in split {
        let u = &units[s.unit];
        split_names.insert(u.name.clone());
        let codegen_heavy = u.rmeta.is_some() && u.codegen() > 0.5 * u.duration;
        rep.finding(
            Finding::new(Severity::Medium, "timings/split-candidate", format!("Your crate {} is {:.0}% of the critical path's time ({}); split it", u.label(), share(s.end - s.start), secs(s.end - s.start)))
                .krate(&u.name, Some(&u.version))
                .detail(if codegen_heavy {
                    format!("{} of it is code generation (frontend {}), so generic code instantiated here is the bigger cost", secs(u.codegen()), secs(u.duration - u.codegen()))
                } else {
                    "Nothing else can run while it compiles: everything after it on the path waits for it.".to_string()
                })
                .fix(if codegen_heavy {
                    "Move independent modules into separate workspace crates that compile in parallel, and find the generic functions driving codegen with `sm-crates mono`"
                } else {
                    "Move independent modules (and the types they share) into separate workspace crates so they compile in parallel; keep the crates downstream of the split thin"
                }),
        );
    }
    for u in units {
        if wall >= 1.0 && share(u.duration) > 30.0 && !split_names.contains(&u.name) {
            rep.finding(
                Finding::new(Severity::Medium, "timings/dominant-crate", format!("{} takes {:.0}% of the wall time ({})", u.label(), share(u.duration), secs(u.duration)))
                    .krate(&u.name, Some(&u.version))
                    .detail(match u.rmeta {
                        Some(_) => format!("frontend {} / codegen {}", secs(u.duration - u.codegen()), secs(u.codegen())),
                        None => "no frontend/codegen split recorded".into(),
                    })
                    .fix("If it is your crate: split it into smaller crates that compile in parallel and reduce generic instantiations (`sm-crates mono`). If it is a dependency: check for heavy optional features you can turn off, and in dev builds look at `[profile.dev.package.\"*\"] opt-level` overrides that make dependencies slow to compile"),
            );
        }
    }
    let mut heavy: Vec<&Unit> = units.iter().filter(|u| u.rmeta.is_some() && u.codegen() >= 2.0 && u.codegen() > 0.6 * u.duration && share(u.codegen()) >= 10.0).collect();
    heavy.sort_by(|a, b| b.codegen().partial_cmp(&a.codegen()).unwrap_or(std::cmp::Ordering::Equal));
    for u in heavy.iter().take(5) {
        rep.finding(
            Finding::new(Severity::Low, "timings/codegen-heavy", format!("{} spends {} ({:.0}% of its time) in code generation", u.label(), secs(u.codegen()), u.codegen() / u.duration.max(1e-9) * 100.0))
                .krate(&u.name, Some(&u.version))
                .fix("Code generation scales with monomorphized generic code: inspect it with `sm-crates mono`, move work behind non-generic inner functions, and keep `codegen-units` > 1 and `opt-level` low for dev builds"),
        );
    }
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    // under half the machine's cores (at most 8 counted) busy on average
    if wall >= 5.0 && cpus >= 2 && parallelism < cpus.min(8) as f64 * 0.5 && units.len() >= 4 {
        rep.finding(
            Finding::new(Severity::Info, "timings/low-parallelism", format!("Average parallelism is {parallelism:.1} jobs on a {cpus}-CPU machine"))
                .detail(format!("The critical path covers {:.0}% of the wall time.", share(on_path)))
                .fix("The build is a long serial chain; shortening the critical path (above) matters more than adding cores"),
        );
    }

    let first = path.first().map(|s| units[s.unit].name.clone()).unwrap_or_default();
    let lastn = path.last().map(|s| units[s.unit].name.clone()).unwrap_or_default();
    rep.summary(format!(
        "{} units in {} wall time; critical path of {} units ({first} → {lastn}) covers {:.0}% of it; average parallelism {parallelism:.1}",
        units.len(),
        util::human_duration(wall),
        path.len(),
        share(on_path)
    ));
    if data.fresh > 0 {
        rep.note(format!("{} unit(s) were already up to date and are not part of this measurement.", data.fresh));
    }
    if waits > 0.1 {
        rep.note(format!("{} of the path is time units waited for a free job slot (-j / CPU count {cpus}).", secs(waits)));
    }
    rep.data = json!({
        "wall_secs": pu::round(wall, 3),
        "cpu_secs": pu::round(cpu, 3),
        "units": units.len(),
        "fresh_units": data.fresh,
        "parallelism": pu::round(parallelism, 2),
        "critical_path_secs": pu::round(on_path, 3),
        "critical_path_share": pu::round(share(on_path), 1),
        "critical_path": path.iter().map(|s| {
            let u = &units[s.unit];
            json!({"name": u.name, "version": u.version, "target": u.target.trim(), "mode": u.mode, "start": pu::round(s.start, 3), "end": pu::round(s.end, 3), "rmeta_only": s.rmeta_only, "wait": pu::round(s.wait, 3)})
        }).collect::<Vec<_>>(),
        "longest": longest.iter().take(top).map(|u| json!({"name": u.name, "version": u.version, "target": u.target.trim(), "duration": u.duration, "rmeta": u.rmeta, "codegen": pu::round(u.codegen(), 3)})).collect::<Vec<_>>(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape of cargo 1.97's report (trimmed): `unblocked_*` and `sections`.
    const NEW: &str = r#"<script>
const UNIT_DATA = [
  {"i": 0, "name": "proc-macro2", "version": "1.0.0", "mode": "todo", "target": "", "features": [], "start": 0.5, "duration": 1.0,
   "unblocked_units": [], "unblocked_rmeta_units": [1], "sections": [["frontend", {"start": 0.0, "end": 0.6}], ["codegen", {"start": 0.6, "end": 1.0}]]},
  {"i": 1, "name": "syn", "version": "2.0.0", "mode": "todo", "target": "", "features": [], "start": 1.1, "duration": 3.0,
   "unblocked_units": [2], "unblocked_rmeta_units": [], "sections": [["frontend", {"start": 0.0, "end": 2.0}], ["codegen", {"start": 2.0, "end": 3.0}]]},
  {"i": 2, "name": "serde_derive", "version": "1.0.0", "mode": "todo", "target": "", "features": [], "start": 4.1, "duration": 2.0,
   "unblocked_units": [3], "unblocked_rmeta_units": [], "sections": null},
  {"i": 3, "name": "app", "version": "0.1.0", "mode": "todo", "target": " app \"bin\"", "features": [], "start": 6.2, "duration": 0.5,
   "unblocked_units": [], "unblocked_rmeta_units": [], "sections": null},
  {"i": 4, "name": "libc", "version": "0.2.0", "mode": "run-custom-build", "target": " build-script (run)", "features": [], "start": 0.0, "duration": 0.2,
   "unblocked_units": [], "unblocked_rmeta_units": [], "sections": null}
];
const CONCURRENCY_DATA = [{"t": 0.0, "active": 2, "waiting": 0, "inactive": 3}, {"t": 6.7, "active": 0, "waiting": 0, "inactive": 0}];
const CPU_USAGE = [];
</script>"#;

    /// Older cargo: `unlocked_*` and `rmeta_time`.
    const OLD: &str = r#"const UNIT_DATA = [{"i":0,"name":"a","version":"1.0.0","mode":"todo","target":"","start":0.0,"duration":1.0,"rmeta_time":0.5,"unlocked_units":[],"unlocked_rmeta_units":[1]},
{"i":1,"name":"b","version":"1.0.0","mode":"todo","target":"","start":0.6,"duration":1.0,"rmeta_time":0.9,"unlocked_units":[],"unlocked_rmeta_units":[]}];"#;

    #[test]
    fn parses_new_layout_and_walks_path() {
        let d = parse_html(NEW).unwrap();
        assert_eq!(d.units.len(), 5);
        assert_eq!(d.units[0].rmeta, Some(0.6));
        assert!(d.units[4].is_build_script_run());
        assert_eq!(d.avg_concurrency, Some(2.0));
        let p = critical_path(&d.units);
        let names: Vec<&str> = p.iter().map(|s| d.units[s.unit].name.as_str()).collect();
        assert_eq!(names, ["proc-macro2", "syn", "serde_derive", "app"]);
        assert!(p[0].rmeta_only);
        assert!((p[0].end - 1.1).abs() < 1e-9, "rmeta end = start + frontend");
        assert!((p[3].wait - 0.1).abs() < 1e-9);
    }

    #[test]
    fn parses_old_layout() {
        let d = parse_html(OLD).unwrap();
        assert_eq!(d.units[0].rmeta, Some(0.5));
        let p = critical_path(&d.units);
        // b ends last at 1.6; a released it at its rmeta (0.5)
        assert_eq!(p.len(), 2);
        assert_eq!(d.units[p[0].unit].name, "a");
        assert!(p[0].rmeta_only);
    }

    #[test]
    fn findings_from_synthetic_build() {
        let d = parse_html(NEW).unwrap();
        let mut rep = Report::new("timings", "x");
        analyze(&d, &Pkgs::default(), 10, &mut rep);
        let codes: Vec<&str> = rep.findings.iter().map(|f| f.code.as_str()).collect();
        assert!(codes.contains(&"timings/proc-macro-on-path"), "{codes:?}");
        assert!(codes.contains(&"timings/dominant-crate"), "{codes:?}");
        assert_eq!(rep.data["critical_path"].as_array().unwrap().len(), 4);
        assert!(rep.summary.as_deref().unwrap().contains("critical path of 4 units"));
    }

    #[test]
    fn own_crate_on_the_path_is_a_split_candidate() {
        let d = parse_html(NEW).unwrap();
        let mut rep = Report::new("timings", "x");
        let pkgs = Pkgs { members: BTreeSet::from(["syn".to_string()]), ..Default::default() };
        analyze(&d, &pkgs, 10, &mut rep);
        let split: Vec<&Finding> = rep.findings.iter().filter(|f| f.code == "timings/split-candidate").collect();
        assert_eq!(split.len(), 1);
        assert_eq!(split[0].krate.as_deref(), Some("syn"));
        // not reported twice as a dominant crate
        assert!(!rep.findings.iter().any(|f| f.code == "timings/dominant-crate" && f.krate.as_deref() == Some("syn")));
    }

    #[test]
    fn rejects_non_report() {
        assert!(parse_html("<html>nothing</html>").is_err());
        let d = parse_html(r#"const UNIT_DATA = [{"i":0,"name":"a","version":"1.0.0","target":"","start":0.0,"duration":0.0,"unblocked_units":[]}];"#).unwrap();
        assert_eq!((d.units.len(), d.fresh), (0, 1));
        let mut rep = Report::new("timings", "x");
        analyze(&d, &Pkgs::default(), 10, &mut rep);
        assert!(rep.summary.unwrap().contains("nothing was compiled"));
    }
}
