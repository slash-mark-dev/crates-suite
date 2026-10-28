//! Future-Breakage Forecast: Future-incompatibility warnings and upcoming-toolchain errors in your dependency tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::project::{MetaOpts, Metadata};
use crate::registry::index;
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::perf_util::{self as pu, Diag};
use crate::tools::{Group, Tool};
use crate::util;

pub struct FutureCompat;

const OPTS: &[Opt] = &[
    Opt::flag("all-targets", "Check tests, examples and benches too (cargo check --all-targets)"),
    Opt::value("features", "LIST", "Features to enable (comma-separated)"),
    Opt::flag("all-features", "Enable all features"),
    Opt::flag("no-default-features", "Disable default features"),
    Opt::flag("verify", "For each fixable dependency, run `cargo update -p` in a temporary copy of the project and re-check"),
    Opt::flag("beta", "Also check with the beta toolchain and report new errors/warnings (needs `rustup toolchain install beta`)"),
    Opt::flag("nightly", "Also check with the nightly toolchain and report new errors/warnings"),
    Opt::value("crater", "EXPERIMENT", "Crater run to compare against (default: the next release's beta run, e.g. beta-1.98-1)"),
    Opt::flag("no-crater", "Do not fetch crater results"),
    Opt::value("timeout", "SECS", "Time limit per cargo run (default 1800)"),
];

/// Where crater publishes its reports (`SM_CRATER_URL` overrides it).
fn crater_base() -> String {
    std::env::var("SM_CRATER_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| v.trim_end_matches('/').to_string())
        .unwrap_or_else(|| "https://crater-reports.s3.amazonaws.com".to_string())
}

impl Tool for FutureCompat {
    fn name(&self) -> &'static str {
        "futurecompat"
    }
    fn title(&self) -> &'static str {
        "Future-Breakage Forecast"
    }
    fn group(&self) -> Group {
        Group::Api
    }
    fn summary(&self) -> &'static str {
        "Future-incompatibility warnings and upcoming-toolchain errors in your dependency tree"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Finds code in your project and its dependencies that a future Rust release will reject. Runs
`cargo check --future-incompat-report --message-format json` on the workspace (in a private target
directory under the cache) and reads the report cargo stores in .future-incompat-report.json: for
every package, each future-incompatibility lint with its message, location, tracking issue and
when it becomes an error. Lints in your own crates come from the JSON diagnostics (exact lint name
and location) and are high; in dependencies they are medium, or high when rustc names the edition
or release that turns them into errors. For each affected dependency the live crates.io index is
checked: if a newer semver-compatible release exists the fix is `cargo update -p NAME`, otherwise
the newest major. --verify proves it: in a temporary copy of the project it runs the update and
re-checks, so the original tree and lock file are untouched. Current stable/beta versions and the
next stable's expected date (6-week cadence) come from static.rust-lang.org channel manifests.
Crater: the Rust release team builds and tests every crate on crates.io with each upcoming
release (the beta run `beta-1.NN-1`, or any experiment named with --crater). Its list of regressed
crates (crater-reports.s3.amazonaws.com/EXPERIMENT/retry-regressed-list.txt) is matched against
your locked dependencies: a dependency in it failed to build or test with that compiler (the list
also holds failures crater considers spurious, so a match is medium and the report has the
details). Crater tests each crate's newest release, so a match on an older locked version is low.
When the report is not published yet or cannot be reached this is a note, not an error.
--beta/--nightly re-check with those toolchains (if installed) and report errors and warnings in
your code that stable does not produce. Limits: dependencies' ordinary warnings are capped by cargo
and not shown; a lint only appears for code that is actually compiled with your features/targets."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates futurecompat",
            "sm-crates futurecompat --verify --all-targets",
            "sm-crates futurecompat --crater beta-1.98-1 --json",
            "sm-crates futurecompat --beta --no-crater",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo; network for the crates.io index, crater reports and Rust release data; beta/nightly toolchains for --beta/--nightly"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        pu::require_manifest(ctx)?;
        let timeout = pu::timeout(args, 1800)?;
        let meta = Metadata::load(ctx, &MetaOpts::default())?;
        let members: BTreeSet<String> = meta.members().iter().map(|p| p.spec()).collect();
        let member_ids: BTreeSet<String> = meta.workspace_members.iter().cloned().collect();
        let mut rep = Report::new("futurecompat", format!("project {}", meta.members().iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")));

        let target = pu::target_dir(ctx, "futurecompat", None)?;
        pu::progress(args, "running cargo check --future-incompat-report");
        let stable = check(ctx, args, ctx.project_root(), &target, None, timeout)?;
        if stable.success == Some(false) {
            rep.note(format!("cargo check failed on stable: {}", stable.first_error));
        }

        // own code: exact lints from JSON diagnostics
        let own: Vec<&Diag> = stable.diags.iter().filter(|d| member_ids.contains(&d.package_id) && d.is_future_incompat()).collect();
        // per package from the stored report
        let mut items: Vec<(String, Vec<Item>)> = stable.report.iter().map(|(k, v)| (k.clone(), parse_package_text(v))).collect();
        items.retain(|(spec, _)| !members.contains(spec) || own.is_empty());
        // name lints in dependency items using what we know
        let known: BTreeMap<String, String> = own.iter().map(|d| (d.message.clone(), d.code.clone())).collect();
        for (_, its) in &mut items {
            for it in its.iter_mut() {
                if it.lint.is_none() {
                    it.lint = known.get(&it.message).cloned().or_else(|| lint_for(&it.message, it.issue));
                }
            }
        }

        let mut t = Table::new("Future-incompatibility warnings", &["Package", "Lint", "Becomes an error", "Location", "Fix"]);
        let mut data_items = Vec::new();
        for d in &own {
            let when = d.children.iter().find(|c| c.contains("previously accepted")).map(|c| timeline(c)).unwrap_or_else(|| "in a future release".into());
            let (name, version) = pu::package_id_name_version(&d.package_id);
            t.row([format!("{name}@{version} (your code)"), d.code.clone(), when.clone(), d.location(), "change your code".into()]);
            let mut f = Finding::new(Severity::High, "futurecompat/own-code", format!("{}: {} ({})", d.code, d.message, when)).krate(&name, Some(&version)).fix(fix_hint(&d.code, issue_of(&d.children.join("\n"))));
            if let (Some(file), line) = (&d.file, d.line) {
                f = f.at(file.clone(), line);
            }
            f = f.detail(d.children.iter().filter(|c| c.contains("issue #") || c.contains("previously accepted")).cloned().collect::<Vec<_>>().join("\n"));
            rep.finding(f);
            data_items.push(json!({"package": name, "version": version, "own_code": true, "lint": d.code, "message": d.message, "location": d.location(), "becomes_error": when}));
        }

        let deps: Vec<(String, String, Vec<Item>)> = items
            .into_iter()
            .filter(|(_, its)| !its.is_empty())
            .map(|(spec, its)| {
                let (n, v) = spec.split_once('@').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or((spec.clone(), String::new()));
                (n, v, its)
            })
            .collect();
        let names: Vec<String> = deps.iter().filter(|(n, v, _)| !members.contains(&format!("{n}@{v}"))).map(|(n, _, _)| n.clone()).collect();
        let mut index_data: BTreeMap<String, Result<Vec<index::IndexVersion>>> = BTreeMap::new();
        for n in &names {
            if !index_data.contains_key(n) {
                index_data.insert(n.clone(), index::versions(ctx, n));
            }
        }
        let mut unreachable = Vec::new();
        for (name, version, its) in &deps {
            let own_member = members.contains(&format!("{name}@{version}"));
            let upd = if own_member {
                Update::Own
            } else {
                match index_data.get(name) {
                    Some(Ok(vs)) => suggest_update(Some(vs), version),
                    Some(Err(Error::NotFound(_))) => Update::NotPublished,
                    _ => Update::Unknown,
                }
            };
            if matches!(upd, Update::Unknown) {
                unreachable.push(name.clone());
            }
            let verified = if args.flag("verify") && matches!(upd, Update::Compatible(_)) {
                pu::progress(args, &format!("verifying `cargo update -p {name}@{version}` in a temporary copy"));
                Some(verify(ctx, args, &meta.workspace_root, name, version, &target, timeout))
            } else {
                None
            };
            for it in its {
                let when = it.timeline.clone().unwrap_or_else(|| "in a future release".into());
                let lint = it.lint.clone().unwrap_or_else(|| it.issue.map(|n| format!("issue #{n}")).unwrap_or_else(|| "unknown".into()));
                t.row([format!("{name}@{version}{}", if own_member { " (your code)" } else { "" }), lint.clone(), when.clone(), it.location.clone().unwrap_or_default(), upd.short()]);
                let sev = if own_member || is_specific(&when) { Severity::High } else { Severity::Medium };
                let mut f = Finding::new(sev, if own_member { "futurecompat/own-code" } else { "futurecompat/dependency" }, format!("{lint}: {} ({when})", it.message))
                    .krate(name, Some(version))
                    .fix(upd.fix(name, version));
                let mut detail = Vec::new();
                if let Some(l) = &it.location {
                    detail.push(format!("at {l}"));
                }
                if let Some(n) = it.issue {
                    detail.push(format!("tracking issue: https://github.com/rust-lang/rust/issues/{n}"));
                }
                if let Some(v) = &verified {
                    detail.push(v.text());
                }
                f = f.detail(detail.join("\n"));
                rep.finding(f);
                data_items.push(json!({
                    "package": name, "version": version, "own_code": own_member, "lint": it.lint, "issue": it.issue, "message": it.message,
                    "location": it.location, "becomes_error": when, "update": upd.json(), "verified": verified.as_ref().map(|v| v.json()),
                }));
            }
        }
        rep.table(t);
        if !unreachable.is_empty() {
            rep.note(format!("newer versions could not be looked up (index unreachable or offline) for: {}", unreachable.join(", ")));
        }

        // Rust release channels
        let channels = release_channels(ctx);
        let mut ct = Table::new("Rust release channels", &["Channel", "Version", "Date"]);
        for (ch, info) in &channels.list {
            ct.row([ch.clone(), info.0.clone(), info.1.clone()]);
        }
        if let Some((v, d)) = &channels.next_stable {
            ct.row(["next stable".to_string(), v.clone(), format!("expected {d}")]);
        }
        if let Some(local) = local_rustc() {
            ct.row(["installed".to_string(), local, String::new()]);
        }
        rep.table(ct);
        for n in &channels.notes {
            rep.note(n.clone());
        }

        // crater: which locked dependencies regressed in the upcoming release's run
        let crater_data = if args.flag("no-crater") {
            json!({"status": "skipped"})
        } else {
            let experiment = match args.value("crater") {
                Some(e) => Some(e.to_string()),
                None => default_experiment(&channels),
            };
            match experiment {
                None => {
                    rep.note("crater skipped: the upcoming release is unknown (no beta channel data and `rustc -V` failed); name a run with --crater EXPERIMENT");
                    json!({"status": "unknown-experiment"})
                }
                Some(ex) => crater_section(ctx, &meta, args.flag("all-targets"), &ex, &mut index_data, &mut rep),
            }
        };

        // beta / nightly
        let mut channel_data = Vec::new();
        for ch in ["beta", "nightly"] {
            if !args.flag(ch) {
                continue;
            }
            if !pu::has_toolchain(ch) {
                rep.note(format!("--{ch} skipped: the {ch} toolchain is not installed. Install it with `rustup toolchain install {ch}`."));
                continue;
            }
            pu::progress(args, &format!("running cargo +{ch} check"));
            let ctarget = pu::target_dir(ctx, "futurecompat", Some(ch))?;
            let other = check(ctx, args, ctx.project_root(), &ctarget, Some(ch), timeout)?;
            let fresh = new_diagnostics(&stable.diags, &other.diags, &member_ids);
            let mut ft = Table::new(format!("New on {ch}"), &["Level", "Code", "Message", "Location"]);
            for d in &fresh {
                ft.row([d.level.clone(), d.code.clone(), d.message.clone(), d.location()]);
                let (name, version) = pu::package_id_name_version(&d.package_id);
                let is_err = d.level.starts_with("error");
                let mut f = Finding::new(
                    if is_err { Severity::High } else { Severity::Low },
                    if is_err { format!("futurecompat/breaks-on-{ch}") } else { format!("futurecompat/new-warning-{ch}") },
                    format!("{} on {ch}: {}{}", if is_err { "Error" } else { "New warning" }, if d.code.is_empty() { String::new() } else { format!("{}: ", d.code) }, d.message),
                )
                .krate(&name, Some(&version))
                .fix(if is_err { format!("Fix this before the next {ch} reaches stable; reproduce with `cargo +{ch} check`") } else { format!("Review with `cargo +{ch} check`; new lints often become errors or defaults later") });
                if let Some(file) = &d.file {
                    f = f.at(file.clone(), d.line);
                }
                rep.finding(f);
            }
            if other.success == Some(false) && stable.success != Some(false) && !fresh.iter().any(|d| d.level.starts_with("error")) {
                rep.finding(
                    Finding::new(Severity::High, format!("futurecompat/breaks-on-{ch}"), format!("The project does not build on {ch}: {}", other.first_error))
                        .fix(format!("Reproduce with `cargo +{ch} check`")),
                );
            }
            rep.table(ft);
            channel_data.push(json!({"channel": ch, "success": other.success, "new": fresh.iter().map(|d| json!({"level": d.level, "code": d.code, "message": d.message, "location": d.location(), "package_id": d.package_id})).collect::<Vec<_>>()}));
        }

        // the build already fails on the current stable compiler (e.g. a dependency hit a lint that
        // has since become a hard error); own-code lints that are deny-by-default are reported above
        if stable.success == Some(false) && !rep.findings.iter().any(|f| f.code == "futurecompat/own-code") {
            let errs: Vec<&Diag> = stable.diags.iter().filter(|d| d.level.starts_with("error")).collect();
            let pkgs: BTreeSet<String> = errs.iter().map(|d| pu::package_id_name_version(&d.package_id)).map(|(n, v)| format!("{n}@{v}")).collect();
            let mut f = Finding::new(
                Severity::High,
                "futurecompat/build-fails",
                if pkgs.is_empty() { format!("The project does not build on the installed stable toolchain: {}", stable.first_error) } else { format!("Does not build on the installed stable toolchain: errors in {}", pkgs.iter().cloned().collect::<Vec<_>>().join(", ")) },
            )
            .fix("A dependency that no longer compiles has usually hit a former future-incompatibility warning that is now an error: update it (`cargo update -p NAME`, or a newer major), or replace it");
            let mut detail: Vec<String> = errs.iter().map(|d| format!("{} {}{}", pu::package_id_name_version(&d.package_id).0, if d.code.is_empty() { String::new() } else { format!("[{}] ", d.code) }, d.message)).collect();
            let mut seen = BTreeSet::new();
            detail.retain(|l| seen.insert(l.clone()));
            detail.truncate(10);
            if !detail.is_empty() {
                f = f.detail(detail.join("\n"));
            }
            if let [one] = pkgs.iter().collect::<Vec<_>>().as_slice() {
                if let Some((n, v)) = one.split_once('@') {
                    f = f.krate(n, Some(v));
                }
            }
            rep.finding(f);
        }
        let own_n = rep.findings.iter().filter(|f| f.code == "futurecompat/own-code").count();
        let dep_n = rep.findings.iter().filter(|f| f.code == "futurecompat/dependency").count();
        let crater_n = rep.findings.iter().filter(|f| f.code == "futurecompat/crater-regression").count();
        let pk: BTreeSet<&str> = deps.iter().filter(|(n, v, _)| !members.contains(&format!("{n}@{v}"))).map(|(n, _, _)| n.as_str()).collect();
        let mut summary = if own_n + dep_n == 0 {
            "no future-incompatibility warnings".to_string()
        } else {
            format!("{own_n} future-incompatibility warning(s) in your code, {dep_n} in {} dependency(ies)", pk.len())
        };
        match crater_data.get("experiment").and_then(Value::as_str) {
            Some(ex) if crater_data["status"] == "ok" => summary.push_str(&format!("; {crater_n} dependency(ies) regressed in crater run {ex}")),
            _ => {}
        }
        if own_n + dep_n + crater_n == 0 {
            summary.push_str(": nothing in the build is known to break");
        }
        // never present a partial check as a clean one
        if stable.success == Some(false) {
            summary.push_str("; cargo check failed, so only the code that compiled was checked");
        }
        if matches!(crater_data["status"].as_str(), Some("unavailable" | "not-found" | "unknown-experiment")) {
            summary.push_str("; crater results could not be checked (see notes)");
        }
        rep.summary(summary);
        rep.data = json!({
            "items": data_items,
            "crater": crater_data,
            "build_success": stable.success,
            "channels": channels.list.iter().map(|(c, (v, d))| json!({"channel": c, "version": v, "date": d})).collect::<Vec<_>>(),
            "next_stable": channels.next_stable.as_ref().map(|(v, d)| json!({"version": v, "expected": d})),
            "toolchains": channel_data,
        });
        Ok(rep)
    }
}

struct CheckRun {
    diags: Vec<Diag>,
    success: Option<bool>,
    first_error: String,
    /// The new future-incompat report from this run: package spec -> rendered text.
    report: BTreeMap<String, String>,
}

fn report_file(target: &Path) -> std::path::PathBuf {
    target.join(".future-incompat-report.json")
}

/// The report id cargo printed for this run (`cargo report future-incompatibilities --id N`).
/// cargo reuses an id when the report is unchanged, so the id must come from this run's output.
pub fn report_id(stderr: &str) -> Option<u64> {
    let t = pu::strip_ansi(stderr);
    let rest = t.split("future-incompatibilities --id ").last().filter(|_| t.contains("future-incompatibilities --id "))?;
    // the summary note comes last; a per-package line may also carry `--package`
    rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
}

/// The report with this id in cargo's stored file: package spec -> text (ANSI removed).
pub fn read_report(text: &str, id: u64) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(v) = serde_json::from_str::<Value>(text) else { return out };
    let reports: Vec<&Value> = v.get("reports").and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    if let Some(r) = reports.iter().find(|r| r.get("id").and_then(Value::as_u64) == Some(id)) {
        if let Some(pp) = r.get("per_package").and_then(Value::as_object) {
            for (k, t) in pp {
                out.insert(k.clone(), pu::strip_ansi(t.as_str().unwrap_or("")));
            }
        }
    }
    out
}

fn check(ctx: &Ctx, args: &Args, dir: &Path, target: &Path, toolchain: Option<&str>, timeout: Duration) -> Result<CheckRun> {
    let mut cmd = pu::cargo(ctx);
    cmd.current_dir(dir);
    if let Some(t) = toolchain {
        cmd.arg(format!("+{t}"));
    }
    cmd.args(["check", "--workspace", "--message-format", "json"]);
    if toolchain.is_none() {
        cmd.arg("--future-incompat-report");
    }
    if args.flag("all-targets") {
        cmd.arg("--all-targets");
    }
    cmd.args(pu::feature_args(args));
    pu::offline_flag(ctx, &mut cmd);
    cmd.env("CARGO_TARGET_DIR", target);
    let out = util::run(&mut cmd, timeout)?;
    if out.timed_out {
        return Err(Error::Env(format!("cargo check did not finish within {}s (raise --timeout)", timeout.as_secs())));
    }
    let msgs = pu::messages(&out.stdout);
    if msgs.is_empty() && !out.success() {
        return Err(Error::Env(format!("cargo check{} failed: {}", toolchain.map(|t| format!(" (+{t})")).unwrap_or_default(), pu::first_error(&out.stderr))));
    }
    let report = match (toolchain, report_id(&out.stderr)) {
        (None, Some(id)) => std::fs::read_to_string(report_file(target)).map(|t| read_report(&t, id)).unwrap_or_default(),
        _ => BTreeMap::new(),
    };
    Ok(CheckRun { diags: pu::diagnostics(&msgs), success: pu::build_succeeded(&msgs).or(Some(out.success())), first_error: pu::first_error(&out.stderr), report })
}

/// One future-incompatibility warning from cargo's per-package report text.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub message: String,
    pub lint: Option<String>,
    pub location: Option<String>,
    pub issue: Option<u64>,
    /// e.g. "in a future release", "in Rust 2024 and in a future release in all editions"
    pub timeline: Option<String>,
}

/// Parse "The package `x v1.0.0` currently triggers the following future incompatibility lints:\n> warning: ..."
pub fn parse_package_text(text: &str) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::new();
    for raw in text.lines() {
        let Some(l) = raw.strip_prefix('>') else { continue };
        let l = l.strip_prefix(' ').unwrap_or(l);
        let head = ["warning: ", "error: "].iter().find_map(|p| l.strip_prefix(p)).or_else(|| {
            // `warning[E0000]: msg`
            let (lvl, rest) = l.split_once('[')?;
            if lvl == "warning" || lvl == "error" { rest.split_once("]: ").map(|x| x.1) } else { None }
        });
        if let Some(msg) = head {
            out.push(Item { message: msg.trim().to_string(), lint: None, location: None, issue: None, timeline: None });
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        let t = l.trim();
        if cur.location.is_none() {
            if let Some(loc) = t.strip_prefix("--> ") {
                cur.location = Some(loc.trim().to_string());
            }
        }
        if t.contains("previously accepted by the compiler") && cur.timeline.is_none() {
            cur.timeline = Some(timeline(t));
        }
        if cur.issue.is_none() {
            cur.issue = issue_of(t);
        }
        if cur.lint.is_none() {
            for p in ["#[warn(", "#[deny(", "#[forbid("] {
                if let Some(rest) = t.split(p).nth(1) {
                    if let Some(name) = rest.split(')').next() {
                        cur.lint = Some(name.to_string());
                    }
                }
            }
        }
    }
    out
}

/// "... it will become a hard error in Rust 2024 and in a future release in all editions!" ->
/// "in Rust 2024 and in a future release in all editions".
fn timeline(t: &str) -> String {
    for key in ["will become a hard error ", "will change its meaning ", "will be rejected "] {
        if let Some(rest) = t.split(key).nth(1) {
            return rest.trim().trim_end_matches(['!', '.']).to_string();
        }
    }
    "in a future release".into()
}

/// Whether the timeline names a specific edition or release.
fn is_specific(when: &str) -> bool {
    when.contains("Rust 20") || when.contains("Rust 1.") || when.contains("edition 20")
}

fn issue_of(t: &str) -> Option<u64> {
    let rest = t.split("issue #").nth(1)?;
    rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
}

/// Lint names for well-known future-incompatibility messages (cargo's report omits them).
fn lint_for(message: &str, issue: Option<u64>) -> Option<String> {
    const BY_MESSAGE: &[(&str, &str)] = &[
        ("trailing semicolon in macro used in expression position", "semicolon_in_expressions_from_macros"),
        ("this function depends on never type fallback being `()`", "dependency_on_unit_never_type_fallback"),
        ("never type fallback affects this", "never_type_fallback_flowing_into_unsafe"),
        ("cannot specify lifetime arguments explicitly if late bound lifetime parameters are present", "late_bound_lifetime_arguments"),
        ("defaults for type parameters are only allowed in", "invalid_type_param_default"),
        ("creating a shared reference to mutable static", "static_mut_refs"),
        ("creating a mutable reference to mutable static", "static_mut_refs"),
    ];
    const BY_ISSUE: &[(u64, &str)] = &[(79813, "semicolon_in_expressions_from_macros"), (35203, "patterns_in_fns_without_body"), (42868, "late_bound_lifetime_arguments")];
    BY_MESSAGE
        .iter()
        .find(|(m, _)| message.starts_with(m))
        .map(|(_, l)| l.to_string())
        .or_else(|| issue.and_then(|n| BY_ISSUE.iter().find(|(i, _)| *i == n)).map(|(_, l)| l.to_string()))
}

fn fix_hint(lint: &str, issue: Option<u64>) -> String {
    let more = issue.map(|n| format!(" (details: https://github.com/rust-lang/rust/issues/{n})")).unwrap_or_default();
    match lint {
        "semicolon_in_expressions_from_macros" => format!("Remove the trailing `;` from the macro body used in expression position, or wrap the body in braces{more}"),
        "dependency_on_unit_never_type_fallback" | "never_type_fallback_flowing_into_unsafe" => format!("Annotate the type that currently falls back to `()` explicitly (e.g. `f::<()>()` or `let x: () = ...`){more}"),
        _ => format!("Follow the compiler's suggestion for `{lint}`; `cargo fix` applies machine-applicable ones{more}"),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Update {
    /// A newer semver-compatible version exists.
    Compatible(String),
    /// Only a newer incompatible (major) version exists.
    Major(String),
    /// Already the newest version.
    Newest,
    /// Index unreachable.
    Unknown,
    /// Not on crates.io (path or git dependency).
    NotPublished,
    /// A workspace member.
    Own,
}

impl Update {
    fn short(&self) -> String {
        match self {
            Update::Compatible(v) => format!("cargo update → {v}"),
            Update::Major(v) => format!("upgrade to {v} (breaking)"),
            Update::Newest => "no newer release".into(),
            Update::Unknown => "?".into(),
            Update::NotPublished => "not on crates.io".into(),
            Update::Own => "change your code".into(),
        }
    }
    fn fix(&self, name: &str, version: &str) -> String {
        match self {
            Update::Compatible(v) => format!("`cargo update -p {name}@{version}` (newest compatible release: {v}); rerun to confirm the warning is gone, or use --verify"),
            Update::Major(v) => format!("No compatible fix release; upgrade the requirement to {name} = \"{v}\" (semver-incompatible, check its changelog), or report the warning upstream"),
            Update::Newest => format!("{name} {version} is the newest release: report the warning to its maintainers (or send a fix) and, meanwhile, use a [patch.crates-io] entry with a fixed fork"),
            Update::Unknown => format!("Check for a newer release of {name} (the crates.io index could not be reached)"),
            Update::NotPublished => format!("{name} is not published on crates.io (path or git dependency): fix it at its source or update the git revision"),
            Update::Own => "Change your code before the lint becomes an error".into(),
        }
    }
    fn json(&self) -> Value {
        match self {
            Update::Compatible(v) => json!({"kind": "compatible", "version": v}),
            Update::Major(v) => json!({"kind": "major", "version": v}),
            Update::Newest => json!({"kind": "newest"}),
            Update::Unknown => json!({"kind": "unknown"}),
            Update::NotPublished => json!({"kind": "not-published"}),
            Update::Own => json!({"kind": "own"}),
        }
    }
}

fn suggest_update(versions: Option<&[index::IndexVersion]>, current: &str) -> Update {
    let Some(vs) = versions else { return Update::Unknown };
    let Some(cur) = util::parse_version(current) else { return Update::Unknown };
    let compat = semver::VersionReq::parse(&format!("^{cur}")).ok().and_then(|r| index::best_match(vs, &r)).and_then(|v| v.version()).filter(|v| *v > cur && v.pre.is_empty());
    if let Some(v) = compat {
        return Update::Compatible(v.to_string());
    }
    match index::latest(vs).and_then(|v| v.version()) {
        Some(v) if v > cur => Update::Major(v.to_string()),
        _ => Update::Newest,
    }
}

#[derive(Debug, Clone)]
enum Verified {
    Fixed(String),
    Still(String),
    /// `cargo update` kept the same version (no newer compatible release reachable).
    NotUpdated(String),
    Failed(String),
}

impl Verified {
    fn text(&self) -> String {
        match self {
            Verified::Fixed(v) => format!("verified: after `cargo update` to {v} the warning is gone"),
            Verified::Still(v) => format!("verified: still reported after `cargo update` to {v}; a newer release does not fix it"),
            Verified::NotUpdated(v) => format!("verification inconclusive: `cargo update` kept {v} (the newer release is not available to cargo here)"),
            Verified::Failed(e) => format!("verification failed: {e}"),
        }
    }
    fn json(&self) -> Value {
        match self {
            Verified::Fixed(v) => json!({"result": "fixed", "version": v}),
            Verified::Still(v) => json!({"result": "still-present", "version": v}),
            Verified::NotUpdated(v) => json!({"result": "not-updated", "version": v}),
            Verified::Failed(e) => json!({"result": "failed", "error": e}),
        }
    }
}

/// `cargo update -p name@version` in a temp copy of the workspace, re-check, and see whether
/// `name` is still reported. The whole workspace is copied (its Cargo.lock and `[workspace]`
/// live at the root even when --project names a member).
fn verify(ctx: &Ctx, args: &Args, ws_root: &Path, name: &str, version: &str, target: &Path, timeout: Duration) -> Verified {
    let (tmp, dir) = match pu::copy_project(ws_root, "futurecompat-verify") {
        Ok(x) => x,
        Err(e) => return Verified::Failed(e.to_string()),
    };
    let result = (|| -> std::result::Result<Verified, String> {
        let mut up = pu::cargo(ctx);
        up.current_dir(&dir).args(["update", "-p", &format!("{name}@{version}")]);
        pu::offline_flag(ctx, &mut up);
        let o = util::run(&mut up, timeout).map_err(|e| e.to_string())?;
        if !o.success() {
            return Err(format!("cargo update failed: {}", pu::first_error(&o.stderr)));
        }
        let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap_or_default();
        let new_v = crate::project::parse_lockfile(&lock)
            .ok()
            .and_then(|ps| ps.into_iter().filter(|p| p.name == name).map(|p| p.version).max_by(|a, b| util::parse_version(a).cmp(&util::parse_version(b))))
            .unwrap_or_else(|| "?".into());
        if new_v == version {
            return Ok(Verified::NotUpdated(new_v));
        }
        let run = check(ctx, args, &dir, target, None, timeout).map_err(|e| e.to_string())?;
        let still = run.report.keys().any(|k| k.split('@').next() == Some(name));
        Ok(if still { Verified::Still(new_v) } else { Verified::Fixed(new_v) })
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result.unwrap_or_else(Verified::Failed)
}

/// Diagnostics in workspace members that appear with the other toolchain but not on stable.
fn new_diagnostics(stable: &[Diag], other: &[Diag], members: &BTreeSet<String>) -> Vec<Diag> {
    let key = |d: &Diag| (d.code.clone(), d.file.clone(), d.line, d.message.clone());
    let seen: BTreeSet<_> = stable.iter().map(key).collect();
    other
        .iter()
        .filter(|d| members.contains(&d.package_id) || d.level.starts_with("error"))
        .filter(|d| d.level.starts_with("error") || d.level == "warning")
        .filter(|d| !seen.contains(&key(d)))
        .cloned()
        .collect()
}

struct Channels {
    /// channel -> (version, date)
    list: Vec<(String, (String, String))>,
    next_stable: Option<(String, String)>,
    notes: Vec<String>,
}

/// Parse a channel manifest: (`[pkg.rust] version`, top-level `date`).
pub fn parse_channel(text: &str) -> Option<(String, String)> {
    let mut date = None;
    let mut version = None;
    let mut section = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            section = l.trim_matches(['[', ']']).to_string();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let v = v.trim().trim_matches('"').to_string();
        match (section.as_str(), k.trim()) {
            ("", "date") => date = Some(v),
            ("pkg.rust", "version") if version.is_none() => version = Some(v),
            _ => {}
        }
        if date.is_some() && version.is_some() {
            break;
        }
    }
    let version = version?;
    // "1.97.0 (2d8144b78 2026-06-30)" -> "1.97.0"
    let short = version.split_whitespace().next().unwrap_or(&version).to_string();
    Some((short, date.unwrap_or_default()))
}

fn release_channels(ctx: &Ctx) -> Channels {
    let mut c = Channels { list: vec![], next_stable: None, notes: vec![] };
    for ch in ["stable", "beta"] {
        let url = format!("{}/channel-rust-{ch}.toml", ctx.endpoints.rust_dist);
        match ctx.http.get(&url, Ttl::HOURS_6) {
            Ok(r) if r.ok() => match parse_channel(&r.text()) {
                Some(x) => c.list.push((ch.to_string(), x)),
                None => c.notes.push(format!("could not parse the {ch} channel manifest")),
            },
            Ok(r) => c.notes.push(format!("Rust {ch} channel data unavailable ({url} returned HTTP {})", r.status)),
            Err(e) => c.notes.push(format!("Rust {ch} channel data unavailable: {e}")),
        }
    }
    let stable = c.list.iter().find(|(ch, _)| ch == "stable").map(|x| x.1.clone());
    let beta = c.list.iter().find(|(ch, _)| ch == "beta").map(|x| x.1.clone());
    if let (Some((_, sdate)), Some((bver, _))) = (stable, beta) {
        if let Some(t) = util::parse_time(&sdate) {
            let next = bver.split('-').next().unwrap_or(&bver).to_string();
            c.next_stable = Some((next, util::format_date(t + 42 * 86_400)));
        }
    }
    c
}

/// The beta crater run of the next release: `beta-1.NN-1`, from the beta channel version, else
/// the installed rustc's minor + 1.
fn default_experiment(channels: &Channels) -> Option<String> {
    let beta = channels.list.iter().find(|(c, _)| c == "beta").map(|(_, (v, _))| v.clone());
    let minor = match beta.as_deref().and_then(util::parse_version) {
        Some(v) => v.minor,
        None => util::parse_version(local_rustc()?.split_whitespace().next()?)?.minor + 1,
    };
    Some(format!("beta-1.{minor}-1"))
}

/// Crate names in crater's `retry-regressed-list.txt` (registry crates are bare names;
/// GitHub repositories are `org/repo` and skipped).
pub fn parse_regressed_list(text: &str) -> BTreeSet<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.contains('/') && !l.starts_with('#')).map(util::normalize_crate_name).collect()
}

/// Fetch the crater run's regressed crates and report locked dependencies among them.
fn crater_section(
    ctx: &Ctx,
    meta: &Metadata,
    dev: bool,
    experiment: &str,
    index_data: &mut BTreeMap<String, Result<Vec<index::IndexVersion>>>,
    rep: &mut Report,
) -> Value {
    let base = crater_base();
    let report_url = format!("{base}/{experiment}/index.html");
    let url = format!("{base}/{experiment}/retry-regressed-list.txt");
    let text = match ctx.http.get(&url, Ttl::DAY) {
        Ok(r) if r.ok() => r.text(),
        Ok(r) if matches!(r.status, 403 | 404) => {
            rep.note(format!("crater: no report published for {experiment} yet ({url} returned HTTP {}); name another run with --crater", r.status));
            return json!({"status": "not-found", "experiment": experiment});
        }
        Ok(r) => {
            rep.note(format!("crater results unavailable: {url} returned HTTP {}", r.status));
            return json!({"status": "unavailable", "experiment": experiment});
        }
        Err(e) => {
            rep.note(format!("crater results unavailable for {experiment}: {e}"));
            return json!({"status": "unavailable", "experiment": experiment});
        }
    };
    let regressed = parse_regressed_list(&text);
    let mut matched = Vec::new();
    let mut t = Table::new(format!("Crater regressions ({experiment})"), &["Dependency", "Locked", "Tested (newest)", "Via"]);
    for p in meta.registry_packages(dev) {
        if !regressed.contains(&util::normalize_crate_name(&p.name)) {
            continue;
        }
        let newest = index_data
            .entry(p.name.clone())
            .or_insert_with(|| index::versions(ctx, &p.name))
            .as_ref()
            .ok()
            .and_then(|vs| index::latest(vs))
            .map(|v| v.vers.clone());
        let same = newest.as_deref().is_none_or(|n| n == p.version);
        let via = meta.path_to(&p.id).join(" -> ");
        t.row([p.name.clone(), p.version.clone(), newest.clone().unwrap_or_else(|| "?".into()), via.clone()]);
        let mut detail = vec![format!("crater report: {report_url}"), "crater's retry list includes real regressions and spurious failures; the report shows which".to_string()];
        if !via.is_empty() {
            detail.push(format!("dependency path: {via}"));
        }
        if !same {
            detail.push(format!("crater tested {} {}; your lock file has {}, which may or may not be affected", p.name, newest.clone().unwrap_or_default(), p.version));
        }
        rep.finding(
            Finding::new(
                // the retry list also holds crater's spurious regressions and prepare failures
                // (e.g. download errors), so a match is a lead to check, not proof of breakage
                if same { Severity::Medium } else { Severity::Low },
                "futurecompat/crater-regression",
                format!("{} is on crater run {experiment}'s regressed list: it may fail to build or pass its tests with the upcoming compiler", p.name),
            )
            .krate(&p.name, Some(&p.version))
            .detail(detail.join("\n"))
            .fix(format!(
                "Open the crater report and search for {} to see the error; check its issue tracker for a fix release, then `cargo update -p {}` (or pin/patch until one exists)",
                p.name, p.name
            )),
        );
        matched.push(json!({"name": p.name, "version": p.version, "tested": newest, "same_version": same}));
    }
    rep.table(t);
    json!({"status": "ok", "experiment": experiment, "report": report_url, "regressed_total": regressed.len(), "matched": matched})
}

fn local_rustc() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let o = util::run(std::process::Command::new(rustc).arg("-V"), Duration::from_secs(30)).ok()?;
    o.success().then(|| o.stdout.trim().trim_start_matches("rustc ").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What cargo 1.97 stores in target/.future-incompat-report.json (ANSI codes as written).
    const REPORT: &str = r#"{"version":0,"next_id":3,"reports":[
{"id":1,"suggestion_message":"","per_package":{"old@0.1.0":"x"}},
{"id":2,"suggestion_message":"to solve this problem...","per_package":{"fcdep@1.0.0":"The package `fcdep v1.0.0` currently triggers the following future incompatibility lints:\n> \u001b[1m\u001b[33mwarning\u001b[0m\u001b[1m: trailing semicolon in macro used in expression position\u001b[0m\n>  \u001b[1m\u001b[94m--> \u001b[0m/v/fcdep-1.0.0/src/lib.rs:2:30\n>   |\n>   = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in a future release!\n>   = note: for more information, see issue #79813 <https://github.com/rust-lang/rust/issues/79813>\n> \n> warning: this function depends on never type fallback being `()`\n>  --> /v/fcdep-1.0.0/src/lib.rs:5:1\n>   = warning: this was previously accepted by the compiler but is being phased out; it will become a hard error in Rust 2024 and in a future release in all editions!\n>   = note: for more information, see <https://doc.rust-lang.org/edition-guide/rust-2024/never-type-fallback.html>\n>   = note: `#[warn(dependency_on_unit_never_type_fallback)]` on by default\n"}}]}"#;

    #[test]
    fn reads_newest_report_and_items() {
        let stderr = "warning: the following packages contain code that will be rejected by a future version of Rust: fcdep v1.0.0\n        - detailed warning command: `cargo report future-incompatibilities --id 2 --package fcdep@1.0.0`\nnote: this report can be shown with `cargo report future-incompatibilities --id 2`\n";
        assert_eq!(report_id(stderr), Some(2));
        assert_eq!(report_id("    Finished `dev` profile"), None);
        let r = read_report(REPORT, 2);
        assert_eq!(r.keys().collect::<Vec<_>>(), ["fcdep@1.0.0"]);
        assert!(read_report(REPORT, 7).is_empty());
        let items = parse_package_text(&r["fcdep@1.0.0"]);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].message, "trailing semicolon in macro used in expression position");
        assert_eq!(items[0].location.as_deref(), Some("/v/fcdep-1.0.0/src/lib.rs:2:30"));
        assert_eq!(items[0].issue, Some(79813));
        assert_eq!(items[0].timeline.as_deref(), Some("in a future release"));
        assert_eq!(lint_for(&items[0].message, items[0].issue).as_deref(), Some("semicolon_in_expressions_from_macros"));
        assert_eq!(items[1].lint.as_deref(), Some("dependency_on_unit_never_type_fallback"));
        assert_eq!(items[1].timeline.as_deref(), Some("in Rust 2024 and in a future release in all editions"));
        assert!(is_specific(items[1].timeline.as_deref().unwrap()));
        assert!(!is_specific("in a future release"));
    }

    #[test]
    fn channel_manifest() {
        let t = "manifest-version = \"2\"\ndate = \"2026-06-30\"\n[pkg.cargo]\nversion = \"0.98.0 (abc 2026-06-25)\"\n[pkg.rust]\nversion = \"1.97.0 (2d8144b78 2026-06-26)\"\n";
        assert_eq!(parse_channel(t), Some(("1.97.0".into(), "2026-06-30".into())));
        assert_eq!(parse_channel("nothing"), None);
    }

    fn iv(v: &str) -> index::IndexVersion {
        serde_json::from_value(json!({"name": "x", "vers": v, "cksum": "", "deps": [], "features": {}})).unwrap()
    }

    #[test]
    fn updates() {
        let vs = vec![iv("1.0.0"), iv("1.0.3"), iv("2.1.0")];
        assert_eq!(suggest_update(Some(&vs), "1.0.0"), Update::Compatible("1.0.3".into()));
        assert_eq!(suggest_update(Some(&vs), "1.0.3"), Update::Major("2.1.0".into()));
        assert_eq!(suggest_update(Some(&vs), "2.1.0"), Update::Newest);
        assert_eq!(suggest_update(None, "1.0.0"), Update::Unknown);
    }

    #[test]
    fn diff_toolchains() {
        let d = |code: &str, level: &str, line: usize| Diag {
            code: code.into(),
            level: level.into(),
            message: "m".into(),
            package_id: "path+file:///p#0.1.0".into(),
            target_kind: vec![],
            file: Some("src/lib.rs".into()),
            line: Some(line),
            column: Some(1),
            machine_applicable: false,
            children: vec![],
            rendered: String::new(),
        };
        let members = BTreeSet::from(["path+file:///p#0.1.0".to_string()]);
        let stable = vec![d("unused", "warning", 1)];
        let beta = vec![d("unused", "warning", 1), d("E0308", "error", 4), d("new_lint", "warning", 9)];
        let n = new_diagnostics(&stable, &beta, &members);
        assert_eq!(n.iter().map(|x| x.code.as_str()).collect::<Vec<_>>(), ["E0308", "new_lint"]);
    }
}
