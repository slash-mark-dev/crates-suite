//! Miri UB Runner: Run dependency test suites under Miri to catch undefined behaviour and data races.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::common::{self, CrateRef, Select};
use crate::tools::unsafe_hotspots::{analyze, library_files, par_map};
use crate::tools::{Group, Tool};
use crate::util;

pub struct Miri;

const OPTS: &[Opt] = &[
    Opt::value("only", "A,B", "Only run these dependencies (comma-separated names)"),
    Opt::value("max", "N", "Run at most N project dependencies, those with the most unsafe code first (default 5)"),
    Opt::value("timeout", "SECS", "Time limit per crate (default 600)"),
    Opt::value("miriflags", "FLAGS", "MIRIFLAGS for the run, e.g. \"-Zmiri-disable-isolation\" (default: inherit the environment)"),
    Opt::flag("many-seeds", "Also run each test with seeds 0..4 (-Zmiri-many-seeds=0..4) to vary scheduling and addresses"),
    Opt::flag("lib", "Only run the library's unit tests (skips integration tests and doctests; much faster)"),
    Opt::value("features", "LIST", "Features to enable for the crate under test"),
    Opt::flag("plan", "Show which crates would run and why, without running anything"),
];

impl Tool for Miri {
    fn name(&self) -> &'static str {
        "miri"
    }
    fn title(&self) -> &'static str {
        "Miri UB Runner"
    }
    fn group(&self) -> Group {
        Group::Soundness
    }
    fn summary(&self) -> &'static str {
        "Run dependency test suites under Miri to catch undefined behaviour and data races"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Runs each crate's own test suite under Miri, the Rust UB interpreter. Crates named on the command
line are run as given; otherwise the project's crates.io dependencies are ranked by how many unsafe
blocks their library code has (same lexer as `sm-crates unsafe`) and the top --max (default 5) with
unsafe code are run. Each crate is unpacked from its verified .crate into a fresh temporary copy (the
cache is never modified) and `cargo +nightly miri test --no-fail-fast` runs there with a shared
target directory under the cache. Output is parsed for Miri's error classes: Undefined Behavior and
data races (critical), deadlocks and memory leaks (medium), unsupported operations such as FFI (info:
Miri could not check that test), ordinary test failures (low), timeouts and build failures (info).
Limits: Miri only sees code paths the crate's tests execute, is 10-100x slower than native, and
published crates may need network access for dev-dependencies. A clean run is evidence, not proof.
Use --plan to see the selection without running. SM_CRATES_CARGO overrides the cargo executable."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates miri --plan",
            "sm-crates miri smallvec@1.13.2 --lib",
            "sm-crates miri --max 3 --timeout 1200",
            "sm-crates miri bytes --many-seeds --miriflags=-Zmiri-strict-provenance",
        ]
    }
    fn requires(&self) -> &'static str {
        "network, nightly toolchain with the miri component"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let max: usize = args.parse_or("max", 5)?;
        let timeout: u64 = args.parse_or("timeout", 600)?;
        let explicit = !args.positional.is_empty() || !args.list("only").is_empty();
        let (subject, crates, _) = common::select(ctx, args, Select::default())?;
        let mut crates = common::only(args, crates);
        let mut rep = Report::new("miri", subject);
        if args.positional.is_empty() {
            // only dependencies built for this machine
            if let Some(ids) = host_package_ids(ctx) {
                let before = crates.len();
                crates.retain(|c| c.id.as_ref().is_none_or(|id| ids.contains(id)));
                if crates.len() < before {
                    rep.note(format!("{} dependency(ies) only used on other platforms were left out", before - crates.len()));
                }
            }
        }
        common::non_empty(&crates)?;

        // Rank by unsafe code.
        let scans = par_map(&crates, 4, |c| c.source_dir(ctx).map(|d| analyze(&library_files(&d))));
        let mut plan: Vec<Planned> = Vec::new();
        for (c, s) in crates.into_iter().zip(scans) {
            match s {
                Ok(u) => plan.push(Planned { krate: c, unsafe_blocks: u.blocks, unsafe_total: u.blocks + u.unsafe_fns + u.unsafe_impls, selected: false, reason: String::new() }),
                Err(e) => rep.note(format!("{}: skipped, source unavailable: {e}", c.spec())),
            }
        }
        if explicit {
            for p in &mut plan {
                p.selected = true;
                p.reason = format!("requested; {} unsafe block(s)", p.unsafe_blocks);
            }
        } else {
            plan.sort_by(|a, b| {
                let sys = |p: &Planned| p.krate.name.ends_with("-sys") || p.krate.name.ends_with("_sys");
                sys(a).cmp(&sys(b)).then(b.unsafe_blocks.cmp(&a.unsafe_blocks)).then(b.unsafe_total.cmp(&a.unsafe_total)).then(a.krate.name.cmp(&b.krate.name))
            });
            let mut taken = 0;
            for p in &mut plan {
                if p.unsafe_total == 0 {
                    p.reason = "no unsafe code in library sources".into();
                } else if p.krate.name.ends_with("-sys") || p.krate.name.ends_with("_sys") {
                    p.reason = "FFI bindings (-sys): Miri cannot call foreign functions; name it to run anyway".into();
                } else if taken < max {
                    taken += 1;
                    p.selected = true;
                    p.reason = format!("{} unsafe block(s), rank {taken}", p.unsafe_blocks);
                } else {
                    p.reason = format!("{} unsafe block(s); beyond --max {max}", p.unsafe_blocks);
                }
            }
        }
        let selected: Vec<&Planned> = plan.iter().filter(|p| p.selected).collect();
        let flags = miriflags(args);

        if args.flag("plan") {
            let mut t = Table::new("Miri plan", &["Crate", "Version", "Unsafe blocks", "Run", "Why"]);
            for p in &plan {
                t.row([p.krate.name.clone(), p.krate.version.clone(), p.unsafe_blocks.to_string(), if p.selected { "yes" } else { "no" }.into(), p.reason.clone()]);
            }
            rep.table(t);
            rep.summary(format!("would run {} of {} crate(s) under Miri", selected.len(), plan.len()));
            rep.note(format!(
                "command per crate: {}cargo +nightly miri test --no-fail-fast{} (timeout {timeout}s)",
                flags.as_ref().map(|f| format!("MIRIFLAGS=\"{f}\" ")).unwrap_or_default(),
                if args.flag("lib") { " --lib" } else { "" }
            ));
            rep.data = json!({"plan": plan.iter().map(|p| json!({"crate": p.krate.name, "version": p.krate.version, "unsafe_blocks": p.unsafe_blocks, "selected": p.selected, "reason": p.reason})).collect::<Vec<_>>()});
            return Ok(rep);
        }
        if selected.is_empty() {
            rep.summary("nothing to run: no selected crate has unsafe code (name crates explicitly to run them anyway)");
            return Ok(rep);
        }
        check_toolchain(ctx)?;
        let target_dir = ctx.cache_subdir("miri-target")?;
        let mut t = Table::new("Miri results", &["Crate", "Version", "Result", "Tests", "Duration"]);
        let mut data = Vec::new();
        for p in &selected {
            let c = &p.krate;
            let r = run_one(ctx, c, args, flags.as_deref(), &target_dir, Duration::from_secs(timeout))?;
            t.row([c.name.clone(), c.version.clone(), r.outcome.label().to_string(), r.tests_label(), util::human_duration(r.secs)]);
            for f in r.findings(c, timeout) {
                rep.finding(f);
            }
            data.push(json!({
                "crate": c.name, "version": c.version, "unsafe_blocks": p.unsafe_blocks, "result": r.outcome.label(),
                "passed": r.passed, "failed": r.failed, "duration_secs": (r.secs * 10.0).round() / 10.0,
                "errors": r.errors.iter().map(|e| json!({"kind": e.kind.code(), "message": e.message, "location": e.location, "test": e.test})).collect::<Vec<_>>(),
                "failed_tests": r.failed_tests, "exit_code": r.exit_code,
            }));
        }
        rep.table(t);
        let ub = rep.findings.iter().filter(|f| f.severity == Severity::Critical).count();
        rep.summary(format!("ran {} crate(s) under Miri: {ub} undefined-behavior/data-race error(s)", selected.len()));
        if let Some(f) = &flags {
            rep.note(format!("MIRIFLAGS=\"{f}\""));
        }
        rep.note("Miri checks only the paths the crate's tests execute; a clean run is evidence, not proof.");
        rep.data = json!({"results": data, "miriflags": flags});
        Ok(rep)
    }
}

struct Planned {
    krate: CrateRef,
    unsafe_blocks: usize,
    unsafe_total: usize,
    selected: bool,
    reason: String,
}

fn miriflags(args: &Args) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    match args.value("miriflags") {
        Some(f) => parts.push(f.to_string()),
        None => {
            if let Ok(f) = std::env::var("MIRIFLAGS") {
                if !f.trim().is_empty() {
                    parts.push(f);
                }
            }
        }
    }
    if args.flag("many-seeds") {
        parts.push("-Zmiri-many-seeds=0..4".into());
    }
    let s = parts.join(" ").trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Package ids reachable when building for the host platform (`None` if it cannot be determined).
fn host_package_ids(ctx: &Ctx) -> Option<std::collections::BTreeSet<String>> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let o = util::run(Command::new(rustc).arg("-vV"), Duration::from_secs(60)).ok()?;
    let host = o.stdout.lines().find_map(|l| l.strip_prefix("host: "))?.trim().to_string();
    let opts = crate::project::MetaOpts { filter_platform: Some(host), ..Default::default() };
    let meta = crate::project::Metadata::load(ctx, &opts).ok()?;
    Some(meta.reachable(false, true))
}

fn check_toolchain(ctx: &Ctx) -> Result<()> {
    let install = "Install it with:\n  rustup toolchain install nightly --component miri\n  cargo +nightly miri setup";
    // RUSTUP_AUTO_INSTALL=0: never download a toolchain as a side effect of this check
    let out = util::run(
        Command::new(&ctx.cargo).args(["+nightly", "miri", "--version"]).env("RUSTUP_AUTO_INSTALL", "0"),
        Duration::from_secs(120),
    );
    match out {
        Ok(o) if o.success() => Ok(()),
        Ok(o) => Err(Error::Env(format!(
            "Miri is not available: `cargo +nightly miri --version` failed ({}). {install}",
            o.stderr
                .lines()
                .find(|l| l.trim_start().starts_with("error"))
                .or_else(|| o.stderr.lines().find(|l| !l.trim().is_empty()))
                .unwrap_or("no output")
                .trim()
        ))),
        Err(e) => Err(Error::Env(format!("Miri is not available: {e}. {install}"))),
    }
}

/// Copy a directory tree (regular files only, skipping `target/`, `.git/` and the cache marker).
pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for f in util::walk_files(from) {
        let rel = f.strip_prefix(from).unwrap_or(&f);
        if rel.as_os_str() == ".sm-complete" {
            continue;
        }
        let dest = to.join(rel);
        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::copy(&f, &dest)?;
    }
    Ok(())
}

/// Copy a crate's source to a fresh temp dir and make it its own workspace root.
pub fn scratch_copy(src: &Path, label: &str) -> Result<(PathBuf, PathBuf)> {
    let tmp = util::temp_dir(label)?;
    let dir = tmp.join("pkg");
    copy_tree(src, &dir)?;
    let manifest = dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)?;
    let parsed: Option<toml::Value> = toml::from_str(&text).ok();
    if parsed.as_ref().and_then(|v| v.get("workspace")).is_none() {
        std::fs::write(&manifest, format!("{text}\n[workspace]\n"))?;
    }
    Ok((tmp, dir))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ub,
    DataRace,
    Deadlock,
    Leak,
    Unsupported,
}

impl Kind {
    fn code(&self) -> &'static str {
        match self {
            Kind::Ub => "miri/undefined-behavior",
            Kind::DataRace => "miri/data-race",
            Kind::Deadlock => "miri/deadlock",
            Kind::Leak => "miri/leak",
            Kind::Unsupported => "miri/unsupported",
        }
    }
    fn severity(&self) -> Severity {
        match self {
            Kind::Ub | Kind::DataRace => Severity::Critical,
            Kind::Deadlock | Kind::Leak => Severity::Medium,
            Kind::Unsupported => Severity::Info,
        }
    }
}

#[derive(Debug, Clone)]
struct MiriError {
    kind: Kind,
    message: String,
    location: Option<String>,
    test: Option<String>,
    context: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ub,
    DataRace,
    Deadlock,
    Leak,
    TestsFailed,
    Unsupported,
    BuildFailed,
    TimedOut,
    Ok,
}

impl Outcome {
    fn label(&self) -> &'static str {
        match self {
            Outcome::Ub => "UNDEFINED BEHAVIOR",
            Outcome::DataRace => "DATA RACE",
            Outcome::Deadlock => "deadlock",
            Outcome::Leak => "memory leak",
            Outcome::TestsFailed => "tests failed",
            Outcome::Unsupported => "partly unsupported",
            Outcome::BuildFailed => "build failed",
            Outcome::TimedOut => "timed out",
            Outcome::Ok => "ok",
        }
    }
}

#[derive(Debug, Clone)]
struct RunResult {
    outcome: Outcome,
    errors: Vec<MiriError>,
    passed: usize,
    failed: usize,
    failed_tests: Vec<String>,
    build_error: Option<String>,
    secs: f64,
    exit_code: Option<i32>,
    command: String,
}

impl RunResult {
    fn tests_label(&self) -> String {
        if self.passed + self.failed == 0 {
            "-".into()
        } else if self.failed > 0 {
            format!("{} passed, {} failed", self.passed, self.failed)
        } else {
            format!("{} passed", self.passed)
        }
    }

    fn findings(&self, c: &CrateRef, timeout: u64) -> Vec<Finding> {
        let mut out = Vec::new();
        let fix = format!("Reproduce in the crate source with: {}; report it upstream and consider pinning a version without it", self.command);
        for e in &self.errors {
            let what = match e.kind {
                Kind::Ub => "Undefined Behavior",
                Kind::DataRace => "Data race",
                Kind::Deadlock => "Deadlock",
                Kind::Leak => "Memory leak",
                Kind::Unsupported => "Miri could not run a test (unsupported operation)",
            };
            let msg = format!("{what}: {}", e.message);
            let mut detail = Vec::new();
            if let Some(t) = &e.test {
                detail.push(format!("test: {t}"));
            }
            if let Some(l) = &e.location {
                detail.push(format!("at {l}"));
            }
            detail.extend(e.context.iter().cloned());
            let mut f = Finding::new(e.kind.severity(), e.kind.code(), msg).krate(&c.name, Some(&c.version)).detail(detail.join("\n"));
            if let Some((file, line)) = e.location.as_deref().and_then(split_loc) {
                f = f.at(file, Some(line));
            }
            f = match e.kind {
                Kind::Unsupported => f.fix("Usually FFI or a platform API Miri does not emulate; gate such tests with #[cfg_attr(miri, ignore)]"),
                Kind::Leak => f.fix(format!("Check for leaked allocations (mem::forget, Box::leak, Rc cycles); {}", self.command)),
                _ => f.fix(fix.clone()),
            };
            out.push(f);
        }
        if self.failed > 0 && !self.errors.iter().any(|e| matches!(e.kind, Kind::Ub | Kind::DataRace)) {
            out.push(
                Finding::new(Severity::Low, "miri/test-failed", format!("{} test(s) failed under Miri without a Miri error", self.failed))
                    .krate(&c.name, Some(&c.version))
                    .detail(self.failed_tests.iter().take(10).cloned().collect::<Vec<_>>().join("\n"))
                    .fix("Often tests that depend on timing, the file system (try -Zmiri-disable-isolation) or are too slow; check whether they also fail natively"),
            );
        }
        match self.outcome {
            Outcome::TimedOut => out.push(
                Finding::new(Severity::Info, "miri/timeout", format!("Miri run did not finish within {timeout}s"))
                    .krate(&c.name, Some(&c.version))
                    .detail(format!("{} test(s) finished before the limit", self.passed + self.failed))
                    .fix("Raise --timeout, or use --lib to run only unit tests"),
            ),
            Outcome::BuildFailed => out.push(
                Finding::new(Severity::Info, "miri/build-failed", "Test suite did not build under Miri")
                    .krate(&c.name, Some(&c.version))
                    .detail(self.build_error.clone().unwrap_or_default())
                    .fix("Published crates may need network access for dev-dependencies or files not included in the package; try --lib or --features"),
            ),
            _ => {}
        }
        out
    }
}

fn split_loc(l: &str) -> Option<(&str, usize)> {
    // path:line:col
    let mut it = l.rsplitn(3, ':');
    let _col = it.next()?;
    let line: usize = it.next()?.parse().ok()?;
    let file = it.next()?;
    Some((file, line))
}

fn run_one(ctx: &Ctx, c: &CrateRef, args: &Args, flags: Option<&str>, target_dir: &Path, timeout: Duration) -> Result<RunResult> {
    let src = c.source_dir(ctx)?;
    let (tmp, dir) = scratch_copy(&src, &format!("miri-{}", c.name))?;
    let mut cmd = Command::new(&ctx.cargo);
    cmd.args(["+nightly", "miri", "test", "--no-fail-fast"]);
    let mut shown = String::from("cargo +nightly miri test");
    if args.flag("lib") {
        cmd.arg("--lib");
        shown.push_str(" --lib");
    }
    if let Some(f) = args.value("features") {
        cmd.args(["--features", f]);
        shown.push_str(&format!(" --features {f}"));
    }
    if ctx.offline {
        cmd.arg("--offline");
    }
    cmd.current_dir(&dir).env("CARGO_TARGET_DIR", target_dir);
    if let Some(f) = flags {
        cmd.env("MIRIFLAGS", f);
        shown = format!("MIRIFLAGS=\"{f}\" {shown}");
    }
    let out = util::run(&mut cmd, timeout);
    let _ = std::fs::remove_dir_all(&tmp);
    let out = out?;
    let mut r = parse_output(&out.stdout, &out.stderr, out.code, out.timed_out);
    r.secs = out.elapsed.as_secs_f64();
    r.command = shown;
    Ok(r)
}

/// Parse `cargo miri test` output.
fn parse_output(stdout: &str, stderr: &str, code: Option<i32>, timed_out: bool) -> RunResult {
    let mut errors = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut failed_tests = Vec::new();
    let mut started: Vec<String> = Vec::new();
    for line in stdout.lines().chain(stderr.lines()) {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("test result: ") {
            passed += number_before(rest, " passed");
            failed += number_before(rest, " failed");
        } else if let Some(name) = l.strip_prefix("test ") {
            if let Some((n, res)) = name.rsplit_once(" ... ") {
                if res.trim() == "FAILED" {
                    failed_tests.push(n.trim().to_string());
                }
            } else if let Some(n) = name.strip_suffix(" ...") {
                started.push(n.trim().to_string());
            }
        }
    }
    let lines: Vec<&str> = stderr.lines().chain(stdout.lines()).collect();
    for (k, line) in lines.iter().enumerate() {
        let l = line.trim_start();
        let (kind, msg) = if let Some(m) = l.strip_prefix("error: Undefined Behavior: ") {
            (if m.contains("Data race detected") { Kind::DataRace } else { Kind::Ub }, m)
        } else if let Some(m) = l.strip_prefix("error: memory leaked: ") {
            (Kind::Leak, m)
        } else if let Some(m) = l.strip_prefix("error: unsupported operation: ") {
            (Kind::Unsupported, m)
        } else if let Some(m) = l.strip_prefix("error: deadlock: ") {
            (Kind::Deadlock, m)
        } else {
            continue;
        };
        let mut location = None;
        let mut test = None;
        let mut context = Vec::new();
        for next in lines.iter().skip(k + 1).take(60) {
            let n = next.trim();
            if n.starts_with("error:") || n.starts_with("test result:") {
                break;
            }
            if location.is_none() {
                if let Some(loc) = n.strip_prefix("--> ") {
                    location = Some(loc.trim().to_string());
                }
            }
            if let Some(rest) = n.split("on thread `").nth(1) {
                if let Some(name) = rest.split('`').next() {
                    if name != "main" && test.is_none() {
                        test = Some(name.to_string());
                    }
                }
            }
            if (n.starts_with("= help:") || n.starts_with("= note:")) && context.len() < 3 && !n.contains("BACKTRACE") {
                context.push(n.trim_start_matches("= ").to_string());
            }
        }
        if test.is_none() && kind != Kind::Leak {
            test = started.last().cloned();
        }
        errors.push(MiriError { kind, message: msg.trim().to_string(), location, test, context });
    }
    let build_error = if errors.is_empty() && passed + failed == 0 && !timed_out && code != Some(0) {
        stderr
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("error[E") || l.starts_with("error: failed") || l.starts_with("error: could not") || l.starts_with("error: no matching") || l.starts_with("error:"))
            .map(|s| s.to_string())
            .or_else(|| Some(stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("cargo exited with an error").trim().to_string()))
    } else {
        None
    };
    let has = |k: Kind| errors.iter().any(|e| e.kind == k);
    let outcome = if has(Kind::Ub) {
        Outcome::Ub
    } else if has(Kind::DataRace) {
        Outcome::DataRace
    } else if has(Kind::Deadlock) {
        Outcome::Deadlock
    } else if has(Kind::Leak) {
        Outcome::Leak
    } else if timed_out {
        Outcome::TimedOut
    } else if failed > 0 {
        Outcome::TestsFailed
    } else if has(Kind::Unsupported) {
        Outcome::Unsupported
    } else if build_error.is_some() {
        Outcome::BuildFailed
    } else {
        Outcome::Ok
    };
    RunResult { outcome, errors, passed, failed, failed_tests, build_error, secs: 0.0, exit_code: code, command: String::new() }
}

fn number_before(s: &str, suffix: &str) -> usize {
    let Some(pos) = s.find(suffix) else { return 0 };
    s[..pos].rsplit(|c: char| !c.is_ascii_digit()).next().and_then(|n| n.parse().ok()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UB: &str = r#"running 3 tests
test tests::fine ... ok
test tests::reads_freed ... "#;
    const UB_ERR: &str = r#"   Compiling ubcrate v0.1.0 (/tmp/x)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.31s
     Running unittests src/lib.rs (target/miri/x86_64-unknown-linux-gnu/debug/deps/ubcrate-1234)
error: Undefined Behavior: memory access failed: alloc211 has been freed, so this pointer is dangling
  --> src/lib.rs:7:14
   |
7  |     unsafe { *p }
   |              ^^ Undefined Behavior occurred here
   |
   = help: this indicates a bug in the program: it performed an invalid operation, and caused Undefined Behavior
   = help: see https://doc.rust-lang.org/nightly/reference/behavior-considered-undefined.html for further information
help: alloc211 was allocated here:
  --> src/lib.rs:4:17
   = note: BACKTRACE (of the first span) on thread `tests::reads_freed`:
   = note: inside `read_freed` at src/lib.rs:7:14: 7:16

note: some details are omitted, run with `MIRIFLAGS=-Zmiri-backtrace=full` for a verbose backtrace

error: aborting due to 1 previous error

error: test failed, to rerun pass `--lib`
"#;

    #[test]
    fn parses_ub_with_location_and_test() {
        let r = parse_output(UB, UB_ERR, Some(101), false);
        assert_eq!(r.outcome, Outcome::Ub);
        assert_eq!(r.errors.len(), 1);
        let e = &r.errors[0];
        assert_eq!(e.kind, Kind::Ub);
        assert!(e.message.starts_with("memory access failed"));
        assert_eq!(e.location.as_deref(), Some("src/lib.rs:7:14"));
        assert_eq!(e.test.as_deref(), Some("tests::reads_freed"));
        assert_eq!(split_loc("src/lib.rs:7:14"), Some(("src/lib.rs", 7)));
        assert!(r.build_error.is_none());
    }

    #[test]
    fn parses_race_leak_unsupported_and_results() {
        let err = "error: Undefined Behavior: Data race detected between (1) non-atomic write on thread `unnamed-1` and (2) non-atomic read on thread `main` at alloc1\n  --> src/sync.rs:20:9\n\
                   error: memory leaked: alloc77 (Rust heap, size: 8, align: 8), allocated here:\n  --> src/lib.rs:3:5\n\
                   error: unsupported operation: can't call foreign function `ffi_thing` on OS `linux`\n  --> src/ffi.rs:9:1\n";
        let out = "test result: ok. 12 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 3.1s\ntest a::b ... FAILED\ntest result: FAILED. 4 passed; 1 failed; 0 ignored\n";
        let r = parse_output(out, err, Some(101), false);
        let kinds: Vec<Kind> = r.errors.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, [Kind::DataRace, Kind::Leak, Kind::Unsupported]);
        assert_eq!(r.outcome, Outcome::DataRace);
        assert_eq!((r.passed, r.failed), (16, 1));
        assert_eq!(r.failed_tests, ["a::b"]);
        assert_eq!(r.errors[0].test, None);
    }

    #[test]
    fn build_failure_and_clean() {
        let r = parse_output("", "   Compiling x v1.0.0\nerror[E0432]: unresolved import `foo`\nerror: could not compile `x`\n", Some(101), false);
        assert_eq!(r.outcome, Outcome::BuildFailed);
        assert_eq!(r.build_error.as_deref(), Some("error[E0432]: unresolved import `foo`"));
        let r = parse_output("test result: ok. 5 passed; 0 failed; 0 ignored\n", "", Some(0), false);
        assert_eq!(r.outcome, Outcome::Ok);
        let r = parse_output("test result: ok. 2 passed; 0 failed\n", "", None, true);
        assert_eq!(r.outcome, Outcome::TimedOut);
    }

    #[test]
    fn numbers() {
        assert_eq!(number_before("ok. 12 passed; 3 failed;", " passed"), 12);
        assert_eq!(number_before("ok. 12 passed; 3 failed;", " failed"), 3);
        assert_eq!(number_before("nothing", " passed"), 0);
    }
}
