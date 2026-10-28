//! Release Profile Advisor: Measure LTO, codegen-units, panic=abort and opt-level on your project and report the trade-offs.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata};
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc;
use crate::tools::perf_util as pu;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Profile;

const OPTS: &[Opt] = &[
    Opt::value("variants", "A,B", "Variants to measure (default: baseline,lto-thin,lto-fat,panic-abort,opt-s,opt-z,strip; see the list above)"),
    Opt::flag("quick", "Measure only baseline, lto-thin and strip"),
    Opt::value("package", "NAME", "Workspace package that has the binary"),
    Opt::value("bin", "NAME", "Binary to build (default: the package's only or first binary)"),
    Opt::value("features", "LIST", "Features to enable (comma-separated)"),
    Opt::flag("all-features", "Enable all features"),
    Opt::flag("no-default-features", "Disable default features"),
    Opt::value("bench-cmd", "CMD", "Benchmark command run for each variant; {bin} is replaced by the binary path, e.g. \"{bin} --input data.txt\""),
    Opt::value("runs", "N", "Benchmark runs per variant; the median is reported (default 5)"),
    Opt::value("timeout", "SECS", "Time limit per cargo build (default 3600)"),
    Opt::value("bench-timeout", "SECS", "Time limit per benchmark run (default 300)"),
];

/// A profile variant: name, `CARGO_PROFILE_RELEASE_*` overrides, description.
struct Variant {
    name: &'static str,
    env: &'static [(&'static str, &'static str)],
    about: &'static str,
}

const VARIANTS: &[Variant] = &[
    Variant { name: "baseline", env: &[], about: "the project's own [profile.release]" },
    Variant { name: "lto-thin", env: &[("LTO", "thin")], about: "thin LTO across crates" },
    Variant { name: "lto-fat", env: &[("LTO", "fat"), ("CODEGEN_UNITS", "1")], about: "fat LTO with one codegen unit (slowest build, best optimization)" },
    Variant { name: "cgu1", env: &[("CODEGEN_UNITS", "1")], about: "one codegen unit per crate" },
    Variant { name: "panic-abort", env: &[("PANIC", "abort")], about: "abort on panic instead of unwinding" },
    Variant { name: "opt-s", env: &[("OPT_LEVEL", "s")], about: "optimize for size" },
    Variant { name: "opt-z", env: &[("OPT_LEVEL", "z")], about: "optimize aggressively for size" },
    Variant { name: "strip", env: &[("STRIP", "symbols")], about: "strip symbols from the binary" },
    Variant { name: "line-tables", env: &[("DEBUG", "line-tables-only")], about: "keep line tables for backtraces/profilers" },
    Variant { name: "min-size", env: &[("OPT_LEVEL", "z"), ("LTO", "fat"), ("CODEGEN_UNITS", "1"), ("PANIC", "abort"), ("STRIP", "symbols")], about: "every size setting combined" },
    Variant { name: "max-speed", env: &[("LTO", "fat"), ("CODEGEN_UNITS", "1"), ("PANIC", "abort")], about: "fat LTO, one codegen unit, panic=abort" },
];

const DEFAULT: &[&str] = &["baseline", "lto-thin", "lto-fat", "panic-abort", "opt-s", "opt-z", "strip"];
const QUICK: &[&str] = &["baseline", "lto-thin", "strip"];

impl Tool for Profile {
    fn name(&self) -> &'static str {
        "profile"
    }
    fn title(&self) -> &'static str {
        "Release Profile Advisor"
    }
    fn group(&self) -> Group {
        Group::Performance
    }
    fn summary(&self) -> &'static str {
        "Measure LTO, codegen-units, panic=abort and opt-level on your project and report the trade-offs"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Builds the project's binary in release mode once per profile variant and measures the result,
without editing Cargo.toml: each variant is applied with CARGO_PROFILE_RELEASE_* environment
overrides (LTO, CODEGEN_UNITS, PANIC, OPT_LEVEL, STRIP, DEBUG) in its own target directory under
the cache, so dependencies are built once per variant and reused on later runs. For every variant
it records the full build time, the time to rebuild only your crate (after `cargo clean -p`, which
is what you pay on each change and includes LTO/linking), the binary size, and with --bench-cmd
the median runtime of a command you supply. Variants: baseline (your current profile), lto-thin,
lto-fat (+codegen-units=1), cgu1, panic-abort, opt-s, opt-z, strip, line-tables, min-size (all size
settings), max-speed. It then names the smallest binary, the fastest runtime and a best trade-off
(the smallest variant that saves at least 5% without slowing the program or tripling rebuilds)
and prints the [profile.release] snippet to paste. If your code calls catch_unwind, panic=abort
variants get a warning: with abort, panics can no longer be caught. Build times depend on machine
load; runtime numbers are only as good as your benchmark command. Progress goes to stderr."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates profile --quick",
            "sm-crates profile --variants baseline,opt-z,min-size --bench-cmd \"{bin} --version\" --runs 3",
            "sm-crates profile --variants strip,line-tables --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo (no network unless dependencies must be downloaded)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        pu::require_manifest(ctx)?;
        let variants = chosen_variants(args)?;
        let runs: usize = args.parse_or("runs", 5)?;
        let bench = args.value("bench-cmd").map(pu::split_words).filter(|w| !w.is_empty());
        let timeout = pu::timeout(args, 3600)?;
        let bench_timeout = Duration::from_secs(args.parse_or("bench-timeout", 300u64)?.max(1));
        let meta = Metadata::load(ctx, &MetaOpts { no_deps: true, ..Default::default() })?;
        let pkg = crate::tools::mono::pick_package(&meta, args.value("package"), ctx.project_root())?;
        let bins: Vec<&str> = pkg.targets.iter().filter(|t| t.kind.iter().any(|k| k == "bin")).map(|t| t.name.as_str()).collect();
        let bin = match args.value("bin") {
            Some(b) if bins.contains(&b) => b.to_string(),
            Some(b) => return Err(Error::Usage(format!("package `{}` has no binary `{b}` (binaries: {})", pkg.name, bins.join(", ")))),
            None => match bins.first() {
                Some(b) => b.to_string(),
                None => return Err(Error::Usage(format!("package `{}` has no binary target; profile measures a binary (use --package)", pkg.name))),
            },
        };
        let mut rep = Report::new("profile", format!("{} (bin {bin})", pkg.name));
        let baseline_profile = release_profile(&meta.workspace_root);
        let unwind_uses = catch_unwind_uses(&pkg.dir());

        let mut results: Vec<Measured> = Vec::new();
        for (k, v) in variants.iter().enumerate() {
            pu::progress(args, &format!("[{}/{}] {}: building ({})", k + 1, variants.len(), v.name, v.about));
            let m = measure(ctx, args, v, &pkg.name, &bin, timeout)?;
            let mut m = m;
            if let (Some(words), Some(exe)) = (&bench, &m.exe) {
                let (times, err) = bench_runs(ctx, words, exe, runs.max(1), bench_timeout);
                m.runtime = pu::median(&times);
                m.bench_error = err;
            }
            pu::progress(
                args,
                &format!(
                    "[{}/{}] {}: {}, crate rebuild {}{}",
                    k + 1,
                    variants.len(),
                    v.name,
                    m.size.map(util::human_bytes).unwrap_or_else(|| "build failed".into()),
                    m.final_secs.map(fmt_secs).unwrap_or_else(|| "-".into()),
                    m.runtime.map(|r| format!(", runtime {}", fmt_secs(r))).unwrap_or_default()
                ),
            );
            results.push(m);
        }
        report(&mut rep, &results, &baseline_profile, &unwind_uses, bench.is_some(), runs);
        Ok(rep)
    }
}

fn chosen_variants(args: &Args) -> Result<Vec<&'static Variant>> {
    let names: Vec<String> = if !args.list("variants").is_empty() {
        args.list("variants")
    } else if args.flag("quick") {
        QUICK.iter().map(|s| s.to_string()).collect()
    } else {
        DEFAULT.iter().map(|s| s.to_string()).collect()
    };
    let mut out: Vec<&'static Variant> = Vec::new();
    for n in names {
        let v = VARIANTS.iter().find(|v| v.name == n).ok_or_else(|| {
            Error::Usage(format!("unknown variant `{n}` (choose from: {})", VARIANTS.iter().map(|v| v.name).collect::<Vec<_>>().join(", ")))
        })?;
        if !out.iter().any(|o| o.name == v.name) {
            out.push(v);
        }
    }
    if !out.iter().any(|v| v.name == "baseline") {
        out.insert(0, &VARIANTS[0]);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct Measured {
    name: &'static str,
    env: &'static [(&'static str, &'static str)],
    full_secs: Option<f64>,
    /// The full build reused dependencies from an earlier run.
    deps_cached: bool,
    final_secs: Option<f64>,
    size: Option<u64>,
    exe: Option<PathBuf>,
    runtime: Option<f64>,
    bench_error: Option<String>,
    error: Option<String>,
}

fn build_cmd(ctx: &Ctx, args: &Args, v: &Variant, target: &Path, sub: &[&str]) -> Command {
    let mut c = pu::cargo(ctx);
    c.args(sub);
    pu::offline_flag(ctx, &mut c);
    c.env("CARGO_TARGET_DIR", target);
    for (k, val) in v.env {
        c.env(format!("CARGO_PROFILE_RELEASE_{k}"), val);
    }
    if sub.first() == Some(&"build") {
        c.args(pu::feature_args(args));
    }
    c
}

fn measure(ctx: &Ctx, args: &Args, v: &'static Variant, pkg: &str, bin: &str, timeout: Duration) -> Result<Measured> {
    let target = pu::target_dir(ctx, "profile", Some(v.name))?;
    let deps_cached = target.join("release").is_dir();
    let mut m = Measured { name: v.name, env: v.env, full_secs: None, deps_cached, final_secs: None, size: None, exe: None, runtime: None, bench_error: None, error: None };
    let build = ["build", "--release", "-p", pkg, "--bin", bin, "--message-format", "json"];
    let out = util::run(&mut build_cmd(ctx, args, v, &target, &build), timeout)?;
    if !out.success() {
        m.error = Some(if out.timed_out { format!("build timed out after {}s", timeout.as_secs()) } else { pu::first_error(&out.stderr) });
        if v.name == "baseline" {
            return Err(Error::Env(format!("the baseline release build failed: {}", m.error.clone().unwrap_or_default())));
        }
        return Ok(m);
    }
    m.full_secs = Some(out.elapsed.as_secs_f64());
    // rebuild only the final crate: what each code change costs (includes LTO and linking)
    let _ = util::run(&mut build_cmd(ctx, args, v, &target, &["clean", "--release", "-p", pkg]), Duration::from_secs(300));
    let out2 = util::run(&mut build_cmd(ctx, args, v, &target, &build), timeout)?;
    if !out2.success() {
        m.error = Some(pu::first_error(&out2.stderr));
        return Ok(m);
    }
    m.final_secs = Some(out2.elapsed.as_secs_f64());
    m.exe = executable(&out2.stdout, bin);
    m.size = m.exe.as_ref().and_then(|p| std::fs::metadata(p).ok()).map(|md| md.len());
    if m.exe.is_none() {
        m.error = Some("cargo reported no executable".into());
    }
    Ok(m)
}

/// The `executable` of the bin target from cargo's JSON messages.
fn executable(stdout: &str, bin: &str) -> Option<PathBuf> {
    pu::messages(stdout)
        .iter()
        .filter(|v| v.get("reason").and_then(Value::as_str) == Some("compiler-artifact"))
        .filter(|v| v.get("target").and_then(|t| t.get("name")).and_then(Value::as_str) == Some(bin))
        .find_map(|v| v.get("executable").and_then(Value::as_str).map(PathBuf::from))
}

fn bench_runs(ctx: &Ctx, words: &[String], exe: &Path, runs: usize, timeout: Duration) -> (Vec<f64>, Option<String>) {
    let exe_s = exe.to_string_lossy();
    let w: Vec<String> = words.iter().map(|x| x.replace("{bin}", &exe_s)).collect();
    let mut times = Vec::new();
    for _ in 0..runs {
        let mut c = Command::new(&w[0]);
        c.args(&w[1..]).current_dir(ctx.project_root());
        match util::run(&mut c, timeout) {
            Ok(o) if o.success() => times.push(o.elapsed.as_secs_f64()),
            Ok(o) if o.timed_out => return (times, Some(format!("benchmark timed out after {}s", timeout.as_secs()))),
            Ok(o) => return (times, Some(format!("benchmark exited with {:?}: {}", o.code, o.stderr.lines().last().unwrap_or("").trim()))),
            Err(e) => return (times, Some(e.to_string())),
        }
    }
    (times, None)
}

/// `[profile.release]` of the workspace root manifest as `key = value` pairs (TOML-formatted values).
fn release_profile(root: &Path) -> Vec<(String, String)> {
    let Some(m) = rustsrc::manifest(root) else { return vec![] };
    let Some(t) = m.get("profile").and_then(|p| p.get("release")).and_then(|r| r.as_table()) else { return vec![] };
    t.iter().filter(|(_, v)| !v.is_table()).map(|(k, v)| (k.clone(), v.to_string())).collect()
}

/// `catch_unwind` call sites in a package's non-test sources (file, line).
fn catch_unwind_uses(dir: &Path) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for f in rustsrc::load_crate(dir, rustsrc::LoadOpts { auxiliary: false, build_script: false }) {
        let tests = rustsrc::items::test_ranges(&f.code);
        for (k, t) in f.code.iter().enumerate() {
            if t.ident("catch_unwind") && !rustsrc::items::in_ranges(&tests, k) {
                out.push((f.rel.clone(), t.line));
            }
        }
    }
    out
}

fn toml_key(env: &str) -> &'static str {
    match env {
        "LTO" => "lto",
        "CODEGEN_UNITS" => "codegen-units",
        "PANIC" => "panic",
        "OPT_LEVEL" => "opt-level",
        "STRIP" => "strip",
        "DEBUG" => "debug",
        _ => "",
    }
}

fn toml_value(key: &str, v: &str) -> String {
    if key == "codegen-units" || (key == "opt-level" && v.chars().all(|c| c.is_ascii_digit())) {
        v.to_string()
    } else {
        format!("\"{v}\"")
    }
}

/// The `[profile.release]` section for a variant: the project's settings with the variant's overrides.
fn snippet(base: &[(String, String)], env: &[(&str, &str)]) -> String {
    let mut lines: Vec<(String, String)> = base.to_vec();
    for (k, v) in env {
        let key = toml_key(k).to_string();
        let val = toml_value(&key, v);
        match lines.iter_mut().find(|(k2, _)| *k2 == key) {
            Some(e) => e.1 = val,
            None => lines.push((key, val)),
        }
    }
    let mut s = String::from("[profile.release]");
    for (k, v) in lines {
        s.push_str(&format!("\n{k} = {v}"));
    }
    s
}

fn fmt_secs(x: f64) -> String {
    if x < 1.0 { format!("{:.0}ms", x * 1000.0) } else { format!("{x:.1}s") }
}

fn report(rep: &mut Report, results: &[Measured], base_prof: &[(String, String)], unwind: &[(String, usize)], benched: bool, runs: usize) {
    let base = results.iter().find(|m| m.name == "baseline");
    let bsize = base.and_then(|b| b.size).map(|s| s as f64).unwrap_or(0.0);
    let btime = base.and_then(|b| b.final_secs).unwrap_or(0.0);
    let brun = base.and_then(|b| b.runtime);
    let mut headers = vec!["Variant", "Size", "Δ size", "Crate rebuild", "Δ rebuild", "Full build"];
    if benched {
        headers.extend(["Runtime (median)", "Δ runtime"]);
    }
    let mut t = Table::new("Release profile variants", &headers);
    for m in results {
        let mut row = vec![
            m.name.to_string(),
            m.size.map(util::human_bytes).unwrap_or_else(|| "failed".into()),
            m.size.map(|s| pu::pct_delta(s as f64, bsize)).unwrap_or_default(),
            m.final_secs.map(fmt_secs).unwrap_or_default(),
            m.final_secs.map(|s| pu::pct_delta(s, btime)).unwrap_or_default(),
            m.full_secs.map(|s| format!("{}{}", fmt_secs(s), if m.deps_cached { " (deps cached)" } else { "" })).unwrap_or_default(),
        ];
        if benched {
            row.push(m.runtime.map(fmt_secs).unwrap_or_else(|| if m.bench_error.is_some() { "failed".into() } else { "-".into() }));
            row.push(match (m.runtime, brun) {
                (Some(r), Some(b)) => pu::pct_delta(r, b),
                _ => String::new(),
            });
        }
        t.row(row);
    }
    rep.table(t);

    let ok: Vec<&Measured> = results.iter().filter(|m| m.size.is_some()).collect();
    let aborts = |m: &Measured| m.env.iter().any(|(k, v)| *k == "PANIC" && *v == "abort");
    let smallest = ok.iter().min_by_key(|m| m.size.unwrap_or(u64::MAX)).copied();
    // a variant only counts as faster when it beats the baseline by more than 2% (timing noise)
    let fastest = ok
        .iter()
        .filter(|m| m.runtime.is_some())
        .min_by(|a, b| a.runtime.partial_cmp(&b.runtime).unwrap_or(std::cmp::Ordering::Equal))
        .copied()
        .filter(|f| match (f.runtime, brun) {
            (Some(r), Some(b)) => r < b * 0.98,
            _ => true,
        })
        .or(if benched { base } else { None });
    // trade-off: smallest binary that does not cost runtime (within 3% of baseline when measured;
    // without a benchmark, excluding size-optimized opt-levels) and keeps crate rebuilds under 3x
    let tradeoff = ok
        .iter()
        .filter(|m| m.name != "baseline")
        .filter(|m| unwind.is_empty() || !aborts(m))
        .filter(|m| match (m.runtime, brun) {
            (Some(r), Some(b)) => r <= b * 1.03,
            _ => !m.env.iter().any(|(k, _)| *k == "OPT_LEVEL"),
        })
        .filter(|m| btime <= 0.0 || m.final_secs.is_some_and(|s| s <= btime * 3.0 + 1.0))
        // worth a profile change only when the binary shrinks by at least 5%
        .filter(|m| m.size.is_some_and(|s| (s as f64) <= bsize * 0.95))
        .min_by_key(|m| m.size.unwrap_or(u64::MAX))
        .copied();

    let mut rt = Table::new("Recommendation", &["Goal", "Variant", "Result"]);
    let size_txt = |m: &Measured| format!("{} ({} vs baseline)", m.size.map(util::human_bytes).unwrap_or_default(), m.size.map(|s| pu::pct_delta(s as f64, bsize)).unwrap_or_default());
    if let Some(s) = smallest {
        rt.row(["Smallest binary".to_string(), s.name.to_string(), size_txt(s)]);
    }
    if let Some(f) = fastest {
        rt.row(["Fastest runtime".to_string(), f.name.to_string(), format!("{} ({} vs baseline, median of {runs})", f.runtime.map(fmt_secs).unwrap_or_default(), match (f.runtime, brun) { (Some(r), Some(b)) => pu::pct_delta(r, b), _ => "-".into() })]);
    }
    match tradeoff {
        Some(m) => rt.row([
            "Best trade-off".to_string(),
            m.name.to_string(),
            format!("{}; crate rebuild {}{}", size_txt(m), m.final_secs.map(fmt_secs).unwrap_or_default(), if benched { "; no runtime regression" } else { "; same opt-level" }),
        ]),
        None => rt.row(["Best trade-off".to_string(), "baseline".to_string(), "no variant was 5% smaller without a runtime or build-time cost".to_string()]),
    }
    rep.table(rt);

    let chosen = tradeoff.or(smallest);
    let snip = chosen.map(|m| snippet(base_prof, m.env)).unwrap_or_default();
    if let Some(m) = tradeoff {
        rep.finding(
            Finding::new(Severity::Info, "profile/recommendation", format!("Use the {} variant: {}", m.name, size_txt(m)))
                .detail(snip.clone())
                .fix("Paste the [profile.release] section above into the workspace root Cargo.toml"),
        );
    }
    if let Some(s) = smallest.filter(|s| s.name != "baseline" && Some(s.name) != tradeoff.map(|t| t.name) && s.size.is_some_and(|z| (z as f64) <= bsize * 0.95)) {
        rep.finding(
            Finding::new(Severity::Low, "profile/smallest", format!("Smallest binary with {}: {}", s.name, size_txt(s)))
                .detail(snippet(base_prof, s.env))
                .fix(if benched { "Check the runtime column before adopting a size-optimized profile" } else { "Size-optimized settings can slow the program down; rerun with --bench-cmd to measure" }),
        );
    }
    if !unwind.is_empty() && results.iter().any(|m| aborts(m)) {
        let (f, l) = &unwind[0];
        rep.finding(
            Finding::new(Severity::Medium, "profile/abort-breaks-catch-unwind", format!("panic = \"abort\" would break catch_unwind ({} call site(s))", unwind.len()))
                .at(f.clone(), Some(*l))
                .detail(unwind.iter().take(10).map(|(f, l)| format!("{f}:{l}")).collect::<Vec<_>>().join("\n"))
                .fix("With panic=abort a panic terminates the process and catch_unwind never returns Err; keep panic = \"unwind\" or remove the reliance on catching panics"),
        );
    }
    for m in results.iter().filter(|m| m.error.is_some()) {
        rep.finding(Finding::new(Severity::Low, "profile/variant-failed", format!("The {} variant did not build", m.name)).detail(m.error.clone().unwrap_or_default()));
    }
    for m in results.iter().filter(|m| m.bench_error.is_some()) {
        rep.note(format!("{}: {}", m.name, m.bench_error.clone().unwrap_or_default()));
    }
    rep.summary(match (smallest, tradeoff) {
        (Some(s), Some(t)) => format!("{} variants built; smallest: {} ({}); recommended: {}", results.len(), s.name, size_txt(s), t.name),
        (Some(s), None) => format!("{} variants built; smallest: {} ({}); baseline is already the best trade-off", results.len(), s.name, size_txt(s)),
        _ => "no variant built".into(),
    });
    if !snip.is_empty() {
        rep.note(format!("Snippet for the {} variant:\n{snip}", chosen.map(|m| m.name).unwrap_or("")));
    }
    rep.note("'Crate rebuild' is the time to rebuild only this package after `cargo clean -p` (what each change costs, including LTO and linking); dependencies are cached per variant under the sm-crates cache.");
    rep.data = json!({
        "variants": results.iter().map(|m| json!({
            "name": m.name,
            "settings": m.env.iter().map(|(k, v)| (toml_key(k).to_string(), Value::String(v.to_string()))).collect::<serde_json::Map<_, _>>(),
            "size_bytes": m.size, "rebuild_secs": m.final_secs.map(|x| pu::round(x, 3)), "full_build_secs": m.full_secs.map(|x| pu::round(x, 3)),
            "deps_cached": m.deps_cached, "runtime_secs": m.runtime.map(|x| pu::round(x, 4)), "error": m.error, "bench_error": m.bench_error,
        })).collect::<Vec<_>>(),
        "smallest": smallest.map(|m| m.name),
        "fastest": fastest.map(|m| m.name),
        "recommended": tradeoff.map(|m| m.name),
        "snippet": snip,
        "catch_unwind": unwind.iter().map(|(f, l)| format!("{f}:{l}")).collect::<Vec<_>>(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &'static str, size: u64, rebuild: f64, run: Option<f64>) -> Measured {
        let env = VARIANTS.iter().find(|v| v.name == name).map(|v| v.env).unwrap_or(&[]);
        Measured { name, env, full_secs: Some(rebuild * 2.0), deps_cached: false, final_secs: Some(rebuild), size: Some(size), exe: None, runtime: run, bench_error: None, error: None }
    }

    #[test]
    fn snippets_merge_project_settings() {
        let base = vec![("lto".to_string(), "\"thin\"".to_string()), ("debug".to_string(), "true".to_string())];
        let s = snippet(&base, &[("LTO", "fat"), ("CODEGEN_UNITS", "1"), ("OPT_LEVEL", "z")]);
        assert_eq!(s, "[profile.release]\nlto = \"fat\"\ndebug = true\ncodegen-units = 1\nopt-level = \"z\"");
        assert_eq!(toml_value("opt-level", "3"), "3");
    }

    #[test]
    fn recommends_tradeoff_and_warns_on_catch_unwind() {
        let rs = vec![m("baseline", 1000, 1.0, Some(1.0)), m("strip", 600, 1.0, Some(1.0)), m("opt-z", 400, 1.1, Some(1.5)), m("panic-abort", 500, 1.0, Some(0.9))];
        let mut rep = Report::new("profile", "x");
        report(&mut rep, &rs, &[], &[("src/main.rs".into(), 3)], true, 3);
        assert_eq!(rep.data["smallest"], "opt-z");
        assert_eq!(rep.data["fastest"], "panic-abort");
        // panic-abort is excluded because the code catches panics; opt-z is slower
        assert_eq!(rep.data["recommended"], "strip");
        assert!(rep.findings.iter().any(|f| f.code == "profile/abort-breaks-catch-unwind" && f.severity == Severity::Medium));
        assert!(rep.data["snippet"].as_str().unwrap().contains("strip = \"symbols\""));
    }

    #[test]
    fn variant_selection() {
        let mut a = Args::default();
        a.set_value("variants", "opt-z,strip");
        let v: Vec<&str> = chosen_variants(&a).unwrap().iter().map(|v| v.name).collect();
        assert_eq!(v, ["baseline", "opt-z", "strip"]);
        a.set_value("variants", "nope");
        assert!(chosen_variants(&a).is_err());
    }
}
