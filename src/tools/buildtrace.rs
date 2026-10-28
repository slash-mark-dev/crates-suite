//! Build Script Sandbox Trace: run build scripts and proc macros under a tracer and record every file,
//! network and process access.
//!
//! Build scripts and proc macros are arbitrary code that runs on the developer's
//! machine (and in CI, next to deploy credentials) the moment `cargo build`
//! starts. This tool builds the project in a fresh target directory with a
//! decoy home and a scrubbed environment, records what each piece of
//! build-time code does, and maps every event back to the crate responsible.
//!
//! Two modes:
//! * `strace` (Linux with strace): every exec, file, socket and process call of
//!   every process cargo starts is recorded; processes are attributed through
//!   the process tree (build-script-build executables, and rustc processes that
//!   load proc-macro libraries).
//! * `portable` (macOS, Windows, or no strace): PATH shims record programs
//!   started by name, a before/after snapshot of source, project and home
//!   directories records writes, and canary files in the decoy home record
//!   reads through access times. Network access is not observable.
//!
//! Both modes add a static scan of build-script and proc-macro sources for
//! environment variables they read, and the `cargo:` directives each build
//! script printed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{Metadata, Package};
use crate::registry::CrateSpec;
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::supplychain_util as su;
use crate::tools::{Group, Tool};
use crate::util;

pub struct BuildTrace;

const OPTS: &[Opt] = &[
    Opt::value("only", "A,B", "Only report these crates (the whole project is still built)"),
    Opt::value("features", "LIST", "Features to enable for the build"),
    Opt::flag("all-features", "Build with --all-features"),
    Opt::flag("no-default-features", "Build with --no-default-features"),
    Opt::flag("release", "Build the release profile"),
    Opt::flag("portable", "Use the portable observer even when strace is available"),
    Opt::flag("no-network", "Linux: run the build in an empty network namespace (unshare -rn), so connections fail but are still recorded"),
    Opt::flag("real-home", "Keep the real HOME for the build instead of a decoy home with canary credentials"),
    Opt::value("timeout", "SECS", "Time limit for the traced build (default 1800)"),
    Opt::flag("keep", "Keep the temporary target directory, decoy home and trace log (their paths are printed)"),
];

/// Syscalls recorded in strace mode. `?` makes strace ignore names the architecture lacks.
const TRACE_SET: &str = "?execve,?execveat,?clone,?clone3,?fork,?vfork,?open,?openat,?openat2,?creat,?mkdir,?mkdirat,?unlink,?unlinkat,?rename,?renameat,?renameat2,?link,?linkat,?symlink,?symlinkat,?chmod,?fchmodat,?truncate,?access,?faccessat,?faccessat2,?chdir,?connect,?bind,?listen,?sendto,?sendmsg";

impl Tool for BuildTrace {
    fn name(&self) -> &'static str {
        "buildtrace"
    }
    fn title(&self) -> &'static str {
        "Build Script Sandbox Trace"
    }
    fn group(&self) -> Group {
        Group::SupplyChain
    }
    fn summary(&self) -> &'static str {
        "Run build scripts and proc macros under a tracer and record every file, network and process access"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Builds the project (or, for CRATE[@VERSION] arguments, a throwaway project that depends on them)
with `cargo build` in a fresh target directory, so every build script and proc macro really runs, and
records what that build-time code does. Each event is attributed to the crate whose build script
(build-script-build and everything it starts) or proc macro (the rustc process that loads it while
compiling another crate) caused it.

The build runs with a decoy HOME holding canary credentials (~/.ssh/id_rsa, ~/.aws/credentials,
~/.cargo/credentials.toml, ~/.netrc, ...) and a decoy CARGO_HOME (registry caches linked, config
without tokens, the canary credentials.toml), with token-like environment variables (*_TOKEN, *_KEY,
*_SECRET, AWS_*, SSH_AUTH_SOCK, ...) removed, RUSTC_WRAPPER disabled, and dependencies fetched
beforehand so the build itself runs --offline. --no-network (Linux) also runs it in an empty network
namespace. This contains secrets reached through $HOME and the environment, not code that reads
absolute paths: it is an observation harness, not a security boundary. Run untrusted crates in a VM.

Modes. strace (Linux with strace installed and ptrace allowed) is the only full trace: every
exec, open/create/rename/unlink, connect/bind/sendto of every process is recorded. portable (macOS,
Windows, no strace, or --portable) sees only programs started by name through PATH shims (Unix),
files changed in package sources, the project and home (before/after snapshot), and canary reads
via access times; it cannot see network access or absolute-path programs, and cannot attribute
file changes outside a package's own directory. The report says which mode ran.

Findings: network connections (high; local services medium; an ssh-agent or docker socket
critical), listening sockets (high), reads of credential files (critical when opened, high when
attempted, medium when only probed), writes outside OUT_DIR/target (high; into the package's own
sources high; temp files low), network tools started (curl, wget, nc, ssh, git fetch/clone: high),
unknown programs (medium) and helper programs such as sh, perl, python (low). Compilers, linkers
and build tools (cc, gcc, clang, ar, ld, cmake, make, pkg-config, rustc ...) are listed but not
flagged. Build-script and proc-macro sources are also scanned for environment variables they read
(env::var, env!, option_env!, cargo:rerun-if-env-changed): token-like names are high, reading the
whole environment is low. CRATE mode only compiles proc macros; they run when code uses them, so
trace a project that does; there --features applies to the named crates (`feat` or `crate/feat`).
SM_CRATES_CARGO overrides the cargo executable."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates buildtrace",
            "sm-crates buildtrace --no-network --json",
            "sm-crates buildtrace openssl-sys@0.9.103 --features vendored",
            "sm-crates buildtrace libz-sys --portable --fail-on medium",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo; strace on Linux for the full trace (portable observer elsewhere); network unless dependencies are cached"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let timeout = Duration::from_secs(args.parse_or("timeout", 1800u64)?.max(10));
        let mut cleanup: Vec<PathBuf> = Vec::new();
        let result = trace(ctx, args, timeout, &mut cleanup);
        if !args.flag("keep") {
            for p in &cleanup {
                let _ = std::fs::remove_dir_all(p);
                let _ = std::fs::remove_file(p);
            }
        }
        result
    }
}

// ---------------------------------------------------------------- the run

fn trace(ctx: &Ctx, args: &Args, timeout: Duration, cleanup: &mut Vec<PathBuf>) -> Result<Report> {
    // 1. What to build.
    let (subject, manifest, crate_mode) = if args.positional.is_empty() {
        let m = ctx.manifest_path();
        if !m.is_file() {
            return Err(Error::Env(format!("no Cargo.toml at {} (run inside a Cargo project, pass --project DIR, or name crates)", m.display())));
        }
        (format!("project {}", ctx.project_root().display()), m, false)
    } else {
        let mut resolved = Vec::new();
        for p in &args.positional {
            let spec = CrateSpec::parse(p)?;
            resolved.push(spec.resolve(ctx)?);
        }
        let deps: Vec<(String, String)> = resolved.iter().map(|v| (v.name.clone(), v.vers.clone())).collect();
        let dir = util::temp_dir("buildtrace-probe")?;
        cleanup.push(dir.clone());
        let mut toml = String::from("[package]\nname = \"sm-buildtrace-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\n");
        // --features / --all-features / --no-default-features apply to the named crates, not the probe
        let per_crate = probe_features(&resolved, &args.list("features"), args.flag("all-features"))?;
        for ((n, v), feats) in deps.iter().zip(&per_crate) {
            let list = feats.iter().map(|f| format!("{f:?}")).collect::<Vec<_>>().join(", ");
            let ndf = if args.flag("no-default-features") { ", default-features = false" } else { "" };
            toml.push_str(&format!("{n} = {{ version = \"={v}\", features = [{list}]{ndf} }}\n"));
        }
        toml.push_str("\n[workspace]\n");
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("Cargo.toml"), toml)?;
        std::fs::write(dir.join("src").join("lib.rs"), "")?;
        let label = deps.iter().map(|(n, v)| format!("{n}@{v}")).collect::<Vec<_>>().join(", ");
        (label, dir.join("Cargo.toml"), true)
    };
    let project_dir = manifest.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut rep = Report::new("buildtrace", subject);

    let homes = Homes::detect();
    let real_env = BuildEnv::from_process();

    // 2. Fetch first (with the real environment), so the traced build runs --offline.
    if !ctx.offline {
        let mut c = Command::new(&ctx.cargo);
        c.args(["fetch", "--manifest-path"]).arg(&manifest).current_dir(&project_dir).env("CARGO_TERM_COLOR", "never");
        let o = util::run(&mut c, timeout)?;
        if !o.success() {
            return Err(Error::Env(format!("cargo fetch failed:\n{}", tail(&o.stderr, 15))));
        }
    }
    let meta = load_metadata(ctx, &manifest, args, crate_mode)?;

    // 3. Which packages run code at build time.
    let reach = meta.reachable(false, true);
    let actors: Vec<&Package> = meta.packages.iter().filter(|p| reach.contains(&p.id) && (p.has_build_script() || p.is_proc_macro())).collect();
    let only: Vec<String> = args.list("only").iter().map(|s| util::normalize_crate_name(s)).collect();
    let wanted = |name: &str| only.is_empty() || only.contains(&util::normalize_crate_name(name));
    if actors.is_empty() {
        rep.summary("no build scripts or proc macros in the dependency graph: no third-party code runs at build time");
        rep.data = json!({"mode": Value::Null, "crates": [], "build": Value::Null});
        return Ok(rep);
    }

    // 4. Static scan: environment variables read by build scripts and proc macros.
    let mut crates: BTreeMap<(String, String), CrateTrace> = BTreeMap::new();
    for p in &actors {
        let e = crates.entry((p.name.clone(), p.version.clone())).or_insert_with(|| CrateTrace::new(p, &meta));
        e.env = scan_env(p);
    }

    // 5. Mode and sandbox.
    let want_net_isolation = args.flag("no-network");
    let mut mode = Mode::Portable;
    let mut mode_note: Option<String> = None;
    let mut strace_extra: Vec<&str> = vec!["--seccomp-bpf"];
    if args.flag("portable") {
        mode_note = Some("portable mode requested with --portable".into());
    } else if !cfg!(target_os = "linux") {
        mode_note = Some("strace tracing is Linux-only; used the portable observer".into());
    } else {
        match strace_probe() {
            Ok(extra) => {
                strace_extra = extra;
                mode = Mode::Strace;
            }
            Err(e) => mode_note = Some(format!("strace unavailable ({e}); used the portable observer. Install strace (e.g. `apt install strace`) for a full trace")),
        }
    }
    let net_isolated = if want_net_isolation {
        if cfg!(target_os = "linux") && util::run(Command::new("unshare").args(["-rn", "true"]), Duration::from_secs(30)).map(|o| o.success()).unwrap_or(false) {
            true
        } else {
            rep.note("--no-network: `unshare -rn` is not available here (needs Linux user namespaces); the build ran with network access");
            false
        }
    } else {
        false
    };

    let work = util::temp_dir("buildtrace")?;
    cleanup.push(work.clone());
    let target_dir = work.join("target");
    let log_path = work.join("trace.log");
    let decoy = if args.flag("real-home") { None } else { Some(make_decoy_home(&work.join("home"))?) };
    let shim_dir = if mode == Mode::Portable && cfg!(unix) { Some(make_shims(&work.join("shims"), &work.join("shims.log"))?) } else { None };

    let mut env = real_env.clone();
    let scrubbed = env.scrub();
    env.set("CARGO_TERM_COLOR", "never");
    env.set("RUSTC_WRAPPER", "");
    env.set("CARGO_BUILD_RUSTC_WRAPPER", "");
    env.remove("CARGO_TARGET_DIR");
    env.remove("CARGO_BUILD_TARGET_DIR");
    // CARGO_HOME: with a decoy home, a decoy cargo home too. Build scripts see $CARGO_HOME, and
    // the real one holds credentials.toml (the registry token) and token settings in config.toml.
    let mut decoy_cargo: Option<PathBuf> = None;
    if let Some(h) = homes.cargo_home.as_ref() {
        match decoy.as_ref().map(|d| make_decoy_cargo_home(h, &d.root)) {
            Some(Ok(dc)) => {
                env.set("CARGO_HOME", &dc.to_string_lossy());
                decoy_cargo = Some(dc);
            }
            Some(Err(e)) => {
                rep.note(format!("could not set up a decoy CARGO_HOME ({e}); build scripts could read the real {}", h.display()));
                env.set("CARGO_HOME", &h.to_string_lossy());
            }
            None => env.set("CARGO_HOME", &h.to_string_lossy()),
        }
    }
    if let Some(h) = homes.rustup_home.as_ref() {
        env.set("RUSTUP_HOME", &h.to_string_lossy());
    }
    if let Some(d) = &decoy {
        env.set("HOME", &d.root.to_string_lossy());
        if cfg!(windows) {
            env.set("USERPROFILE", &d.root.to_string_lossy());
        }
    }
    if let Some((dir, log)) = &shim_dir {
        let path = std::env::join_paths(std::iter::once(dir.clone()).chain(std::env::split_paths(&std::ffi::OsString::from(env.get("PATH").unwrap_or_default())))).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        env.set("PATH", &path);
        env.set("SM_BUILDTRACE_LOG", &log.to_string_lossy());
    }

    // 6. Snapshot (portable).
    let snap_roots = snapshot_roots(&meta, &homes, decoy.as_ref());
    let before = if mode == Mode::Portable { Some(snapshot(&snap_roots)) } else { None };

    // 7. The build.
    let mut argv: Vec<String> = Vec::new();
    if net_isolated {
        argv.extend(["unshare".into(), "-rn".into()]);
    }
    if mode == Mode::Strace {
        argv.extend(["strace", "-f", "-qq", "-v", "-yy", "-s", "4096", "-e", "signal=none", "-e"].iter().map(|s| s.to_string()));
        argv.push(format!("trace={TRACE_SET}"));
        argv.extend(strace_extra.iter().map(|s| s.to_string()));
        argv.push("-o".into());
        argv.push(log_path.to_string_lossy().into_owned());
    }
    argv.push(ctx.cargo.clone());
    argv.extend(["build", "--message-format", "json-render-diagnostics", "--offline", "--manifest-path"].iter().map(|s| s.to_string()));
    argv.push(manifest.to_string_lossy().into_owned());
    argv.push("--target-dir".into());
    argv.push(target_dir.to_string_lossy().into_owned());
    if args.flag("release") {
        argv.push("--release".into());
    }
    if args.flag("all-features") && !crate_mode {
        argv.push("--all-features".into());
    }
    if args.flag("no-default-features") && !crate_mode {
        argv.push("--no-default-features".into());
    }
    let features = if crate_mode { Vec::new() } else { args.list("features") };
    if !features.is_empty() {
        argv.push("--features".into());
        argv.push(features.join(","));
    }
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(&project_dir).env_clear().envs(env.vars.iter().map(|(k, v)| (k, v)));
    let out = util::run(&mut cmd, timeout)?;
    let build_ok = out.success();

    // 8. What cargo reported: build scripts run, their OUT_DIRs, proc macros built.
    let mut out_dirs: Vec<(String, (String, String))> = Vec::new();
    for line in out.stdout.lines().filter(|l| l.starts_with('{')) {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let Some(pkg) = v["package_id"].as_str().and_then(|id| meta.package(id)) else { continue };
        let key = (pkg.name.clone(), pkg.version.clone());
        match v["reason"].as_str() {
            Some("build-script-executed") => {
                if let Some(ct) = crates.get_mut(&key) {
                    ct.ran_build_script = true;
                    ct.links_libs = v["linked_libs"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    ct.link_paths = v["linked_paths"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                    ct.rustc_env = v["env"].as_array().map(|a| a.iter().filter_map(|x| x[0].as_str().map(String::from)).collect()).unwrap_or_default();
                    if let Some(od) = v["out_dir"].as_str() {
                        out_dirs.push((od.to_string(), key.clone()));
                        let output = Path::new(od).parent().map(|p| p.join("output"));
                        if let Some(text) = output.and_then(|p| std::fs::read_to_string(p).ok()) {
                            ct.apply_directives(&text);
                        }
                    }
                }
            }
            Some("compiler-artifact") => {
                if v["target"]["kind"].as_array().is_some_and(|k| k.iter().any(|x| x == "proc-macro")) {
                    if let Some(ct) = crates.get_mut(&key) {
                        ct.macro_built = true;
                    }
                }
            }
            _ => {}
        }
    }

    // 9. Events.
    let mut zones = Zones::new(&meta, &homes, decoy.as_ref(), &target_dir, &out_dirs, &work);
    if let (Some(real), Some(dc)) = (&homes.cargo_home, &decoy_cargo) {
        zones.alias_cargo_home(real, dc);
    }
    let mut unattributed = CrateTrace::unattributed();
    let mut portable_info = json!(null);
    match mode {
        Mode::Strace => {
            let open = || std::fs::File::open(&log_path).map(std::io::BufReader::new);
            if let Err(e) = open() {
                return Err(Error::Env(format!("strace log {}: {e}", log_path.display())));
            }
            let ev = parse_strace(open, &meta)?;
            apply_events(&ev, &zones, &mut crates);
            if let Ok(m) = std::fs::metadata(&log_path) {
                rep.note(format!("strace recorded {} of exec, file and socket calls", util::human_bytes(m.len())));
            }
        }
        Mode::Portable => {
            if let Some(before) = &before {
                let after = snapshot(&snap_roots);
                portable_changes(before, &after, &zones, &mut crates, &mut unattributed);
            }
            let read_detection = decoy.as_ref().is_some_and(|d| d.atime_works);
            if let Some(d) = decoy.as_ref().filter(|d| d.atime_works) {
                for (path, label) in &d.canaries {
                    if canary_read(path) {
                        unattributed.sensitive.insert(zones.display(&path.to_string_lossy()), Sensitive { label: label.to_string(), access: Access::Opened });
                    }
                }
            }
            if let Some((_, log)) = &shim_dir {
                apply_shim_log(log, &meta, &mut crates, &mut unattributed);
            }
            portable_info = json!({
                "process_shims": shim_dir.is_some(),
                "canary_read_detection": read_detection,
                "network_observed": false,
            });
        }
    }
    if mode == Mode::Portable {
        rep.note(format!(
            "portable observer: programs started by name via PATH shims{}, file changes by before/after snapshot, canary reads by access time{}; network access and absolute-path programs are NOT observed",
            if shim_dir.is_none() { " (unavailable on this OS)" } else { "" },
            if decoy.as_ref().is_some_and(|d| !d.atime_works) { " (unavailable: the file system does not update access times)" } else { "" }
        ));
    }
    if let Some(n) = &mode_note {
        rep.note(n.clone());
    }

    // 10. Report.
    let mut summary_t = Table::new("Build-time code", &["Crate", "Version", "Kind", "Ran", "Programs", "Network", "Writes outside", "Credential access", "Env vars"]);
    let mut proc_t = Table::new("Programs started", &["Crate", "Program", "Class", "Runs", "Example"]);
    let mut net_t = Table::new("Network activity", &["Crate", "Operation", "Address", "Result"]);
    let mut data = Vec::new();
    let mut all: Vec<&CrateTrace> = crates.values().collect();
    if !unattributed.is_empty() {
        all.push(&unattributed);
    }
    for ct in all {
        if !ct.unattributed && !wanted(&ct.name) {
            continue;
        }
        for f in ct.findings() {
            rep.finding(f);
        }
        if !ct.unattributed {
            summary_t.row([
                ct.name.clone(),
                ct.version.clone(),
                ct.kinds.iter().cloned().collect::<Vec<_>>().join(" + "),
                ct.ran_label(),
                if ct.procs.is_empty() { "-".into() } else { ct.procs.keys().map(|(p, _)| p.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(", ") },
                ct.net.len().to_string(),
                ct.writes.len().to_string(),
                ct.sensitive.len().to_string(),
                ct.env_label(),
            ]);
        }
        for ((prog, class), p) in &ct.procs {
            proc_t.row([ct.display_name(), prog.clone(), class.label().to_string(), if p.found { p.count.to_string() } else { "not found".into() }, p.example.clone()]);
        }
        for n in &ct.net {
            net_t.row([ct.display_name(), n.op.clone(), n.address.clone(), n.result.clone()]);
        }
        data.push(ct.to_json());
    }
    rep.table(summary_t);
    rep.table(proc_t);
    rep.table(net_t);

    if !build_ok {
        let why = if out.timed_out { format!("timed out after {}s", timeout.as_secs()) } else { tail(&out.stderr, 12) };
        rep.finding(
            Finding::new(Severity::Info, "buildtrace/build-failed", "the traced build did not finish; build-time code after the failure point was not observed")
                .detail(why)
                .fix("fix the build (e.g. install missing system libraries) and run again"),
        );
    }
    let flagged = rep.findings.iter().filter(|f| f.severity >= Severity::Medium).count();
    let bs = crates.values().filter(|c| c.ran_build_script).count();
    let pm = crates.values().filter(|c| c.kinds.contains("proc macro")).count();
    rep.summary(format!(
        "{} mode: {bs} build script(s) ran, {pm} proc-macro crate(s) built; {flagged} finding(s) at medium or above{}",
        mode.label(),
        if build_ok { "" } else { " (build failed: trace incomplete)" }
    ));
    if !scrubbed.is_empty() {
        rep.note(format!("removed from the build environment: {}", scrubbed.join(", ")));
    }
    if crate_mode && pm > 0 {
        rep.note("CRATE mode compiles proc macros but does not run them (they only run where code uses them); trace a project that uses them to observe their behaviour");
    }
    if net_isolated {
        rep.note("the build ran in an empty network namespace (--no-network): connections were attempted but could not succeed");
    }
    if args.flag("keep") {
        rep.note(format!("kept: target dir {}, decoy home {}, trace {}", target_dir.display(), work.join("home").display(), log_path.display()));
    }
    rep.data = json!({
        "mode": mode.label(),
        "sandbox": {
            "decoy_home": decoy.is_some(),
            "decoy_cargo_home": decoy_cargo.is_some(),
            "network_isolated": net_isolated,
            "scrubbed_env": scrubbed,
            "rustc_wrapper_disabled": true,
        },
        "portable": portable_info,
        "build": {"success": build_ok, "timed_out": out.timed_out, "duration_secs": (out.elapsed.as_secs_f64() * 10.0).round() / 10.0, "command": argv_display(&argv, &work)},
        "crates": data,
    });
    Ok(rep)
}

/// CRATE mode: the features to enable on each named crate. `crate/feat` applies to that crate,
/// a bare `feat` to every named crate that has it (an error if none does).
fn probe_features(crates: &[crate::registry::index::IndexVersion], features: &[String], all: bool) -> Result<Vec<Vec<String>>> {
    let available = |c: &crate::registry::index::IndexVersion| -> BTreeSet<String> {
        let mut f: BTreeSet<String> = c.all_features().into_keys().collect();
        let explicit_dep = c.all_features().values().flatten().any(|x| x.starts_with("dep:"));
        if !explicit_dep {
            f.extend(c.deps.iter().filter(|d| d.optional).map(|d| d.name.clone()));
        }
        f
    };
    let mut out: Vec<Vec<String>> = crates.iter().map(|c| if all { available(c).into_iter().collect() } else { Vec::new() }).collect();
    for f in features {
        let (target, feat) = match f.split_once('/') {
            Some((c, x)) => (Some(util::normalize_crate_name(c)), x.to_string()),
            None => (None, f.clone()),
        };
        let mut used = false;
        for (i, c) in crates.iter().enumerate() {
            let matches = match &target {
                Some(t) => *t == util::normalize_crate_name(&c.name),
                None => available(c).contains(&feat),
            };
            if matches {
                if !out[i].contains(&feat) {
                    out[i].push(feat.clone());
                }
                used = true;
            }
        }
        if !used {
            return Err(Error::Usage(format!(
                "--features {f}: none of the named crates ({}) has this feature",
                crates.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ")
            )));
        }
    }
    Ok(out)
}

fn argv_display(argv: &[String], work: &Path) -> String {
    let w = work.to_string_lossy();
    argv.iter().map(|a| a.replace(w.as_ref(), "$WORK")).collect::<Vec<_>>().join(" ")
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

fn load_metadata(ctx: &Ctx, manifest: &Path, args: &Args, crate_mode: bool) -> Result<Metadata> {
    let mut cmd = Command::new(&ctx.cargo);
    cmd.args(["metadata", "--format-version", "1", "--manifest-path"]).arg(manifest).arg("--offline");
    if args.flag("all-features") && !crate_mode {
        cmd.arg("--all-features");
    }
    if args.flag("no-default-features") && !crate_mode {
        cmd.arg("--no-default-features");
    }
    let features = if crate_mode { Vec::new() } else { args.list("features") };
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    let out = util::run(&mut cmd, Duration::from_secs(600))?;
    if !out.success() {
        return Err(Error::Env(format!("cargo metadata failed:\n{}", tail(&out.stderr, 15))));
    }
    serde_json::from_str(&out.stdout).map_err(|e| Error::Parse(format!("cargo metadata output: {e}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Strace,
    Portable,
}

impl Mode {
    fn label(&self) -> &'static str {
        match self {
            Mode::Strace => "strace",
            Mode::Portable => "portable",
        }
    }
}

/// Check that strace runs and may ptrace here; returns extra flags it supports.
fn strace_probe() -> std::result::Result<Vec<&'static str>, String> {
    if util::which("strace").is_none() {
        return Err("strace is not installed".into());
    }
    let probe = |extra: &[&str]| {
        let mut c = Command::new("strace");
        c.args(["-f", "-qq", "-o", "/dev/null", "-e"]).arg(format!("trace={TRACE_SET}")).args(extra).arg("true");
        util::run(&mut c, Duration::from_secs(60))
    };
    match probe(&["--seccomp-bpf"]) {
        Ok(o) if o.success() => return Ok(vec!["--seccomp-bpf"]),
        _ => {}
    }
    match probe(&[]) {
        Ok(o) if o.success() => Ok(vec![]),
        Ok(o) => Err(o.stderr.lines().last().unwrap_or("strace failed (ptrace not permitted?)").trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------- environment

#[derive(Clone)]
struct BuildEnv {
    vars: Vec<(String, String)>,
}

impl BuildEnv {
    fn from_process() -> BuildEnv {
        BuildEnv { vars: std::env::vars_os().map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())).collect() }
    }
    fn get(&self, k: &str) -> Option<String> {
        self.vars.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone())
    }
    fn set(&mut self, k: &str, v: &str) {
        self.remove(k);
        self.vars.push((k.to_string(), v.to_string()));
    }
    fn remove(&mut self, k: &str) {
        self.vars.retain(|(x, _)| x != k);
    }
    /// Remove token-like variables; returns their names.
    fn scrub(&mut self) -> Vec<String> {
        let mut gone: Vec<String> = self.vars.iter().filter(|(k, _)| scrub_env(k)).map(|(k, _)| k.clone()).collect();
        self.vars.retain(|(k, _)| !scrub_env(k));
        gone.sort();
        gone
    }
}

/// Variables removed from the build environment: credential-like names and every AWS_* setting
/// (session tokens, credential URIs and files), except aws-lc-sys build options (AWS_LC_*).
fn scrub_env(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    sensitive_env(name) || (u.starts_with("AWS_") && !u.starts_with("AWS_LC_"))
}

/// Whether an environment variable name looks like it holds a credential.
pub fn sensitive_env(name: &str) -> bool {
    let u = name.to_ascii_uppercase();
    if ["CARGO_PKG_", "CARGO_CFG_", "CARGO_FEATURE_", "DEP_", "CARGO_MANIFEST_", "CARGO_ENCODED_"].iter().any(|p| u.starts_with(p)) {
        return false;
    }
    const EXACT: &[&str] = &[
        "SSH_AUTH_SOCK",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AZURE_CLIENT_SECRET",
        "NETRC",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "KUBECONFIG",
        "DOCKER_AUTH_CONFIG",
    ];
    if EXACT.contains(&u.as_str()) {
        return true;
    }
    const SUFFIX: &[&str] = &["_TOKEN", "_SECRET", "_PASSWORD", "_PASSWD", "_PASS", "_KEY", "_PAT", "_CREDENTIALS", "_CREDENTIAL", "_APIKEY", "_AUTH"];
    if SUFFIX.iter().any(|s| u.ends_with(s)) {
        return true;
    }
    u.starts_with("AWS_SECRET") || u.starts_with("SECRET_") || u.contains("PRIVATE_KEY") || u == "TOKEN" || u == "PASSWORD"
}

/// Environment variables a build script or proc macro reads, from its sources.
#[derive(Debug, Clone, Default)]
struct EnvUse {
    referenced: BTreeSet<String>,
    declared: BTreeSet<String>,
    enumerates: bool,
    /// file where each sensitive name was found
    sources: BTreeMap<String, String>,
}

/// `env::var("X")`, `var_os("X")`, `env!("X")`, `option_env!("X")` names, and whether the whole environment is enumerated.
pub fn env_refs(text: &str) -> (BTreeSet<String>, bool) {
    let mut names = BTreeSet::new();
    for pat in ["var(", "var_os(", "env!(", "option_env!(", "env! (", "var ("] {
        let mut start = 0;
        while let Some(i) = text[start..].find(pat) {
            let at = start + i;
            start = at + pat.len();
            // `var(` must not be the tail of a longer identifier (e.g. `my_var(`)
            if pat.starts_with("var") {
                let prev = text[..at].chars().next_back();
                if prev.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
            }
            let rest = text[start..].trim_start();
            if let Some(r) = rest.strip_prefix('"') {
                if let Some(end) = r.find('"') {
                    let n = &r[..end];
                    if !n.is_empty() && n.len() < 100 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                        names.insert(n.to_string());
                    }
                }
            }
        }
    }
    let enumerates = ["env::vars()", "env::vars_os()", "vars_os()", "std::env::vars ()"].iter().any(|p| text.contains(p))
        || text.contains("vars()") && text.contains("use std::env");
    (names, enumerates)
}

fn scan_env(p: &Package) -> EnvUse {
    let mut out = EnvUse::default();
    let mut files: BTreeSet<PathBuf> = BTreeSet::new();
    for t in &p.targets {
        let is_bs = t.kind.iter().any(|k| k == "custom-build");
        let is_pm = t.kind.iter().any(|k| k == "proc-macro");
        if !(is_bs || is_pm) {
            continue;
        }
        files.insert(t.src_path.clone());
        // modules next to the entry file (build/main.rs + build/foo.rs; src/**)
        if let Some(dir) = t.src_path.parent() {
            if is_pm || dir != p.dir() {
                for f in util::walk_files(dir).into_iter().filter(|f| f.extension().is_some_and(|e| e == "rs")).take(500) {
                    files.insert(f);
                }
            }
        }
    }
    for f in files {
        let Ok(text) = util::read_to_string_lossy(&f) else { continue };
        let (names, en) = env_refs(&text);
        out.enumerates |= en;
        for n in names {
            if sensitive_env(&n) {
                out.sources.entry(n.clone()).or_insert_with(|| util::rel(&p.dir(), &f));
            }
            out.referenced.insert(n);
        }
    }
    out
}

// ---------------------------------------------------------------- places

struct Homes {
    real_home: Option<PathBuf>,
    cargo_home: Option<PathBuf>,
    rustup_home: Option<PathBuf>,
}

impl Homes {
    fn detect() -> Homes {
        let real_home = su::home_dir();
        let rustup_home = std::env::var_os("RUSTUP_HOME").map(PathBuf::from).or_else(|| real_home.as_ref().map(|h| h.join(".rustup"))).filter(|p| p.is_dir());
        Homes { cargo_home: su::cargo_home().filter(|p| p.is_dir()), rustup_home, real_home }
    }
}

struct Decoy {
    root: PathBuf,
    canaries: Vec<(PathBuf, &'static str)>,
    atime_works: bool,
}

const CANARY_TIME: u64 = 1_000_000_000; // 2001-09-09

const CANARIES: &[(&str, &str)] = &[
    (".ssh/id_rsa", "SSH private key"),
    (".ssh/id_ed25519", "SSH private key"),
    (".aws/credentials", "AWS credentials"),
    (".cargo/credentials.toml", "cargo registry token"),
    (".netrc", ".netrc passwords"),
    (".git-credentials", "git credentials"),
    (".config/gh/hosts.yml", "GitHub CLI token"),
    (".docker/config.json", "Docker registry credentials"),
    (".kube/config", "Kubernetes credentials"),
    (".npmrc", "npm token"),
    (".pypirc", "PyPI credentials"),
    (".config/gcloud/credentials.db", "Google Cloud credentials"),
];

fn make_decoy_home(root: &Path) -> Result<Decoy> {
    std::fs::create_dir_all(root)?;
    let mut canaries = Vec::new();
    for (rel, label) in CANARIES {
        let p = root.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&p, format!("SM-CRATES BUILDTRACE CANARY: not a real {label}\n"))?;
        set_old_times(&p);
        canaries.push((p, *label));
    }
    // does this file system record reads in atime?
    let probe = root.join(".sm-atime-probe");
    std::fs::write(&probe, b"probe")?;
    set_old_times(&probe);
    let _ = std::fs::read(&probe);
    let atime_works = canary_read(&probe);
    let _ = std::fs::remove_file(&probe);
    Ok(Decoy { root: root.to_path_buf(), canaries, atime_works })
}

/// A CARGO_HOME inside the decoy home for the build: the real `registry` and `git` caches are
/// linked (the build runs --offline from them), `config.toml` is copied without registry tokens,
/// and `credentials.toml` is the decoy's canary.
fn make_decoy_cargo_home(real: &Path, decoy_root: &Path) -> Result<PathBuf> {
    let dir = decoy_root.join(".cargo");
    std::fs::create_dir_all(&dir)?;
    for sub in ["registry", "git"] {
        let src = real.join(sub);
        if src.is_dir() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&src, dir.join(sub))?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_dir(&src, dir.join(sub))?;
        }
    }
    for cfg in ["config.toml", "config"] {
        if let Ok(text) = std::fs::read_to_string(real.join(cfg)) {
            let clean = strip_registry_tokens(&text).ok_or_else(|| Error::Parse(format!("{} is not valid TOML", real.join(cfg).display())))?;
            std::fs::write(dir.join(cfg), clean)?;
        }
    }
    Ok(dir)
}

/// Cargo config without `registry.token` / `registries.<name>.token`.
pub fn strip_registry_tokens(text: &str) -> Option<String> {
    let mut v: toml::Table = toml::from_str(text).ok()?;
    if let Some(r) = v.get_mut("registry").and_then(|r| r.as_table_mut()) {
        r.remove("token");
    }
    if let Some(rs) = v.get_mut("registries").and_then(|r| r.as_table_mut()) {
        for (_, r) in rs.iter_mut() {
            if let Some(t) = r.as_table_mut() {
                t.remove("token");
            }
        }
    }
    toml::to_string(&v).ok()
}

fn set_old_times(p: &Path) {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(CANARY_TIME);
    if let Ok(f) = std::fs::File::options().write(true).open(p) {
        let _ = f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t));
    }
}

fn canary_read(p: &Path) -> bool {
    std::fs::metadata(p)
        .and_then(|m| m.accessed())
        .ok()
        .and_then(|a| a.duration_since(SystemTime::UNIX_EPOCH).ok())
        .is_some_and(|d| d.as_secs() > CANARY_TIME + 60)
}

/// Where a path is, relative to the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Zone {
    /// target dir or an OUT_DIR
    Target,
    /// a package's own source directory
    PackageSource,
    /// the project being built
    Workspace,
    Temp,
    /// device files, /proc/self
    Device,
    /// toolchain, cargo home, system directories
    System,
    Home,
    Other,
}

struct Zones {
    target: Vec<String>,
    out_dirs: Vec<(String, (String, String))>,
    packages: Vec<(String, (String, String))>,
    workspace: Vec<String>,
    temp: Vec<String>,
    system: Vec<String>,
    homes: Vec<(String, &'static str)>,
    work: Vec<String>,
}

fn path_forms(p: &Path) -> Vec<String> {
    let mut v = vec![p.to_string_lossy().trim_end_matches('/').to_string()];
    if let Ok(c) = p.canonicalize() {
        let c = c.to_string_lossy().trim_end_matches('/').to_string();
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v.retain(|s| !s.is_empty());
    v
}

fn under(p: &str, prefix: &str) -> bool {
    p == prefix || (p.starts_with(prefix) && p.as_bytes().get(prefix.len()) == Some(&b'/'))
}

impl Zones {
    fn new(meta: &Metadata, homes: &Homes, decoy: Option<&Decoy>, target: &Path, out_dirs: &[(String, (String, String))], work: &Path) -> Zones {
        let mut packages = Vec::new();
        for p in &meta.packages {
            if meta.is_member(&p.id) {
                continue;
            }
            for f in path_forms(&p.dir()) {
                packages.push((f, (p.name.clone(), p.version.clone())));
            }
        }
        // longest prefix first
        packages.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let mut workspace = path_forms(&meta.workspace_root);
        for m in meta.members() {
            workspace.extend(path_forms(&m.dir()));
        }
        let mut temp = path_forms(&std::env::temp_dir());
        temp.extend(["/tmp".to_string(), "/var/tmp".to_string(), "/dev/shm".to_string()]);
        let mut system: Vec<String> = ["/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/etc", "/opt", "/nix", "/snap", "/proc", "/sys", "/run", "/var/lib", "/var/cache", "/System", "/Library", "/Applications", "/private/etc", "/Library/Developer"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        for h in [&homes.cargo_home, &homes.rustup_home].into_iter().flatten() {
            system.extend(path_forms(h));
        }
        let mut hs = Vec::new();
        if let Some(d) = decoy {
            for f in path_forms(&d.root) {
                hs.push((f, "~"));
            }
        }
        if let Some(h) = &homes.real_home {
            for f in path_forms(h) {
                hs.push((f, "~"));
            }
        }
        hs.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let mut od: Vec<(String, (String, String))> = Vec::new();
        for (d, k) in out_dirs {
            for f in path_forms(Path::new(d)) {
                od.push((f, k.clone()));
            }
        }
        Zones { target: path_forms(target), out_dirs: od, packages, workspace, temp, system, homes: hs, work: path_forms(work) }
    }

    fn zone(&self, p: &str) -> Zone {
        if self.target.iter().any(|t| under(p, t)) || self.out_dirs.iter().any(|(t, _)| under(p, t)) {
            return Zone::Target;
        }
        if p.starts_with("/dev/") || p == "/dev" || p.starts_with("/proc/self/") || p.starts_with("/proc/thread-self/") || p.starts_with("pipe:") || p.starts_with("anon_inode:") {
            return Zone::Device;
        }
        if self.packages.iter().any(|(d, _)| under(p, d)) {
            return Zone::PackageSource;
        }
        if self.workspace.iter().any(|d| under(p, d)) {
            return Zone::Workspace;
        }
        // cargo and rustup homes usually live in the home directory: check them first
        if self.system.iter().any(|d| under(p, d)) {
            return Zone::System;
        }
        // the decoy home lives inside the temporary work dir: check homes before it
        if self.homes.iter().any(|(h, _)| under(p, h)) {
            return Zone::Home;
        }
        if self.work.iter().any(|w| under(p, w)) {
            return Zone::Target;
        }
        if self.temp.iter().any(|d| under(p, d)) {
            return Zone::Temp;
        }
        Zone::Other
    }

    /// The build sees registry sources through the decoy CARGO_HOME (`<decoy>/registry/src/...`
    /// links to the real cache): treat those paths like the real ones.
    fn alias_cargo_home(&mut self, real: &Path, decoy: &Path) {
        let d = decoy.to_string_lossy().trim_end_matches('/').to_string();
        let mut extra = Vec::new();
        for r in path_forms(real) {
            for (p, k) in &self.packages {
                if under(p, &r) {
                    extra.push((format!("{d}{}", &p[r.len()..]), k.clone()));
                }
            }
        }
        self.packages.extend(extra);
        self.packages.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for sub in ["registry", "git"] {
            self.system.push(format!("{d}/{sub}"));
        }
    }

    /// Which package's source directory `p` is in.
    fn package_of(&self, p: &str) -> Option<&(String, String)> {
        self.packages.iter().find(|(d, _)| under(p, d)).map(|(_, k)| k)
    }

    /// Path for display: homes as `~`.
    fn display(&self, p: &str) -> String {
        for (h, tilde) in &self.homes {
            if under(p, h) {
                return format!("{tilde}{}", &p[h.len()..]);
            }
        }
        p.to_string()
    }
}

/// What a credential-like path is, if it is one.
pub fn sensitive_path(p: &str) -> Option<&'static str> {
    let comps: Vec<&str> = p.split(['/', '\\']).filter(|c| !c.is_empty()).collect();
    let has = |c: &str| comps.contains(&c);
    let file = comps.last().copied().unwrap_or("");
    let pair = |a: &str, b: &str| comps.windows(2).any(|w| w[0] == a && w[1] == b);
    if has(".ssh") {
        return Some(if file.starts_with("id_") && !file.ends_with(".pub") { "SSH private key" } else { "SSH configuration" });
    }
    if has(".aws") {
        return Some("AWS credentials");
    }
    if has(".gnupg") {
        return Some("GnuPG keyring");
    }
    if has(".cargo") && (file == "credentials" || file == "credentials.toml") {
        return Some("cargo registry token");
    }
    if file == ".netrc" || file == "_netrc" {
        return Some(".netrc passwords");
    }
    if file == ".git-credentials" {
        return Some("git credentials");
    }
    if pair("gh", "hosts.yml") || pair(".config", "hub") {
        return Some("GitHub CLI token");
    }
    if has(".docker") && file == "config.json" {
        return Some("Docker registry credentials");
    }
    if has(".kube") {
        return Some("Kubernetes credentials");
    }
    if file == ".npmrc" || file == ".pypirc" || pair(".gem", "credentials") {
        return Some("package registry token");
    }
    if has("gcloud") || has(".azure") || pair(".config", "doctl") {
        return Some("cloud credentials");
    }
    if file == ".bash_history" || file == ".zsh_history" || file == ".python_history" || file == ".psql_history" {
        return Some("shell history");
    }
    if has(".password-store") || has("keyrings") || has("Keychains") {
        return Some("password store / keychain");
    }
    if has(".mozilla") || has("google-chrome") || has("chromium") || has("BraveSoftware") || file == "Login Data" || file == "Cookies" {
        return Some("browser profile");
    }
    if has(".bitcoin") || has(".ethereum") || has(".electrum") || file == "wallet.dat" {
        return Some("cryptocurrency wallet");
    }
    if p == "/etc/shadow" || p == "/etc/gshadow" || p.starts_with("/etc/sudoers") {
        return Some("system password database");
    }
    if p.starts_with("/run/secrets") || p.starts_with("/var/run/secrets") {
        return Some("container secrets");
    }
    if comps.len() == 3 && comps[0] == "proc" && comps[2] == "environ" {
        return Some("process environment");
    }
    None
}

// ---------------------------------------------------------------- per crate

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProgClass {
    Toolchain,
    Helper,
    Built,
    Unknown,
    NetworkTool,
}

impl ProgClass {
    fn label(&self) -> &'static str {
        match self {
            ProgClass::Toolchain => "compiler/build tool",
            ProgClass::Helper => "helper",
            ProgClass::Built => "built by the build",
            ProgClass::Unknown => "other",
            ProgClass::NetworkTool => "NETWORK TOOL",
        }
    }
}

/// Program name without directory, `.exe`, version suffix (`gcc-13`) or target prefix (`x86_64-linux-gnu-gcc`).
pub fn program_name(path: &str) -> String {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    let mut b = base.to_string();
    // gcc-13, python3.12, clang-18
    while let Some(i) = b.rfind(['-', '.']) {
        if i > 0 && b[i + 1..].chars().all(|c| c.is_ascii_digit()) && !b[i + 1..].is_empty() {
            b.truncate(i);
        } else {
            break;
        }
    }
    b
}

const TOOLCHAIN: &[&str] = &[
    "cc", "c++", "cpp", "gcc", "g++", "clang", "clang++", "clang-cl", "cl", "link", "lib", "ld", "lld", "ld.lld", "ld.bfd", "ld.gold", "ld64.lld", "mold", "ar", "llvm-ar", "ranlib",
    "llvm-ranlib", "as", "nasm", "yasm", "strip", "objcopy", "llvm-objcopy", "rustc", "rustdoc", "cargo", "clippy-driver", "rustup", "cmake", "ctest", "make", "gmake", "mingw32-make",
    "ninja", "pkg-config", "pkgconf", "cc1", "cc1plus", "cc1obj", "collect2", "lto-wrapper", "lto1", "windres", "dlltool", "emcc", "xcrun", "libtool", "llvm-config", "bindgen", "nvcc",
    "ml64", "armasm", "rc", "mt", "zig", "build-script-build",
];
const HELPERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "env", "perl", "python", "python3", "uname", "sed", "awk", "gawk", "grep", "cat", "cp", "mv", "mkdir", "rm", "ln", "touch", "tr", "sort", "head", "tail",
    "xargs", "find", "test", "[", "expr", "date", "which", "install", "autoconf", "autoreconf", "automake", "aclocal", "libtoolize", "m4", "configure", "bison", "flex", "yacc", "lex",
    "protoc", "flatc", "gperf", "patch", "tar", "xz", "gzip", "bzip2", "unzip", "git", "rustfmt", "sysctl", "getconf", "ldconfig", "xcode-select", "sw_vers", "lsb_release", "cygpath",
    "basename", "dirname", "realpath", "readlink", "chmod", "true", "false", "echo", "printf", "cut", "wc", "diff", "cmp", "od", "file", "nproc", "pwsh-version", "cmd", "vswhere",
];
const NETWORK_TOOLS: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "tftp", "telnet", "nslookup", "dig", "host", "ping", "powershell", "pwsh", "certutil", "bitsadmin",
    "aria2c", "httpie", "http", "fetch", "openssl", "gh", "aws", "gcloud", "az", "docker", "podman", "kubectl", "npm", "pip", "pip3",
];

fn classify_program(path: &str, argv: &[String], zones: Option<&Zones>) -> ProgClass {
    let n = program_name(path);
    let tail_match = |list: &[&str]| list.iter().any(|t| n == *t || (n.ends_with(&format!("-{t}")) && n.len() > t.len() + 1 && n.contains('-')));
    if n == "git" {
        let net = ["clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote"];
        if argv.iter().skip(1).any(|a| net.contains(&a.as_str())) {
            return ProgClass::NetworkTool;
        }
        return ProgClass::Helper;
    }
    if NETWORK_TOOLS.contains(&n.as_str()) {
        return ProgClass::NetworkTool;
    }
    if tail_match(TOOLCHAIN) {
        return ProgClass::Toolchain;
    }
    if zones.is_some_and(|z| z.zone(path) == Zone::Target) {
        return ProgClass::Built;
    }
    if HELPERS.contains(&n.as_str()) {
        return ProgClass::Helper;
    }
    ProgClass::Unknown
}

#[derive(Debug, Clone)]
struct ProcUse {
    count: usize,
    example: String,
    found: bool,
}

#[derive(Debug, Clone)]
struct Net {
    op: String,
    address: String,
    family: String,
    port: Option<u16>,
    result: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Access {
    Probed,
    Attempted,
    Opened,
}

#[derive(Debug, Clone)]
struct Sensitive {
    label: String,
    access: Access,
}

#[derive(Debug, Clone)]
struct CrateTrace {
    name: String,
    version: String,
    /// "build script", "proc macro", "build script (workspace member)"
    kinds: BTreeSet<String>,
    member: bool,
    unattributed: bool,
    ran_build_script: bool,
    macro_built: bool,
    /// crates whose compilation loaded this proc macro
    macro_hosts: BTreeSet<String>,
    procs: BTreeMap<(String, ProgClass), ProcUse>,
    net: Vec<Net>,
    /// path -> zone label
    writes: BTreeMap<String, &'static str>,
    temp_writes: usize,
    sensitive: BTreeMap<String, Sensitive>,
    unusual_reads: BTreeSet<String>,
    env: EnvUse,
    links_libs: Vec<String>,
    link_paths: Vec<String>,
    rustc_env: Vec<String>,
    warnings: usize,
    /// when events of several proc macros cannot be told apart
    shared_with: BTreeSet<String>,
}

impl CrateTrace {
    fn new(p: &Package, meta: &Metadata) -> CrateTrace {
        let member = meta.is_member(&p.id);
        let mut kinds = BTreeSet::new();
        if p.has_build_script() {
            kinds.insert(if member { "build script (workspace member)".to_string() } else { "build script".to_string() });
        }
        if p.is_proc_macro() {
            kinds.insert(if member { "proc macro (workspace member)".to_string() } else { "proc macro".to_string() });
        }
        CrateTrace { name: p.name.clone(), version: p.version.clone(), kinds, member, ..CrateTrace::blank() }
    }

    fn blank() -> CrateTrace {
        CrateTrace {
            name: String::new(),
            version: String::new(),
            kinds: BTreeSet::new(),
            member: false,
            unattributed: false,
            ran_build_script: false,
            macro_built: false,
            macro_hosts: BTreeSet::new(),
            procs: BTreeMap::new(),
            net: Vec::new(),
            writes: BTreeMap::new(),
            temp_writes: 0,
            sensitive: BTreeMap::new(),
            unusual_reads: BTreeSet::new(),
            env: EnvUse::default(),
            links_libs: Vec::new(),
            link_paths: Vec::new(),
            rustc_env: Vec::new(),
            warnings: 0,
            shared_with: BTreeSet::new(),
        }
    }

    fn unattributed() -> CrateTrace {
        CrateTrace { name: "(unattributed)".into(), unattributed: true, ..CrateTrace::blank() }
    }

    fn is_empty(&self) -> bool {
        self.procs.is_empty() && self.net.is_empty() && self.writes.is_empty() && self.sensitive.is_empty()
    }

    fn display_name(&self) -> String {
        if self.unattributed { self.name.clone() } else { format!("{}@{}", self.name, self.version) }
    }

    fn ran_label(&self) -> String {
        let mut parts = Vec::new();
        if self.kinds.iter().any(|k| k.starts_with("build script")) {
            parts.push(if self.ran_build_script { "build script ran".to_string() } else { "build script not run".to_string() });
        }
        if self.kinds.iter().any(|k| k.starts_with("proc macro")) {
            parts.push(if self.macro_hosts.is_empty() {
                if self.macro_built { "macro built".to_string() } else { "macro not built".to_string() }
            } else {
                format!("macro loaded by {}", self.macro_hosts.len())
            });
        }
        parts.join(", ")
    }

    fn env_label(&self) -> String {
        let s: Vec<String> = self.env.referenced.iter().chain(self.env.declared.iter()).filter(|n| sensitive_env(n)).cloned().collect::<BTreeSet<_>>().into_iter().collect();
        let n = self.env.referenced.len() + self.env.declared.difference(&self.env.referenced).count();
        let mut out = n.to_string();
        if !s.is_empty() {
            out.push_str(&format!(" ({})", s.join(", ")));
        }
        if self.env.enumerates {
            out.push_str(" +all");
        }
        out
    }

    fn apply_directives(&mut self, text: &str) {
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("cargo::").or_else(|| line.strip_prefix("cargo:")) else { continue };
            let Some((k, v)) = rest.split_once('=') else { continue };
            match k {
                "rerun-if-env-changed" => {
                    self.env.declared.insert(v.trim().to_string());
                }
                "warning" => self.warnings += 1,
                _ => {}
            }
        }
    }

    fn proc(&mut self, path: &str, argv: &[String], class: ProgClass, found: bool) {
        let name = program_name(path);
        let e = self.procs.entry((name, class)).or_insert_with(|| ProcUse { count: 0, example: String::new(), found });
        if found {
            e.count += 1;
            e.found = true;
        }
        if e.example.is_empty() || (found && e.count == 1) {
            let shown: Vec<String> = argv.iter().take(8).map(|a| if a.len() > 60 { format!("{}…", &a[..a.char_indices().nth(57).map(|x| x.0).unwrap_or(a.len())]) } else { a.clone() }).collect();
            e.example = shown.join(" ");
            if argv.len() > 8 {
                e.example.push_str(" …");
            }
        }
    }

    fn findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        let who = |f: Finding| if self.unattributed { f } else { f.krate(&self.name, Some(&self.version)) };
        let actor = if self.unattributed {
            "build-time code (crate unknown in portable mode)".to_string()
        } else if self.kinds.iter().all(|k| k.starts_with("proc macro")) {
            "proc macro".to_string()
        } else if self.kinds.iter().all(|k| k.starts_with("build script")) {
            "build script".to_string()
        } else {
            "build script or proc macro".to_string()
        };
        let shared = if self.shared_with.is_empty() { String::new() } else { format!(" (or one of the other proc macros loaded at the same time: {})", self.shared_with.iter().cloned().collect::<Vec<_>>().join(", ")) };
        // network
        let mut net_by_sev: BTreeMap<Severity, Vec<&Net>> = BTreeMap::new();
        for n in &self.net {
            let sev = if n.family == "AF_UNIX" {
                Severity::Critical
            } else if n.op == "listen" || n.op == "bind" {
                Severity::High
            } else if is_loopback(&n.address) && n.port != Some(53) {
                Severity::Medium
            } else {
                Severity::High
            };
            net_by_sev.entry(sev).or_default().push(n);
        }
        for (sev, ns) in net_by_sev.iter().rev() {
            let unix = ns.iter().all(|n| n.family == "AF_UNIX");
            let msg = if unix {
                format!("{actor} connects to a credential socket: {}", ns.iter().map(|n| n.address.clone()).collect::<Vec<_>>().join(", "))
            } else if *sev == Severity::Medium {
                format!("{actor} connects to local services: {}", ns.iter().map(|n| n.address.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(", "))
            } else {
                format!("{actor} uses the network: {}", ns.iter().map(|n| format!("{} {}", n.op, n.address)).collect::<BTreeSet<_>>().into_iter().take(6).collect::<Vec<_>>().join(", "))
            };
            out.push(
                who(Finding::new(*sev, if unix { "buildtrace/agent-socket" } else { "buildtrace/network" }, msg))
                    .detail(format!("{}{shared}", ns.iter().take(20).map(|n| format!("{} {} ({}) -> {}", n.op, n.address, n.family, n.result)).collect::<Vec<_>>().join("\n")))
                    .fix("builds must not need the network: vendor what the build downloads, or ask the maintainers why it connects; pin the previous version meanwhile"),
            );
        }
        // credentials
        if !self.sensitive.is_empty() {
            let worst = self.sensitive.values().map(|s| s.access).max().unwrap_or(Access::Probed);
            let sev = match worst {
                Access::Opened => Severity::Critical,
                Access::Attempted => Severity::High,
                Access::Probed => Severity::Medium,
            };
            let labels: BTreeSet<&str> = self.sensitive.values().map(|s| s.label.as_str()).collect();
            let verb = match worst {
                Access::Opened => "reads",
                Access::Attempted => "tries to read",
                Access::Probed => "probes for",
            };
            out.push(
                who(Finding::new(sev, "buildtrace/credential-access", format!("{actor} {verb} credential files: {}", labels.into_iter().collect::<Vec<_>>().join(", "))))
                    .detail(format!(
                        "{}{shared}",
                        self.sensitive
                            .iter()
                            .take(20)
                            .map(|(p, s)| format!("{p} ({}, {})", s.label, match s.access {
                                Access::Opened => "opened",
                                Access::Attempted => "open attempted, file absent",
                                Access::Probed => "existence checked",
                            }))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ))
                    .fix("treat this as a compromised dependency: remove it, rotate any credentials that were reachable from builds, and report it to the crates.io team (help@crates.io)"),
            );
        }
        // writes
        let src: Vec<&String> = self.writes.iter().filter(|(_, z)| **z == "own source").map(|(p, _)| p).collect();
        let other: Vec<(&String, &&str)> = self.writes.iter().filter(|(_, z)| **z != "own source").collect();
        if !src.is_empty() {
            out.push(
                who(Finding::new(Severity::High, "buildtrace/writes-source", format!("{actor} modifies its own source directory ({} path(s))", src.len())))
                    .detail(src.iter().take(20).map(|s| s.to_string()).collect::<Vec<_>>().join("\n"))
                    .fix("build scripts must only write to OUT_DIR (cargo docs); generated code in the source tree can differ from what was reviewed"),
            );
        }
        if !other.is_empty() {
            out.push(
                who(Finding::new(Severity::High, "buildtrace/writes-outside", format!("{actor} writes outside OUT_DIR and the target directory ({} path(s))", other.len())))
                    .detail(format!("{}{shared}", other.iter().take(20).map(|(p, z)| format!("{p} ({z})")).collect::<Vec<_>>().join("\n")))
                    .fix("find out why it writes there; writes to the home directory or the project can plant code that runs later"),
            );
        }
        if self.temp_writes > 0 && !self.unattributed {
            out.push(who(Finding::new(Severity::Low, "buildtrace/writes-temp", format!("{actor} writes {} file(s) in the system temp directory", self.temp_writes))).fix("usually harmless scratch files; OUT_DIR is the documented place"));
        }
        // programs
        let mut by_class: BTreeMap<ProgClass, Vec<String>> = BTreeMap::new();
        for ((p, class), u) in &self.procs {
            by_class.entry(*class).or_default().push(if u.found { p.clone() } else { format!("{p} (not found)") });
        }
        for (class, progs) in by_class.iter().rev() {
            let (sev, code, what, fix) = match class {
                ProgClass::NetworkTool => (Severity::High, "buildtrace/spawns-network-tool", "starts network tools", "builds must not download or upload anything; vendor the data or replace the dependency"),
                ProgClass::Unknown => (Severity::Medium, "buildtrace/spawns-program", "starts programs", "check what these programs are and why the build needs them"),
                ProgClass::Built => (Severity::Medium, "buildtrace/runs-built-program", "runs programs it compiled during the build", "check what the generated programs do (they were traced too)"),
                ProgClass::Helper => (Severity::Low, "buildtrace/spawns-helper", "starts helper programs", "common for C build systems (configure, perl, python); check they match the crate's purpose"),
                ProgClass::Toolchain => continue,
            };
            let detail = self
                .procs
                .iter()
                .filter(|((_, c), _)| c == class)
                .map(|((p, _), u)| format!("{p}: {}", if u.found { format!("{}x, e.g. `{}`", u.count, u.example) } else { format!("not installed, tried `{}`", u.example) }))
                .collect::<Vec<_>>()
                .join("\n");
            out.push(who(Finding::new(sev, code, format!("{actor} {what}: {}", progs.join(", ")))).detail(format!("{detail}{shared}")).fix(fix));
        }
        // environment
        let mut secrets: BTreeMap<String, String> = BTreeMap::new();
        for n in self.env.referenced.iter().filter(|n| sensitive_env(n)) {
            secrets.insert(n.clone(), format!("referenced in {}", self.env.sources.get(n).cloned().unwrap_or_else(|| "source".into())));
        }
        for n in self.env.declared.iter().filter(|n| sensitive_env(n)) {
            secrets.entry(n.clone()).or_insert_with(|| "declared with cargo:rerun-if-env-changed".into());
        }
        if !secrets.is_empty() {
            out.push(
                who(Finding::new(Severity::High, "buildtrace/secret-env", format!("{actor} reads credential-like environment variables: {}", secrets.keys().cloned().collect::<Vec<_>>().join(", "))))
                    .detail(secrets.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("\n"))
                    .fix("CI secrets are visible to every build script; check why it needs this variable and keep secrets out of build environments"),
            );
        }
        if self.env.enumerates {
            out.push(
                who(Finding::new(Severity::Low, "buildtrace/env-enumeration", format!("{actor} iterates over the whole environment (env::vars)")))
                    .fix("usually used to collect CARGO_FEATURE_* variables; it also sees every secret in the build environment"),
            );
        }
        out
    }

    fn to_json(&self) -> Value {
        json!({
            "crate": if self.unattributed { Value::Null } else { json!(self.name) },
            "version": if self.unattributed { Value::Null } else { json!(self.version) },
            "unattributed": self.unattributed,
            "kinds": self.kinds,
            "workspace_member": self.member,
            "build_script_ran": self.ran_build_script,
            "proc_macro_built": self.macro_built,
            "proc_macro_loaded_by": self.macro_hosts,
            "shared_with": self.shared_with,
            "processes": self.procs.iter().map(|((p, c), u)| json!({"program": p, "class": c.label(), "count": u.count, "found": u.found, "example": u.example})).collect::<Vec<_>>(),
            "network": self.net.iter().map(|n| json!({"op": n.op, "family": n.family, "address": n.address, "port": n.port, "result": n.result})).collect::<Vec<_>>(),
            "writes_outside": self.writes.iter().map(|(p, z)| json!({"path": p, "zone": z})).collect::<Vec<_>>(),
            "temp_writes": self.temp_writes,
            "credential_access": self.sensitive.iter().map(|(p, s)| json!({"path": p, "what": s.label, "access": match s.access { Access::Opened => "opened", Access::Attempted => "attempted", Access::Probed => "probed" }})).collect::<Vec<_>>(),
            "unusual_reads": self.unusual_reads.iter().take(200).collect::<Vec<_>>(),
            "env": {
                "referenced": self.env.referenced,
                "declared": self.env.declared,
                "enumerates_environment": self.env.enumerates,
                "sensitive": self.env.referenced.iter().chain(self.env.declared.iter()).filter(|n| sensitive_env(n)).cloned().collect::<BTreeSet<_>>(),
            },
            "directives": {"link_libs": self.links_libs, "link_search": self.link_paths, "rustc_env": self.rustc_env, "warnings": self.warnings},
        })
    }
}

fn is_loopback(a: &str) -> bool {
    a.starts_with("127.") || a.starts_with("[::1]") || a.starts_with("::1") || a.starts_with("localhost")
}

// ---------------------------------------------------------------- strace log

/// One decoded syscall line.
#[derive(Debug, Clone, PartialEq)]
pub struct Sys {
    pub pid: u32,
    pub name: String,
    pub args: Vec<String>,
    /// Return value (`-1` on error).
    pub ret: i64,
    /// `ENOENT` etc.
    pub errno: Option<String>,
    /// Path decoration of the returned fd (`= 3</real/path>`).
    pub ret_path: Option<String>,
}

/// Join `<unfinished ...>` / `<... name resumed>` pairs and decode each complete line.
pub struct LineJoiner {
    pending: HashMap<u32, String>,
}

impl Default for LineJoiner {
    fn default() -> Self {
        Self::new()
    }
}

impl LineJoiner {
    pub fn new() -> LineJoiner {
        LineJoiner { pending: HashMap::new() }
    }

    pub fn push(&mut self, line: &str) -> Option<Sys> {
        let line = line.trim_end_matches(['\n', '\r']);
        let (pid, rest) = line.split_once(' ')?;
        let pid: u32 = pid.trim().parse().ok()?;
        let rest = rest.trim_start();
        if rest.starts_with("+++") || rest.starts_with("---") {
            return None;
        }
        if let Some(head) = rest.strip_suffix("<unfinished ...>") {
            self.pending.insert(pid, head.trim_end().to_string());
            return None;
        }
        let full = if let Some(r) = rest.strip_prefix("<... ") {
            let (_, tail) = r.split_once(" resumed>")?;
            let head = self.pending.remove(&pid)?;
            let tail = tail.trim_start();
            // `head` ends after the last argument printed; `tail` starts with the rest (often `)`)
            if head.ends_with('(') || tail.starts_with(')') || tail.starts_with(',') { format!("{head}{tail}") } else { format!("{head}, {tail}") }
        } else {
            rest.to_string()
        };
        parse_sys(pid, &full)
    }
}

/// Decode `name(args) = ret ...`.
pub fn parse_sys(pid: u32, s: &str) -> Option<Sys> {
    let open = s.find('(')?;
    let name = s[..open].trim().to_string();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    // strace pads short lines, so the `)` and the ` = ` may be separated by several spaces
    let (close, ret_at) = s.rmatch_indices(" = ").find_map(|(i, _)| {
        let before = s[..i].trim_end();
        before.ends_with(')').then(|| (before.len() - 1, i + 3))
    })?;
    if close < open {
        return None;
    }
    let args = split_top(&s[open + 1..close]);
    let ret_s = s[ret_at..].trim();
    let mut it = ret_s.splitn(2, ' ');
    let ret_tok = it.next().unwrap_or("");
    let after = it.next().unwrap_or("").trim();
    let (num, deco) = match ret_tok.find('<') {
        Some(i) => (&ret_tok[..i], Some(ret_tok[i + 1..].trim_end_matches('>').to_string())),
        None => (ret_tok, None),
    };
    let ret: i64 = if num == "?" { 0 } else { num.parse().or_else(|_| i64::from_str_radix(num.trim_start_matches("0x"), 16)).unwrap_or(0) };
    // the decoration of `= 3</path with spaces>` may contain spaces
    let ret_path = if deco.is_some() && ret_s.contains('<') {
        let i = ret_s.find('<').unwrap_or(0);
        let j = ret_s.rfind('>').unwrap_or(ret_s.len());
        Some(ret_s[i + 1..j.max(i + 1)].to_string())
    } else {
        None
    };
    let errno = if ret < 0 { after.split_whitespace().next().filter(|e| e.starts_with('E')).map(String::from) } else { None };
    Some(Sys { pid, name, args, ret, errno, ret_path })
}

/// Split an argument list at top-level commas (outside quotes, brackets and braces).
pub fn split_top(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut in_str = false;
    let mut esc = false;
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            '[' | '{' | '(' | '<' => {
                depth += 1;
                cur.push(c);
            }
            ']' | '}' | ')' | '>' => {
                depth -= 1;
                cur.push(c);
            }
            ',' if depth <= 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// A strace string literal (`"a\nb"`, possibly followed by `...`), unescaped.
pub fn cstr(tok: &str) -> Option<String> {
    let t = tok.trim();
    let inner = t.strip_prefix('"')?;
    let mut out: Vec<u8> = Vec::new();
    let mut it = inner.bytes().peekable();
    while let Some(b) = it.next() {
        match b {
            b'"' => break,
            b'\\' => match it.next() {
                Some(b'n') => out.push(b'\n'),
                Some(b't') => out.push(b'\t'),
                Some(b'r') => out.push(b'\r'),
                Some(b'v') => out.push(11),
                Some(b'f') => out.push(12),
                Some(b'x') => {
                    let mut v = 0u8;
                    for _ in 0..2 {
                        if let Some(&h) = it.peek() {
                            if let Some(d) = (h as char).to_digit(16) {
                                v = v * 16 + d as u8;
                                it.next();
                            }
                        }
                    }
                    out.push(v);
                }
                Some(d @ b'0'..=b'7') => {
                    let mut v = (d - b'0') as u32;
                    for _ in 0..2 {
                        match it.peek() {
                            Some(&o @ b'0'..=b'7') => {
                                v = v * 8 + (o - b'0') as u32;
                                it.next();
                            }
                            _ => break,
                        }
                    }
                    out.push(v as u8);
                }
                Some(o) => out.push(o),
                None => {}
            },
            o => out.push(o),
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// `["a", "b"]` -> strings.
pub fn str_array(tok: &str) -> Vec<String> {
    let t = tok.trim();
    let Some(inner) = t.strip_prefix('[').and_then(|x| x.rfind(']').map(|e| &x[..e])) else { return vec![] };
    split_top(inner).iter().filter_map(|x| cstr(x)).collect()
}

/// The path in an fd decoration: `AT_FDCWD</cwd>` or `3</dir>`.
fn deco_path(tok: &str) -> Option<String> {
    let i = tok.find('<')?;
    let j = tok.rfind('>')?;
    (j > i).then(|| tok[i + 1..j].to_string())
}

fn join_path(base: Option<&str>, p: &str) -> String {
    if p.starts_with('/') || base.is_none() {
        return normalize(p);
    }
    normalize(&format!("{}/{p}", base.unwrap_or("")))
}

fn normalize(p: &str) -> String {
    let abs = p.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    let j = parts.join("/");
    if abs { format!("/{j}") } else { j }
}

/// A socket address from `{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}`.
pub fn sockaddr(tok: &str) -> Option<(String, String, Option<u16>)> {
    let fam_i = tok.find("sa_family=")?;
    let fam: String = tok[fam_i + 10..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    let port = tok.find("port=htons(").and_then(|i| tok[i + 11..].split(')').next()?.parse::<u16>().ok());
    let quoted = |key: &str| tok.find(key).and_then(|i| cstr(&tok[i + key.len()..]));
    match fam.as_str() {
        "AF_INET" => {
            let a = quoted("inet_addr(").unwrap_or_default();
            Some((fam, format!("{a}:{}", port.unwrap_or(0)), port))
        }
        "AF_INET6" => {
            let a = tok.find("inet_pton(AF_INET6, ").and_then(|i| cstr(&tok[i + 20..])).unwrap_or_default();
            Some((fam, format!("[{a}]:{}", port.unwrap_or(0)), port))
        }
        "AF_UNIX" => {
            let p = tok.find("sun_path=").map(|i| {
                let r = &tok[i + 9..];
                if let Some(abs) = r.strip_prefix('@') { format!("@{}", cstr(abs).unwrap_or_default()) } else { cstr(r).unwrap_or_default() }
            });
            Some((fam, p.unwrap_or_default(), None))
        }
        _ => Some((fam, String::new(), None)),
    }
}

/// Who is running in a process.
#[derive(Debug, Clone, PartialEq)]
enum Actor {
    None,
    BuildScript(String, String),
    /// rustc compiling `crate`, with proc macros (package name, version) loaded
    Macros(String, Vec<(String, String)>),
}

#[derive(Debug, Clone)]
struct ProcState {
    actor: Actor,
    /// a compiler / build tool (its temp files are not interesting)
    toolchain: bool,
    exe: String,
    cwd: Option<String>,
}

/// Events decoded from a trace, attributed to actors.
#[derive(Debug, Default)]
struct Events {
    items: Vec<(Actor, bool, Event)>,
}

#[derive(Debug, Clone)]
enum Event {
    Exec { path: String, argv: Vec<String>, found: bool },
    Read { path: String, resolved: Option<String>, ok: bool },
    Probe { path: String },
    Write { path: String },
    Net(Net),
}

/// Lines of a trace, decoded lossily (a path with invalid UTF-8 must not abort the parse).
fn trace_lines<R: BufRead>(mut r: R) -> impl Iterator<Item = std::io::Result<String>> {
    let mut buf = Vec::new();
    std::iter::from_fn(move || {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) => None,
            Ok(_) => Some(Ok(String::from_utf8_lossy(&buf).into_owned())),
            Err(e) => Some(Err(e)),
        }
    })
}

/// Parse a trace. `open` is called twice: the log can be gigabytes, so it is streamed rather
/// than held in memory.
fn parse_strace<R: BufRead>(open: impl Fn() -> std::io::Result<R>, meta: &Metadata) -> Result<Events> {
    // pass 1 needs the parent of every pid (a child's first lines can precede the parent's clone return)
    let mut parent: HashMap<u32, u32> = HashMap::new();
    let mut j = LineJoiner::new();
    for l in trace_lines(open()?) {
        if let Some(s) = j.push(&l?) {
            if matches!(s.name.as_str(), "clone" | "clone3" | "fork" | "vfork") && s.ret > 0 {
                parent.entry(s.ret as u32).or_insert(s.pid);
            }
        }
    }
    let macro_libs = proc_macro_libs(meta);
    let mut procs: HashMap<u32, ProcState> = HashMap::new();
    let mut ev = Events::default();
    // per pid: program names whose exec failed, until one succeeds
    let mut failed_exec: HashMap<u32, Vec<(String, Vec<String>)>> = HashMap::new();
    let mut j = LineJoiner::new();
    for l in trace_lines(open()?) {
        let Some(s) = j.push(&l?) else { continue };
        if !procs.contains_key(&s.pid) {
            let st = parent
                .get(&s.pid)
                .and_then(|pp| procs.get(pp))
                .cloned()
                .unwrap_or(ProcState { actor: Actor::None, toolchain: false, exe: String::new(), cwd: None });
            procs.insert(s.pid, st);
        }
        let st = procs.get(&s.pid).cloned().unwrap_or(ProcState { actor: Actor::None, toolchain: false, exe: String::new(), cwd: None });
        // keep the cwd fresh from AT_FDCWD decorations
        if let Some(cwd) = s.args.first().filter(|a| a.starts_with("AT_FDCWD<")).and_then(|a| deco_path(a)) {
            if let Some(p) = procs.get_mut(&s.pid) {
                p.cwd = Some(cwd);
            }
        }
        let cwd = procs.get(&s.pid).and_then(|p| p.cwd.clone());
        let at = |dirfd: &str, p: &str| -> String {
            if p.starts_with('/') {
                return normalize(p);
            }
            let base = deco_path(dirfd).or_else(|| cwd.clone());
            join_path(base.as_deref(), p)
        };
        match s.name.as_str() {
            "execve" | "execveat" => {
                let (pi, ai, ei) = if s.name == "execve" { (0, 1, 2) } else { (1, 2, 3) };
                let Some(path) = s.args.get(pi).and_then(|a| cstr(a)) else { continue };
                let path = if s.name == "execveat" { at(&s.args[0], &path) } else { join_path(cwd.as_deref(), &path) };
                let argv = s.args.get(ai).map(|a| str_array(a)).unwrap_or_default();
                if s.ret != 0 {
                    if st.actor != Actor::None {
                        failed_exec.entry(s.pid).or_default().push((path, argv));
                    }
                    continue;
                }
                let env = s.args.get(ei).map(|a| str_array(a)).unwrap_or_default();
                let getenv = |k: &str| env.iter().find_map(|e| e.strip_prefix(&format!("{k}=")).map(String::from));
                let name = program_name(&path);
                let mut next = st.clone();
                next.exe = path.clone();
                if name == "build-script-build" || (name.starts_with("build-script-") && getenv("HOST").is_some()) {
                    // a build script starts
                    let pkg = getenv("CARGO_PKG_NAME").unwrap_or_else(|| build_dir_package(&path));
                    let ver = getenv("CARGO_PKG_VERSION").or_else(|| meta.packages.iter().find(|p| p.name == pkg).map(|p| p.version.clone())).unwrap_or_default();
                    next.actor = Actor::BuildScript(pkg, ver);
                    next.toolchain = false;
                } else if st.actor == Actor::None {
                    if is_rustc(&name) {
                        let macros = macros_in_argv(&argv, &macro_libs);
                        if !macros.is_empty() {
                            let krate = getenv("CARGO_PKG_NAME").or_else(|| crate_name_arg(&argv)).unwrap_or_default();
                            next.actor = Actor::Macros(krate, macros);
                            next.toolchain = false;
                        }
                    }
                } else {
                    // something started by build-time code
                    let rustc_chain = is_rustc(&name) && is_rustc(&program_name(&st.exe));
                    let class = classify_program(&path, &argv, None);
                    if !rustc_chain {
                        // failed PATH lookups for the same program are just the search
                        if let Some(f) = failed_exec.get_mut(&s.pid) {
                            f.retain(|(p, _)| program_name(p) != name);
                        }
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Exec { path: path.clone(), argv: argv.clone(), found: true }));
                    }
                    next.toolchain = st.toolchain || class == ProgClass::Toolchain;
                }
                procs.insert(s.pid, next);
            }
            _ if st.actor == Actor::None => {
                if s.name == "chdir" && s.ret == 0 {
                    if let (Some(p), Some(ps)) = (s.args.first().and_then(|a| cstr(a)), procs.get_mut(&s.pid)) {
                        ps.cwd = Some(join_path(cwd.as_deref(), &p));
                    }
                }
            }
            "chdir" => {
                if s.ret == 0 {
                    if let (Some(p), Some(ps)) = (s.args.first().and_then(|a| cstr(a)), procs.get_mut(&s.pid)) {
                        ps.cwd = Some(join_path(cwd.as_deref(), &p));
                    }
                }
            }
            "open" | "openat" | "openat2" | "creat" => {
                let (path, flags) = match s.name.as_str() {
                    "open" => (s.args.first().and_then(|a| cstr(a)).map(|p| join_path(cwd.as_deref(), &p)), s.args.get(1).cloned().unwrap_or_default()),
                    "creat" => (s.args.first().and_then(|a| cstr(a)).map(|p| join_path(cwd.as_deref(), &p)), "O_CREAT|O_WRONLY".to_string()),
                    _ => (s.args.get(1).and_then(|a| cstr(a)).map(|p| at(&s.args[0], &p)), s.args.get(2).cloned().unwrap_or_default()),
                };
                let Some(path) = path else { continue };
                let write = ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"].iter().any(|f| flags.contains(f));
                if write {
                    if s.ret >= 0 {
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: s.ret_path.clone().unwrap_or(path) }));
                    }
                } else {
                    ev.items.push((st.actor.clone(), st.toolchain, Event::Read { path, resolved: s.ret_path.clone(), ok: s.ret >= 0 }));
                }
            }
            "access" | "faccessat" | "faccessat2" => {
                let p = if s.name == "access" { s.args.first().and_then(|a| cstr(a)).map(|p| join_path(cwd.as_deref(), &p)) } else { s.args.get(1).and_then(|a| cstr(a)).map(|p| at(&s.args[0], &p)) };
                if let Some(path) = p {
                    ev.items.push((st.actor.clone(), st.toolchain, Event::Probe { path }));
                }
            }
            "mkdir" | "unlink" | "chmod" | "truncate" => {
                if s.ret == 0 {
                    if let Some(p) = s.args.first().and_then(|a| cstr(a)) {
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: join_path(cwd.as_deref(), &p) }));
                    }
                }
            }
            "mkdirat" | "unlinkat" | "fchmodat" => {
                if s.ret == 0 {
                    if let Some(p) = s.args.get(1).and_then(|a| cstr(a)) {
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: at(&s.args[0], &p) }));
                    }
                }
            }
            "rename" | "link" | "symlink" => {
                if s.ret == 0 {
                    let a = s.args.first().and_then(|a| cstr(a));
                    let b = s.args.get(1).and_then(|a| cstr(a));
                    if s.name == "rename" {
                        if let Some(a) = a {
                            ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: join_path(cwd.as_deref(), &a) }));
                        }
                    }
                    if let Some(b) = b {
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: join_path(cwd.as_deref(), &b) }));
                    }
                }
            }
            "renameat" | "renameat2" | "linkat" => {
                if s.ret == 0 && s.args.len() >= 4 {
                    if s.name != "linkat" {
                        if let Some(a) = cstr(&s.args[1]) {
                            ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: at(&s.args[0], &a) }));
                        }
                    }
                    if let Some(b) = cstr(&s.args[3]) {
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: at(&s.args[2], &b) }));
                    }
                }
            }
            "symlinkat" => {
                if s.ret == 0 && s.args.len() >= 3 {
                    if let Some(b) = cstr(&s.args[2]) {
                        ev.items.push((st.actor.clone(), st.toolchain, Event::Write { path: at(&s.args[1], &b) }));
                    }
                }
            }
            "connect" | "bind" | "sendto" | "sendmsg" => {
                let tok = match s.name.as_str() {
                    "sendto" => s.args.get(4).cloned(),
                    "sendmsg" => s.args.get(1).filter(|m| m.contains("msg_name=")).cloned(),
                    _ => s.args.get(1).cloned(),
                };
                let Some(tok) = tok.filter(|t| t.contains("sa_family=")) else { continue };
                let Some((family, address, port)) = sockaddr(&tok) else { continue };
                if !matches!(family.as_str(), "AF_INET" | "AF_INET6" | "AF_UNIX") {
                    continue;
                }
                if family == "AF_UNIX" && !credential_socket(&address) {
                    continue;
                }
                let result = if s.ret >= 0 { "ok".to_string() } else { s.errno.clone().unwrap_or_else(|| "failed".into()) };
                let result = if result == "EINPROGRESS" { "in progress (non-blocking)".to_string() } else { result };
                let op = match s.name.as_str() {
                    "sendto" | "sendmsg" => "send",
                    o => o,
                };
                ev.items.push((st.actor.clone(), st.toolchain, Event::Net(Net { op: op.into(), address, family, port, result })));
            }
            "listen" => {
                let addr = s.args.first().and_then(|a| deco_path(a)).unwrap_or_default();
                ev.items.push((st.actor.clone(), st.toolchain, Event::Net(Net { op: "listen".into(), address: addr, family: "socket".into(), port: None, result: if s.ret == 0 { "ok".into() } else { "failed".into() } })));
            }
            _ => {}
        }
    }
    // programs that were looked up but never found
    for (pid, fails) in failed_exec {
        let Some(st) = procs.get(&pid) else { continue };
        let mut seen = BTreeSet::new();
        for (path, argv) in fails {
            if seen.insert(program_name(&path)) {
                ev.items.push((st.actor.clone(), st.toolchain, Event::Exec { path, argv, found: false }));
            }
        }
    }
    Ok(ev)
}

fn credential_socket(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    (l.contains("ssh") && (l.contains("agent") || l.contains("auth"))) || l.contains("gpg-agent") || l.contains("docker.sock") || l.contains("podman.sock") || l.contains("keyring") || l.contains("1password")
}

fn is_rustc(name: &str) -> bool {
    name == "rustc" || name == "clippy-driver"
}

fn crate_name_arg(argv: &[String]) -> Option<String> {
    argv.iter().position(|a| a == "--crate-name").and_then(|i| argv.get(i + 1)).cloned().filter(|n| n != "___")
}

/// `target/debug/build/<pkg>-<hash>/build-script-build` -> `<pkg>`.
fn build_dir_package(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let dir = parts.iter().rev().nth(1).copied().unwrap_or("");
    match dir.rsplit_once('-') {
        Some((n, h)) if h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit()) => n.to_string(),
        _ => dir.to_string(),
    }
}

/// proc-macro library crate name (`serde_derive`) -> package (name, version)s.
fn proc_macro_libs(meta: &Metadata) -> HashMap<String, Vec<(String, String)>> {
    let mut m: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for p in &meta.packages {
        for t in &p.targets {
            if t.kind.iter().any(|k| k == "proc-macro") {
                m.entry(t.name.replace('-', "_")).or_default().push((p.name.clone(), p.version.clone()));
            }
        }
    }
    m
}

/// Proc macros passed to rustc as `--extern name=…/libname-hash.so`.
fn macros_in_argv(argv: &[String], libs: &HashMap<String, Vec<(String, String)>>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (i, a) in argv.iter().enumerate() {
        let v = if a == "--extern" { argv.get(i + 1).map(|s| s.as_str()) } else { a.strip_prefix("--extern=") };
        let Some(v) = v else { continue };
        let Some((_, path)) = v.split_once('=') else { continue };
        if !(path.ends_with(".so") || path.ends_with(".dylib") || path.ends_with(".dll")) {
            continue;
        }
        let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
        let stem = file.strip_prefix("lib").unwrap_or(file);
        let stem = stem.rsplit_once('.').map(|x| x.0).unwrap_or(stem);
        let krate = stem.rsplit_once('-').map(|x| x.0).unwrap_or(stem);
        match libs.get(krate) {
            Some(pkgs) => {
                for p in pkgs.iter().take(1) {
                    if !out.contains(p) {
                        out.push(p.clone());
                    }
                }
            }
            None => out.push((krate.to_string(), String::new())),
        }
    }
    out
}

/// Turn attributed events into per-crate results.
fn apply_events(ev: &Events, zones: &Zones, crates: &mut BTreeMap<(String, String), CrateTrace>) {
    for (actor, toolchain, e) in &ev.items {
        let (keys, host): (Vec<(String, String)>, Option<String>) = match actor {
            Actor::None => continue,
            Actor::BuildScript(n, v) => (vec![(n.clone(), v.clone())], None),
            Actor::Macros(krate, ms) => (ms.clone(), Some(krate.clone())),
        };
        // the first proc macro carries shared events; the others are named in `shared_with`
        let key = keys[0].clone();
        let others: Vec<String> = keys.iter().skip(1).map(|(n, _)| n.clone()).collect();
        let ct = crates.entry(key.clone()).or_insert_with(|| {
            let mut c = CrateTrace::blank();
            c.name = key.0.clone();
            c.version = key.1.clone();
            c
        });
        if let Some(h) = &host {
            ct.macro_hosts.insert(h.clone());
        }
        let is_macro = host.is_some();
        let mut interesting = false;
        match e {
            Event::Exec { path, argv, found } => {
                let class = classify_program(path, argv, Some(zones));
                // rustc links proc macros and binaries with the system linker: not the macro's doing
                if is_macro && class == ProgClass::Toolchain {
                    continue;
                }
                ct.proc(path, argv, class, *found);
                interesting = class != ProgClass::Toolchain;
            }
            Event::Read { path, resolved, ok } => {
                let label = sensitive_path(path).or_else(|| resolved.as_deref().and_then(sensitive_path));
                if let Some(label) = label {
                    let acc = if *ok { Access::Opened } else { Access::Attempted };
                    let e = ct.sensitive.entry(zones.display(path)).or_insert(Sensitive { label: label.into(), access: acc });
                    e.access = e.access.max(acc);
                    interesting = true;
                } else if *ok && !*toolchain {
                    let z = zones.zone(resolved.as_deref().unwrap_or(path));
                    if matches!(z, Zone::Other | Zone::Home) {
                        ct.unusual_reads.insert(zones.display(path));
                    }
                }
            }
            Event::Probe { path } => {
                if let Some(label) = sensitive_path(path) {
                    let e = ct.sensitive.entry(zones.display(path)).or_insert(Sensitive { label: label.into(), access: Access::Probed });
                    e.access = e.access.max(Access::Probed);
                    interesting = true;
                }
            }
            Event::Write { path } => {
                let z = zones.zone(path);
                match z {
                    Zone::Target | Zone::Device => {}
                    Zone::Temp => {
                        if !*toolchain && !is_macro {
                            ct.temp_writes += 1;
                        }
                    }
                    Zone::PackageSource => {
                        let own = zones.package_of(path).is_some_and(|k| *k == key);
                        ct.writes.insert(zones.display(path), if own { "own source" } else { "another package's source" });
                        interesting = true;
                    }
                    Zone::Workspace => {
                        ct.writes.insert(zones.display(path), "project directory");
                        interesting = true;
                    }
                    Zone::Home => {
                        ct.writes.insert(zones.display(path), "home directory");
                        interesting = true;
                    }
                    Zone::System => {
                        ct.writes.insert(zones.display(path), "system or toolchain directory");
                        interesting = true;
                    }
                    Zone::Other => {
                        ct.writes.insert(zones.display(path), "elsewhere");
                        interesting = true;
                    }
                }
            }
            Event::Net(n) => {
                if !ct.net.iter().any(|x| x.op == n.op && x.address == n.address && x.result == n.result) {
                    ct.net.push(n.clone());
                }
                interesting = true;
            }
        }
        if interesting && !others.is_empty() {
            ct.shared_with.extend(others.iter().cloned());
        }
        if let Some(h) = &host {
            for k in keys.iter().skip(1) {
                if let Some(o) = crates.get_mut(k) {
                    o.macro_hosts.insert(h.clone());
                }
            }
        }
    }
}

// ---------------------------------------------------------------- portable observer

/// PATH shims for programs build scripts commonly start by name. Each shim
/// appends one record to the log and then runs the real program.
fn make_shims(dir: &Path, log: &Path) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(log, b"")?;
    let names: BTreeSet<&str> = NETWORK_TOOLS
        .iter()
        .chain(["cc", "c++", "gcc", "g++", "clang", "clang++", "ar", "cmake", "make", "ninja", "pkg-config", "nasm", "perl", "python", "python3", "sh", "bash", "git", "uname", "whoami", "id", "hostname", "node", "sudo", "env"].iter())
        .copied()
        .collect();
    for n in names {
        let real = util::which(n);
        let run = match &real {
            Some(r) => format!("exec '{}' \"$@\"", r.to_string_lossy().replace('\'', "'\\''")),
            None => format!("echo \"{n}: not found\" >&2\nexit 127"),
        };
        let found = if real.is_some() { "1" } else { "0" };
        let script = format!(
            "#!/bin/sh\nRS=$(printf '\\036'); US=$(printf '\\037')\nr=\"{n}${{RS}}${{CARGO_PKG_NAME-}}${{RS}}${{CARGO_PKG_VERSION-}}${{RS}}${{HOST:+build-script}}${{RS}}{found}${{RS}}\"\nfor a in \"$@\"; do r=\"$r$a$US\"; done\nprintf '%s\\n' \"$r\" >> \"${{SM_BUILDTRACE_LOG:-/dev/null}}\" 2>/dev/null\n{run}\n"
        );
        let p = dir.join(n);
        std::fs::write(&p, script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok((dir.to_path_buf(), log.to_path_buf()))
}

/// One shim record: program, package, version, role (`build-script` or empty), found flag, args.
pub fn parse_shim_line(l: &str) -> Option<(String, String, String, bool, bool, Vec<String>)> {
    let f: Vec<&str> = l.splitn(6, '\u{1e}').collect();
    if f.len() < 6 {
        return None;
    }
    let args: Vec<String> = f[5].split('\u{1f}').filter(|a| !a.is_empty()).map(String::from).collect();
    Some((f[0].to_string(), f[1].to_string(), f[2].to_string(), f[3] == "build-script", f[4] == "1", args))
}

fn apply_shim_log(log: &Path, meta: &Metadata, crates: &mut BTreeMap<(String, String), CrateTrace>, unattributed: &mut CrateTrace) {
    let Ok(text) = std::fs::read_to_string(log) else { return };
    for l in text.lines() {
        let Some((prog, pkg, ver, build_script, found, args)) = parse_shim_line(l) else { continue };
        if pkg.is_empty() {
            continue; // cargo itself
        }
        let mut argv = vec![prog.clone()];
        argv.extend(args);
        let class = classify_program(&prog, &argv, None);
        if !build_script && class == ProgClass::Toolchain {
            continue; // rustc running the linker
        }
        let key = (pkg.clone(), ver.clone());
        let ct = if build_script {
            crates.get_mut(&key)
        } else {
            // started from a rustc process: one of the proc macros loaded while compiling `pkg`
            let p = meta.packages.iter().find(|p| p.name == pkg && p.version == ver);
            let macros: Vec<(String, String)> = p
                .and_then(|p| meta.node(&p.id))
                .map(|n| n.deps.iter().filter_map(|d| meta.package(&d.pkg)).filter(|d| d.is_proc_macro()).map(|d| (d.name.clone(), d.version.clone())).collect())
                .unwrap_or_default();
            match macros.len() {
                1 => crates.get_mut(&macros[0]),
                _ => None,
            }
        };
        match ct {
            Some(c) => c.proc(&prog, &argv, class, found),
            None => {
                unattributed.proc(&prog, &argv, class, found);
            }
        }
    }
}

type Snapshot = HashMap<PathBuf, (u64, Option<SystemTime>)>;

/// Roots whose files are compared before and after the build: (root, recursive).
fn snapshot_roots(meta: &Metadata, homes: &Homes, decoy: Option<&Decoy>) -> Vec<(PathBuf, bool)> {
    let mut roots: Vec<(PathBuf, bool)> = vec![(meta.workspace_root.clone(), true)];
    for p in &meta.packages {
        let d = p.dir();
        if !d.starts_with(&meta.workspace_root) {
            roots.push((d, true));
        }
    }
    if let Some(d) = decoy {
        roots.push((d.root.clone(), true));
    }
    if let Some(h) = &homes.real_home {
        roots.push((h.clone(), false));
        for sub in [".ssh", ".cargo/bin", ".local/bin", ".config", ".aws"] {
            roots.push((h.join(sub), false));
        }
    }
    roots
}

fn snapshot(roots: &[(PathBuf, bool)]) -> Snapshot {
    let mut m = Snapshot::new();
    for (r, recursive) in roots {
        let files: Vec<PathBuf> = if *recursive {
            util::walk_files(r)
        } else {
            std::fs::read_dir(r).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect()).unwrap_or_default()
        };
        for f in files {
            if let Ok(md) = std::fs::metadata(&f) {
                m.insert(f, (md.len(), md.modified().ok()));
            }
        }
    }
    m
}

fn portable_changes(before: &Snapshot, after: &Snapshot, zones: &Zones, crates: &mut BTreeMap<(String, String), CrateTrace>, unattributed: &mut CrateTrace) {
    let mut changed: Vec<(&PathBuf, &'static str)> = Vec::new();
    for (p, meta) in after {
        match before.get(p) {
            None => changed.push((p, "created")),
            Some(b) if b != meta => changed.push((p, "modified")),
            _ => {}
        }
    }
    for p in before.keys() {
        if !after.contains_key(p) {
            changed.push((p, "deleted"));
        }
    }
    changed.sort();
    for (p, how) in changed {
        let s = p.to_string_lossy().replace('\\', "/");
        let file = s.rsplit('/').next().unwrap_or("");
        // cargo's own lock and cache-tracking files in the (decoy) CARGO_HOME
        if s.ends_with("/Cargo.lock") || s.contains("/.sm-atime-probe") || s.ends_with(".cargo-ok") || file.starts_with(".package-cache") || file.starts_with(".global-cache") {
            continue;
        }
        let shown = format!("{} ({how})", zones.display(&s));
        match zones.zone(&s) {
            Zone::PackageSource => {
                let key = zones.package_of(&s).cloned();
                match key.and_then(|k| crates.get_mut(&k)) {
                    Some(c) => {
                        c.writes.insert(shown, "own source");
                    }
                    None => {
                        unattributed.writes.insert(shown, "a package's source");
                    }
                }
            }
            Zone::Workspace => {
                unattributed.writes.insert(shown, "project directory");
            }
            Zone::Home => {
                unattributed.writes.insert(shown, "home directory");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_unfinished_lines_and_decodes() {
        let mut j = LineJoiner::new();
        assert!(j.push("20302 clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0x7fb433ac8000, stack_size=0x9000}, 88 <unfinished ...>").is_none());
        let s = j.push("20302 <... clone3 resumed>)             = 20305").unwrap();
        assert_eq!((s.pid, s.name.as_str(), s.ret), (20302, "clone3", 20305));
        let s = j.push("20443 openat(AT_FDCWD</tmp/claude-0/bt1>, \"/root/.ssh/id_rsa\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)").unwrap();
        assert_eq!(s.ret, -1);
        assert_eq!(s.errno.as_deref(), Some("ENOENT"));
        assert_eq!(cstr(&s.args[1]).as_deref(), Some("/root/.ssh/id_rsa"));
        assert_eq!(deco_path(&s.args[0]).as_deref(), Some("/tmp/claude-0/bt1"));
        let s = j.push("11227 openat(AT_FDCWD</tmp>, \"/usr/lib/ssl/openssl.cnf\", O_RDONLY) = 3</etc/ssl/openssl.cnf>").unwrap();
        assert_eq!(s.ret_path.as_deref(), Some("/etc/ssl/openssl.cnf"));
        assert!(j.push("11227 connect(5<TCP:[14509]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"1.1.1.1\")}, 16 <unfinished ...>").is_none());
        let s = j.push("11227 <... connect resumed>)            = -1 EINPROGRESS (Operation now in progress)").unwrap();
        assert_eq!(s.name, "connect");
        assert_eq!(sockaddr(&s.args[1]), Some(("AF_INET".into(), "1.1.1.1:80".into(), Some(80))));
        let s = j.push("9 execve(\"/usr/bin/cat\", [\"cat\", \"a b\", \"q\\\"x\"], [\"HOME=/h\", \"CARGO_PKG_NAME=x\"]) = 0").unwrap();
        assert_eq!(str_array(&s.args[1]), vec!["cat", "a b", "q\"x"]);
        assert_eq!(str_array(&s.args[2])[1], "CARGO_PKG_NAME=x");
        assert!(j.push("9 +++ exited with 0 +++").is_none());
        let s = j.push("7 connect(3<UNIX:[1]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, \"2606:4700::1\", &sin6_addr), sin6_scope_id=0}, 28) = 0").unwrap();
        assert_eq!(sockaddr(&s.args[1]).unwrap().1, "[2606:4700::1]:443");
        let s = j.push("7 connect(3<UNIX:[1]>, {sa_family=AF_UNIX, sun_path=\"/tmp/ssh-XXXX/agent.123\"}, 110) = 0").unwrap();
        let (f, a, _) = sockaddr(&s.args[1]).unwrap();
        assert!(f == "AF_UNIX" && credential_socket(&a));
        assert_eq!(cstr("\"\\303\\251\\x41\"...").as_deref(), Some("éA"));
    }

    #[test]
    fn classifies_paths_programs_and_env() {
        assert_eq!(sensitive_path("/home/u/.ssh/id_ed25519"), Some("SSH private key"));
        assert_eq!(sensitive_path("/home/u/.cargo/credentials.toml"), Some("cargo registry token"));
        assert_eq!(sensitive_path("/proc/123/environ"), Some("process environment"));
        assert_eq!(sensitive_path("/usr/lib/x86_64-linux-gnu/libssh.so.4"), None);
        assert_eq!(sensitive_path("/home/u/.cargo/registry/src/x/lib.rs"), None);
        assert_eq!(program_name("/usr/bin/x86_64-linux-gnu-gcc-13"), "x86_64-linux-gnu-gcc");
        assert_eq!(program_name("C:\\bin\\curl.exe"), "curl");
        assert_eq!(program_name("/usr/bin/python3.12"), "python3");
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(classify_program("/usr/bin/x86_64-linux-gnu-gcc-13", &a(&["gcc"]), None), ProgClass::Toolchain);
        assert_eq!(classify_program("/usr/bin/curl", &a(&["curl"]), None), ProgClass::NetworkTool);
        assert_eq!(classify_program("/usr/bin/git", &a(&["git", "rev-parse", "HEAD"]), None), ProgClass::Helper);
        assert_eq!(classify_program("/usr/bin/git", &a(&["git", "clone", "x"]), None), ProgClass::NetworkTool);
        assert_eq!(classify_program("/opt/x/frobnicate", &a(&["frobnicate"]), None), ProgClass::Unknown);
        assert!(sensitive_env("GITHUB_TOKEN") && sensitive_env("AWS_SECRET_ACCESS_KEY") && sensitive_env("CARGO_REGISTRIES_MY_TOKEN") && sensitive_env("SSH_AUTH_SOCK"));
        assert!(scrub_env("AWS_CONTAINER_CREDENTIALS_FULL_URI") && scrub_env("AWS_WEB_IDENTITY_TOKEN_FILE") && !scrub_env("AWS_LC_SYS_STATIC"));
        assert!(!sensitive_env("OUT_DIR") && !sensitive_env("CARGO_PKG_NAME") && !sensitive_env("PATH") && !sensitive_env("CARGO_FEATURE_KEY"));
        let (n, en) = env_refs("let t = std::env::var(\"GITHUB_TOKEN\"); env!(\"CARGO_PKG_NAME\"); my_var(\"NOPE\"); for (k, v) in std::env::vars() {}");
        assert!(n.contains("GITHUB_TOKEN") && n.contains("CARGO_PKG_NAME") && !n.contains("NOPE"), "{n:?}");
        assert!(en);
        assert_eq!(build_dir_package("/t/debug/build/libz-sys-0123456789abcdef/build-script-build"), "libz-sys");
        let rec = "curl\u{1e}sneaky\u{1e}1.0.0\u{1e}build-script\u{1e}0\u{1e}-s\u{1f}http://x\u{1f}";
        let (p, pkg, _, bs, found, args) = parse_shim_line(rec).unwrap();
        assert!(p == "curl" && pkg == "sneaky" && bs && !found);
        assert_eq!(args, vec!["-s", "http://x"]);
    }

    #[test]
    fn decoy_cargo_home_hides_tokens_and_keeps_attribution() {
        let cfg = "[registry]\ntoken = \"cio-SECRET\"\ndefault = \"crates-io\"\n\n[registries.corp]\nindex = \"sparse+https://corp/\"\ntoken = \"corp-SECRET\"\n\n[source.crates-io]\nreplace-with = \"corp\"\n";
        let clean = strip_registry_tokens(cfg).unwrap();
        assert!(!clean.contains("SECRET") && clean.contains("replace-with") && clean.contains("sparse+https://corp/"), "{clean}");
        let real = std::env::temp_dir().join(format!("smc-bt-real-{}", std::process::id()));
        let decoy = std::env::temp_dir().join(format!("smc-bt-decoy-{}", std::process::id()));
        std::fs::create_dir_all(real.join("registry/src/idx/foo-1.0.0")).unwrap();
        std::fs::write(real.join("credentials.toml"), "[registry]\ntoken = \"REAL\"\n").unwrap();
        std::fs::write(real.join("config.toml"), cfg).unwrap();
        let dc = make_decoy_cargo_home(&real, &decoy).unwrap();
        assert!(dc.join("registry/src/idx/foo-1.0.0").is_dir(), "registry cache is linked");
        assert!(!dc.join("credentials.toml").exists(), "the real credentials are not copied");
        assert!(!std::fs::read_to_string(dc.join("config.toml")).unwrap().contains("SECRET"));
        let meta: Metadata = serde_json::from_value(json!({
            "packages": [{"name": "foo", "version": "1.0.0", "id": "foo 1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index",
                          "manifest_path": real.join("registry/src/idx/foo-1.0.0/Cargo.toml"), "targets": []}],
            "workspace_members": [], "resolve": null, "workspace_root": "/w", "target_directory": "/w/target"
        }))
        .unwrap();
        let homes = Homes { real_home: None, cargo_home: Some(real.clone()), rustup_home: None };
        let mut zones = Zones::new(&meta, &homes, None, Path::new("/t"), &[], Path::new("/work"));
        zones.alias_cargo_home(&real, &dc);
        let via_decoy = format!("{}/registry/src/idx/foo-1.0.0/gen.rs", dc.display());
        assert_eq!(zones.zone(&via_decoy), Zone::PackageSource);
        assert_eq!(zones.package_of(&via_decoy), Some(&("foo".to_string(), "1.0.0".to_string())));
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_dir_all(&decoy);
    }

    #[test]
    fn crate_mode_features_go_to_the_named_crates() {
        let iv = |name: &str, feats: &[&str]| -> crate::registry::index::IndexVersion {
            serde_json::from_value(json!({"name": name, "vers": "1.0.0", "cksum": "x", "deps": [{"name": "opt", "req": "1", "optional": true}],
                "features": feats.iter().map(|f| (f.to_string(), json!([]))).collect::<serde_json::Map<_, _>>()}))
            .unwrap()
        };
        let cs = vec![iv("openssl-sys", &["vendored"]), iv("libz-sys", &["static", "default"])];
        let f = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(probe_features(&cs, &f(&["vendored", "libz-sys/static"]), false).unwrap(), vec![f(&["vendored"]), f(&["static"])]);
        assert_eq!(probe_features(&cs, &f(&["opt"]), false).unwrap(), vec![f(&["opt"]), f(&["opt"])], "optional deps are implicit features");
        assert!(probe_features(&cs, &f(&["nope"]), false).is_err());
        assert_eq!(probe_features(&cs, &[], true).unwrap()[1], f(&["default", "opt", "static"]));
    }

    #[test]
    fn attributes_build_script_and_proc_macro_events() {
        let meta: Metadata = serde_json::from_value(json!({
            "packages": [
                {"name": "sneaky", "version": "1.0.0", "id": "sneaky 1.0.0", "source": "registry+https://github.com/rust-lang/crates.io-index", "manifest_path": "/reg/sneaky-1.0.0/Cargo.toml",
                 "targets": [{"name": "build-script-build", "kind": ["custom-build"], "src_path": "/reg/sneaky-1.0.0/build.rs"}]},
                {"name": "pm", "version": "0.1.0", "id": "pm 0.1.0", "source": "registry+https://github.com/rust-lang/crates.io-index", "manifest_path": "/reg/pm-0.1.0/Cargo.toml",
                 "targets": [{"name": "pm", "kind": ["proc-macro"], "src_path": "/reg/pm-0.1.0/src/lib.rs"}]},
                {"name": "app", "version": "0.1.0", "id": "app 0.1.0", "source": null, "manifest_path": "/w/Cargo.toml", "targets": []}
            ],
            "workspace_members": ["app 0.1.0"], "resolve": null, "workspace_root": "/w", "target_directory": "/w/target"
        }))
        .unwrap();
        // the child's exec appears before the parent's clone return, as in real traces
        let log = r#"100 execve("/root/.cargo/bin/cargo", ["cargo", "build"], ["HOME=/h"]) = 0
101 execve("/t/debug/build/sneaky-0123456789abcdef/build-script-build", ["/t/debug/build/sneaky-0123456789abcdef/build-script-build"], ["CARGO_PKG_NAME=sneaky", "CARGO_PKG_VERSION=1.0.0", "HOST=x86_64-unknown-linux-gnu"]) = 0
100 <... clone3 resumed>) = 101
100 clone3({flags=CLONE_VM}, 88) = 102
100 openat(AT_FDCWD</w>, "/h/.ssh/id_rsa", O_RDONLY) = 3</h/.ssh/id_rsa>
101 openat(AT_FDCWD</reg/sneaky-1.0.0>, "/h/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3</h/.ssh/id_rsa>
101 openat(AT_FDCWD</reg/sneaky-1.0.0>, "gen.rs", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4</reg/sneaky-1.0.0/gen.rs>
101 connect(4<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH (Network is unreachable)
101 clone3({flags=CLONE_VM|CLONE_VFORK}, 88) = 103
103 execve("/usr/local/bin/wget", ["wget", "http://x"], ["HOST=x"]) = -1 ENOENT (No such file or directory)
103 execve("/usr/bin/wget", ["wget", "http://x"], ["HOST=x"]) = -1 ENOENT (No such file or directory)
101 clone3({flags=CLONE_VM|CLONE_VFORK}, 88) = 104
104 execve("/usr/bin/sh", ["sh", "-c", "true"], ["HOST=x"]) = 0
104 openat(AT_FDCWD</reg/sneaky-1.0.0>, "/tmp/scratch", O_WRONLY|O_CREAT, 0666) = 3</tmp/scratch>
102 execve("/rt/bin/rustc", ["rustc", "--crate-name", "app", "--extern", "pm=/t/debug/deps/libpm-0123456789abcdef.so"], ["CARGO_PKG_NAME=app"]) = 0
102 openat(AT_FDCWD</w>, "/h/.aws/credentials", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
102 openat(AT_FDCWD</w>, "/t/debug/deps/app.o", O_WRONLY|O_CREAT, 0644) = 5</t/debug/deps/app.o>
102 clone3({flags=CLONE_VM|CLONE_VFORK}, 88) = 105
105 execve("/usr/bin/cc", ["cc", "-o", "/t/debug/app"], []) = 0
"#;
        let ev = parse_strace(|| Ok(std::io::BufReader::new(log.as_bytes())), &meta).unwrap();
        assert!(ev.items.iter().all(|(a, _, _)| *a != Actor::None), "cargo's own events are not kept: {:?}", ev.items);
        let homes = Homes { real_home: Some(PathBuf::from("/h")), cargo_home: None, rustup_home: None };
        let zones = Zones::new(&meta, &homes, None, Path::new("/t"), &[], Path::new("/work"));
        let mut crates = BTreeMap::new();
        apply_events(&ev, &zones, &mut crates);
        let s = &crates[&("sneaky".to_string(), "1.0.0".to_string())];
        assert_eq!(s.sensitive["~/.ssh/id_rsa"].access, Access::Opened);
        assert_eq!(s.writes.get("/reg/sneaky-1.0.0/gen.rs"), Some(&"own source"));
        assert_eq!(s.net[0].address, "192.0.2.1:9");
        assert_eq!(s.net[0].result, "ENETUNREACH");
        assert!(s.procs.contains_key(&("sh".to_string(), ProgClass::Helper)));
        assert!(!s.procs[&("wget".to_string(), ProgClass::NetworkTool)].found);
        assert_eq!(s.temp_writes, 1);
        let pm = &crates[&("pm".to_string(), "0.1.0".to_string())];
        assert_eq!(pm.sensitive["~/.aws/credentials"].access, Access::Attempted);
        assert!(pm.macro_hosts.contains("app"));
        assert!(pm.procs.is_empty(), "the linker started by rustc is not the macro's: {:?}", pm.procs);
        assert!(pm.writes.is_empty());
        let codes: Vec<String> = s.findings().iter().map(|f| f.code.clone()).collect();
        for c in ["buildtrace/network", "buildtrace/credential-access", "buildtrace/writes-source", "buildtrace/spawns-network-tool", "buildtrace/spawns-helper", "buildtrace/writes-temp"] {
            assert!(codes.contains(&c.to_string()), "{c} missing from {codes:?}");
        }
        let f = s.findings().into_iter().find(|f| f.code == "buildtrace/credential-access").unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }
}
