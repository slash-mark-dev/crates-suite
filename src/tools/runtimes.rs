//! Async Runtime Conflict Detector: Mixed async runtimes, duplicate Tokio majors, and blocking calls inside async dependencies.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Package};
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::items::{fns, in_ranges, matching, test_ranges};
use crate::rustsrc::{Kind, LoadOpts, SourceFile, Token, load_crate};
use crate::tools::features_util as fu;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Runtimes;

const OPTS: &[Opt] = &[
    Opt::flag("deps", "Also scan the sources of runtime-coupled dependencies for blocking calls in async code"),
    Opt::flag("no-scan", "Skip the blocking-in-async source scan"),
];

impl Tool for Runtimes {
    fn name(&self) -> &'static str {
        "runtimes"
    }
    fn title(&self) -> &'static str {
        "Async Runtime Conflict Detector"
    }
    fn group(&self) -> Group {
        Group::Features
    }
    fn summary(&self) -> &'static str {
        "Mixed async runtimes, duplicate Tokio majors, and blocking calls inside async dependencies"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Finds async runtime conflicts in the project's dependency graph (`cargo metadata`).
Runtimes recognised: tokio (0.1/0.2/0.3/1 majors), actix-rt (tokio), async-std and
async-global-executor, smol and async-executor, glommio, monoio, compio, embassy-executor, plus the
plain executors futures-executor and wasm-bindgen-futures (listed, never counted as a conflict).
Runtime-coupled crates are mapped to runtimes through their normal dependency on a runtime crate and
through runtime-selection features (sqlx/sea-orm `runtime-tokio*`/`runtime-async-std*`, redis
`tokio-comp`/`async-std-comp`, mongodb `tokio-runtime`/`async-std-runtime`, rdkafka `tokio`, ...).
A runtime crate that only other runtime crates depend on (async-std's executor stack, compat layers)
does not count on its own. Findings: two runtime families in the release graph (high,
`runtimes/mixed`) and two tokio majors (high, `runtimes/tokio-majors`), each with the chains from a
workspace member; a runtime only reached through dev-dependencies (info). tokio 1 with none of
its runtime-backed features (rt, rt-multi-thread, net, time, fs, process, signal, io-std, full) is
listed as utilities only and does not count as a runtime.
Blocking in async (lexer, workspace members; --deps adds runtime-coupled dependencies): inside
`async fn` bodies and `async {}` blocks, std::thread::sleep, std::fs / std::net calls (also through
`use std::fs` imports), stdin().read_line, reqwest::blocking, `.block_on(` (nested runtime panic) and
a std Mutex guard bound with `let ... = x.lock()` that is still alive at a later `.await` in the
same block (medium, with file:line). Code inside spawn_blocking/block_in_place/thread::spawn
arguments and #[test] code is ignored. The graph is filtered for the host platform. Limits: the scan is lexical (no type information), so a `fs::` alias for an async fs module is
recognised only through its `use` line."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &["sm-crates runtimes", "sm-crates runtimes --deps", "sm-crates runtimes --json --fail-on medium"]
    }
    fn requires(&self) -> &'static str {
        "cargo, network (sources of dependencies with --deps)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let manifest = ctx.manifest_path();
        if !manifest.is_file() {
            return Err(Error::Env(format!("no Cargo.toml at {} (run inside a Cargo project or pass --project DIR)", manifest.display())));
        }
        let host = fu::host_triple()?;
        let meta = fu::load_metadata_at(ctx, &manifest, &MetaOpts { filter_platform: Some(host.clone()), ..Default::default() })?;
        let label = meta.members().iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
        let mut rep = Report::new("runtimes", format!("project {label}"));
        let release = meta.reachable(false, false);
        let with_dev = meta.reachable(true, false);
        // `cargo metadata` unifies features over dev-dependencies; the release build's own
        // features (resolver 2 keeps dev-only features out) come from `cargo tree -e normal`.
        let unified = fu::metadata_active(&meta);
        let active = match fu::cargo_tree(ctx, &manifest, "normal", &host, &[]) {
            Ok(lines) => {
                let mut a = fu::active_from_tree(&meta, &fu::tree_features(&lines, false));
                for (id, f) in &unified {
                    a.entry(id.clone()).or_insert_with(|| f.clone());
                }
                a
            }
            Err(e) => {
                rep.note(format!("release features unavailable ({e}); using features unified with dev-dependencies"));
                unified
            }
        };

        // ---- runtime packages
        let mut rts: Vec<Rt> = Vec::new();
        for p in &meta.packages {
            let Some((family, aux)) = runtime_family(&p.name) else { continue };
            let in_rel = release.contains(&p.id);
            if !in_rel && !with_dev.contains(&p.id) {
                continue;
            }
            let dependents: Vec<(&Package, bool)> = meta
                .dependents_of(&p.id)
                .into_iter()
                .filter(|(q, e)| if in_rel { release.contains(&q.id) && e.is_normal() } else { with_dev.contains(&q.id) })
                .map(|(q, _)| (q, runtime_family(&q.name).is_some()))
                .collect();
            let internal = !dependents.is_empty() && dependents.iter().all(|(_, is_rt)| *is_rt);
            // tokio 1 without any runtime-backed feature (only sync, macros, io-util...) runs on any executor
            let aux = aux || (p.name == "tokio" && tokio_without_runtime(&p.version, active.get(&p.id)));
            rts.push(Rt {
                id: p.id.clone(),
                name: p.name.clone(),
                version: p.version.clone(),
                family: family_label(family, &p.name, &p.version),
                base_family: family.to_string(),
                aux,
                release: in_rel,
                internal,
                dependents: dependents.iter().map(|(q, _)| q.spec()).collect(),
            });
        }
        rts.sort_by(|a, b| a.family.cmp(&b.family).then(a.name.cmp(&b.name)).then(a.version.cmp(&b.version)));

        // ---- coupled crates
        let mut coupled: Vec<(String, String, String)> = Vec::new();
        for p in &meta.packages {
            if !release.contains(&p.id) || runtime_family(&p.name).is_some() {
                continue;
            }
            let Some(node) = meta.node(&p.id) else { continue };
            let mut found: BTreeMap<String, String> = BTreeMap::new();
            for e in node.deps.iter().filter(|e| e.is_normal()) {
                if let Some(rt) = rts.iter().find(|r| r.id == e.pkg) {
                    found.entry(rt.family.clone()).or_insert_with(|| format!("depends on {}", rt.name));
                }
            }
            let empty = BTreeSet::new();
            for f in active.get(&p.id).unwrap_or(&empty) {
                if let Some(fam) = feature_runtime(&p.name, f) {
                    let label = rts.iter().find(|r| r.base_family == fam && r.release).map(|r| r.family.clone()).unwrap_or_else(|| fam.to_string());
                    found.insert(label, format!("feature `{f}`"));
                }
            }
            for (fam, how) in found {
                coupled.push((p.spec(), fam, how));
            }
        }

        // ---- findings
        let counted: Vec<&Rt> = rts.iter().filter(|r| r.release && !r.aux && !r.internal).collect();
        let families: BTreeSet<&str> = counted.iter().map(|r| r.base_family.as_str()).collect();
        if families.len() > 1 {
            let mut detail = Vec::new();
            for r in &counted {
                detail.push(format!("{}: {}", r.family, meta.path_to(&r.id).join(" -> ")));
            }
            let fams: Vec<&str> = families.iter().copied().collect();
            rep.finding(
                Finding::new(Severity::High, "runtimes/mixed", format!("{} async runtimes in the release build: {}", fams.len(), fams.join(", ")))
                    .detail(detail.join("\n"))
                    .fix("pick one runtime: switch the coupled crates' runtime features (e.g. sqlx `runtime-tokio`), or replace crates tied to the other runtime; mixing them means two thread pools and futures that panic outside their own reactor"),
            );
        }
        let tokio_majors: BTreeSet<String> = rts.iter().filter(|r| r.release && r.name == "tokio" && !r.aux).map(|r| r.family.clone()).collect();
        if tokio_majors.len() > 1 {
            let detail: Vec<String> = rts.iter().filter(|r| r.release && r.name == "tokio" && !r.aux).map(|r| format!("tokio {}: {}", r.version, meta.path_to(&r.id).join(" -> "))).collect();
            rep.finding(
                Finding::new(Severity::High, "runtimes/tokio-majors", format!("{} tokio majors in the release build: {}", tokio_majors.len(), tokio_majors.into_iter().collect::<Vec<_>>().join(", ")))
                    .krate("tokio", None::<String>)
                    .detail(detail.join("\n"))
                    .fix("upgrade the crates that pull the old tokio (see the chains); a future from one tokio major panics with 'there is no reactor running' on the other"),
            );
        }
        for r in rts.iter().filter(|r| !r.release && !r.aux && !r.internal) {
            rep.finding(
                Finding::new(Severity::Info, "runtimes/dev-only", format!("{} is only used by dev-dependencies (tests, examples, benches)", r.family))
                    .krate(r.name.clone(), Some(r.version.clone()))
                    .detail(meta.path_to(&r.id).join(" -> ")),
            );
        }

        // ---- blocking scan
        let mut scanned = 0usize;
        let mut blocking_json = Vec::new();
        if !args.flag("no-scan") {
            let mut targets: Vec<(String, String, std::path::PathBuf)> = meta.members().iter().map(|p| (p.name.clone(), p.version.clone(), p.dir())).collect();
            if args.flag("deps") {
                let names: BTreeSet<&str> = coupled.iter().map(|c| c.0.as_str()).collect();
                for p in meta.packages.iter().filter(|p| names.contains(p.spec().as_str()) && !meta.is_member(&p.id)) {
                    let dir = if p.is_crates_io() { crate::registry::download::unpacked(ctx, &p.name, &p.version) } else { Ok(p.dir()) };
                    match dir {
                        Ok(d) => targets.push((p.name.clone(), p.version.clone(), d)),
                        Err(e) => rep.note(format!("{}: source unavailable ({e})", p.spec())),
                    }
                }
            }
            for (name, version, dir) in &targets {
                let files = load_crate(dir, LoadOpts { auxiliary: false, build_script: false });
                for f in &files {
                    scanned += 1;
                    for b in blocking_calls(f) {
                        blocking_json.push(json!({"crate": name, "version": version, "file": f.rel, "line": b.line, "kind": b.kind, "code": b.text}));
                        rep.finding(
                            Finding::new(Severity::Medium, "runtimes/blocking-in-async", b.message)
                                .krate(name.clone(), Some(version.clone()))
                                .at(f.rel.clone(), Some(b.line))
                                .detail(b.text)
                                .fix(b.fix),
                        );
                    }
                }
            }
        }

        // ---- tables
        let mut t = Table::new("Async runtimes", &["Runtime", "Version(s)", "Build", "Pulled in by"]);
        let mut by_family: BTreeMap<(String, bool), Vec<&Rt>> = BTreeMap::new();
        for r in &rts {
            by_family.entry((r.family.clone(), r.release)).or_default().push(r);
        }
        for ((fam, rel), v) in &by_family {
            let vers: BTreeSet<String> = v.iter().map(|r| format!("{}@{}", r.name, r.version)).collect();
            let by: BTreeSet<String> = v.iter().flat_map(|r| r.dependents.iter().cloned()).collect();
            let mut by: Vec<String> = by.into_iter().collect();
            if by.len() > 6 {
                let n = by.len() - 6;
                by.truncate(6);
                by.push(format!("+{n} more"));
            }
            let note = if v.iter().all(|r| r.aux && r.name == "tokio") {
                " (utilities only, no runtime features)"
            } else if v.iter().all(|r| r.aux) {
                " (executor only)"
            } else if v.iter().all(|r| r.internal) {
                " (inside another runtime)"
            } else {
                ""
            };
            t.row([format!("{fam}{note}"), vers.into_iter().collect::<Vec<_>>().join(", "), if *rel { "release" } else { "dev only" }.into(), by.join(", ")]);
        }
        rep.table(t);
        let mut ct = Table::new("Runtime-coupled crates", &["Crate", "Runtime", "Coupling"]);
        for (c, f, how) in &coupled {
            ct.row([c.clone(), f.clone(), how.clone()]);
        }
        rep.table(ct);

        let fam_list: Vec<&str> = families.iter().copied().collect();
        rep.summary(format!(
            "{} in the release build; {} runtime-coupled crate(s); {} blocking call(s) in async code across {scanned} file(s)",
            if fam_list.is_empty() { "no async runtime".to_string() } else { format!("runtime(s): {}", fam_list.join(", ")) },
            coupled.len(),
            blocking_json.len()
        ));
        rep.note(format!("dependency graph filtered for the host platform ({host}); target-specific dependencies of other platforms are not included"));
        rep.data = json!({
            "runtimes": rts.iter().map(|r| json!({"crate": r.name, "version": r.version, "runtime": r.family, "release": r.release, "executor_only": r.aux, "internal": r.internal, "dependents": r.dependents, "chain": meta.path_to(&r.id)})).collect::<Vec<_>>(),
            "families": fam_list,
            "coupled": coupled.iter().map(|(c, f, h)| json!({"crate": c, "runtime": f, "how": h})).collect::<Vec<_>>(),
            "blocking": blocking_json,
        });
        Ok(rep)
    }
}

struct Rt {
    id: String,
    name: String,
    version: String,
    family: String,
    base_family: String,
    aux: bool,
    release: bool,
    internal: bool,
    dependents: Vec<String>,
}

/// Runtime family of a crate and whether it is only an executor (no I/O reactor).
pub fn runtime_family(name: &str) -> Option<(&'static str, bool)> {
    Some(match name {
        "tokio" | "actix-rt" => ("tokio", false),
        "async-std" | "async-global-executor" => ("async-std", false),
        "smol" | "async-executor" => ("smol", false),
        "glommio" => ("glommio", false),
        "monoio" => ("monoio", false),
        "compio" | "compio-runtime" => ("compio", false),
        "embassy-executor" => ("embassy", false),
        "futures-executor" => ("futures-executor", true),
        "wasm-bindgen-futures" => ("wasm-bindgen-futures", true),
        _ => return None,
    })
}

/// tokio 1.x with none of the features that need a tokio runtime to work.
fn tokio_without_runtime(version: &str, features: Option<&BTreeSet<String>>) -> bool {
    const RUNTIME: &[&str] = &["full", "rt", "rt-multi-thread", "net", "time", "process", "signal", "fs", "io-std"];
    let major1 = util::parse_version(version).is_some_and(|v| v.major >= 1);
    major1 && features.is_some_and(|f| !f.iter().any(|x| RUNTIME.contains(&x.as_str())))
}

fn family_label(family: &str, name: &str, version: &str) -> String {
    if name == "tokio" {
        let b = util::parse_version(version).map(|v| util::semver_bucket(&v)).unwrap_or_else(|| version.to_string());
        format!("tokio {b}")
    } else {
        family.to_string()
    }
}

/// Runtime selected by a well-known runtime feature of a coupled crate.
fn feature_runtime(krate: &str, f: &str) -> Option<&'static str> {
    let tokio = |s: &str| s.starts_with("runtime-tokio") || s.starts_with("runtime-actix");
    let astd = |s: &str| s.starts_with("runtime-async-std");
    match krate {
        "sqlx" | "sqlx-core" | "sqlx-rt" | "sea-orm" | "sea-query-binder" | "sqlx-postgres" | "sqlx-mysql" | "sqlx-sqlite" | "sqlx-macros-core" => {
            if tokio(f) || f == "_rt-tokio" {
                Some("tokio")
            } else if astd(f) || f == "_rt-async-std" {
                Some("async-std")
            } else {
                None
            }
        }
        "redis" => match f {
            "tokio-comp" | "tokio-rustls-comp" | "tokio-native-tls-comp" => Some("tokio"),
            "async-std-comp" | "async-std-rustls-comp" | "async-std-native-tls-comp" => Some("async-std"),
            "smol-comp" => Some("smol"),
            _ => None,
        },
        "mongodb" => match f {
            "tokio-runtime" => Some("tokio"),
            "async-std-runtime" => Some("async-std"),
            _ => None,
        },
        "rdkafka" if f == "tokio" => Some("tokio"),
        "lapin" | "amq-protocol" if f.contains("tokio") => Some("tokio"),
        "zbus" => match f {
            "tokio" => Some("tokio"),
            "async-io" => Some("smol"),
            _ => None,
        },
        "async-tungstenite" => match f {
            "tokio-runtime" => Some("tokio"),
            "async-std-runtime" => Some("async-std"),
            _ => None,
        },
        _ => None,
    }
}

/// One blocking call found in async code.
#[derive(Debug, Clone)]
pub struct Blocking {
    pub line: usize,
    pub kind: &'static str,
    pub message: String,
    pub fix: String,
    pub text: String,
}

fn find_call_args(code: &[Token], names: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..code.len() {
        if code[i].kind == Kind::Ident && names.contains(&code[i].text.as_str()) && code.get(i + 1).is_some_and(|t| t.punct("(")) {
            if let Some(c) = matching(code, i + 1) {
                out.push((i + 1, c));
            }
        }
    }
    out
}

/// What a file imports from a std module (`use std::fs;`, `use std::fs::File;`, `use std::net::{..}`).
fn imports(code: &[Token]) -> String {
    let mut s = String::new();
    let mut i = 0;
    while i < code.len() {
        if code[i].ident("use") {
            let mut j = i + 1;
            while j < code.len() && !code[j].punct(";") {
                s.push_str(&code[j].text);
                j += 1;
            }
            s.push('\n');
            i = j;
        }
        i += 1;
    }
    s
}

/// Blocking calls inside async contexts of one file.
pub fn blocking_calls(f: &SourceFile) -> Vec<Blocking> {
    let code = &f.code;
    let tests = test_ranges(code);
    let all_fns = fns(code);
    // regions: (open, close, is_async)
    let mut regions: Vec<(usize, usize, bool)> = Vec::new();
    for fun in &all_fns {
        if let Some((a, b)) = fun.body {
            regions.push((a, b, fun.is_async));
        }
    }
    for i in 0..code.len() {
        if code[i].ident("async") {
            let mut j = i + 1;
            if code.get(j).is_some_and(|t| t.ident("move")) {
                j += 1;
            }
            if code.get(j).is_some_and(|t| t.punct("{")) {
                if let Some(c) = matching(code, j) {
                    regions.push((j, c, true));
                }
            }
        }
    }
    for (a, b) in find_call_args(code, &["spawn_blocking", "block_in_place", "spawn_blocking_with", "unblock"]) {
        regions.push((a, b, false));
    }
    // std::thread::spawn(...)
    for i in 2..code.len() {
        if code[i].ident("spawn") && code[i - 1].punct("::") && code[i - 2].ident("thread") && code.get(i + 1).is_some_and(|t| t.punct("(")) {
            if let Some(c) = matching(code, i + 1) {
                regions.push((i + 1, c, false));
            }
        }
    }
    let in_async = |idx: usize| -> bool {
        regions.iter().filter(|(a, b, _)| *a < idx && idx < *b).min_by_key(|(a, b, _)| b - a).is_some_and(|r| r.2)
    };
    let imp = imports(code);
    let std_fs = imp.contains("std::fs") && !imp.contains("tokio::fs") && !imp.contains("async_std::fs");
    let std_net = imp.contains("std::net") && !imp.contains("tokio::net") && !imp.contains("async_std::net");
    let std_file = imp.contains("std::fs::File") || (imp.contains("std::fs::{") && imp.lines().any(|l| l.starts_with("std::fs::{") && l.contains("File")));
    let id = |i: usize, s: &str| code.get(i).is_some_and(|t| t.ident(s));
    let p = |i: usize, s: &str| code.get(i).is_some_and(|t| t.punct(s));
    let prev_is_path = |i: usize| i > 0 && code[i - 1].punct("::");
    let mut out = Vec::new();
    let mut push = |i: usize, kind: &'static str, message: String, fix: &str| {
        out.push(Blocking { line: code[i].line, kind, message, fix: fix.to_string(), text: f.line_text(code[i].line).trim().to_string() });
    };
    for i in 0..code.len() {
        if code[i].kind != Kind::Ident || in_ranges(&tests, i) || !in_async(i) {
            continue;
        }
        let t = code[i].text.as_str();
        match t {
            "thread" if p(i + 1, "::") && id(i + 2, "sleep") && (!prev_is_path(i) || id(i.wrapping_sub(2), "std")) => {
                push(i, "thread-sleep", "std::thread::sleep blocks the executor thread inside async code".into(), "use tokio::time::sleep(d).await (or async_std::task::sleep / smol::Timer::after)");
            }
            "fs" if p(i + 1, "::") && code.get(i + 2).is_some_and(|x| x.kind == Kind::Ident) && ((prev_is_path(i) && id(i.wrapping_sub(2), "std")) || (!prev_is_path(i) && std_fs)) => {
                push(i, "std-fs", format!("blocking std::fs::{} inside async code", code[i + 2].text), "use tokio::fs / async_std::fs, or move the call into spawn_blocking");
            }
            "File" if !prev_is_path(i) && std_file && p(i + 1, "::") && (id(i + 2, "open") || id(i + 2, "create")) => {
                push(i, "std-fs", format!("blocking std::fs::File::{} inside async code", code[i + 2].text), "use tokio::fs::File / async_std::fs::File, or move the call into spawn_blocking");
            }
            "net" if p(i + 1, "::") && prev_is_path(i) && id(i.wrapping_sub(2), "std") && code.get(i + 2).is_some_and(|x| matches!(x.text.as_str(), "TcpStream" | "TcpListener" | "UdpSocket")) => {
                push(i, "std-net", format!("blocking std::net::{} inside async code", code[i + 2].text), "use tokio::net / async_std::net types");
            }
            "TcpStream" | "TcpListener" | "UdpSocket" if !prev_is_path(i) && std_net && p(i + 1, "::") && (id(i + 2, "connect") || id(i + 2, "bind")) => {
                push(i, "std-net", format!("blocking std::net::{}::{} inside async code", t, code[i + 2].text), "use tokio::net / async_std::net types");
            }
            "stdin" if p(i + 1, "(") && p(i + 2, ")") && p(i + 3, ".") && (id(i + 4, "read_line") || id(i + 4, "lines") || id(i + 4, "read_to_string")) => {
                push(i, "stdin", "blocking stdin read inside async code".into(), "use tokio::io::stdin() with AsyncBufReadExt, or read on a spawn_blocking thread");
            }
            "reqwest" if p(i + 1, "::") && id(i + 2, "blocking") => {
                push(i, "reqwest-blocking", "reqwest::blocking inside async code (it starts its own runtime and panics inside one)".into(), "use the async reqwest::Client and .await the request");
            }
            "block_on" if i > 0 && (code[i - 1].punct(".") || code[i - 1].punct("::")) && p(i + 1, "(") => {
                push(i, "block-on", "block_on inside async code: nested runtimes panic ('Cannot start a runtime from within a runtime') or deadlock".into(), "`.await` the future instead of blocking on it");
            }
            "let" => {
                if let Some(b) = guard_across_await(code, i) {
                    push(b.0, "mutex-guard-across-await", format!("Mutex guard `{}` is held across `.await` (line {})", b.1, b.2), "use tokio::sync::Mutex (lock().await), or drop the guard before the .await (scope it in a block or call drop(guard))");
                }
            }
            _ => {}
        }
    }
    out
}

/// `let g = x.lock()[.unwrap()|.expect(..)|?];` followed by an `.await` in the same block
/// before `drop(g)`. Returns (token, guard name, await line).
fn guard_across_await(code: &[Token], let_idx: usize) -> Option<(usize, String, usize)> {
    let mut j = let_idx + 1;
    if code.get(j).is_some_and(|t| t.ident("mut")) {
        j += 1;
    }
    let name = code.get(j).filter(|t| t.kind == Kind::Ident)?.text.clone();
    if name == "_" {
        return None;
    }
    // statement end
    let mut depth = 0i32;
    let mut k = j;
    let mut end = None;
    while k < code.len() {
        match code[k].text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                if depth == 0 {
                    return None;
                }
                depth -= 1
            }
            ";" if depth == 0 => {
                end = Some(k);
                break;
            }
            _ => {}
        }
        k += 1;
    }
    let end = end?;
    // expression must end in `.lock()` (+ unwrap/expect/?), and not `.lock().await`
    let lock = (j..end).rev().find(|&x| code[x].ident("lock") && x > 0 && code[x - 1].punct(".") && code.get(x + 1).is_some_and(|t| t.punct("(")))?;
    let close = matching(code, lock + 1)?;
    let mut x = close + 1;
    while x < end {
        if code[x].punct("?") {
            x += 1;
        } else if code[x].punct(".") && (code.get(x + 1).is_some_and(|t| t.ident("unwrap") || t.ident("expect"))) && code.get(x + 2).is_some_and(|t| t.punct("(")) {
            x = matching(code, x + 2)? + 1;
        } else {
            return None;
        }
    }
    // the enclosing block
    let mut d = 0i32;
    let mut open = None;
    for y in (0..let_idx).rev() {
        if code[y].punct("}") {
            d += 1;
        } else if code[y].punct("{") {
            if d == 0 {
                open = Some(y);
                break;
            }
            d -= 1;
        }
    }
    let block_end = matching(code, open?)?;
    let mut y = end + 1;
    let mut depth = 0i32;
    while y < block_end {
        let t = &code[y];
        if t.punct("{") {
            depth += 1;
        } else if t.punct("}") {
            depth -= 1;
        }
        if t.ident("drop") && code.get(y + 1).is_some_and(|t| t.punct("(")) && code.get(y + 2).is_some_and(|t| t.ident(&name)) && depth == 0 {
            return None;
        }
        if t.punct(".") && code.get(y + 1).is_some_and(|t| t.ident("await")) {
            return Some((let_idx, name, code[y + 1].line));
        }
        y += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(src: &str) -> Vec<Blocking> {
        let dir = std::env::temp_dir();
        blocking_calls(&SourceFile::from_text(&dir, &dir.join("src/lib.rs"), src.to_string()))
    }

    #[test]
    fn finds_blocking_calls_in_async_code() {
        let src = r#"
use std::fs;
use std::sync::Mutex;
pub async fn handler(m: &Mutex<u8>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let s = fs::read_to_string("x").unwrap();
    let g = m.lock().unwrap();
    other().await;
    tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(1)));
    let v = m.lock().unwrap().clone();
    rt.block_on(other());
}
pub fn sync_fn() { std::thread::sleep(std::time::Duration::from_millis(5)); }
pub async fn ok(m: &tokio::sync::Mutex<u8>) {
    let g = m.lock().await;
    other().await;
    { let h = m2.lock().unwrap(); drop(h); }
    let j = async { reqwest::blocking::get("x") };
}
"#;
        let b = scan(src);
        let kinds: Vec<(&str, usize)> = b.iter().map(|x| (x.kind, x.line)).collect();
        assert_eq!(
            kinds,
            [("thread-sleep", 5), ("std-fs", 6), ("mutex-guard-across-await", 7), ("block-on", 11), ("reqwest-blocking", 18)],
            "{kinds:?}"
        );
    }

    #[test]
    fn families() {
        assert_eq!(runtime_family("actix-rt"), Some(("tokio", false)));
        assert_eq!(runtime_family("futures-executor"), Some(("futures-executor", true)));
        assert_eq!(family_label("tokio", "tokio", "0.2.25"), "tokio 0.2");
        assert_eq!(family_label("tokio", "tokio", "1.40.0"), "tokio 1");
        assert_eq!(feature_runtime("sqlx", "runtime-tokio-rustls"), Some("tokio"));
        assert_eq!(feature_runtime("sqlx", "runtime-async-std-native-tls"), Some("async-std"));
        assert_eq!(feature_runtime("redis", "tokio-comp"), Some("tokio"));
        assert_eq!(feature_runtime("serde", "std"), None);
        let f = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<String>>();
        assert!(tokio_without_runtime("1.40.0", Some(&f(&["sync", "macros"]))));
        assert!(!tokio_without_runtime("1.40.0", Some(&f(&["sync", "rt"]))));
        assert!(!tokio_without_runtime("0.2.25", Some(&f(&["sync"]))));
    }
}
