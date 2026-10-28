//! no_std Readiness: Which dependencies pull in std or alloc, and the Cargo.toml changes that get you to no_std.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{Metadata, Package};
use crate::registry::index;
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::features_util::{self as fu, Active, Enabler, StdInfo, StdKind, StdVerdict, TargetCfg};
use crate::tools::{Group, Tool};
use crate::util;

pub struct NoStd;

const OPTS: &[Opt] = &[
    Opt::value("target", "TRIPLE", "Evaluate for this target (e.g. thumbv7em-none-eabihf) and, when its std/core is installed, run cargo check for it"),
    Opt::value("package", "NAME", "Workspace member to analyze (default: the root package)"),
    Opt::flag("no-default-features", "Analyze the build with --no-default-features"),
    Opt::value("features", "LIST", "Features to enable on the analyzed package"),
    Opt::flag("all", "List every dependency, not only those that need std or alloc"),
    Opt::value("timeout", "SECS", "Time limit for the cargo check run (default 600)"),
];

impl Tool for NoStd {
    fn name(&self) -> &'static str {
        "nostd"
    }
    fn title(&self) -> &'static str {
        "no_std Readiness"
    }
    fn group(&self) -> Group {
        Group::Features
    }
    fn summary(&self) -> &'static str {
        "Which dependencies pull in std or alloc, and the Cargo.toml changes that get you to no_std"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Answers: what stops this package from building without std, and what do I change?
Target: the local package (--project, --package) or a crate named on the command line (unpacked
from crates.io into a scratch workspace). The root's crate attribute is read with the lexer:
#![no_std], or #![cfg_attr(not(feature = \"std\"), no_std)] evaluated with the active features.
Every normal dependency of the release graph (`cargo tree -e normal --target T`, proc-macro and
build-dependency subtrees excluded, with the features actually enabled) is unpacked and classified:
no_std, no_std unless feature X (e.g. `std`, possibly enabled through `default`), or always std;
active `extern crate std` items count as std, active `extern crate alloc` means it needs alloc.
For each blocking dependency the tool explains who turns the std feature on (dependency
declarations, default features, [features] entries of the dependents) and suggests the
Cargo.toml line `dep = { version = \"...\", default-features = false, features = [...] }`. For
always-std crates.io dependencies it checks the live index for a newer version that has a `std`
feature (and its rust-version). Severity: high when the root declares no_std or the target has no
std, else medium; alloc-only dependencies are info.
--target T: target cfgs are evaluated for T; when T's standard library (or core) is installed
(sysroot check) `cargo check --target T --message-format json` runs and errors such as \"can't find
crate for `std`\" are attributed to the package that failed. Otherwise a note says
`rustup target add T`. Limits: std use behind macros or build scripts is not seen statically."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates nostd",
            "sm-crates nostd serde_json@1.0.140",
            "sm-crates nostd semver@1.0.26 --no-default-features --target thumbv7em-none-eabihf",
            "sm-crates nostd hashbrown@0.15.2 --all",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo, network (index lookups; named crates); rustup target for real cross-checks"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let timeout: u64 = args.parse_or("timeout", 600)?;
        let subj = fu::subject(ctx, args, "nostd")?;
        let meta = &subj.meta;
        let root = subj.package().ok_or_else(|| Error::Env("package not found in cargo metadata".into()))?.clone();
        let mut rep = Report::new("nostd", subj.label.clone());
        let host = fu::host_triple()?;
        let target = args.value("target").map(String::from);
        let tcfg: Option<TargetCfg> = match &target {
            Some(t) => Some(fu::target_cfg(t)?),
            None => None,
        };
        let triple = target.clone().unwrap_or_else(|| host.clone());

        let mut flags: Vec<String> = vec!["-p".into(), root.spec()];
        if args.flag("no-default-features") {
            flags.push("--no-default-features".into());
        }
        let feats = args.list("features");
        if !feats.is_empty() {
            flags.push("--features".into());
            flags.push(feats.join(","));
        }
        let lines = fu::cargo_tree(ctx, &subj.manifest, "normal", &triple, &flags)?;
        let active = fu::active_from_tree(meta, &fu::tree_features(&lines, true));

        // ---- root
        let empty = BTreeSet::new();
        let root_feats = active.get(&root.id).unwrap_or(&empty);
        let root_info = StdInfo::analyze(&root.dir());
        let root_claims = matches!(root_info.kind, StdKind::NoStd | StdKind::NoStdIf(_));
        let root_verdict = root_info.verdict(root_feats, tcfg.as_ref());
        let target_lacks_std = tcfg.as_ref().is_some_and(|t| !t.has_std());
        // high when the analyzed configuration is meant to be no_std
        let blocking_sev = if root_verdict == StdVerdict::NoStd && root_claims || target_lacks_std { Severity::High } else { Severity::Medium };
        if root_claims && root_verdict != StdVerdict::NoStd {
            rep.note(format!("{} supports no_std but this build enables std; re-run with --no-default-features (plus the features you need) to check the no_std configuration", root.name));
        }

        // ---- dependencies
        let mut rows: Vec<Row> = Vec::new();
        let mut index_failures = Vec::new();
        for (id, f) in &active {
            if *id == root.id {
                continue;
            }
            let Some(p) = meta.package(id) else { continue };
            if p.is_proc_macro() {
                continue;
            }
            let info = StdInfo::analyze(&p.dir());
            let verdict = info.verdict(f, tcfg.as_ref());
            let alloc = info.needs_alloc(f, tcfg.as_ref());
            let (status, enabled_by, fix) = match &verdict {
                StdVerdict::NoStd => ("no_std".to_string(), String::new(), String::new()),
                StdVerdict::Unknown => ("unknown (no library source)".to_string(), String::new(), String::new()),
                StdVerdict::StdViaFeatures(fs) => {
                    let by = who_enables(meta, &active, &root, id, fs);
                    let fix = fix_line(meta, &active, &root, p, fs);
                    (format!("std via feature {}", fs.join(", ")), by, fix)
                }
                StdVerdict::AlwaysStd => {
                    let (fix, err) = newer_hint(ctx, p);
                    if let Some(e) = err {
                        index_failures.push(e);
                    }
                    ("always std".to_string(), String::new(), fix)
                }
            };
            rows.push(Row { p: p.clone(), verdict, alloc, status, enabled_by, fix, info_root: info.root_file.clone(), confirmed: None });
        }
        rows.sort_by(|a, b| a.p.name.cmp(&b.p.name).then(a.p.version.cmp(&b.p.version)));
        if !index_failures.is_empty() {
            rep.note(format!("could not check newer versions on the index for: {}", index_failures.join(", ")));
        }

        // ---- real check
        let mut check_json = serde_json::Value::Null;
        if let Some(t) = &target {
            if fu::target_installed(t) {
                let target_dir = ctx.cache_subdir("nostd-target")?;
                let mut cargs = vec!["--target".to_string(), t.clone()];
                cargs.extend(flags.iter().cloned());
                let r = fu::cargo_check(ctx, &subj.manifest, &cargs, &target_dir, Duration::from_secs(timeout))?;
                let mut by_pkg: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
                for e in &r.errors {
                    by_pkg.entry((e.package.clone(), e.version.clone())).or_default().push(e.message.clone());
                }
                let mut ct = Table::new(format!("cargo check --target {t}"), &["Package", "Errors", "First error"]);
                for ((n, v), msgs) in &by_pkg {
                    ct.row([format!("{n}@{v}"), msgs.len().to_string(), msgs[0].clone()]);
                    if let Some(row) = rows.iter_mut().find(|r| &r.p.name == n && &r.p.version == v) {
                        row.confirmed = Some(msgs[0].clone());
                    } else if n != &root.name {
                        rep.finding(
                            Finding::new(blocking_sev, "nostd/check-fails", format!("does not build for {t}: {}", msgs[0]))
                                .krate(n.clone(), Some(v.clone()))
                                .fix(format!("reproduce with `cargo check --target {t} {}`", flags.join(" "))),
                        );
                    }
                }
                if r.success {
                    ct.row(["(all)".to_string(), "0".into(), "build succeeded".into()]);
                } else if r.errors.is_empty() {
                    ct.row(["(cargo)".to_string(), "-".into(), r.stderr_error.clone().unwrap_or_else(|| "cargo check failed".into())]);
                }
                rep.table(ct);
                check_json = json!({"target": t, "success": r.success, "errors": r.errors.iter().map(|e| json!({"package": e.package, "version": e.version, "message": e.message, "file": e.file, "line": e.line})).collect::<Vec<_>>()});
            } else {
                rep.note(format!("the standard library for {t} is not installed, so only static analysis ran; install it with `rustup target add {t}` for a real `cargo check --target {t}`"));
            }
        }

        // ---- findings and table
        let mut t = Table::new(format!("Normal dependencies of {} for {triple}", root.spec()), &["Dependency", "Version", "std status", "Needs alloc", "Enabled by", "Fix"]);
        let mut data = Vec::new();
        let mut blocking = 0;
        for r in &rows {
            let is_blocking = matches!(r.verdict, StdVerdict::StdViaFeatures(_) | StdVerdict::AlwaysStd);
            if is_blocking {
                blocking += 1;
                let msg = match &r.verdict {
                    StdVerdict::StdViaFeatures(fs) => format!("links std because feature {} is enabled", fs.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", ")),
                    _ => "always links std (no #![no_std])".to_string(),
                };
                let msg = if r.confirmed.is_some() { format!("{msg} (confirmed by cargo check)") } else { msg };
                let mut detail = Vec::new();
                if !r.enabled_by.is_empty() {
                    detail.push(format!("enabled by: {}", r.enabled_by));
                }
                if let Some(c) = &r.confirmed {
                    detail.push(format!("cargo check: {c}"));
                }
                let path = meta.path_to(&r.p.id);
                if path.len() > 1 {
                    detail.push(format!("path: {}", path.join(" -> ")));
                }
                let mut f = Finding::new(blocking_sev, "nostd/blocking-dep", msg).krate(r.p.name.clone(), Some(r.p.version.clone()));
                if !detail.is_empty() {
                    f = f.detail(detail.join("\n"));
                }
                if let Some(rf) = &r.info_root {
                    f = f.at(format!("{}/{}", r.p.spec(), rf), None);
                }
                if !r.fix.is_empty() {
                    f = f.fix(r.fix.clone());
                }
                rep.finding(f);
            } else if r.alloc && r.verdict == StdVerdict::NoStd {
                rep.finding(
                    Finding::new(Severity::Info, "nostd/needs-alloc", "no_std but needs `alloc` (extern crate alloc)")
                        .krate(r.p.name.clone(), Some(r.p.version.clone()))
                        .fix("provide a #[global_allocator] on targets without one, or pick features of this crate that avoid alloc"),
                );
            }
            if args.flag("all") || is_blocking || r.alloc {
                t.row([r.p.name.clone(), r.p.version.clone(), r.status.clone(), if r.alloc { "yes" } else { "" }.into(), r.enabled_by.clone(), r.fix.clone()]);
            }
            data.push(json!({
                "crate": r.p.name, "version": r.p.version, "status": r.status, "blocking": is_blocking, "needs_alloc": r.alloc,
                "features": active.get(&r.p.id), "enabled_by": r.enabled_by, "fix": r.fix, "check_error": r.confirmed,
            }));
        }
        rep.table(t);
        let root_status = match (&root_info.kind, &root_verdict) {
            (StdKind::Unknown, _) => "has no library target".to_string(),
            (_, StdVerdict::NoStd) => "is no_std with these features".to_string(),
            (StdKind::NoStdIf(c), StdVerdict::StdViaFeatures(fs)) => format!("is no_std only when cfg({c}) holds; feature {} turns std on", fs.join(", ")),
            (_, StdVerdict::StdViaFeatures(fs)) => format!("links std through feature {}", fs.join(", ")),
            _ => "does not declare #![no_std]".to_string(),
        };
        if !root_claims && root_info.kind != StdKind::Unknown {
            rep.finding(
                Finding::new(Severity::Info, "nostd/root-uses-std", format!("{} {root_status}", root.name))
                    .krate(root.name.clone(), Some(root.version.clone()))
                    .fix("add #![cfg_attr(not(feature = \"std\"), no_std)] to the crate root and a default `std` feature"),
            );
        }
        rep.summary(format!("{} {root_status}; {blocking} of {} normal dependenc(ies) need std for {triple}", root.name, rows.len()));
        rep.note("features are those `cargo tree -e normal` resolves for this build; proc-macros and build-dependencies run on the host and are excluded");
        rep.data = json!({
            "package": root.name, "version": root.version, "target": triple, "target_has_std": tcfg.as_ref().map(|t| t.has_std()).unwrap_or(true),
            "root": {"declares_no_std": root_claims, "status": root_status, "features": root_feats},
            "dependencies": data, "check": check_json,
        });
        Ok(rep)
    }
}

struct Row {
    p: Package,
    verdict: StdVerdict,
    alloc: bool,
    status: String,
    enabled_by: String,
    fix: String,
    info_root: Option<String>,
    confirmed: Option<String>,
}

/// Declarations (outside the package itself) that turn the given features on, following the
/// package's own feature table (`default -> std`). Returns the enabler and the feature chain.
fn outside_enablers(meta: &Metadata, active: &Active, id: &str, feats: &[String]) -> Vec<(Enabler, Vec<String>)> {
    let mut out = Vec::new();
    for f in feats {
        let mut stack = vec![(f.clone(), vec![f.clone()])];
        let mut seen = BTreeSet::new();
        while let Some((g, chain)) = stack.pop() {
            if !seen.insert(g.clone()) || chain.len() > 6 {
                continue;
            }
            // only declarations from packages that are part of this build count
            for e in fu::enablers(meta, active, id, &g).into_iter().filter(|e| active.contains_key(&e.by) && (e.kind == "self" || e.kind == "normal")) {
                if e.kind == "self" {
                    if let Some(h) = &e.via_feature {
                        let mut c = chain.clone();
                        c.insert(0, h.clone());
                        stack.push((h.clone(), c));
                    }
                } else {
                    out.push((e, chain.clone()));
                }
            }
        }
    }
    out
}

/// Short description of who turns the given features on.
fn who_enables(meta: &Metadata, active: &Active, root: &Package, id: &str, feats: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    for (e, chain) in outside_enablers(meta, active, id, feats) {
        let src = match &e.via_feature {
            Some(g) if e.by == root.id => format!("{}[{g}]{}", e.by_spec, if fu::feature_closure(&root.features, &["default".to_string()]).contains(g) { " (default)" } else { "" }),
            Some(g) => format!("{}[{g}]", e.by_spec),
            None if e.how.contains("default features") => format!("{} (default features on)", e.by_spec),
            None => format!("{} ({})", e.by_spec, e.how),
        };
        out.push(format!("{src} -> {}", chain.join(" -> ")));
    }
    out.sort();
    out.dedup();
    if out.len() > 3 {
        let n = out.len() - 3;
        out.truncate(3);
        out.push(format!("+{n} more"));
    }
    out.join("; ")
}

/// How to turn the std features off: a root feature to drop, the Cargo.toml line for a direct
/// dependency, or the dependents to change.
fn fix_line(meta: &Metadata, active: &Active, root: &Package, p: &Package, culprits: &[String]) -> String {
    let empty = BTreeSet::new();
    let ens = outside_enablers(meta, active, &p.id, culprits);
    // 1. the root's own feature turns it on
    let root_feats: BTreeSet<String> = ens.iter().filter(|(e, _)| e.by == root.id).filter_map(|(e, _)| e.via_feature.clone()).collect();
    if !root_feats.is_empty() {
        let on = active.get(&root.id).unwrap_or(&empty);
        let keep: Vec<String> = on
            .iter()
            .filter(|f| *f != "default" && !root_feats.contains(*f) && !fu::is_dep_feature(root, f))
            .filter(|f| fu::feature_closure(&root.features, std::slice::from_ref(*f)).is_disjoint(&root_feats))
            .cloned()
            .collect();
        return format!(
            "turn off {}'s feature {}: build with --no-default-features{}",
            root.name,
            root_feats.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", "),
            if keep.is_empty() { String::new() } else { format!(" --features {}", keep.join(",")) }
        );
    }
    // 2. a direct dependency declaration of the root
    let on = active.get(&p.id).unwrap_or(&empty);
    let keep: Vec<String> = on
        .iter()
        .filter(|f| *f != "default" && !culprits.contains(f) && !fu::is_dep_feature(p, f))
        .filter(|f| {
            let c = fu::feature_closure(&p.features, std::slice::from_ref(*f));
            culprits.iter().all(|x| !c.contains(x))
        })
        .cloned()
        .collect();
    let feats = if keep.is_empty() { String::new() } else { format!(", features = [{}]", keep.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ")) };
    let direct = root.dependencies.iter().find(|d| d.kind() == "normal" && util::normalize_crate_name(&d.name) == util::normalize_crate_name(&p.name));
    if let Some(d) = direct {
        if ens.iter().any(|(e, _)| e.by == root.id) {
            return fu::dep_line_without_defaults(d, &keep);
        }
    }
    // 3. other dependents
    let by: BTreeSet<String> = ens.iter().filter(|(e, _)| e.by != root.id).map(|(e, _)| e.by_spec.clone()).collect();
    format!(
        "{} is turned on by {}: make them use {} with default-features = false{feats} (usually through their own `std` feature)",
        culprits.join(", "),
        if by.is_empty() { "its dependents".to_string() } else { by.into_iter().collect::<Vec<_>>().join(", ") },
        p.name
    )
}

/// For an always-std crates.io dependency: does a newer version have a `std` feature?
fn newer_hint(ctx: &Ctx, p: &Package) -> (String, Option<String>) {
    if !p.is_crates_io() {
        return ("not from crates.io: make it no_std or replace it".into(), None);
    }
    let has_std_now = p.features.contains_key("std");
    let vs = match index::versions(ctx, &p.name) {
        Ok(v) => v,
        Err(e) => return ("no no_std support in this version; find a no_std alternative".into(), Some(format!("{} ({e})", p.name))),
    };
    let cur = util::parse_version(&p.version);
    let newer = vs
        .iter()
        .filter(|v| !v.yanked && !v.is_prerelease())
        .filter(|v| v.version().is_some_and(|x| cur.as_ref().is_none_or(|c| &x > c)))
        .filter(|v| v.all_features().contains_key("std"))
        .max_by(|a, b| a.version().cmp(&b.version()));
    match newer {
        Some(v) if !has_std_now => (
            format!(
                "{}@{} has a `std` feature (likely optional std){}: upgrade and use default-features = false",
                p.name,
                v.vers,
                v.rust_version.as_ref().map(|r| format!(", rust-version {r}")).unwrap_or_default()
            ),
            None,
        ),
        _ if has_std_now => (
            format!("{} has a `std` feature but no #![no_std] attribute was found in its crate root (it may use a form the lexer does not read); check its docs, or gate it behind your own `std` feature", p.name),
            None,
        ),
        _ => ("no no_std support (no `std` feature in any newer version); replace it or gate it behind your own `std` feature".into(), None),
    }
}
