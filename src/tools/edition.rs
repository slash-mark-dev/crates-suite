//! Edition Migration Planner: Edition-2024 readiness of every workspace member and the migration lints each will hit.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata, Package};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::perf_util::{self as pu, Diag};
use crate::tools::{Group, Tool};
use crate::util;

pub struct Edition;

const OPTS: &[Opt] = &[
    Opt::value("to", "EDITION", "Target edition: 2018, 2021 or 2024 (default: the next edition after each member's current one)"),
    Opt::value("package", "A,B", "Only plan these workspace members"),
    Opt::value("features", "LIST", "Features to enable (comma-separated)"),
    Opt::flag("all-features", "Enable all features (lint code behind every feature)"),
    Opt::flag("no-default-features", "Disable default features"),
    Opt::flag("dry-run-fix", "Copy the workspace to a temp dir, run `cargo fix --edition`, bump the edition and check that it still compiles"),
    Opt::value("timeout", "SECS", "Time limit per cargo run (default 1800)"),
];

pub const EDITIONS: [&str; 4] = ["2015", "2018", "2021", "2024"];

/// Minimum Rust version that understands each edition.
fn min_rust(edition: &str) -> Option<&'static str> {
    match edition {
        "2018" => Some("1.31"),
        "2021" => Some("1.56"),
        "2024" => Some("1.85"),
        _ => None,
    }
}

fn next_edition(e: &str) -> Option<&'static str> {
    let k = EDITIONS.iter().position(|x| *x == e)?;
    EDITIONS.get(k + 1).copied()
}

/// Edition-migration lints (the rust-20xx-compatibility groups) and the edition each prepares for.
const EDITION_LINTS: &[(&str, &str)] = &[
    ("anonymous_parameters", "2018"),
    ("absolute_paths_not_starting_with_crate", "2018"),
    ("keyword_idents_2018", "2018"),
    ("tyvar_behind_raw_pointer", "2018"),
    ("array_into_iter", "2021"),
    ("bare_trait_objects", "2021"),
    ("ellipsis_inclusive_range_patterns", "2021"),
    ("non_fmt_panics", "2021"),
    ("rust_2021_incompatible_closure_captures", "2021"),
    ("rust_2021_incompatible_or_patterns", "2021"),
    ("rust_2021_prefixes_incompatible_syntax", "2021"),
    ("rust_2021_prelude_collisions", "2021"),
    ("boxed_slice_into_iter", "2024"),
    ("dependency_on_unit_never_type_fallback", "2024"),
    ("deprecated_safe_2024", "2024"),
    ("edition_2024_expr_fragment_specifier", "2024"),
    ("if_let_rescope", "2024"),
    ("impl_trait_overcaptures", "2024"),
    ("keyword_idents_2024", "2024"),
    ("missing_unsafe_on_extern", "2024"),
    ("never_type_fallback_flowing_into_unsafe", "2024"),
    ("rust_2024_guarded_string_incompatible_syntax", "2024"),
    ("rust_2024_incompatible_pat", "2024"),
    ("rust_2024_prelude_collisions", "2024"),
    ("static_mut_refs", "2024"),
    ("tail_expr_drop_order", "2024"),
    ("unsafe_attr_outside_unsafe", "2024"),
    ("unsafe_op_in_unsafe_fn", "2024"),
];

impl Tool for Edition {
    fn name(&self) -> &'static str {
        "edition"
    }
    fn title(&self) -> &'static str {
        "Edition Migration Planner"
    }
    fn group(&self) -> Group {
        Group::Api
    }
    fn summary(&self) -> &'static str {
        "Edition-2024 readiness of every workspace member and the migration lints each will hit"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Plans moving each workspace member to a newer edition without changing any code. Reads every
member's edition and rust-version from cargo metadata, then runs `cargo check --workspace
--all-targets --message-format json` with RUSTFLAGS=\"-W rust-20xx-compatibility\" (appended to
your own RUSTFLAGS) in a private target directory under the cache, so your target/ is not
invalidated. Each migration lint hit is counted per member and split into auto-fixable (its
suggestion is MachineApplicable, which is what `cargo fix --edition` applies) and manual (listed
with file:line). Members are ordered leaves-first (members that depend on no other member come
first). It also flags a rust-version below what the target edition needs (2024 needs 1.85) as
high, notes members that inherit `edition` from [workspace.package] (they move together), and
checks rustfmt's style_edition. --dry-run-fix copies the workspace to a temp dir, runs `cargo fix
--edition`, bumps the edition and runs cargo check: real verification that the migration compiles,
with the list of files it changed; your tree is never touched. Editions are per crate, so your
dependencies' editions and MSRVs do not matter. Lints only see code compiled with the chosen
features and this platform's cfgs; `cargo fix --edition` moves one edition at a time."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &["sm-crates edition", "sm-crates edition --to 2024 --dry-run-fix", "sm-crates edition --all-features --json"]
    }
    fn requires(&self) -> &'static str {
        "cargo (no network unless dependencies must be downloaded)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        pu::require_manifest(ctx)?;
        let timeout = pu::timeout(args, 1800)?;
        let to = args.value("to").map(str::to_string);
        if let Some(t) = &to {
            if !EDITIONS.contains(&t.as_str()) || t == "2015" {
                return Err(Error::Usage(format!("--to must be 2018, 2021 or 2024 (got {t})")));
            }
        }
        let meta = Metadata::load(ctx, &MetaOpts::default())?;
        let only = args.list("package");
        let mut members: Vec<&Package> = meta.members();
        if !only.is_empty() {
            members.retain(|p| only.iter().any(|o| util::normalize_crate_name(o) == util::normalize_crate_name(&p.name)));
            if members.is_empty() {
                return Err(Error::Usage(format!("no workspace member matches --package {}", only.join(","))));
            }
        }
        let order = leaves_first(&meta, &members);
        let mut rep = Report::new("edition", format!("workspace {}", meta.workspace_root.display()));

        let mut plans: Vec<Plan> = Vec::new();
        for id in &order {
            let Some(p) = meta.package(id) else { continue };
            let current = if p.edition.is_empty() { "2015".to_string() } else { p.edition.clone() };
            let target = match &to {
                Some(t) => t.clone(),
                None => next_edition(&current).unwrap_or(&current).to_string(),
            };
            let raw = std::fs::read_to_string(&p.manifest_path).unwrap_or_default();
            plans.push(Plan {
                id: p.id.clone(),
                name: p.name.clone(),
                version: p.version.clone(),
                manifest: util::rel(&meta.workspace_root, &p.manifest_path),
                needs: edition_index(&target) > edition_index(&current),
                current,
                target,
                rust_version: p.rust_version.clone(),
                inherited: inherits_edition(&raw),
                lints: BTreeMap::new(),
            });
        }
        let needing: Vec<&Plan> = plans.iter().filter(|p| p.needs).collect();
        if needing.is_empty() {
            let mut t = Table::new("Members", &["Member", "Edition"]);
            for p in &plans {
                t.row([p.name.clone(), p.current.clone()]);
            }
            rep.table(t);
            rep.summary(format!("nothing to migrate: every member is already on edition {}", to.clone().unwrap_or_else(|| "2024 (the latest)".into())));
            rep.data = json!({"members": plans.iter().map(Plan::json).collect::<Vec<_>>()});
            return Ok(rep);
        }

        // lint groups for every edition step any member needs
        let mut groups: BTreeSet<String> = BTreeSet::new();
        for p in &needing {
            for e in EDITIONS.iter().filter(|e| edition_index(e) > edition_index(&p.current) && edition_index(e) <= edition_index(&p.target)) {
                groups.insert(format!("rust-{e}-compatibility"));
            }
        }
        let flags: Vec<String> = groups.iter().flat_map(|g| ["-W".to_string(), g.clone()]).collect();
        let target_dir = pu::target_dir(ctx, "edition", None)?;
        pu::progress(args, &format!("running cargo check --workspace --all-targets with {}", flags.join(" ")));
        let mut cmd = pu::cargo(ctx);
        cmd.args(["check", "--workspace", "--all-targets", "--message-format", "json"]).args(pu::feature_args(args));
        pu::offline_flag(ctx, &mut cmd);
        cmd.env("CARGO_TARGET_DIR", &target_dir);
        add_rustflags(&mut cmd, &flags);
        let out = util::run(&mut cmd, timeout)?;
        if out.timed_out {
            return Err(Error::Env(format!("cargo check did not finish within {}s (raise --timeout)", timeout.as_secs())));
        }
        let msgs = pu::messages(&out.stdout);
        if msgs.is_empty() && !out.success() {
            return Err(Error::Env(format!("cargo check failed: {}", pu::first_error(&out.stderr))));
        }
        if pu::build_succeeded(&msgs) == Some(false) {
            rep.note(format!("the project does not currently compile ({}); lints are only reported for code that type-checks", pu::first_error(&out.stderr)));
        }
        let diags = pu::diagnostics(&msgs);
        for p in plans.iter_mut().filter(|p| p.needs) {
            // only lints of the editions this member moves through (another member may need a later group)
            for d in diags.iter().filter(|d| d.package_id == p.id && lint_edition(d).is_some_and(|e| edition_index(e) > edition_index(&p.current) && edition_index(e) <= edition_index(&p.target))) {
                p.lints.entry(d.code.clone()).or_default().push(d.clone());
            }
        }
        render(&mut rep, &plans, &meta.workspace_root);

        if args.flag("dry-run-fix") {
            dry_run(ctx, args, &plans, &meta.workspace_root, timeout, &mut rep)?;
        }
        Ok(rep)
    }
}

fn edition_index(e: &str) -> usize {
    EDITIONS.iter().position(|x| *x == e).unwrap_or(0)
}

#[derive(Debug, Clone)]
struct Plan {
    id: String,
    name: String,
    version: String,
    /// Manifest path relative to the workspace root.
    manifest: String,
    current: String,
    target: String,
    needs: bool,
    rust_version: Option<String>,
    inherited: bool,
    /// lint -> hits
    lints: BTreeMap<String, Vec<Diag>>,
}

impl Plan {
    fn auto(&self) -> usize {
        self.lints.values().flatten().filter(|d| d.machine_applicable).count()
    }
    fn manual(&self) -> usize {
        self.lints.values().flatten().filter(|d| !d.machine_applicable).count()
    }
    fn json(&self) -> Value {
        json!({
            "name": self.name, "version": self.version, "edition": self.current, "target": self.target, "needs_migration": self.needs,
            "rust_version": self.rust_version, "edition_inherited": self.inherited, "manifest": self.manifest,
            "auto_fixable": self.auto(), "manual": self.manual(),
            "lints": self.lints.iter().map(|(l, ds)| json!({
                "lint": l, "count": ds.len(), "auto_fixable": ds.iter().filter(|d| d.machine_applicable).count(),
                "locations": ds.iter().map(|d| json!({"location": d.location(), "machine_applicable": d.machine_applicable, "message": d.message})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }
}

/// The edition a migration lint prepares for (`None` for other diagnostics). Lints not in the
/// table are recognized by the edition guide link or "hard error in Rust 20xx" in their notes.
fn lint_edition(d: &Diag) -> Option<&'static str> {
    if d.code.is_empty() || d.code.starts_with('E') {
        return None;
    }
    if let Some((_, e)) = EDITION_LINTS.iter().find(|(l, _)| *l == d.code) {
        return Some(e);
    }
    for c in &d.children {
        for e in ["2018", "2021", "2024"] {
            if c.contains(&format!("edition-guide/rust-{e}")) || c.contains(&format!("hard error in Rust {e}")) || c.contains(&format!("in Rust {e}")) {
                return EDITIONS.iter().find(|x| **x == e).copied();
            }
        }
    }
    None
}

/// Whether a member's Cargo.toml says `edition.workspace = true`.
fn inherits_edition(manifest: &str) -> bool {
    inherits_key(manifest, "edition")
}

/// Whether a member's Cargo.toml says `KEY.workspace = true` in [package].
fn inherits_key(manifest: &str, key: &str) -> bool {
    let Ok(v) = toml::from_str::<toml::Value>(manifest) else { return false };
    v.get("package")
        .and_then(|p| p.get(key))
        .and_then(|e| e.get("workspace"))
        .and_then(|w| w.as_bool())
        .unwrap_or(false)
}

/// cargo's first error line plus its innermost `Caused by:` line (the actual reason for
/// errors such as "failed to load manifest").
fn error_with_cause(stderr: &str) -> String {
    let first = pu::first_error(stderr);
    let clean = pu::strip_ansi(stderr);
    let lines: Vec<&str> = clean.lines().collect();
    let cause = lines.iter().rposition(|l| l.trim() == "Caused by:").and_then(|k| lines[k + 1..].iter().map(|l| l.trim()).find(|l| !l.is_empty()));
    match cause {
        Some(c) if c != first => format!("{first}: {c}"),
        _ => first,
    }
}

/// Append lint flags to the user's RUSTFLAGS (or CARGO_ENCODED_RUSTFLAGS, which takes precedence).
fn add_rustflags(cmd: &mut std::process::Command, flags: &[String]) {
    if let Ok(enc) = std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        let mut parts: Vec<String> = if enc.is_empty() { vec![] } else { enc.split('\x1f').map(String::from).collect() };
        parts.extend(flags.iter().cloned());
        cmd.env("CARGO_ENCODED_RUSTFLAGS", parts.join("\x1f"));
    } else {
        let mut s = std::env::var("RUSTFLAGS").unwrap_or_default();
        for f in flags {
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(f);
        }
        cmd.env("RUSTFLAGS", s);
    }
}

/// Members ordered so that each comes after the members it depends on (normal and build edges).
fn leaves_first(meta: &Metadata, members: &[&Package]) -> Vec<String> {
    let ids: BTreeSet<String> = members.iter().map(|p| p.id.clone()).collect();
    let mut deps: BTreeMap<String, BTreeSet<String>> = ids.iter().map(|i| (i.clone(), BTreeSet::new())).collect();
    if let Some(res) = &meta.resolve {
        for n in &res.nodes {
            if !ids.contains(&n.id) {
                continue;
            }
            for d in &n.deps {
                if ids.contains(&d.pkg) && d.pkg != n.id && !d.is_dev() {
                    deps.entry(n.id.clone()).or_default().insert(d.pkg.clone());
                }
            }
        }
    }
    let name = |id: &str| meta.package(id).map(|p| p.name.clone()).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    let mut left: BTreeSet<String> = ids;
    while !left.is_empty() {
        let mut ready: Vec<String> = left.iter().filter(|i| deps.get(*i).is_none_or(|ds| ds.iter().all(|d| out.contains(d)))).cloned().collect();
        if ready.is_empty() {
            // cycle (only possible through dev-dependencies being ignored wrongly): take the rest by name
            ready = left.iter().cloned().collect();
        }
        ready.sort_by_key(|i| name(i));
        for r in ready {
            left.remove(&r);
            out.push(r);
        }
    }
    out
}

fn lint_fix(lint: &str) -> &'static str {
    match lint {
        "static_mut_refs" => "Take raw pointers with `&raw const X` / `&raw mut X`, or replace the `static mut` with an atomic, `Mutex`, `OnceLock` or `SyncUnsafeCell`",
        "if_let_rescope" => "The `if let` scrutinee's temporaries now drop before the `else` block: check lock guards and RefCell borrows, or use `match` to keep the old drop order",
        "tail_expr_drop_order" => "Temporaries in a block's tail expression now drop before its locals: check code that relies on the old order (guards, borrows)",
        "impl_trait_overcaptures" => "`impl Trait` in return position now captures all lifetimes in scope; add `+ use<..>` listing only what it should capture",
        "edition_2024_expr_fragment_specifier" => "`$e:expr` now also matches `const {}` and `_`; use `$e:expr_2021` where the macro relies on the old behaviour",
        "dependency_on_unit_never_type_fallback" | "never_type_fallback_flowing_into_unsafe" => "Never-type fallback changes from `()` to `!`: annotate the type explicitly",
        "unsafe_op_in_unsafe_fn" => "Wrap unsafe operations inside `unsafe fn` bodies in explicit `unsafe {}` blocks",
        "rust_2024_incompatible_pat" => "Write the binding modes or reference patterns explicitly as the lint suggests",
        "boxed_slice_into_iter" | "array_into_iter" => "`into_iter()` now iterates by value; use `.iter()` to keep iterating by reference",
        "rust_2021_incompatible_closure_captures" => "Closures now capture disjoint fields; add `let _ = &x;` inside the closure where drop order matters",
        _ => "See the edition guide entry linked in the lint; `cargo fix --edition` cannot apply this one automatically",
    }
}

fn render(rep: &mut Report, plans: &[Plan], root: &Path) {
    let mut t = Table::new("Migration plan (leaves first)", &["#", "Member", "Edition", "Target", "rust-version", "Auto-fixable", "Manual", "Status"]);
    for (k, p) in plans.iter().enumerate() {
        let status = if !p.needs {
            "already there".to_string()
        } else if p.lints.is_empty() {
            "ready: no migration lints".into()
        } else if p.manual() == 0 {
            "cargo fix --edition handles all".into()
        } else {
            format!("{} manual change(s)", p.manual())
        };
        t.row([
            (k + 1).to_string(),
            p.name.clone(),
            format!("{}{}", p.current, if p.inherited { " (workspace)" } else { "" }),
            if p.needs { p.target.clone() } else { "-".into() },
            p.rust_version.clone().unwrap_or_else(|| "-".into()),
            p.auto().to_string(),
            p.manual().to_string(),
            status,
        ]);
    }
    rep.table(t);
    let mut lt = Table::new("Migration lints", &["Member", "Lint", "Hits", "Auto-fixable", "Manual"]);
    let mut mt = Table::new("Manual changes", &["Member", "Lint", "Location", "Message"]);
    let mut manual_rows = 0;
    for p in plans.iter().filter(|p| p.needs) {
        for (lint, ds) in &p.lints {
            let auto = ds.iter().filter(|d| d.machine_applicable).count();
            lt.row([p.name.clone(), lint.clone(), ds.len().to_string(), auto.to_string(), (ds.len() - auto).to_string()]);
            let manual: Vec<&Diag> = ds.iter().filter(|d| !d.machine_applicable).collect();
            for d in &manual {
                if manual_rows < 100 {
                    mt.row([p.name.clone(), lint.clone(), d.location(), d.message.clone()]);
                    manual_rows += 1;
                }
            }
            if let Some(first) = manual.first() {
                let mut f = Finding::new(Severity::Medium, "edition/manual-fix", format!("{lint}: {} place(s) need a manual change before moving to edition {}", manual.len(), p.target))
                    .krate(&p.name, Some(&p.version))
                    .detail(manual.iter().take(10).map(|d| format!("{} {}", d.location(), d.message)).collect::<Vec<_>>().join("\n"))
                    .fix(lint_fix(lint));
                if let Some(file) = &first.file {
                    f = f.at(file.clone(), first.line);
                }
                rep.finding(f);
            }
        }
        if p.auto() > 0 {
            rep.finding(
                Finding::new(Severity::Info, "edition/auto-fix", format!("{} lint hit(s) are fixed automatically by cargo fix --edition", p.auto()))
                    .krate(&p.name, Some(&p.version))
                    .fix(format!("cargo fix --edition -p {} --allow-dirty, then set edition = \"{}\"", p.name, next_edition(&p.current).unwrap_or(&p.target))),
            );
        }
        if let (Some(rv), Some(min)) = (&p.rust_version, min_rust(&p.target)) {
            let (a, b) = (util::parse_version(rv), util::parse_version(min));
            if let (Some(a), Some(b)) = (a, b) {
                if a < b {
                    rep.finding(
                        Finding::new(Severity::High, "edition/rust-version-too-low", format!("rust-version {rv} is too old for edition {} (needs {min})", p.target))
                            .krate(&p.name, Some(&p.version))
                            .at(p.manifest.clone(), None)
                            .fix(format!("Raise rust-version to at least {min} (a breaking change for users on older compilers), or stay on edition {}", p.current)),
                    );
                }
            }
        } else if p.rust_version.is_none() {
            if let Some(min) = min_rust(&p.target) {
                rep.finding(
                    Finding::new(Severity::Info, "edition/no-rust-version", format!("No rust-version declared; edition {} needs Rust {min} or newer", p.target))
                        .krate(&p.name, Some(&p.version))
                        .fix(format!("Add rust-version = \"{min}\" (or higher) to [package] so older toolchains get a clear error")),
                );
            }
        }
        if edition_index(&p.target) > edition_index(&p.current) + 1 {
            rep.finding(
                Finding::new(Severity::Info, "edition/multi-step", format!("{} → {} is {} edition steps", p.current, p.target, edition_index(&p.target) - edition_index(&p.current)))
                    .krate(&p.name, Some(&p.version))
                    .fix("cargo fix --edition moves one edition at a time: run it, bump the edition, and repeat"),
            );
        }
    }
    rep.table(lt);
    rep.table(mt);
    let inherited: Vec<&str> = plans.iter().filter(|p| p.needs && p.inherited).map(|p| p.name.as_str()).collect();
    if !inherited.is_empty() {
        rep.note(format!("{} inherit edition from [workspace.package]: changing it there moves them all at once, so migrate them together (or give one its own `edition` first)", inherited.join(", ")));
    }
    if plans.iter().any(|p| p.needs && p.target == "2024") {
        rustfmt_check(rep, root);
    }
    let needing: Vec<&Plan> = plans.iter().filter(|p| p.needs).collect();
    let auto: usize = needing.iter().map(|p| p.auto()).sum();
    let manual: usize = needing.iter().map(|p| p.manual()).sum();
    let ready = needing.iter().filter(|p| p.manual() == 0).count();
    rep.summary(format!(
        "{} of {} member(s) need migration; {ready} can migrate with cargo fix alone; {auto} auto-fixable and {manual} manual lint hit(s)",
        needing.len(),
        plans.len()
    ));
    rep.note("Order: migrate members top to bottom (each after the members it depends on). Per member: cargo fix --edition -p NAME, bump `edition`, cargo check, then cargo fmt.");
    rep.data = json!({"members": plans.iter().map(Plan::json).collect::<Vec<_>>()});
}

/// rustfmt: with edition 2024, `cargo fmt` switches to the 2024 style edition unless `style_edition` is set.
fn rustfmt_check(rep: &mut Report, root: &Path) {
    let cfg = ["rustfmt.toml", ".rustfmt.toml"].iter().map(|n| root.join(n)).find(|p| p.is_file());
    let parsed = cfg.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let style = parsed.as_ref().and_then(|v| v.get("style_edition").or_else(|| v.get("version"))).and_then(|v| v.as_str()).map(String::from);
    let fmt_edition = parsed.as_ref().and_then(|v| v.get("edition")).and_then(|v| v.as_str()).map(String::from);
    match style {
        Some(s) => rep.note(format!("rustfmt style_edition is pinned to {s}; formatting will not change with the edition")),
        None => rep.finding(
            Finding::new(Severity::Info, "edition/rustfmt-style", "cargo fmt will switch to the 2024 style edition after the migration (formatting changes across many files)")
                .detail(match (&cfg, fmt_edition) {
                    (Some(p), Some(e)) => format!("{} sets edition = \"{e}\" but no style_edition", p.display()),
                    (Some(p), None) => format!("{} has no style_edition", p.display()),
                    _ => "no rustfmt.toml".into(),
                })
                .fix("Run cargo fmt in a separate commit after migrating, or set style_edition = \"2021\" in rustfmt.toml to postpone the style change"),
        ),
    }
}

/// Replace (or insert) `edition` in the `[package]` (or `[workspace.package]`) table of a manifest.
pub fn set_edition(manifest: &str, section: &str, edition: &str) -> Option<String> {
    set_key(manifest, section, "edition", edition)
}

/// Replace (or insert) a string `key` in the `[package]` (or `[workspace.package]`) table of a manifest.
pub fn set_key(manifest: &str, section: &str, key_name: &str, value: &str) -> Option<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut done = false;
    let mut header_idx = None;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if cur == section && !done {
                if let Some(h) = header_idx {
                    out.insert(h + 1, format!("{key_name} = \"{value}\""));
                    done = true;
                }
            }
            cur = t.trim_start_matches('[').split(']').next().unwrap_or("").trim().to_string();
            if cur == section {
                header_idx = Some(out.len());
            }
        } else if cur == section && !done {
            let key = t.split('=').next().unwrap_or("").trim();
            if key == key_name {
                out.push(format!("{key_name} = \"{value}\""));
                done = true;
                continue;
            }
        }
        out.push(line.to_string());
    }
    if !done && cur == section {
        if let Some(h) = header_idx {
            out.insert(h + 1, format!("{key_name} = \"{value}\""));
            done = true;
        }
    }
    done.then(|| out.join("\n") + "\n")
}

fn dry_run(ctx: &Ctx, args: &Args, plans: &[Plan], root: &Path, timeout: Duration, rep: &mut Report) -> Result<()> {
    let needing: Vec<&Plan> = plans.iter().filter(|p| p.needs).collect();
    let (tmp, dir) = pu::copy_project(root, "edition-fix")?;
    pu::progress(args, &format!("dry run: cargo fix --edition in a copy of the workspace ({})", dir.display()));
    let result = (|| -> Result<Value> {
        let before = pu::file_hashes(&dir);
        let target_dir = pu::target_dir(ctx, "edition", Some("fix"))?;
        let mut fix = pu::cargo(ctx);
        fix.current_dir(&dir).args(["fix", "--edition", "--allow-dirty", "--allow-no-vcs", "--allow-staged", "--all-targets"]);
        for p in &needing {
            fix.args(["-p", &format!("{}@{}", p.name, p.version)]);
        }
        fix.args(pu::feature_args(args));
        pu::offline_flag(ctx, &mut fix);
        fix.env("CARGO_TARGET_DIR", &target_dir);
        let fo = util::run(&mut fix, timeout)?;
        let fix_ok = fo.success();
        // bump one edition step per member (cargo fix --edition prepared exactly that step)
        let mut bumped = Vec::new();
        let mut ws_done = false;
        for p in &needing {
            let Some(next) = next_edition(&p.current) else { continue };
            let (path, section) = if p.inherited { (dir.join("Cargo.toml"), "workspace.package") } else { (dir.join(&p.manifest), "package") };
            if p.inherited && ws_done {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            if let Some(new) = set_edition(&text, section, next) {
                std::fs::write(&path, new)?;
                bumped.push(format!("{} → {next}", p.name));
                ws_done |= p.inherited;
            }
        }
        // cargo refuses to load a manifest whose rust-version predates its edition, so raise a
        // too-low rust-version in the copy too (reported above as edition/rust-version-too-low)
        let mut raised = Vec::new();
        for p in &needing {
            let (Some(next), Some(rv)) = (next_edition(&p.current), &p.rust_version) else { continue };
            let Some(min) = min_rust(next) else { continue };
            if !matches!((util::parse_version(rv), util::parse_version(min)), (Some(a), Some(b)) if a < b) {
                continue;
            }
            let member = dir.join(&p.manifest);
            let own = std::fs::read_to_string(&member)?;
            let (path, section) = if inherits_key(&own, "rust-version") { (dir.join("Cargo.toml"), "workspace.package") } else { (member, "package") };
            let text = std::fs::read_to_string(&path)?;
            if let Some(new) = set_key(&text, section, "rust-version", min) {
                std::fs::write(&path, new)?;
                raised.push(format!("{} {rv} → {min}", p.name));
            }
        }
        let mut check = pu::cargo(ctx);
        check.current_dir(&dir).args(["check", "--workspace", "--all-targets", "--message-format", "json"]).args(pu::feature_args(args));
        pu::offline_flag(ctx, &mut check);
        check.env("CARGO_TARGET_DIR", &target_dir);
        let co = util::run(&mut check, timeout)?;
        let msgs = pu::messages(&co.stdout);
        let diags = pu::diagnostics(&msgs);
        let errors: Vec<&Diag> = diags.iter().filter(|d| d.level.starts_with("error")).collect();
        let compiles = pu::build_succeeded(&msgs).unwrap_or(co.success()) && errors.is_empty();
        let after = pu::file_hashes(&dir);
        let changed: Vec<String> = after.iter().filter(|(k, v)| before.get(*k) != Some(*v)).map(|(k, _)| k.clone()).collect();
        let mut t = Table::new("Dry-run migration (temporary copy)", &["Step", "Result"]);
        t.row(["cargo fix --edition".to_string(), if fix_ok { "ok".into() } else { format!("failed: {}", error_with_cause(&fo.stderr)) }]);
        t.row(["edition bumped".to_string(), bumped.join(", ")]);
        if !raised.is_empty() {
            t.row(["rust-version raised".to_string(), raised.join(", ")]);
        }
        t.row(["files changed".to_string(), if changed.is_empty() { "none".into() } else { changed.join(", ") }]);
        t.row(["cargo check after migration".to_string(), if compiles { "compiles".into() } else { format!("{} error(s)", errors.len().max(1)) }]);
        rep.table(t);
        if compiles {
            rep.finding(Finding::new(Severity::Info, "edition/dry-run-ok", format!("The migrated copy compiles ({} file(s) changed by cargo fix)", changed.len())).fix("Run the same steps in your tree: cargo fix --edition, bump edition, cargo check"));
        } else {
            let mut f = Finding::new(Severity::Medium, "edition/fix-breaks-build", format!("After cargo fix --edition and the edition bump the workspace does not compile ({} error(s))", errors.len().max(1)))
                .detail(errors.iter().take(10).map(|d| format!("{} {}{}", d.location(), if d.code.is_empty() { String::new() } else { format!("[{}] ", d.code) }, d.message)).collect::<Vec<_>>().join("\n"))
                .fix("Fix the manual items listed above first; these errors are what remains after the automatic fixes");
            if let Some(e) = errors.first() {
                if let Some(file) = &e.file {
                    f = f.at(file.clone(), e.line);
                }
            }
            if errors.is_empty() {
                f = f.detail(error_with_cause(&co.stderr));
            }
            rep.finding(f);
        }
        Ok(json!({"fix_ok": fix_ok, "bumped": bumped, "rust_version_raised": raised, "files_changed": changed, "compiles": compiles, "errors": errors.iter().map(|d| json!({"code": d.code, "message": d.message, "location": d.location()})).collect::<Vec<_>>()}))
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    let v = result?;
    rep.data["dry_run"] = v;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edition_math() {
        assert_eq!(next_edition("2021"), Some("2024"));
        assert_eq!(next_edition("2024"), None);
        assert_eq!(min_rust("2024"), Some("1.85"));
        assert!(edition_index("2024") > edition_index("2015"));
    }

    #[test]
    fn manifest_edits() {
        let m = "[package]\nname = \"a\"\nedition = \"2021\"\n\n[dependencies]\nx = \"1\"\n";
        assert_eq!(set_edition(m, "package", "2024").unwrap(), "[package]\nname = \"a\"\nedition = \"2024\"\n\n[dependencies]\nx = \"1\"\n");
        let m2015 = "[package]\nname = \"a\"\n[dependencies]\n";
        assert_eq!(set_edition(m2015, "package", "2018").unwrap(), "[package]\nedition = \"2018\"\nname = \"a\"\n[dependencies]\n");
        let ws = "[workspace]\nmembers = [\"a\"]\n[workspace.package]\nedition = \"2021\"\n";
        assert!(set_edition(ws, "workspace.package", "2024").unwrap().contains("[workspace.package]\nedition = \"2024\""));
        assert!(set_edition("[lib]\n", "package", "2024").is_none());
        assert_eq!(set_key(m, "package", "rust-version", "1.85").unwrap(), "[package]\nrust-version = \"1.85\"\nname = \"a\"\nedition = \"2021\"\n\n[dependencies]\nx = \"1\"\n");
        assert!(inherits_key("[package]\nrust-version.workspace = true\n", "rust-version"));
        assert!(inherits_edition("[package]\nname = \"a\"\nedition.workspace = true\n"));
        assert!(inherits_edition("[package]\nname = \"a\"\nedition = { workspace = true }\n"));
        assert!(!inherits_edition("[package]\nedition = \"2021\"\n"));
    }

    #[test]
    fn error_cause() {
        let e = "error: failed to load manifest for workspace member `/x/a`\nreferenced by workspace at `/x/Cargo.toml`\n\nCaused by:\n  failed to parse manifest at `/x/a/Cargo.toml`\n\nCaused by:\n  rust-version 1.70 is incompatible with the version (1.85.0) required by the specified edition (2024)\n";
        assert_eq!(error_with_cause(e), "error: failed to load manifest for workspace member `/x/a`: rust-version 1.70 is incompatible with the version (1.85.0) required by the specified edition (2024)");
        assert_eq!(error_with_cause("error: boom\n"), "error: boom");
    }

    #[test]
    fn lint_classification() {
        let mk = |code: &str, children: Vec<String>| Diag {
            code: code.into(),
            level: "warning".into(),
            message: "m".into(),
            package_id: String::new(),
            target_kind: vec![],
            file: None,
            line: None,
            column: None,
            machine_applicable: false,
            children,
            rendered: String::new(),
        };
        assert_eq!(lint_edition(&mk("keyword_idents_2024", vec![])), Some("2024"));
        assert_eq!(lint_edition(&mk("bare_trait_objects", vec![])), Some("2021"));
        assert_eq!(lint_edition(&mk("some_new_lint", vec!["note: for more information, see <https://doc.rust-lang.org/edition-guide/rust-2024/x.html>".into()])), Some("2024"));
        assert_eq!(lint_edition(&mk("unused_variables", vec![])), None);
        assert_eq!(lint_edition(&mk("E0308", vec![])), None);
    }
}
