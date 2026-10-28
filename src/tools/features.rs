//! Feature Bleed Explainer: Explain who enables each feature, and when dev, build or other-target dependencies change your release build.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata, Package};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::features_util::{self as fu, Active, Enabler, TargetCfg};
use crate::tools::{Group, Tool};
use crate::util;

pub struct Features;

const OPTS: &[Opt] = &[
    Opt::value("why", "PKG[/FEATURE]", "Explain who enables PKG's features (or one FEATURE), with the chain from a workspace member"),
    Opt::flag("all", "List every package's release features, not only the ones that differ"),
];

impl Tool for Features {
    fn name(&self) -> &'static str {
        "features"
    }
    fn title(&self) -> &'static str {
        "Feature Bleed Explainer"
    }
    fn group(&self) -> Group {
        Group::Features
    }
    fn summary(&self) -> &'static str {
        "Explain who enables each feature, and when dev, build or other-target dependencies change your release build"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Explains the project's resolved features and where they come from.
Resolver: reads the workspace root Cargo.toml (`resolver` key; a root package on edition 2021
implies \"2\", 2024 implies \"3\"; a virtual workspace without `resolver` uses \"1\"). Resolver 1
unifies features of dev-, build- and other-target dependencies into the release build: high
finding `features/resolver-v1` when such dependencies exist (low when there are none yet).
Feature sets come from `cargo tree -f \"{p}|{f}\" --no-dedupe` for the release build
(`-e normal --target HOST`), the test build (`-e normal,dev`) and every platform (`--target all`).
Features active only in the test build are low findings (tests exercise code you do not ship).
For every release feature the tool works out who enables it from `cargo metadata`: each dependency
declaration (respecting rename, kind, target cfg and optional activation), its `features = [...]`,
`default-features`, and `[features]` entries such as `pkg/feat`, `pkg?/feat` and `dep:pkg` of the
declaring package's active features. A release feature that only dev-, build- or other-target
declarations explain is feature bleed (high under resolver 1, else medium).
Droppable defaults: for each direct dependency with default features on, the optional crates its
default features pull in and the `default-features = false, features = [...]` line that keeps the
rest (low). --why PKG[/FEATURE] prints every chain that turns a feature on.
Limits: cargo tree reports features per package name and version, so a package built twice (host
and target) shows the union; features passed on the command line are not modelled."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &["sm-crates features", "sm-crates features --why serde/std", "sm-crates features --why syn --json", "sm-crates features --all --markdown"]
    }
    fn requires(&self) -> &'static str {
        "cargo"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let manifest = ctx.manifest_path();
        if !manifest.is_file() {
            return Err(Error::Env(format!("no Cargo.toml at {} (run inside a Cargo project or pass --project DIR)", manifest.display())));
        }
        let meta = fu::load_metadata_at(ctx, &manifest, &MetaOpts::default())?;
        let members: Vec<&Package> = meta.members();
        let label = members.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ");
        let mut rep = Report::new("features", format!("project {label}"));
        let host = fu::host_triple()?;
        let host_cfg = fu::target_cfg(&host)?;

        // ---- resolver
        let (resolver, why_resolver) = resolver_version(&meta);
        let nonnormal = declarations_summary(&meta);
        if resolver == "1" {
            // nothing to leak yet: a latent problem, not a current one
            let sev = if nonnormal.is_empty() { Severity::Low } else { Severity::High };
            rep.finding(
                Finding::new(sev, "features/resolver-v1", format!("feature resolver 1 is in effect ({why_resolver})"))
                    .detail(if nonnormal.is_empty() {
                        "resolver 1 unifies features of dev-, build- and target-specific dependencies into the release build".to_string()
                    } else {
                        format!("features of these dependencies leak into the release build: {}", nonnormal.iter().take(8).cloned().collect::<Vec<_>>().join(", "))
                    })
                    .at(util::rel(ctx.project_root(), &meta.workspace_root.join("Cargo.toml")), None)
                    .fix("add `resolver = \"2\"` (or \"3\") under [workspace], or move the package to edition 2021+"),
            );
        }

        // ---- feature sets
        let rel_lines = fu::cargo_tree(ctx, &manifest, "normal", &host, &[])?;
        let test_lines = fu::cargo_tree(ctx, &manifest, "normal,dev", &host, &[])?;
        let all_lines = fu::cargo_tree(ctx, &manifest, "normal", "all", &[])?;
        let rel_tf = fu::tree_features(&rel_lines, true);
        let test_tf = fu::tree_features(&test_lines, true);
        let all_tf = fu::tree_features(&all_lines, true);
        let rel = fu::active_from_tree(&meta, &rel_tf);
        let test = fu::active_from_tree(&meta, &test_tf);
        let all = fu::active_from_tree(&meta, &all_tf);
        // --why also covers host code (proc-macros and their dependencies)
        let mut union = rel.clone();
        let host_too: Vec<Active> = [&rel_lines, &test_lines, &all_lines].iter().map(|l| fu::active_from_tree(&meta, &fu::tree_features(l, false))).collect();
        for (k, v) in test.iter().chain(all.iter()).chain(host_too.iter().flatten()) {
            union.entry(k.clone()).or_default().extend(v.iter().cloned());
        }
        let by_id = meta.by_id();
        let spec = |id: &str| by_id.get(id).map(|p| p.spec()).unwrap_or_else(|| id.to_string());

        // ---- --why
        if let Some(w) = args.value("why") {
            let (pname, feat) = match w.split_once('/') {
                Some((p, f)) => (p, Some(f)),
                None => (w, None),
            };
            let pkgs: Vec<&Package> = meta.packages.iter().filter(|p| util::normalize_crate_name(&p.name) == util::normalize_crate_name(pname) && union.contains_key(&p.id)).collect();
            if pkgs.is_empty() {
                return Err(Error::Usage(format!("`{pname}` is not in this project's dependency graph")));
            }
            let mut t = Table::new(format!("Why {w}"), &["Feature", "Enabled by", "How", "Kind", "Path from workspace"]);
            let mut rows_json = Vec::new();
            for p in pkgs {
                let feats: Vec<String> = match feat {
                    Some(f) => vec![f.to_string()],
                    None => union.get(&p.id).map(|s| s.iter().cloned().collect()).unwrap_or_default(),
                };
                for f in feats {
                    if !union.get(&p.id).is_some_and(|s| s.contains(&f)) {
                        t.row([format!("{}[{f}]", p.spec()), "-".into(), "not enabled in any build".into(), String::new(), String::new()]);
                        continue;
                    }
                    let mut visited = BTreeSet::new();
                    explain(&meta, &union, &host_cfg, &p.id, &f, 0, &mut visited, &mut |row: WhyRow| {
                        rows_json.push(json!({"package": row.pkg, "feature": row.feature, "by": row.by, "how": row.how, "kind": row.kind, "path": row.path, "depth": row.depth}));
                        t.row([format!("{}{}[{}]", "  ".repeat(row.depth), row.pkg, row.feature), row.by, row.how, row.kind, row.path]);
                    });
                }
            }
            rep.summary(format!("{} reason(s) for {w}", t.rows.len()));
            rep.table(t);
            rep.data = json!({"why": w, "chains": rows_json, "resolver": resolver});
            return Ok(rep);
        }

        // ---- justification of release features
        let justified = justify(&meta, &rel, &host_cfg);
        let mut bleed_rows = Vec::new();
        let mut unexplained: Vec<(String, String, Vec<Enabler>)> = Vec::new();
        let mut bleeding: BTreeSet<(String, String)> = BTreeSet::new();
        let mut bleed_json = Vec::new();
        for (id, feats) in &rel {
            for f in feats {
                if justified.contains(&(id.clone(), f.clone())) {
                    continue;
                }
                let ens = fu::enablers(&meta, &union, id, f);
                let sources: Vec<&Enabler> = ens
                    .iter()
                    .filter(|e| e.kind == "dev" || e.kind == "build" || fu::dep_target_applies(e.target.as_deref(), &host_cfg) == Some(false) || (e.kind == "normal" && !rel.contains_key(&e.by)))
                    .collect();
                if sources.is_empty() {
                    unexplained.push((id.clone(), f.clone(), ens));
                    continue;
                }
                let mut desc: Vec<String> = sources.iter().map(|e| format!("{} ({}{}) {}", e.by_spec, e.kind, e.target.as_ref().map(|t| format!(", {t}")).unwrap_or_default(), e.how)).collect();
                desc.dedup();
                let dev_or_build = sources.iter().any(|e| e.kind == "dev" || e.kind == "build");
                let sev = if resolver == "1" && dev_or_build { Severity::High } else { Severity::Medium };
                let pkg = by_id.get(id.as_str());
                rep.finding(
                    Finding::new(sev, "features/bleed", format!("feature `{f}` is on in the release build only because of {}", kinds_label(&sources)))
                        .krate(pkg.map(|p| p.name.clone()).unwrap_or_default(), pkg.map(|p| p.version.clone()))
                        .detail(desc.join("\n"))
                        .fix(if resolver == "1" {
                            "switch to resolver 2 so dev-, build- and other-target dependency features stay out of the release build".to_string()
                        } else {
                            format!("enable `{f}` explicitly if the release build needs it, or stop the declaration above from requesting it")
                        }),
                );
                bleeding.insert((id.clone(), f.clone()));
                bleed_rows.push((spec(id), f.clone(), desc.join("; ")));
                bleed_json.push(json!({"package": spec(id), "feature": f, "sources": desc}));
            }
        }
        // features turned on by a bleeding feature (`default` -> `std`) bleed too; they are not unexplained
        let mut follow: Vec<String> = Vec::new();
        loop {
            let before = unexplained.len();
            unexplained.retain(|(id, f, ens)| {
                let via_bleed = ens.iter().any(|e| e.via_feature.as_ref().is_some_and(|g| bleeding.contains(&(e.by.clone(), g.clone()))));
                if via_bleed {
                    bleeding.insert((id.clone(), f.clone()));
                    follow.push(format!("{}[{f}]", spec(id)));
                }
                !via_bleed
            });
            if unexplained.len() == before {
                break;
            }
        }
        if !follow.is_empty() {
            follow.sort();
            rep.note(format!("{} more release feature(s) are on only because a bleeding feature enables them: {}", follow.len(), follow.join(", ")));
        }
        if !unexplained.is_empty() {
            rep.note(format!("{} release feature(s) could not be attributed to a declaration (e.g. set on the command line or by a renamed/patched dependency)", unexplained.len()));
        }

        // ---- test-only features
        let mut t = Table::new("Features that differ between builds", &["Package", "Release features", "Test-only", "Other platforms only", "Bleed"]);
        let mut pkg_json = Vec::new();
        let mut ids: BTreeSet<&String> = rel.keys().collect();
        ids.extend(test.keys());
        for id in ids {
            let r = rel.get(id).cloned().unwrap_or_default();
            let te = test.get(id).cloned().unwrap_or_default();
            let al = all.get(id).cloned().unwrap_or_default();
            let test_only: Vec<String> = if rel.contains_key(id) { te.difference(&r).cloned().collect() } else { vec![] };
            let other: Vec<String> = al.difference(&r).cloned().collect();
            let bleed: Vec<String> = bleed_rows.iter().filter(|b| b.0 == spec(id)).map(|b| b.1.clone()).collect();
            if !test_only.is_empty() && !meta.is_member(id) {
                let pkg = by_id.get(id.as_str());
                let mut reasons: Vec<String> = test_only
                    .iter()
                    .flat_map(|f| fu::enablers(&meta, &test, id, f).into_iter().filter(|e| e.kind == "dev" || !rel.contains_key(&e.by)).map(move |e| format!("{f}: {} {}", e.by_spec, e.how)))
                    .collect();
                reasons.dedup();
                rep.finding(
                    Finding::new(Severity::Low, "features/test-only", format!("features {} are only on in the test build", list(&test_only)))
                        .krate(pkg.map(|p| p.name.clone()).unwrap_or_default(), pkg.map(|p| p.version.clone()))
                        .detail(if reasons.is_empty() { "enabled through dev-dependencies".to_string() } else { reasons.join("\n") })
                        .fix("tests run code the release build does not contain; add the features to the normal dependency, or test the release configuration too (`cargo test --no-default-features ...`/`cargo hack`)"),
                );
            }
            let show = args.flag("all") || !test_only.is_empty() || !other.is_empty() || !bleed.is_empty();
            if show && rel.contains_key(id) {
                t.row([spec(id), r.iter().cloned().collect::<Vec<_>>().join(","), test_only.join(","), other.join(","), bleed.join(",")]);
            }
            pkg_json.push(json!({"package": spec(id), "release": r, "test": te, "all_targets": al, "test_only": test_only, "other_platforms_only": other}));
        }
        rep.table(t);

        // ---- droppable defaults
        let mut dt = Table::new("Default features of direct dependencies", &["Dependency", "Default enables", "Extra crates", "Suggested declaration"]);
        let mut drop_json = Vec::new();
        for m in &members {
            let Some(node) = meta.node(&m.id) else { continue };
            for d in m.dependencies.iter().filter(|d| d.kind() == "normal" && d.uses_default_features) {
                let ext = util::normalize_crate_name(fu::dep_key(d));
                let Some(edge) = node.deps.iter().find(|e| util::normalize_crate_name(&e.name) == ext && e.is_normal()) else { continue };
                let Some(p) = meta.package(&edge.pkg) else { continue };
                if !p.features.contains_key("default") || !rel.contains_key(&p.id) {
                    continue;
                }
                let dfl = fu::feature_closure(&p.features, &["default".to_string()]);
                let explicit = fu::feature_closure(&p.features, &d.features);
                let pulled = optional_deps(p, &dfl);
                let still = optional_deps(p, &explicit);
                let mut extra: Vec<String> = Vec::new();
                for x in pulled.difference(&still) {
                    // only crates that are actually in the release graph and not needed by anyone else
                    let Some(xe) = meta.node(&p.id).and_then(|n| n.deps.iter().find(|e| util::normalize_crate_name(&e.name) == util::normalize_crate_name(x))) else { continue };
                    if !rel.contains_key(&xe.pkg) {
                        continue;
                    }
                    let others = meta.dependents_of(&xe.pkg).into_iter().filter(|(q, e)| q.id != p.id && e.is_normal() && rel.contains_key(&q.id)).count();
                    if others == 0 {
                        extra.push(spec(&xe.pkg));
                    }
                }
                if extra.is_empty() {
                    continue;
                }
                let mut keep: BTreeSet<String> = d.features.iter().cloned().collect();
                for f in dfl.iter().filter(|f| *f != "default" && !fu::is_dep_feature(p, f)) {
                    let pulls = optional_deps(p, &fu::feature_closure(&p.features, std::slice::from_ref(f)));
                    if pulls.is_disjoint(&pulled.difference(&still).cloned().collect()) {
                        keep.insert(f.clone());
                    }
                }
                let keep: Vec<String> = keep.into_iter().collect();
                let suggestion = fu::dep_line_without_defaults(d, &keep);
                dt.row([format!("{} -> {}", m.name, p.spec()), dfl.iter().filter(|f| *f != "default").cloned().collect::<Vec<_>>().join(","), extra.join(", "), suggestion.clone()]);
                rep.finding(
                    Finding::new(Severity::Low, "features/droppable-default", format!("default features of `{}` pull in {} (nothing else in the release build needs them)", p.name, list(&extra)))
                        .krate(m.name.clone(), Some(m.version.clone()))
                        .at(util::rel(ctx.project_root(), &m.manifest_path), None)
                        .detail(format!("default = {:?}", p.features.get("default").cloned().unwrap_or_default()))
                        .fix(format!("if you do not use them: {suggestion}")),
                );
                drop_json.push(json!({"member": m.name, "dependency": p.spec(), "default": dfl, "extra_crates": extra, "suggestion": suggestion}));
            }
        }
        rep.table(dt);
        if !bleed_rows.is_empty() {
            let mut bt = Table::new("Release features enabled only by dev/build/other-target declarations", &["Package", "Feature", "Enabled by"]);
            for (p, f, d) in &bleed_rows {
                bt.row([p.clone(), f.clone(), d.clone()]);
            }
            rep.table(bt);
        }
        let n_rel: usize = rel.values().map(|s| s.len()).sum();
        rep.summary(format!(
            "resolver {resolver}; {} package(s) in the release build with {n_rel} feature(s); {} bleeding, {} test-only finding(s)",
            rel.len(),
            bleed_rows.len(),
            rep.findings.iter().filter(|f| f.code == "features/test-only").count()
        ));
        rep.note(format!("release build = `cargo tree -e normal --target {host}`; test build adds dev-dependencies; proc-macro subtrees (host code) are excluded"));
        rep.data = json!({
            "resolver": resolver, "resolver_reason": why_resolver, "host": host,
            "packages": pkg_json, "bleed": bleed_json, "droppable_defaults": drop_json,
        });
        Ok(rep)
    }
}

fn list(v: &[String]) -> String {
    v.iter().map(|s| format!("`{s}`")).collect::<Vec<_>>().join(", ")
}

fn kinds_label(e: &[&Enabler]) -> String {
    let mut k: BTreeSet<&str> = BTreeSet::new();
    for x in e {
        k.insert(match x.kind.as_str() {
            "dev" => "a dev-dependency",
            "build" => "a build-dependency",
            _ if x.target.is_some() => "an other-platform dependency",
            _ => "a dependency outside the release graph",
        });
    }
    k.into_iter().collect::<Vec<_>>().join(" and ")
}

/// Optional dependencies a set of features activates.
fn optional_deps(p: &Package, feats: &BTreeSet<String>) -> BTreeSet<String> {
    let opt: BTreeSet<&str> = p.dependencies.iter().filter(|d| d.optional).map(fu::dep_key).collect();
    let mut out = BTreeSet::new();
    for f in feats {
        if opt.contains(f.as_str()) && fu::is_dep_feature(p, f) {
            out.insert(f.clone());
        }
        for e in p.features.get(f).into_iter().flatten() {
            let name = if let Some(x) = e.strip_prefix("dep:") {
                Some(x)
            } else if let Some((x, _)) = e.split_once('/') {
                (!x.ends_with('?')).then_some(x)
            } else {
                Some(e.as_str())
            };
            if let Some(n) = name.filter(|n| opt.contains(n)) {
                out.insert(n.to_string());
            }
        }
    }
    out
}

/// Resolver in effect, and why.
pub fn resolver_version(meta: &Metadata) -> (String, String) {
    let root = meta.workspace_root.join("Cargo.toml");
    let t: Option<toml::Value> = std::fs::read_to_string(&root).ok().and_then(|s| toml::from_str(&s).ok());
    let Some(t) = t else { return ("2".into(), "workspace manifest unreadable; assuming 2".into()) };
    let as_str = |v: Option<&toml::Value>| v.and_then(|x| x.as_str()).map(String::from);
    if let Some(r) = as_str(t.get("workspace").and_then(|w| w.get("resolver"))) {
        return (r.clone(), format!("[workspace] resolver = \"{r}\""));
    }
    if let Some(r) = as_str(t.get("package").and_then(|w| w.get("resolver"))) {
        return (r.clone(), format!("[package] resolver = \"{r}\""));
    }
    match t.get("package") {
        None => ("1".into(), "virtual workspace without a `resolver` key defaults to 1 (cargo warns)".into()),
        Some(p) => {
            let ed = match p.get("edition") {
                Some(toml::Value::String(s)) => s.clone(),
                Some(toml::Value::Table(x)) if x.get("workspace").and_then(|v| v.as_bool()) == Some(true) => {
                    as_str(t.get("workspace").and_then(|w| w.get("package")).and_then(|w| w.get("edition"))).unwrap_or_else(|| "2015".into())
                }
                _ => "2015".into(),
            };
            let r = match ed.as_str() {
                "2015" | "2018" => "1",
                "2021" => "2",
                _ => "3",
            };
            (r.into(), format!("root package edition {ed} implies resolver {r}"))
        }
    }
}

/// Declarations that are dev, build or target-specific (what resolver 1 leaks).
fn declarations_summary(meta: &Metadata) -> Vec<String> {
    let mut v = BTreeSet::new();
    for m in meta.members() {
        for d in &m.dependencies {
            if d.kind() != "normal" || d.target.is_some() {
                v.insert(format!("{} ({}{})", d.name, d.kind(), d.target.as_ref().map(|t| format!(", {t}")).unwrap_or_default()));
            }
        }
    }
    v.into_iter().collect()
}

/// (package id, feature) pairs of the release build explained by normal, host-applicable
/// declarations from packages in the release build (fixpoint).
fn justify(meta: &Metadata, rel: &Active, host: &TargetCfg) -> BTreeSet<(String, String)> {
    let mut j: BTreeSet<(String, String)> = BTreeSet::new();
    for m in meta.members() {
        if let Some(fs) = rel.get(&m.id) {
            for f in fu::feature_closure(&m.features, &["default".to_string()]) {
                if fs.contains(&f) {
                    j.insert((m.id.clone(), f));
                }
            }
        }
    }
    let mut cache: BTreeMap<(String, String), Vec<Enabler>> = BTreeMap::new();
    loop {
        let mut changed = false;
        for (id, feats) in rel {
            for f in feats {
                let key = (id.clone(), f.clone());
                if j.contains(&key) {
                    continue;
                }
                let ens = cache.entry(key.clone()).or_insert_with(|| fu::enablers(meta, rel, id, f));
                let ok = ens.iter().any(|e| match e.kind.as_str() {
                    "self" => e.via_feature.as_ref().is_some_and(|h| j.contains(&(id.clone(), h.clone()))),
                    "normal" => {
                        rel.contains_key(&e.by)
                            && fu::dep_target_applies(e.target.as_deref(), host) != Some(false)
                            && e.via_feature.as_ref().is_none_or(|g| j.contains(&(e.by.clone(), g.clone())))
                    }
                    _ => false,
                });
                if ok {
                    j.insert(key);
                    changed = true;
                }
            }
        }
        if !changed {
            return j;
        }
    }
}

struct WhyRow {
    pkg: String,
    feature: String,
    by: String,
    how: String,
    kind: String,
    path: String,
    depth: usize,
}

#[allow(clippy::too_many_arguments)]
fn explain(meta: &Metadata, active: &Active, host: &TargetCfg, id: &str, f: &str, depth: usize, visited: &mut BTreeSet<(String, String)>, out: &mut dyn FnMut(WhyRow)) {
    if depth > 8 || !visited.insert((id.to_string(), f.to_string())) {
        return;
    }
    let spec = meta.package(id).map(|p| p.spec()).unwrap_or_default();
    if meta.is_member(id) {
        if let Some(p) = meta.package(id) {
            if fu::feature_closure(&p.features, &["default".to_string()]).contains(f) {
                out(WhyRow { pkg: spec.clone(), feature: f.into(), by: "workspace member".into(), how: "default features of a member being built".into(), kind: "cli".into(), path: spec.clone(), depth });
            }
        }
    }
    let mut shown: BTreeSet<(String, String)> = BTreeSet::new();
    for e in fu::enablers(meta, active, id, f) {
        // the same declaration repeated for several target cfgs
        if !shown.insert((e.by_spec.clone(), e.how.clone())) {
            continue;
        }
        let path = if e.kind == "self" { String::new() } else { meta.path_to(&e.by).join(" -> ") };
        let kind = match (&e.target, fu::dep_target_applies(e.target.as_deref(), host)) {
            (Some(t), Some(false)) => format!("{} (other platform: {t})", e.kind),
            (Some(t), _) => format!("{} ({t})", e.kind),
            _ => e.kind.clone(),
        };
        out(WhyRow { pkg: spec.clone(), feature: f.into(), by: e.by_spec.clone(), how: e.how.clone(), kind, path, depth });
        if let Some(g) = &e.via_feature {
            explain(meta, active, host, &e.by, g, depth + 1, visited, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_dep_activation() {
        let p: Package = serde_json::from_value(json!({
            "name": "p", "version": "1.0.0", "id": "p", "source": null, "manifest_path": "/x/Cargo.toml",
            "dependencies": [
                {"name": "a", "req": "^1", "kind": null, "optional": true, "uses_default_features": true, "features": [], "target": null, "rename": null},
                {"name": "b", "req": "^1", "kind": null, "optional": true, "uses_default_features": true, "features": [], "target": null, "rename": null},
                {"name": "c", "req": "^1", "kind": null, "optional": true, "uses_default_features": true, "features": [], "target": null, "rename": null}
            ],
            "features": {"default": ["std", "a"], "std": ["b?/std"], "a": ["dep:a"], "c": ["dep:c"], "cx": ["c/x"]}
        }))
        .unwrap();
        let d = fu::feature_closure(&p.features, &["default".into()]);
        assert_eq!(optional_deps(&p, &d), ["a".to_string()].into_iter().collect());
        let cx = fu::feature_closure(&p.features, &["cx".into()]);
        assert_eq!(optional_deps(&p, &cx), ["c".to_string()].into_iter().collect());
    }
}
