//! Successor Finder: Detect crates the ecosystem is leaving and what dependents replace them with.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::project::{MetaOpts, Metadata};
use crate::registry::index::{self, IndexVersion};
use crate::registry::{CrateSpec, api};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::apieco_util::github_repo;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Successor;

const OPTS: &[Opt] = &[
    Opt::value("stale-years", "N", "Project mode: a dependency with no release for N years counts as unmaintained (default 2)"),
    Opt::value("dependents", "N", "Top reverse dependencies (by downloads) to examine (default 60)"),
    Opt::value("scan-top", "N", "Scan the N most-downloaded crates for past users of the crate (default 300; 0 disables)"),
    Opt::value("compare", "A,B", "Extra dependent crates to examine"),
    Opt::flag("all", "Project mode: include transitive dependencies (default: direct only)"),
    Opt::flag("no-advisories", "Do not fetch the RustSec advisory database"),
];

const DEFAULT_DB: &str = "https://github.com/rustsec/advisory-db";

impl Tool for Successor {
    fn name(&self) -> &'static str {
        "successor"
    }
    fn title(&self) -> &'static str {
        "Successor Finder"
    }
    fn group(&self) -> Group {
        Group::Ecosystem
    }
    fn summary(&self) -> &'static str {
        "Detect crates the ecosystem is leaving and what dependents replace them with"
    }
    fn usage(&self) -> &'static str {
        "[CRATE...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Answers \"what did everyone switch to?\" for a crate that is being abandoned, from what dependents
actually did. Candidates are the crate's top reverse dependencies by downloads (crates.io
`/reverse_dependencies`, which only lists dependents whose latest version still uses it), the
--scan-top N most-downloaded crates (crates.io `/crates?sort=recent-downloads`; the main signal for
crates that LEFT, since nothing lists former dependents), crates named with --compare, and nothing
else. For each candidate the sparse index file (no rate limit, fetched in parallel) is walked in
version order: a leaver is a crate that used the subject in some version but not in its latest; the
dependencies that appeared in the first version without it (or the next two) are replacement
candidates, and a leaver that added nothing dropped it without replacement (often for std).
Successors are ranked by the number of leavers that adopted them, weighted by the leavers'
downloads, with evidence (dependent, the version where it switched and its date).

Maintenance signals: the RustSec advisory database (git clone --depth 1 of
https://github.com/rustsec/advisory-db into the cache, refreshed daily; override with
SM_RUSTSEC_DB_URL) for `informational = \"unmaintained\"` advisories, whose text often names
alternatives (crate names in backticks or crates.io links that exist in the index are extracted);
crates.io metadata (last release, releases per year); and whether the GitHub repository is archived
(GitHub API, when reachable).

Findings: medium successor/replace when the subject is unmaintained (advisory, no release for
--stale-years, or archived repository) and a clear successor exists (3+ leavers adopted it, or the
advisory names it); medium successor/unmaintained for an advisory without a clear successor; low
successor/stale when only staleness is known; low successor/ecosystem-leaving when most examined
dependents left a crate not marked unmaintained. Project mode (no CRATE): the project's dependencies
are checked for those maintenance signals first, and only the flagged ones are analyzed. Limits: a
leaver's new dependencies can include unrelated additions made in the same release; small samples
are shown as such."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates successor atty",
            "sm-crates successor atty --compare clap,env_logger,colored,criterion,pretty_env_logger --scan-top 0",
            "sm-crates successor",
            "sm-crates successor lazy_static --dependents 100 --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crates.io API and sparse index, RustSec via git)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let stale_years: f64 = args.parse_or("stale-years", 2.0)?;
        let n_dependents: usize = args.parse_or("dependents", 60)?;
        let scan_top: usize = args.parse_or("scan-top", 300)?;
        let compare = args.list("compare");
        let mut notes: Vec<String> = Vec::new();
        let db = if args.flag("no-advisories") { None } else { advisory_db(ctx, &mut notes) };

        // subjects
        let (subject, names, project_mode) = if !args.positional.is_empty() {
            let mut v = Vec::new();
            for p in &args.positional {
                let s = CrateSpec::parse(p)?;
                index::versions(ctx, &s.name)?;
                v.push(s.name);
            }
            (v.join(", "), v, false)
        } else {
            let meta = Metadata::load(ctx, &MetaOpts::default())?;
            let mut names: BTreeSet<String> = BTreeSet::new();
            if args.flag("all") {
                names.extend(meta.registry_packages(false).iter().map(|p| p.name.clone()));
            } else {
                let by_id = meta.by_id();
                for m in meta.members() {
                    for d in meta.node(&m.id).map(|n| n.deps.clone()).unwrap_or_default() {
                        if let Some(p) = by_id.get(d.pkg.as_str()).filter(|p| p.is_crates_io()) {
                            names.insert(p.name.clone());
                        }
                    }
                }
            }
            let label = meta.members().iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
            (format!("project {label}"), names.into_iter().collect(), true)
        };
        if names.is_empty() {
            return Err(Error::Usage("nothing to analyze: name a crate or run inside a project with crates.io dependencies".into()));
        }

        let mut rep = Report::new("successor", subject);
        let mut overview = Table::new("Maintenance", &["Crate", "Last release", "Releases/yr", "Advisory", "Repo archived", "Dependents examined", "Still using", "Left"]);
        let mut data = Vec::new();
        let mut api_ok = true;
        let mut top: Option<Vec<(String, u64)>> = None;
        let mut checked = 0usize;
        for name in &names {
            let advisories = db.as_deref().map(|d| advisories_for(d, name)).unwrap_or_default();
            let unmaintained_adv = advisories.iter().find(|a| a.informational.as_deref() == Some("unmaintained")).cloned();
            let meta = crate_meta(ctx, name, &mut api_ok);
            let stale = meta.last_release.is_some_and(|t| (util::unix_now() - t) as f64 > stale_years * 365.25 * 86_400.0);
            if project_mode && unmaintained_adv.is_none() && !stale && meta.archived != Some(true) {
                continue;
            }
            checked += 1;
            // candidate dependents
            let mut weights: HashMap<String, u64> = HashMap::new();
            if n_dependents > 0 {
                match top_dependents(ctx, name, n_dependents) {
                    Ok(list) => {
                        for (c, dl) in list {
                            let e = weights.entry(c).or_insert(0);
                            *e = (*e).max(dl);
                        }
                    }
                    Err(e) => {
                        api_ok = false;
                        notes.push(format!("{name}: reverse dependencies unavailable ({e})"));
                    }
                }
            }
            if scan_top > 0 && top.is_none() {
                top = Some(match api::top_crates(ctx, "recent-downloads", scan_top) {
                    Ok(v) => v.iter().filter_map(|c| Some((c["name"].as_str().or(c["id"].as_str())?.to_string(), c["recent_downloads"].as_u64().unwrap_or(0)))).collect(),
                    Err(e) => {
                        api_ok = false;
                        notes.push(format!("top crates unavailable ({e}); use --compare to name dependents to examine"));
                        Vec::new()
                    }
                });
            }
            for (c, dl) in top.iter().flatten() {
                let e = weights.entry(c.clone()).or_insert(0);
                *e = (*e).max(*dl);
            }
            for c in &compare {
                weights.entry(c.clone()).or_insert(0);
            }
            weights.remove(name);
            let cand: Vec<String> = {
                let mut v: Vec<String> = weights.keys().cloned().collect();
                v.sort();
                v
            };
            let idx = index::versions_many(ctx, &cand);
            let mut leavers = Vec::new();
            let mut retained = Vec::new();
            for (c, vs) in &idx {
                let Some(vs) = vs else { continue };
                match usage(vs, name) {
                    Usage::Never => {}
                    Usage::Current => retained.push(c.clone()),
                    Usage::Left(mut l) => {
                        l.dependent = c.clone();
                        l.weight = weights.get(c).copied().unwrap_or(0);
                        leavers.push(l);
                    }
                }
            }
            // advisory-named alternatives that exist
            let mut named: Vec<String> = Vec::new();
            let mut std_alts: Vec<String> = Vec::new();
            if let Some(a) = &unmaintained_adv {
                let (crates, stds) = alternatives(&a.body, name);
                std_alts = stds;
                let exists = index::versions_many(ctx, &crates);
                named = crates.into_iter().filter(|c| exists.get(c).is_some_and(|x| x.is_some())).collect();
            }
            // the unbiased sample, for the leaving ratio
            let (sample_left, sample_kept) = (leavers.len(), retained.len());
            // second hop: dependents of the likely successors that used the subject before
            let mut expand: Vec<String> = named.clone();
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for l in &leavers {
                for d in &l.added {
                    *counts.entry(d.as_str()).or_insert(0) += 1;
                }
            }
            let mut common: Vec<(&str, usize)> = counts.into_iter().filter(|(_, n)| *n >= 2).collect();
            common.sort_by(|a, b| b.1.cmp(&a.1));
            expand.extend(common.iter().map(|(d, _)| d.to_string()));
            if expand.is_empty() {
                if let Some(l) = leavers.iter().max_by_key(|l| l.weight).filter(|l| l.added.len() <= 3) {
                    expand.extend(l.added.iter().cloned());
                }
            }
            let mut uniq = BTreeSet::new();
            expand.retain(|e| uniq.insert(util::normalize_crate_name(e)));
            expand.truncate(4);
            let mut expanded_via: Vec<String> = Vec::new();
            if api_ok && n_dependents > 0 && !expand.is_empty() {
                let mut extra: HashMap<String, (u64, String)> = HashMap::new();
                for cand in &expand {
                    match top_dependents(ctx, cand, 100) {
                        Ok(list) => {
                            for (c, dl) in list {
                                if !idx.contains_key(&c) && c != *name {
                                    extra.entry(c).or_insert((dl, cand.clone()));
                                }
                            }
                        }
                        Err(e) => {
                            notes.push(format!("{cand}: reverse dependencies unavailable ({e})"));
                            break;
                        }
                    }
                }
                let names: Vec<String> = extra.keys().cloned().collect();
                for (c, vs) in index::versions_many(ctx, &names) {
                    let Some(vs) = vs else { continue };
                    if let Usage::Left(mut l) = usage(&vs, name) {
                        let (w, via) = extra.get(&c).cloned().unwrap_or_default();
                        l.dependent = c.clone();
                        l.weight = w;
                        l.via = Some(via);
                        leavers.push(l);
                    }
                }
                expanded_via = expand.clone();
            }
            // rank successors
            let mut ranked: BTreeMap<String, (usize, u64, Vec<usize>)> = BTreeMap::new();
            for (i, l) in leavers.iter().enumerate() {
                for d in &l.added {
                    let e = ranked.entry(d.clone()).or_insert((0, 0, vec![]));
                    e.0 += 1;
                    e.1 += l.weight;
                    e.2.push(i);
                }
            }
            let mut succ: Vec<(String, usize, u64, Vec<usize>)> = ranked.into_iter().map(|(k, (n, w, ix))| (k, n, w, ix)).collect();
            succ.sort_by(|a, b| {
                let an = named.contains(&a.0);
                let bn = named.contains(&b.0);
                b.1.cmp(&a.1).then(bn.cmp(&an)).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0))
            });
            // keep meaningful ones: adopted by 2+ leavers, or named by the advisory
            succ.retain(|s| s.1 >= 2 || named.contains(&s.0) || leavers.len() <= 2);
            for n in &named {
                if !succ.iter().any(|s| &s.0 == n) {
                    succ.push((n.clone(), 0, 0, vec![]));
                }
            }
            // dates for the evidence of the top successors
            let mut dates: HashMap<(String, String), String> = HashMap::new();
            if api_ok {
                let mut wanted: Vec<(String, String)> = Vec::new();
                for s in succ.iter().take(3) {
                    for &i in s.3.iter().take(3) {
                        wanted.push((leavers[i].dependent.clone(), leavers[i].switched_in.clone()));
                    }
                }
                wanted.sort();
                wanted.dedup();
                // one request per version (paging a dependent's whole /versions list costs one
                // rate-limited request per 100 releases)
                for (dep, ver) in wanted.into_iter().take(9) {
                    match api::version(ctx, &dep, &ver) {
                        Ok(v) => {
                            if let Some(d) = v["created_at"].as_str() {
                                dates.insert((dep, ver), d.get(..10).unwrap_or(d).to_string());
                            }
                        }
                        Err(Error::NotFound(_)) => {}
                        Err(_) => break,
                    }
                }
            }
            let evidence = |i: usize| {
                let l: &Leaver = &leavers[i];
                let date = dates.get(&(l.dependent.clone(), l.switched_in.clone())).map(|d| format!(", {d}")).unwrap_or_default();
                format!("{} {} -> {}{date}", l.dependent, l.last_using, l.switched_in)
            };
            let mut t = Table::new(format!("Successors of {name}"), &["Successor", "Leavers", "Weighted downloads", "Named by advisory", "Evidence"]);
            for s in succ.iter().take(10) {
                t.row([
                    s.0.clone(),
                    s.1.to_string(),
                    if s.2 == 0 { "-".into() } else { util::human_count(s.2) },
                    if named.contains(&s.0) { "yes".into() } else { "-".into() },
                    s.3.iter().take(3).map(|&i| evidence(i)).collect::<Vec<_>>().join("; "),
                ]);
            }
            let dropped: Vec<&Leaver> = leavers.iter().filter(|l| l.added.is_empty()).collect();
            if !dropped.is_empty() {
                t.row([
                    "(dropped, nothing added)".to_string(),
                    dropped.len().to_string(),
                    match dropped.iter().map(|l| l.weight).sum::<u64>() {
                        0 => "-".into(),
                        w => util::human_count(w),
                    },
                    if std_alts.is_empty() { "-".into() } else { std_alts.join(", ") },
                    dropped.iter().take(3).map(|l| format!("{} {} -> {}", l.dependent, l.last_using, l.switched_in)).collect::<Vec<_>>().join("; "),
                ]);
            }
            rep.table(t);
            overview.row([
                name.clone(),
                meta.last_release.map(util::format_date).unwrap_or_else(|| "?".into()),
                meta.per_year.map(|p| format!("{p:.1}")).unwrap_or_else(|| "?".into()),
                unmaintained_adv.as_ref().map(|a| a.id.clone()).unwrap_or_else(|| "-".into()),
                match meta.archived {
                    Some(true) => "yes".into(),
                    Some(false) => "no".into(),
                    None => "?".into(),
                },
                (sample_left + sample_kept).to_string(),
                sample_kept.to_string(),
                if leavers.len() > sample_left { format!("{sample_left} (+{} via dependents of {})", leavers.len() - sample_left, expanded_via.join(", ")) } else { sample_left.to_string() },
            ]);

            // findings
            let mut reasons = Vec::new();
            if let Some(a) = &unmaintained_adv {
                reasons.push(format!("RustSec {} ({})", a.id, a.title));
            }
            if stale {
                reasons.push(format!("no release since {}", meta.last_release.map(util::format_date).unwrap_or_default()));
            }
            if meta.archived == Some(true) {
                reasons.push(format!("repository {} is archived", meta.repo.clone().unwrap_or_default()));
            }
            let clear = succ.iter().find(|s| s.1 >= 3 || named.contains(&s.0));
            let examples = |s: &(String, usize, u64, Vec<usize>)| s.3.iter().take(3).map(|&i| evidence(i)).collect::<Vec<_>>().join("; ");
            if !reasons.is_empty() {
                match clear {
                    Some(s) => {
                        let mut fix = format!("Replace {name} with {}", s.0);
                        if s.1 > 0 {
                            fix.push_str(&format!(" ({} dependent(s) switched, e.g. {})", s.1, examples(s)));
                        } else {
                            fix.push_str(" (recommended by the advisory)");
                        }
                        if !std_alts.is_empty() {
                            fix.push_str(&format!("; or use {} from std", std_alts.join(", ")));
                        }
                        rep.finding(
                            Finding::new(Severity::Medium, "successor/replace", format!("{name} is unmaintained ({}); the ecosystem moved to {}", reasons.join("; "), s.0))
                                .krate(name, None::<String>)
                                .detail(format!(
                                    "{sample_left} of {} sampled dependents left {name}, plus {} former users found among the dependents of {}; {} dropped it without adding a dependency",
                                    sample_left + sample_kept,
                                    leavers.len() - sample_left,
                                    if expanded_via.is_empty() { "no successor".to_string() } else { expanded_via.join(", ") },
                                    dropped.len()
                                ))
                                .fix(fix),
                        );
                    }
                    None => {
                        let sev = if unmaintained_adv.is_some() { Severity::Medium } else { Severity::Low };
                        let code = if unmaintained_adv.is_some() { "successor/unmaintained" } else { "successor/stale" };
                        let mut fix = "No clear successor among examined dependents; add candidates with --compare or raise --scan-top".to_string();
                        if !std_alts.is_empty() {
                            fix = format!("The advisory suggests {} from std", std_alts.join(", "));
                        }
                        rep.finding(
                            Finding::new(sev, code, format!("{name} looks unmaintained ({})", reasons.join("; ")))
                                .krate(name, None::<String>)
                                .detail(format!("{sample_left} of {} sampled dependents left it; {} more former users found via likely successors", sample_left + sample_kept, leavers.len() - sample_left))
                                .fix(fix),
                        );
                    }
                }
            } else if sample_left >= 3 && sample_left > sample_kept {
                let mut f = Finding::new(
                    Severity::Low,
                    "successor/ecosystem-leaving",
                    format!("{sample_left} of {} sampled dependents stopped using {name}", sample_left + sample_kept),
                )
                .krate(name, None::<String>);
                if let Some(s) = succ.first().filter(|s| s.1 >= 2) {
                    f = f.detail(format!("most common replacement: {} ({} leavers, e.g. {})", s.0, s.1, examples(s))).fix(format!("Consider {} for new code", s.0));
                } else {
                    f = f.fix("Check the crate's changelog and issue tracker for its status");
                }
                rep.finding(f);
            }
            data.push(json!({
                "crate": name,
                "last_release": meta.last_release.map(util::format_unix),
                "releases_per_year": meta.per_year,
                "repository": meta.repo,
                "archived": meta.archived,
                "advisories": advisories.iter().map(|a| json!({"id": a.id, "informational": a.informational, "title": a.title, "date": a.date})).collect::<Vec<_>>(),
                "unmaintained": !reasons.is_empty(),
                "reasons": reasons,
                "examined": sample_left + sample_kept,
                "sample_leavers": sample_left,
                "expanded_via": expanded_via,
                "retained": retained,
                "leavers": leavers.iter().map(|l| json!({"dependent": l.dependent, "last_using": l.last_using, "switched_in": l.switched_in, "date": dates.get(&(l.dependent.clone(), l.switched_in.clone())), "added": l.added, "weight": l.weight, "found_via": l.via})).collect::<Vec<_>>(),
                "advisory_alternatives": named,
                "std_alternatives": std_alts,
                "successors": succ.iter().map(|s| json!({"crate": s.0, "leavers": s.1, "weighted_downloads": s.2, "named_by_advisory": named.contains(&s.0), "evidence": s.3.iter().map(|&i| evidence(i)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
            }));
        }
        rep.tables.insert(0, overview);
        if project_mode && checked == 0 {
            rep.summary(format!("none of {} dependencies is flagged unmaintained (RustSec) or stale ({stale_years} years without a release)", names.len()));
        } else {
            let flagged = rep.findings.iter().filter(|f| f.code == "successor/replace").count();
            rep.summary(format!("{checked} crate(s) analyzed; {flagged} with a clear successor"));
        }
        if !api_ok {
            notes.push("crates.io API data was partly unavailable: dependents came only from the sources that responded (sparse index walks still ran).".into());
        }
        for n in notes {
            rep.note(n);
        }
        rep.note("A leaver's new dependencies may include unrelated additions from the same release; look at the evidence column.");
        rep.data = json!({"crates": data});
        Ok(rep)
    }
}

// ------------------------------------------------------------------ dependents

/// Top `n` dependents of a crate by downloads (crates.io lists dependents whose current version uses it).
fn top_dependents(ctx: &Ctx, name: &str, n: usize) -> Result<Vec<(String, u64)>> {
    let (deps, vers, _) = api::reverse_dependencies(ctx, name, n.div_ceil(100).clamp(1, 10))?;
    let by_vid: HashMap<u64, (&str, u64)> =
        vers.iter().filter_map(|v| Some((v["id"].as_u64()?, (v["crate"].as_str()?, v["downloads"].as_u64().unwrap_or(0))))).collect();
    // dev-dependency edges never show up in `usage` (it walks normal and build dependencies), so
    // they would only take slots from real dependents
    let mut list: Vec<(String, u64)> = deps
        .iter()
        .filter(|d| d["kind"].as_str() != Some("dev"))
        .filter_map(|d| {
            let (c, dl) = by_vid.get(&d["version_id"].as_u64()?)?;
            Some((c.to_string(), d["downloads"].as_u64().unwrap_or(*dl)))
        })
        .collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut seen = BTreeSet::new();
    list.retain(|(c, _)| seen.insert(c.clone()));
    list.truncate(n);
    Ok(list)
}

#[derive(Debug, Clone, Default)]
pub struct Leaver {
    pub dependent: String,
    pub last_using: String,
    pub switched_in: String,
    pub added: Vec<String>,
    pub weight: u64,
    /// Found among the dependents of this successor candidate (second hop).
    pub via: Option<String>,
}

pub enum Usage {
    Never,
    Current,
    Left(Leaver),
}

fn runtime_deps(v: &IndexVersion) -> BTreeSet<String> {
    v.deps.iter().filter(|d| d.kind() != "dev").map(|d| util::normalize_crate_name(d.package_name())).collect()
}

/// How a dependent's version history uses crate `x`.
pub fn usage(vs: &[IndexVersion], x: &str) -> Usage {
    let xn = util::normalize_crate_name(x);
    let mut sorted: Vec<(&IndexVersion, semver::Version)> = vs.iter().filter_map(|v| v.version().map(|s| (v, s))).filter(|(_, s)| s.pre.is_empty()).collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    let uses = |v: &IndexVersion| runtime_deps(v).contains(&xn);
    let Some(last_using) = sorted.iter().rposition(|(v, _)| uses(v)) else { return Usage::Never };
    let latest = sorted.iter().rposition(|(v, _)| !v.yanked).unwrap_or(sorted.len() - 1);
    if last_using >= latest {
        return Usage::Current;
    }
    // everything the crate depended on while it still used `x`
    let before: BTreeSet<String> = sorted[..=last_using].iter().flat_map(|(v, _)| runtime_deps(v)).collect();
    let mut added = BTreeSet::new();
    for (v, _) in sorted.iter().skip(last_using + 1).take(3) {
        for d in runtime_deps(v) {
            if !before.contains(&d) && d != xn {
                added.insert(d);
            }
        }
    }
    // report names as published (hyphens), not normalized
    let display: HashMap<String, String> = sorted
        .iter()
        .flat_map(|(v, _)| v.deps.iter().map(|d| (util::normalize_crate_name(d.package_name()), d.package_name().to_string())))
        .collect();
    Usage::Left(Leaver {
        dependent: String::new(),
        last_using: sorted[last_using].0.vers.clone(),
        switched_in: sorted[last_using + 1].0.vers.clone(),
        added: added.into_iter().map(|a| display.get(&a).cloned().unwrap_or(a)).collect(),
        weight: 0,
        via: None,
    })
}

// ------------------------------------------------------------------ crates.io / GitHub metadata

#[derive(Debug, Default)]
struct CrateMeta {
    last_release: Option<i64>,
    per_year: Option<f64>,
    repo: Option<String>,
    archived: Option<bool>,
}

fn crate_meta(ctx: &Ctx, name: &str, api_ok: &mut bool) -> CrateMeta {
    let mut m = CrateMeta::default();
    let k = match api::krate(ctx, name) {
        Ok(k) => k,
        Err(_) => {
            *api_ok = false;
            return m;
        }
    };
    let rec = api::crate_record(&k);
    m.repo = rec["repository"].as_str().map(str::to_string);
    let mut times: Vec<i64> = k["versions"].as_array().into_iter().flatten().filter(|v| v["yanked"] != true).filter_map(|v| v["created_at"].as_str().and_then(util::parse_time)).collect();
    if times.is_empty() {
        if let Some(t) = rec["updated_at"].as_str().and_then(util::parse_time) {
            times.push(t);
        }
    }
    m.last_release = times.iter().copied().max();
    let created = rec["created_at"].as_str().and_then(util::parse_time).or_else(|| times.iter().copied().min());
    if let (Some(c), false) = (created, times.is_empty()) {
        let years = ((util::unix_now() - c) as f64 / (365.25 * 86_400.0)).max(1.0 / 12.0);
        m.per_year = Some((times.len() as f64 / years * 10.0).round() / 10.0);
    }
    if let Some(r) = m.repo.as_deref().and_then(github_repo) {
        let url = format!("{}/repos/{r}", ctx.endpoints.github_api);
        if let Ok(resp) = ctx.http.get(&url, Ttl::DAY) {
            if resp.ok() {
                m.archived = resp.json().ok().and_then(|v| v["archived"].as_bool());
            }
        }
    }
    m
}

// ------------------------------------------------------------------ RustSec

#[derive(Debug, Clone, Default)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub informational: Option<String>,
    pub date: String,
    pub title: String,
    pub body: String,
}

fn db_url() -> String {
    std::env::var("SM_RUSTSEC_DB_URL").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| DEFAULT_DB.to_string())
}

/// Local checkout of the advisory database, cloned or refreshed (daily) as needed.
fn advisory_db(ctx: &Ctx, notes: &mut Vec<String>) -> Option<PathBuf> {
    let base = ctx.cache_subdir("rustsec").ok()?;
    let url = db_url();
    // one checkout per URL, so a mirror or test repository never mixes with the real one
    let dir = base.join(&util::sha256_hex(url.as_bytes())[..12]);
    let stamp = dir.join(".sm-fetched");
    let fresh = std::fs::read_to_string(&stamp).ok().and_then(|s| s.trim().parse::<i64>().ok()).is_some_and(|t| util::unix_now() - t < 86_400);
    let have = dir.join("crates").is_dir();
    if have && (fresh || ctx.offline) {
        return Some(dir);
    }
    if ctx.offline {
        notes.push("RustSec advisory database is not cached and --offline was given; advisories were not checked".into());
        return None;
    }
    if util::which("git").is_none() {
        notes.push("git is not installed; RustSec advisories were not checked (install git)".into());
        return have.then_some(dir);
    }
    let ok = if have {
        let f = util::run(Command::new("git").arg("-C").arg(&dir).args(["fetch", "--depth", "1", "-q", "origin"]), Duration::from_secs(180));
        f.is_ok_and(|o| o.success())
            && util::run(Command::new("git").arg("-C").arg(&dir).args(["reset", "-q", "--hard", "FETCH_HEAD"]), Duration::from_secs(60)).is_ok_and(|o| o.success())
    } else {
        let tmp = base.join(format!(".clone-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let r = util::run(Command::new("git").args(["clone", "--depth", "1", "-q", &url]).arg(&tmp), Duration::from_secs(300));
        let ok = r.is_ok_and(|o| o.success()) && tmp.join("crates").is_dir();
        if ok {
            let _ = std::fs::remove_dir_all(&dir);
            if std::fs::rename(&tmp, &dir).is_err() {
                let _ = std::fs::remove_dir_all(&tmp);
            }
        } else {
            let _ = std::fs::remove_dir_all(&tmp);
        }
        ok
    };
    if ok {
        let _ = std::fs::write(&stamp, util::unix_now().to_string());
    } else if have {
        notes.push("could not refresh the RustSec advisory database; using the cached copy".into());
    } else {
        notes.push(format!("could not clone the RustSec advisory database from {url}; advisories were not checked"));
        return None;
    }
    Some(dir)
}

/// Parse one advisory Markdown file (TOML front matter in a ```toml block, then Markdown).
pub fn parse_advisory(text: &str) -> Option<Advisory> {
    let start = text.find("```toml")?;
    let rest = &text[start + 7..];
    let end = rest.find("```")?;
    let front: toml::Value = toml::from_str(&rest[..end]).ok()?;
    let adv = front.get("advisory")?;
    let body = rest[end + 3..].trim().to_string();
    let title = body.lines().find(|l| l.starts_with('#')).map(|l| l.trim_start_matches('#').trim().to_string()).unwrap_or_default();
    Some(Advisory {
        id: adv.get("id")?.as_str()?.to_string(),
        package: adv.get("package").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        informational: adv.get("informational").and_then(|v| v.as_str()).map(str::to_string),
        date: adv.get("date").map(|d| d.to_string().trim_matches('"').to_string()).unwrap_or_default(),
        title,
        body,
    })
}

pub fn advisories_for(db: &Path, name: &str) -> Vec<Advisory> {
    let mut out = Vec::new();
    for dir in [db.join("crates").join(name), db.join("crates").join(name.replace('_', "-")), db.join("crates").join(name.replace('-', "_"))] {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "md")).collect();
        files.sort();
        for f in files {
            if let Some(a) = std::fs::read_to_string(&f).ok().and_then(|t| parse_advisory(&t)) {
                if !a.id.is_empty() && !out.iter().any(|x: &Advisory| x.id == a.id) {
                    out.push(a);
                }
            }
        }
    }
    out
}

/// Crate names (and std paths) an advisory body recommends.
pub fn alternatives(body: &str, subject: &str) -> (Vec<String>, Vec<String>) {
    let mut crates: Vec<String> = Vec::new();
    let mut stds: Vec<String> = Vec::new();
    let valid = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && util::normalize_crate_name(s) != util::normalize_crate_name(subject)
    };
    let mut push = |s: &str| {
        if valid(s) && !crates.iter().any(|c| util::normalize_crate_name(c) == util::normalize_crate_name(s)) {
            crates.push(s.to_string());
        }
    };
    // `name` in backticks
    let parts: Vec<&str> = body.split('`').collect();
    for (i, p) in parts.iter().enumerate() {
        if i % 2 == 1 {
            let p = p.trim();
            if p.starts_with("std::") || p.starts_with("core::") {
                if !stds.contains(&p.to_string()) {
                    stds.push(p.to_string());
                }
            } else {
                push(p);
            }
        }
    }
    // std paths as link text or doc.rust-lang.org links
    let mut add_std = |p: String| {
        if !stds.contains(&p) {
            stds.push(p);
        }
    };
    let mut rest = body;
    while let Some(p) = rest.find("[std::").or_else(|| rest.find("[core::")) {
        let tail = &rest[p + 1..];
        let path: String = tail.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':').collect();
        add_std(path.trim_end_matches(':').to_string());
        rest = &tail[path.len().min(tail.len())..];
    }
    let mut rest = body;
    while let Some(p) = rest.find("doc.rust-lang.org/") {
        let tail = &rest[p + 18..];
        let url: String = tail.chars().take_while(|c| !c.is_whitespace() && *c != ')' && *c != '#').collect();
        let mut segs: Vec<&str> = url.split('/').filter(|s| !s.is_empty()).collect();
        if segs.first().is_some_and(|s| matches!(*s, "stable" | "beta" | "nightly")) {
            segs.remove(0);
        }
        if segs.first().is_some_and(|s| matches!(*s, "std" | "core" | "alloc")) {
            let mut path: Vec<String> = segs.iter().map(|s| s.to_string()).collect();
            if let Some(last) = path.pop() {
                // trait.IsTerminal.html -> IsTerminal
                let item = last.trim_end_matches(".html").rsplit('.').next().unwrap_or("").to_string();
                if !item.is_empty() && item != "index" {
                    path.push(item);
                }
            }
            add_std(path.join("::"));
        }
        rest = &tail[url.len().min(tail.len())..];
    }
    stds.dedup();
    // crates.io / docs.rs / lib.rs links
    for marker in ["crates.io/crates/", "docs.rs/", "lib.rs/crates/"] {
        let mut rest = body;
        while let Some(p) = rest.find(marker) {
            let tail = &rest[p + marker.len()..];
            let name: String = tail.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
            push(&name);
            rest = &tail[name.len().min(tail.len())..];
        }
    }
    (crates, stds)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADV: &str = "```toml\n[advisory]\nid = \"RUSTSEC-2024-0375\"\npackage = \"atty\"\ndate = \"2024-09-25\"\ninformational = \"unmaintained\"\n\n[versions]\npatched = []\n```\n\n# `atty` is unmaintained\n\nThe maintainer of `atty` has [published](https://github.com/softprops/atty/pull/58) an official notice.\n\n## Recommended alternatives\n\n- [is-terminal](https://crates.io/crates/is-terminal)\n- `std::io::IsTerminal` *nightly-only experimental*\n";

    #[test]
    fn parses_advisory_and_alternatives() {
        let a = parse_advisory(ADV).unwrap();
        assert_eq!(a.id, "RUSTSEC-2024-0375");
        assert_eq!(a.informational.as_deref(), Some("unmaintained"));
        assert_eq!(a.title, "`atty` is unmaintained");
        let (c, s) = alternatives(&a.body, "atty");
        assert_eq!(c, ["is-terminal"]);
        assert_eq!(s, ["std::io::IsTerminal"]);
        let (_, s) = alternatives("use [`IsTerminal`](https://doc.rust-lang.org/std/io/trait.IsTerminal.html) or [std::io::IsTerminal](https://doc.rust-lang.org/stable/std/io/trait.IsTerminal.html)", "atty");
        assert_eq!(s, ["std::io::IsTerminal"]);
    }

    fn v(vers: &str, deps: &[&str]) -> IndexVersion {
        let deps: Vec<serde_json::Value> = deps.iter().map(|d| json!({"name": d, "req": "*"})).collect();
        serde_json::from_value(json!({"name": "x", "vers": vers, "deps": deps, "cksum": "0"})).unwrap()
    }

    #[test]
    fn walks_versions_in_semver_order() {
        // 1.0.1 published after 2.0.0 (maintenance branch) still uses atty: not the latest
        let vs = [v("1.0.0", &["atty", "log"]), v("2.0.0", &["is-terminal", "log"]), v("1.0.1", &["atty"])];
        match usage(&vs, "atty") {
            Usage::Left(l) => {
                assert_eq!(l.last_using, "1.0.1");
                assert_eq!(l.switched_in, "2.0.0");
                assert_eq!(l.added, ["is-terminal"]);
            }
            _ => panic!("expected leaver"),
        }
        assert!(matches!(usage(&[v("1.0.0", &["atty"])], "atty"), Usage::Current));
        assert!(matches!(usage(&[v("1.0.0", &["log"])], "atty"), Usage::Never));
    }
}
