//! cargo-vet Audit Coverage: Import public cargo-vet audit sets and find the smallest audit that covers each dependency.
//!
//! cargo-vet audits are published as plain TOML files by Mozilla, Google, the
//! Bytecode Alliance, ISRG, Zcash and others. This tool imports them (no
//! cargo-vet installation needed), decides for each dependency whether a full
//! audit, a chain of delta audits, a trusted publisher or a wildcard audit
//! certifies the locked version, and for the rest computes the cheapest audit
//! you could do yourself.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use semver::{Version, VersionReq};
use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::registry::{api, download, index};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::common::{self, CrateRef, Select};
use crate::tools::supplychain_util as su;
use crate::tools::unsafe_hotspots::par_map;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Vet;

const OPTS: &[Opt] = &[
    Opt::value("criteria", "NAME", "Criteria normal dependencies must meet (default: safe-to-deploy, or the project's cargo-vet policy)"),
    Opt::value("dev-criteria", "NAME", "Criteria dev-only dependencies must meet (default: safe-to-run)"),
    Opt::value("import", "A,B", "Only import these audit sets from the cargo-vet registry (e.g. mozilla,google); `none` for local audits only"),
    Opt::value("only", "A,B", "Only check these dependencies (comma-separated names)"),
    Opt::flag("no-suggest", "Do not download crates to size the cheapest audit for uncovered dependencies"),
];

const REGISTRY_PATH: &str = "/mozilla/cargo-vet/main/registry.toml";

impl Tool for Vet {
    fn name(&self) -> &'static str {
        "vet"
    }
    fn title(&self) -> &'static str {
        "cargo-vet Audit Coverage"
    }
    fn group(&self) -> Group {
        Group::SupplyChain
    }
    fn summary(&self) -> &'static str {
        "Import public cargo-vet audit sets and find the smallest audit that covers each dependency"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Answers \"who has already reviewed the code I depend on?\" with cargo-vet's public audit sets, without
installing cargo-vet. The registry of audit sets (mozilla/cargo-vet registry.toml on GitHub) lists each
organization's audits.toml; all of them (or --import a,b) are fetched in parallel and cached for a day.
A project's own supply-chain/audits.toml, imports.lock (imported audits and publisher records) and
config.toml (policy criteria, exemptions, extra imports) are merged in when present.

For every crates.io dependency at its locked version (or each CRATE@VERSION named) it decides whether the
version is certified for the required criteria (safe-to-deploy, or safe-to-run for dev-only
dependencies; custom criteria and `implies` are followed): by a full audit of that version, by a chain
of delta audits (\"a -> b\") starting at a fully audited version, by a trusted publisher entry or a
wildcard audit whose user-id published that version inside the start/end dates (publisher from
imports.lock or the crates.io API), or by an exemption in config.toml. A `violation` audit whose range
matches the version is critical. Uncovered dependencies are medium, as are dependencies certified only
safe-to-run where safe-to-deploy is required.

For each uncovered dependency the cheapest audit is sized: a full `cargo vet inspect` of the version
versus `cargo vet diff` from each of the nearest already-certified versions, by downloading both .crate
files and counting changed lines (a multiset line diff: approximate, but fast). Suggestions are sorted
cheapest first. Trusted-publisher matching needs the crates.io API (or imports.lock); when it is
unreachable this is noted and only audits are used."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates vet",
            "sm-crates vet serde@1.0.210 libc@0.2.158 --import mozilla,google",
            "sm-crates vet --criteria safe-to-run --json",
            "sm-crates vet smallvec@1.13.2 --no-suggest",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (cargo-vet audit sets on raw.githubusercontent.com, crate downloads; crates.io API for trusted publishers)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let (subject, crates, meta) = common::select(ctx, args, Select { dev: true, ..Default::default() })?;
        let crates: Vec<CrateRef> = common::only(args, crates).into_iter().filter(|c| c.is_registry()).collect();
        common::non_empty(&crates)?;
        let mut rep = Report::new("vet", subject);

        // Local cargo-vet state, then the public registry.
        let mut store = Store::default();
        let local = load_local(ctx, &mut store, &mut rep);
        let imports = args.list("import");
        fetch_registry(ctx, &imports, &local.imports, &mut store, &mut rep)?;
        if store.sources.iter().all(|s| !s.ok) {
            return Err(Error::Network("no cargo-vet audit set could be loaded".into()));
        }

        let normal_ids = meta.as_ref().map(|m| m.reachable(false, true));
        let criteria = args.value("criteria").map(String::from).or(local.criteria.clone()).unwrap_or_else(|| "safe-to-deploy".into());
        let dev_criteria = args.value("dev-criteria").map(String::from).or(local.dev_criteria.clone()).unwrap_or_else(|| "safe-to-run".into());

        // Publisher data (crates.io API) only for crates that have trusted / wildcard entries.
        let mut api_failed: Option<String> = None;
        let mut checks: Vec<Check> = Vec::new();
        for c in &crates {
            let dev_only = match (&normal_ids, &c.id) {
                (Some(n), Some(id)) => !n.contains(id),
                _ => false,
            };
            let want = if dev_only { dev_criteria.clone() } else { criteria.clone() };
            // a custom criteria named on the command line or in the policy is a local one
            let want_q = qual("local", &want);
            let Some(ver) = util::parse_version(&c.version) else {
                rep.note(format!("{}: version is not semver; skipped", c.spec()));
                continue;
            };
            let mut publisher = store.publishers.get(&(c.name.clone(), ver.to_string())).cloned();
            if publisher.is_none() && store.trusted.contains_key(&c.name) && api_failed.is_none() && !ctx.offline {
                match publisher_from_api(ctx, &c.name, &c.version) {
                    Ok(p) => publisher = p,
                    Err(e) => api_failed = Some(e.to_string()),
                }
            }
            let cov = store.coverage(&c.name, &ver, &want_q, publisher.as_ref());
            let weaker = if cov.status == Status::Uncovered && want != "safe-to-run" && !store.satisfies(&["safe-to-run".into()], &want_q) {
                let w = store.coverage(&c.name, &ver, "safe-to-run", publisher.as_ref());
                (w.status != Status::Uncovered).then_some(w)
            } else {
                None
            };
            checks.push(Check { krate: c.clone(), version: ver, want, dev_only, cov, weaker, suggestions: Vec::new(), size_error: None });
        }
        if let Some(e) = &api_failed {
            rep.note(format!("crates.io API unreachable ({e}); trusted-publisher and wildcard entries were only matched where imports.lock records the publisher"));
        }

        // Size the cheapest audits.
        if !args.flag("no-suggest") {
            let todo: Vec<usize> = checks.iter().enumerate().filter(|(_, c)| c.cov.status == Status::Uncovered).map(|(i, _)| i).collect();
            let sized = par_map(&todo, 6, |&i| suggest(ctx, &checks[i]));
            for (i, r) in todo.into_iter().zip(sized) {
                match r {
                    Ok(s) => checks[i].suggestions = s,
                    Err(e) => checks[i].size_error = Some(e.to_string()),
                }
            }
        }

        // Report.
        let mut t = Table::new("Audit coverage", &["Crate", "Version", "Needs", "Status", "Certified by", "Cheapest audit"]);
        let mut by_org: BTreeMap<String, usize> = BTreeMap::new();
        let (mut covered, mut uncovered, mut lines_total) = (0usize, 0usize, 0usize);
        let mut data = Vec::new();
        for ch in &checks {
            let c = &ch.krate;
            let sugg = ch.suggestions.first();
            match ch.cov.status {
                Status::Uncovered | Status::Violation => {}
                _ => {
                    covered += 1;
                    for o in ch.cov.orgs.iter().take(1) {
                        *by_org.entry(o.clone()).or_default() += 1;
                    }
                }
            }
            if ch.cov.status == Status::Uncovered {
                uncovered += 1;
                lines_total += sugg.map(|s| s.lines).unwrap_or(0);
            }
            t.row([
                c.name.clone(),
                c.version.clone(),
                ch.want.clone(),
                ch.cov.status.label().to_string(),
                if ch.cov.orgs.is_empty() { "-".into() } else { ch.cov.orgs.join(", ") },
                match (ch.cov.status, sugg) {
                    (Status::Uncovered, Some(s)) => format!("{} ({})", s.command, s.size_label()),
                    (Status::Uncovered, None) => ch.size_error.clone().map(|e| format!("not sized: {e}")).unwrap_or_else(|| "-".into()),
                    _ => "-".into(),
                },
            ]);
            for f in ch.findings() {
                rep.finding(f);
            }
            data.push(ch.to_json());
        }
        rep.table(t);
        let mut st = Table::new("Imported audit sets", &["Source", "Audits", "Trusted/wildcard", "Status"]);
        for s in &store.sources {
            st.row([s.name.clone(), s.audits.to_string(), s.trusted.to_string(), if s.ok { "loaded".to_string() } else { s.error.clone() }]);
        }
        rep.table(st);
        let orgs = by_org.iter().map(|(o, n)| format!("{o} {n}")).collect::<Vec<_>>().join(", ");
        rep.summary(format!(
            "{covered} of {} dependencies certified{}; {uncovered} need audits{}",
            checks.len(),
            if orgs.is_empty() { String::new() } else { format!(" ({orgs})") },
            if lines_total > 0 { format!(" (~{lines_total} lines to review with the cheapest audits)") } else { String::new() }
        ));
        rep.note("Line counts for suggested audits use a multiset line diff of the two .crate files: approximate, but the same files `cargo vet diff` shows.");
        rep.note(format!("criteria: {criteria} for normal dependencies, {dev_criteria} for dev-only dependencies"));
        rep.data = json!({
            "criteria": criteria, "dev_criteria": dev_criteria,
            "covered": covered, "uncovered": uncovered, "lines_to_review": lines_total,
            "covered_by": by_org,
            "sources": store.sources.iter().map(|s| json!({"name": s.name, "url": s.url, "loaded": s.ok, "audits": s.audits, "trusted": s.trusted, "error": if s.ok { Value::Null } else { json!(s.error) }})).collect::<Vec<_>>(),
            "crates": data,
        });
        Ok(rep)
    }
}

// ---------------------------------------------------------------- data model

#[derive(Debug, Clone)]
enum Kind {
    Full(Version),
    Delta(Version, Version),
    Violation(VersionReq),
}

#[derive(Debug, Clone)]
struct Audit {
    org: String,
    who: String,
    criteria: Vec<String>,
    kind: Kind,
    notes: Option<String>,
}

#[derive(Debug, Clone)]
struct Trust {
    org: String,
    criteria: Vec<String>,
    user_id: u64,
    start: Option<i64>,
    end: Option<i64>,
    wildcard: bool,
}

/// Who published a version and when (unix seconds).
#[derive(Debug, Clone)]
struct Publisher {
    user_id: u64,
    login: Option<String>,
    when: Option<i64>,
}

#[derive(Debug, Clone)]
struct Source {
    name: String,
    url: String,
    ok: bool,
    audits: usize,
    trusted: usize,
    error: String,
}

#[derive(Default)]
struct Store {
    audits: HashMap<String, Vec<Audit>>,
    trusted: HashMap<String, Vec<Trust>>,
    implies: HashMap<String, Vec<String>>,
    exemptions: HashMap<String, Vec<(Version, Vec<String>)>>,
    publishers: HashMap<(String, String), Publisher>,
    sources: Vec<Source>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Full,
    Delta,
    Trusted,
    Wildcard,
    Exempted,
    Uncovered,
    Violation,
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Status::Full => "audited",
            Status::Delta => "audited (delta chain)",
            Status::Trusted => "trusted publisher",
            Status::Wildcard => "wildcard audit",
            Status::Exempted => "exempted",
            Status::Uncovered => "UNCOVERED",
            Status::Violation => "VIOLATION",
        }
    }
    fn code(&self) -> &'static str {
        match self {
            Status::Full => "full",
            Status::Delta => "delta",
            Status::Trusted => "trusted",
            Status::Wildcard => "wildcard",
            Status::Exempted => "exempted",
            Status::Uncovered => "uncovered",
            Status::Violation => "violation",
        }
    }
}

#[derive(Debug, Clone)]
struct Coverage {
    status: Status,
    orgs: Vec<String>,
    /// Human-readable certification path, e.g. `full 1.0.0 (mozilla) -> 1.0.0..1.0.2 (google)`.
    path: Vec<String>,
    violations: Vec<Audit>,
    /// Versions certified for the criteria (starting points for delta suggestions).
    certified: BTreeSet<Version>,
    /// An imported `trusted` entry that matches (cargo-vet does not import those).
    hint: Option<String>,
}

/// Custom criteria live in their audit set's own namespace (cargo-vet only maps a peer's
/// `safe-to-run` / `safe-to-deploy`, or what its own `implies` reach): `org::name`.
fn qual(org: &str, c: &str) -> String {
    if c == "safe-to-run" || c == "safe-to-deploy" { c.to_string() } else { format!("{org}::{c}") }
}

/// Criteria name for display (namespace removed).
fn unqual(c: &str) -> &str {
    c.rsplit_once("::").map(|x| x.1).unwrap_or(c)
}

fn crit_list(v: Option<&toml::Value>) -> Vec<String> {
    match v {
        Some(toml::Value::String(s)) => vec![s.clone()],
        Some(toml::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

fn ver(s: &str) -> Option<Version> {
    util::parse_version(s.trim())
}

fn date(v: Option<&toml::Value>) -> Option<i64> {
    match v? {
        toml::Value::String(s) => util::parse_time(s),
        toml::Value::Datetime(d) => util::parse_time(&d.to_string()),
        _ => None,
    }
}

impl Store {
    /// Merge one audits.toml-shaped table (`criteria`, `audits`, `trusted`, `wildcard-audits`).
    fn add_audits(&mut self, org: &str, doc: &toml::Value) -> (usize, usize) {
        let (mut na, mut nt) = (0, 0);
        if let Some(cr) = doc.get("criteria").and_then(|c| c.as_table()) {
            for (name, def) in cr {
                let imp: Vec<String> = crit_list(def.get("implies")).iter().map(|c| qual(org, c)).collect();
                if !imp.is_empty() {
                    self.implies.entry(qual(org, name)).or_default().extend(imp);
                }
            }
        }
        if let Some(a) = doc.get("audits").and_then(|a| a.as_table()) {
            for (krate, entries) in a {
                for e in entries.as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
                    let kind = if let Some(v) = e.get("violation").and_then(|v| v.as_str()) {
                        match VersionReq::parse(v) {
                            Ok(r) => Kind::Violation(r),
                            Err(_) => continue,
                        }
                    } else if let Some(d) = e.get("delta").and_then(|d| d.as_str()) {
                        let Some((a, b)) = d.split_once("->") else { continue };
                        match (ver(a), ver(b)) {
                            (Some(a), Some(b)) => Kind::Delta(a, b),
                            _ => continue,
                        }
                    } else if let Some(v) = e.get("version").and_then(|v| v.as_str()).and_then(ver) {
                        Kind::Full(v)
                    } else {
                        continue;
                    };
                    let who = match e.get("who") {
                        Some(toml::Value::String(s)) => s.clone(),
                        Some(toml::Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "),
                        _ => String::new(),
                    };
                    self.audits.entry(krate.clone()).or_default().push(Audit {
                        org: org.to_string(),
                        who,
                        criteria: crit_list(e.get("criteria")).iter().map(|c| qual(org, c)).collect(),
                        kind,
                        notes: e.get("notes").and_then(|n| n.as_str()).map(String::from),
                    });
                    na += 1;
                }
            }
        }
        for (key, wildcard) in [("trusted", false), ("wildcard-audits", true)] {
            if let Some(t) = doc.get(key).and_then(|a| a.as_table()) {
                for (krate, entries) in t {
                    for e in entries.as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
                        let Some(uid) = e.get("user-id").and_then(|u| u.as_integer()) else { continue };
                        self.trusted.entry(krate.clone()).or_default().push(Trust {
                            org: org.to_string(),
                            criteria: crit_list(e.get("criteria")).iter().map(|c| qual(org, c)).collect(),
                            user_id: uid.max(0) as u64,
                            start: date(e.get("start")),
                            end: date(e.get("end")),
                            wildcard,
                        });
                        nt += 1;
                    }
                }
            }
        }
        (na, nt)
    }

    /// Whether any of `have` implies `want` (built-in: safe-to-deploy implies safe-to-run).
    fn satisfies(&self, have: &[String], want: &str) -> bool {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut q: VecDeque<String> = have.iter().cloned().collect();
        while let Some(c) = q.pop_front() {
            if c == want {
                return true;
            }
            if !seen.insert(c.clone()) {
                continue;
            }
            if c == "safe-to-deploy" {
                q.push_back("safe-to-run".into());
            }
            if let Some(imp) = self.implies.get(&c) {
                q.extend(imp.iter().cloned());
            }
        }
        false
    }

    fn coverage(&self, name: &str, v: &Version, want: &str, publisher: Option<&Publisher>) -> Coverage {
        let audits = self.audits.get(name).map(|a| a.as_slice()).unwrap_or(&[]);
        let violations: Vec<Audit> = audits.iter().filter(|a| matches!(&a.kind, Kind::Violation(r) if r.matches(v))).cloned().collect();
        // Certification graph: full audits are roots, deltas are directed edges.
        let mut prev: HashMap<Version, (Option<Version>, String)> = HashMap::new();
        let mut q: VecDeque<Version> = VecDeque::new();
        for a in audits.iter().filter(|a| self.satisfies(&a.criteria, want)) {
            if let Kind::Full(x) = &a.kind {
                if !prev.contains_key(x) {
                    prev.insert(x.clone(), (None, a.org.clone()));
                    q.push_back(x.clone());
                }
            }
        }
        while let Some(x) = q.pop_front() {
            for a in audits.iter().filter(|a| self.satisfies(&a.criteria, want)) {
                if let Kind::Delta(from, to) = &a.kind {
                    if *from == x && !prev.contains_key(to) {
                        prev.insert(to.clone(), (Some(x.clone()), a.org.clone()));
                        q.push_back(to.clone());
                    }
                }
            }
        }
        let certified: BTreeSet<Version> = prev.keys().cloned().collect();
        let mut cov = Coverage { status: Status::Uncovered, orgs: vec![], path: vec![], violations, certified, hint: None };
        if !cov.violations.is_empty() {
            cov.status = Status::Violation;
            cov.orgs = cov.violations.iter().map(|a| a.org.clone()).collect::<BTreeSet<_>>().into_iter().collect();
            return cov;
        }
        if prev.contains_key(v) {
            let mut steps = Vec::new();
            let mut orgs = BTreeSet::new();
            let mut cur = v.clone();
            while let Some((p, org)) = prev.get(&cur) {
                orgs.insert(org.clone());
                match p {
                    Some(p) => {
                        steps.push(format!("{p} -> {cur} ({org})"));
                        cur = p.clone();
                    }
                    None => {
                        steps.push(format!("full {cur} ({org})"));
                        break;
                    }
                }
                if steps.len() > 500 {
                    break;
                }
            }
            steps.reverse();
            cov.status = if steps.len() == 1 { Status::Full } else { Status::Delta };
            cov.orgs = orgs.into_iter().collect();
            cov.path = steps;
            return cov;
        }
        if let Some(p) = publisher {
            for t in self.trusted.get(name).map(|t| t.as_slice()).unwrap_or(&[]) {
                // cargo-vet: start <= publish date < end (dates)
                let in_range = match p.when {
                    Some(w) => t.start.is_none_or(|s| w >= s) && t.end.is_none_or(|e| w < e),
                    None => false,
                };
                if !(t.user_id == p.user_id && in_range && self.satisfies(&t.criteria, want)) {
                    continue;
                }
                // `trusted` entries are never imported by cargo-vet (only wildcard audits are):
                // another organization's trust is a suggestion, not a certification
                if !t.wildcard && t.org != "local" {
                    if cov.hint.is_none() {
                        cov.hint = Some(format!(
                            "{} trusts publisher {}{} for {}; `cargo vet trust {name}{}` would adopt that trust",
                            t.org,
                            p.user_id,
                            p.login.as_deref().map(|l| format!(" ({l})")).unwrap_or_default(),
                            t.criteria.iter().map(|c| unqual(c)).collect::<Vec<_>>().join(", "),
                            p.login.as_deref().map(|l| format!(" {l}")).unwrap_or_default()
                        ));
                    }
                    continue;
                }
                {
                    cov.status = if t.wildcard { Status::Wildcard } else { Status::Trusted };
                    cov.orgs = vec![t.org.clone()];
                    cov.path = vec![format!(
                        "published by user {}{} which {} trusts for {}",
                        p.user_id,
                        p.login.as_deref().map(|l| format!(" ({l})")).unwrap_or_default(),
                        t.org,
                        t.criteria.iter().map(|c| unqual(c)).collect::<Vec<_>>().join(", ")
                    )];
                    return cov;
                }
            }
        }
        for (ev, crit) in self.exemptions.get(name).map(|e| e.as_slice()).unwrap_or(&[]) {
            if ev == v && self.satisfies(crit, want) {
                cov.status = Status::Exempted;
                cov.orgs = vec!["exemption".into()];
                cov.path = vec![format!("exempted in supply-chain/config.toml for {}", crit.iter().map(|c| unqual(c)).collect::<Vec<_>>().join(", "))];
                return cov;
            }
        }
        cov
    }
}

// ---------------------------------------------------------------- loading

#[derive(Default)]
struct Local {
    criteria: Option<String>,
    dev_criteria: Option<String>,
    imports: Vec<(String, Vec<String>)>,
}

fn load_local(ctx: &Ctx, store: &mut Store, rep: &mut Report) -> Local {
    let mut local = Local::default();
    let dir = ctx.project_root().join("supply-chain");
    if !dir.is_dir() {
        return local;
    }
    let read = |f: &str| -> Option<toml::Value> {
        let t = std::fs::read_to_string(dir.join(f)).ok()?;
        match toml::from_str(&t) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("warning: supply-chain/{f}: {e}");
                None
            }
        }
    };
    if let Some(doc) = read("audits.toml") {
        let (a, t) = store.add_audits("local", &doc);
        store.sources.push(Source { name: "local".into(), url: "supply-chain/audits.toml".into(), ok: true, audits: a, trusted: t, error: String::new() });
    }
    if let Some(doc) = read("imports.lock") {
        let (mut a, mut t) = (0, 0);
        if let Some(orgs) = doc.get("audits").and_then(|x| x.as_table()) {
            for (org, body) in orgs {
                let (x, y) = store.add_audits(org, body);
                a += x;
                t += y;
            }
        }
        if let Some(pubs) = doc.get("publisher").and_then(|x| x.as_table()) {
            for (krate, entries) in pubs {
                for e in entries.as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
                    let (Some(v), Some(uid)) = (e.get("version").and_then(|v| v.as_str()).and_then(ver), e.get("user-id").and_then(|u| u.as_integer())) else { continue };
                    store.publishers.insert(
                        (krate.clone(), v.to_string()),
                        Publisher { user_id: uid.max(0) as u64, login: e.get("user-login").and_then(|l| l.as_str()).map(String::from), when: date(e.get("when")) },
                    );
                }
            }
        }
        store.sources.push(Source { name: "imports.lock".into(), url: "supply-chain/imports.lock".into(), ok: true, audits: a, trusted: t, error: String::new() });
    }
    if let Some(cfg) = read("config.toml") {
        if let Some(pol) = cfg.get("policy").and_then(|p| p.as_table()) {
            let members: Vec<&str> = pol.keys().map(|k| k.as_str()).collect();
            for (_, p) in pol {
                if local.criteria.is_none() {
                    local.criteria = crit_list(p.get("criteria")).into_iter().next();
                }
                if local.dev_criteria.is_none() {
                    local.dev_criteria = crit_list(p.get("dev-criteria")).into_iter().next();
                }
            }
            if local.criteria.is_some() {
                rep.note(format!("policy from supply-chain/config.toml ({})", members.join(", ")));
            }
        }
        if let Some(ex) = cfg.get("exemptions").and_then(|e| e.as_table()) {
            for (krate, entries) in ex {
                for e in entries.as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
                    if let Some(v) = e.get("version").and_then(|v| v.as_str()).and_then(ver) {
                        store.exemptions.entry(krate.clone()).or_default().push((v, crit_list(e.get("criteria")).iter().map(|c| qual("local", c)).collect()));
                    }
                }
            }
        }
        if let Some(imp) = cfg.get("imports").and_then(|i| i.as_table()) {
            for (name, body) in imp {
                let urls = match body.get("url") {
                    Some(toml::Value::String(s)) => vec![s.clone()],
                    Some(toml::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                    _ => vec![],
                };
                if !urls.is_empty() {
                    local.imports.push((name.clone(), urls));
                }
            }
        }
    }
    local
}

/// Point raw.githubusercontent.com URLs at the configured mirror (SM_GITHUB_RAW_URL).
fn mirror(ctx: &Ctx, url: &str) -> String {
    match url.strip_prefix("https://raw.githubusercontent.com") {
        Some(rest) => format!("{}{rest}", ctx.endpoints.github_raw),
        None => url.to_string(),
    }
}

fn fetch_registry(ctx: &Ctx, only: &[String], project_imports: &[(String, Vec<String>)], store: &mut Store, rep: &mut Report) -> Result<()> {
    if only.iter().any(|o| o == "none") {
        return Ok(());
    }
    let reg_url = format!("{}{REGISTRY_PATH}", ctx.endpoints.github_raw);
    let mut sets: Vec<(String, Vec<String>)> = Vec::new();
    match ctx.http.get(&reg_url, Ttl::DAY) {
        Ok(r) if r.ok() => {
            let doc: toml::Value = toml::from_str(&r.text()).map_err(|e| Error::Parse(format!("cargo-vet registry.toml: {e}")))?;
            if let Some(reg) = doc.get("registry").and_then(|r| r.as_table()) {
                for (name, body) in reg {
                    let urls = match body.get("url") {
                        Some(toml::Value::String(s)) => vec![s.clone()],
                        Some(toml::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
                        _ => vec![],
                    };
                    sets.push((name.clone(), urls));
                }
            }
        }
        Ok(r) => rep.note(format!("cargo-vet registry {reg_url} returned HTTP {}; using project imports only", r.status)),
        Err(e) => {
            if project_imports.is_empty() && store.sources.is_empty() {
                return Err(e);
            }
            rep.note(format!("cargo-vet registry unavailable ({e}); using project imports only"));
        }
    }
    for (n, u) in project_imports {
        if !sets.iter().any(|(x, _)| x == n) {
            sets.push((n.clone(), u.clone()));
        }
    }
    if !only.is_empty() {
        for o in only {
            if !sets.iter().any(|(n, _)| n == o) {
                rep.note(format!("--import {o}: no such audit set in the cargo-vet registry (known: {})", sets.iter().map(|s| s.0.as_str()).collect::<Vec<_>>().join(", ")));
            }
        }
        sets.retain(|(n, _)| only.contains(n));
    }
    let urls: Vec<(String, String)> = sets.iter().flat_map(|(n, us)| us.iter().map(move |u| (n.clone(), u.clone()))).collect();
    let fetched = ctx.http.get_many(&urls.iter().map(|(_, u)| mirror(ctx, u)).collect::<Vec<_>>(), Ttl::DAY, 8);
    for ((name, url), r) in urls.into_iter().zip(fetched) {
        let mut src = Source { name: name.clone(), url: url.clone(), ok: false, audits: 0, trusted: 0, error: String::new() };
        match r {
            Ok(resp) if resp.ok() => match toml::from_str::<toml::Value>(&resp.text()) {
                Ok(doc) => {
                    let (a, t) = store.add_audits(&name, &doc);
                    src.ok = true;
                    src.audits = a;
                    src.trusted = t;
                }
                Err(e) => src.error = format!("invalid TOML: {}", e.to_string().lines().next().unwrap_or("")),
            },
            Ok(resp) => src.error = format!("HTTP {}", resp.status),
            Err(e) => src.error = e.to_string(),
        }
        store.sources.push(src);
    }
    Ok(())
}

fn publisher_from_api(ctx: &Ctx, name: &str, version: &str) -> Result<Option<Publisher>> {
    let vs = api::versions(ctx, name)?;
    Ok(vs.iter().find(|v| v["num"].as_str() == Some(version)).and_then(|v| {
        let id = v["published_by"]["id"].as_u64()?;
        Some(Publisher {
            user_id: id,
            login: v["published_by"]["login"].as_str().map(String::from),
            when: v["created_at"].as_str().and_then(util::parse_time),
        })
    }))
}

// ---------------------------------------------------------------- per crate

struct Check {
    krate: CrateRef,
    version: Version,
    want: String,
    dev_only: bool,
    cov: Coverage,
    weaker: Option<Coverage>,
    suggestions: Vec<Suggestion>,
    size_error: Option<String>,
}

#[derive(Debug, Clone)]
struct Suggestion {
    command: String,
    from: Option<String>,
    lines: usize,
    added: usize,
    removed: usize,
    files: usize,
}

impl Suggestion {
    fn size_label(&self) -> String {
        match self.from {
            Some(_) => format!("+{} -{} lines, {} file(s)", self.added, self.removed, self.files),
            None => format!("{} lines, {} file(s)", self.lines, self.files),
        }
    }
}

impl Check {
    fn findings(&self) -> Vec<Finding> {
        let c = &self.krate;
        let mut out = Vec::new();
        let k = |f: Finding| f.krate(&c.name, Some(&c.version));
        match self.cov.status {
            Status::Violation => {
                let d = self
                    .cov
                    .violations
                    .iter()
                    .map(|a| {
                        let r = match &a.kind {
                            Kind::Violation(r) => r.to_string(),
                            _ => String::new(),
                        };
                        format!("{}: {} marks {r} as violating {}{}", a.org, a.who, a.criteria.iter().map(|c| unqual(c)).collect::<Vec<_>>().join(", "), a.notes.as_deref().map(|n| format!(" — {n}")).unwrap_or_default())
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                out.push(
                    k(Finding::new(Severity::Critical, "vet/violation", format!("an imported cargo-vet audit marks {}@{} as a violation", c.name, c.version)))
                        .detail(d)
                        .fix("move to a version outside the violation range or replace the dependency"),
                );
            }
            Status::Uncovered => {
                if let Some(w) = &self.weaker {
                    out.push(
                        k(Finding::new(
                            Severity::Medium,
                            "vet/safe-to-run-only",
                            format!("certified only safe-to-run ({}), but {} is required", w.orgs.join(", "), self.want),
                        ))
                        .detail(w.path.join("\n"))
                        .fix(format!("audit it for {} yourself, or relax the policy if this crate never ships", self.want)),
                    );
                } else {
                    let mut f = k(Finding::new(
                        Severity::Medium,
                        "vet/uncovered",
                        format!("no imported audit certifies {}@{} for {}", c.name, c.version, self.want),
                    ));
                    if let Some(s) = self.suggestions.first() {
                        f = f.fix(format!("{} ({}) then `cargo vet certify`", s.command, s.size_label()));
                        if self.suggestions.len() > 1 {
                            f = f.detail(
                                self.suggestions.iter().map(|s| format!("{} — {}", s.command, s.size_label())).collect::<Vec<_>>().join("\n"),
                            );
                        }
                    } else {
                        f = f.fix(format!("cargo vet inspect {} {}", c.name, c.version));
                    }
                    if let Some(h) = &self.cov.hint {
                        let d = f.detail.clone().map(|d| format!("{d}\n")).unwrap_or_default();
                        f = f.detail(format!("{d}NOTE: {h}"));
                    }
                    if !c.via.is_empty() {
                        let d = f.detail.clone().map(|d| format!("{d}\n")).unwrap_or_default();
                        f = f.detail(format!("{d}via {}", c.via.join(" -> ")));
                    }
                    out.push(f);
                }
            }
            Status::Exempted => out.push(k(Finding::new(Severity::Info, "vet/exempted", "covered only by an exemption in supply-chain/config.toml"))),
            _ => {}
        }
        out
    }

    fn to_json(&self) -> Value {
        json!({
            "crate": self.krate.name, "version": self.krate.version, "criteria": self.want, "dev_only": self.dev_only,
            "status": self.cov.status.code(), "certified_by": self.cov.orgs, "path": self.cov.path,
            "safe_to_run_only": self.weaker.as_ref().map(|w| json!({"by": w.orgs, "path": w.path})),
            "certified_versions": self.cov.certified.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            "suggestions": self.suggestions.iter().map(|s| json!({"command": s.command, "from": s.from, "lines": s.lines, "added": s.added, "removed": s.removed, "files": s.files})).collect::<Vec<_>>(),
            "size_error": self.size_error,
            "trust_hint": self.cov.hint,
        })
    }
}

/// The cheapest audits for an uncovered crate: full inspect vs deltas from the nearest certified versions.
fn suggest(ctx: &Ctx, ch: &Check) -> Result<Vec<Suggestion>> {
    let c = &ch.krate;
    let max = 256 * 1024 * 1024;
    let target = su::crate_files(&download::crate_bytes(ctx, &c.name, &c.version)?, max)?;
    let text_lines = |b: &[u8]| if su::is_binary(b) { 0 } else { String::from_utf8_lossy(b).lines().count() };
    let total: usize = target.iter().map(|(_, b)| text_lines(b)).sum();
    let mut out = vec![Suggestion {
        command: format!("cargo vet inspect {} {}", c.name, c.version),
        from: None,
        lines: total,
        added: total,
        removed: 0,
        files: target.len(),
    }];
    // Certified versions for the criteria that are published on crates.io, nearest first.
    let published: BTreeSet<String> = index::versions(ctx, &c.name).map(|vs| vs.iter().map(|v| v.vers.clone()).collect()).unwrap_or_default();
    let mut cands: Vec<&Version> = ch.cov.certified.iter().filter(|v| published.contains(&v.to_string())).collect();
    let dist = |v: &Version| -> (u64, u64, u64) {
        let a = &ch.version;
        (a.major.abs_diff(v.major), a.minor.abs_diff(v.minor), a.patch.abs_diff(v.patch))
    };
    cands.sort_by_key(|v| (dist(v), *v > &ch.version));
    for from in cands.into_iter().take(3) {
        let old = match download::crate_bytes(ctx, &c.name, &from.to_string()).and_then(|b| su::crate_files(&b, max)) {
            Ok(o) => o,
            Err(_) => continue,
        };
        let oldm: HashMap<&str, &[u8]> = old.iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect();
        let newm: HashMap<&str, &[u8]> = target.iter().map(|(p, b)| (p.as_str(), b.as_slice())).collect();
        let paths: BTreeSet<&str> = oldm.keys().chain(newm.keys()).copied().collect();
        let (mut added, mut removed, mut files) = (0, 0, 0);
        for p in paths {
            if matches!(p, ".cargo_vcs_info.json" | ".cargo-ok") {
                continue;
            }
            let (a, b) = (oldm.get(p).copied().unwrap_or(b""), newm.get(p).copied().unwrap_or(b""));
            if a == b {
                continue;
            }
            files += 1;
            if su::is_binary(a) || su::is_binary(b) {
                continue;
            }
            let (x, y) = su::line_delta(&String::from_utf8_lossy(a), &String::from_utf8_lossy(b));
            added += x;
            removed += y;
        }
        out.push(Suggestion {
            command: format!("cargo vet diff {} {from} {}", c.name, c.version),
            from: Some(from.to_string()),
            lines: added + removed,
            added,
            removed,
            files,
        });
    }
    out.sort_by_key(|s| (s.lines, s.from.is_none()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        store_as("org")
    }

    fn store_as(org: &str) -> Store {
        let doc: toml::Value = toml::from_str(
            r#"
[criteria.crypto-reviewed]
description = "x"
implies = "safe-to-deploy"

[[audits.a]]
who = "A"
criteria = "safe-to-deploy"
version = "1.0.0"

[[audits.a]]
who = "A"
criteria = ["safe-to-deploy"]
delta = "1.0.0 -> 1.1.0"

[[audits.a]]
who = "A"
criteria = "safe-to-run"
delta = "1.1.0 -> 1.2.0"

[[audits.b]]
who = "B"
criteria = "crypto-reviewed"
version = "2.0.0"

[[audits.c]]
who = "C"
criteria = "safe-to-deploy"
violation = ">=0.3, <0.3.5"

[[trusted.d]]
criteria = "safe-to-deploy"
user-id = 7
start = "2020-01-01"
end = "2021-01-01"
"#,
        )
        .unwrap();
        let mut s = Store::default();
        s.add_audits(org, &doc);
        s
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn full_delta_and_criteria() {
        let s = store();
        assert_eq!(s.coverage("a", &v("1.0.0"), "safe-to-deploy", None).status, Status::Full);
        let d = s.coverage("a", &v("1.1.0"), "safe-to-deploy", None);
        assert_eq!(d.status, Status::Delta);
        assert_eq!(d.path, vec!["full 1.0.0 (org)", "1.0.0 -> 1.1.0 (org)"]);
        assert_eq!(s.coverage("a", &v("1.2.0"), "safe-to-deploy", None).status, Status::Uncovered);
        assert_eq!(s.coverage("a", &v("1.2.0"), "safe-to-run", None).status, Status::Delta);
        assert_eq!(s.coverage("b", &v("2.0.0"), "safe-to-run", None).status, Status::Full, "custom criteria implies");
        assert_eq!(s.coverage("c", &v("0.3.1"), "safe-to-deploy", None).status, Status::Violation);
        assert_eq!(s.coverage("c", &v("0.3.5"), "safe-to-deploy", None).status, Status::Uncovered);
    }

    #[test]
    fn trusted_publishers_and_dates() {
        let s = store_as("local");
        let p = |when: &str, id| Publisher { user_id: id, login: None, when: util::parse_time(when) };
        assert_eq!(s.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p("2020-06-01", 7))).status, Status::Trusted);
        assert_eq!(s.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p("2022-06-01", 7))).status, Status::Uncovered);
        assert_eq!(s.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p("2020-06-01", 8))).status, Status::Uncovered);
        // cargo-vet: start <= date < end
        assert_eq!(s.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p("2021-01-01T10:00:00Z", 7))).status, Status::Uncovered);
        assert_eq!(s.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p("2020-12-31T23:00:00Z", 7))).status, Status::Trusted);
    }

    #[test]
    fn imported_trust_entries_only_hint_and_criteria_are_namespaced() {
        let doc: toml::Value = toml::from_str(
            r#"
[criteria.reviewed]
description = "x"
implies = "safe-to-deploy"

[[trusted.d]]
criteria = "safe-to-deploy"
user-id = 7
start = "2020-01-01"
end = "2021-01-01"

[[wildcard-audits.w]]
criteria = "safe-to-deploy"
user-id = 7
start = "2020-01-01"
end = "2021-01-01"
"#,
        )
        .unwrap();
        // another org uses the same custom criteria name for something weaker
        let other: toml::Value = toml::from_str("[[audits.e]]\nwho = \"x\"\ncriteria = \"reviewed\"\nversion = \"1.0.0\"\n").unwrap();
        let mut s = Store::default();
        s.add_audits("orga", &doc);
        s.add_audits("orgb", &other);
        let p = Publisher { user_id: 7, login: Some("al".into()), when: util::parse_time("2020-06-01") };
        let c = s.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p));
        assert_eq!(c.status, Status::Uncovered, "cargo-vet never imports `trusted` entries");
        assert!(c.hint.as_deref().unwrap().contains("orga trusts publisher 7 (al)"), "{:?}", c.hint);
        assert_eq!(s.coverage("w", &v("1.0.0"), "safe-to-deploy", Some(&p)).status, Status::Wildcard);
        assert_eq!(s.coverage("e", &v("1.0.0"), "safe-to-run", None).status, Status::Uncovered, "orgb's `reviewed` is not orga's");
        let mut local = Store::default();
        local.add_audits("local", &doc);
        assert_eq!(local.coverage("d", &v("1.0.0"), "safe-to-deploy", Some(&p)).status, Status::Trusted);
    }
}
