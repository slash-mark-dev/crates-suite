//! Publisher Provenance: whether each release came from crates.io Trusted Publishing (OIDC from CI) or
//! a personal API token, and who published it.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata};
use crate::registry::{CrateSpec, api};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::{Group, Tool};
use crate::util;

pub struct TrustPub;

const OPTS: &[Opt] = &[
    Opt::value("since", "DAYS", "Only flag releases published in the last DAYS days (default 365; 0 = whole history)"),
    Opt::value("history", "N", "Releases listed per crate in the history table (default 8 for named crates, 0 for a project)"),
    Opt::value("new-account-days", "N", "A publishing account younger than N days at release time is new (default 60)"),
    Opt::value("only", "A,B", "Only check these dependencies"),
    Opt::flag("all", "Project mode: include transitive dependencies (default: direct dependencies only)"),
];

impl Tool for TrustPub {
    fn name(&self) -> &'static str {
        "trustpub"
    }
    fn title(&self) -> &'static str {
        "Publisher Provenance"
    }
    fn group(&self) -> Group {
        Group::Ecosystem
    }
    fn summary(&self) -> &'static str {
        "Whether each release came from Trusted Publishing or a personal token, and who published it"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Shows how every release of a crate reached crates.io. Data: crates.io `GET /api/v1/crates/{name}`
(one request per crate at the crates.io limit of one per second; falls back to the paginated
`/versions` endpoint when versions are not embedded). For each version crates.io records either
`trustpub_data` ({provider, repository, run_id, sha}: published by a CI workflow through Trusted
Publishing, i.e. a short-lived token minted from the CI provider's OIDC identity, with no long-lived
secret) or `published_by` (the crates.io user whose personal API token uploaded it, with that
account's creation date). Releases older than crates.io's publisher records have neither and are
shown as unknown. The crate record's `trustpub_only` says whether token publishing is disabled.

Releases are walked in publication order and these changes are flagged (only for releases in the
last --since days, default 365):
  high   trustpub/regression          a token-published release after the crate had moved to
                                      Trusted Publishing (a stolen token is the classic way to
                                      publish a malicious release outside CI)
  high   trustpub/new-account         published by an account created less than
                                      --new-account-days (default 60) days before the release
  medium trustpub/first-time-publisher published by a user who never published this crate before
  medium trustpub/repository-changed  Trusted Publishing from a different repository than before
  low    trustpub/publisher-changed   published by a user other than the publishers of the
                                      previous three token releases (returning maintainer)
  info   trustpub/token-still-allowed the latest release used Trusted Publishing but token
                                      publishing is still enabled (trustpub_only is off)

Crates: named on the command line (NAME@VERSION also shows how that version was published), or the
project's direct crates.io dependencies at their locked versions (--all for transitive ones, --only
to pick some). A finding is a lead: maintainers do rotate and backport releases by hand; check the
release against the repository (sm-crates srcverify) and the crate's owners."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates trustpub",
            "sm-crates trustpub cc pyo3 zerocopy",
            "sm-crates trustpub tokio@1.40.0 --history 15",
            "sm-crates trustpub --all --since 90 --json",
            "sm-crates trustpub --only serde,libc --fail-on medium",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crates.io API); cargo for local projects"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let since: i64 = args.parse_or("since", 365i64)?;
        let new_days: i64 = args.parse_or("new-account-days", 60i64)?;
        let (subject, targets, project_mode) = select(ctx, args)?;
        let history: usize = args.parse_or("history", if project_mode { 0 } else { 8 })?;
        let now = util::unix_now();
        let cutoff = if since <= 0 { i64::MIN } else { now - since * 86_400 };
        let mut rep = Report::new("trustpub", subject);
        let mut overview = Table::new(
            "Publishing",
            &["Crate", "Version", "Published", "Via", "Latest release via", "Trusted (recent)", "Publishers", "Token publishing"],
        );
        let mut hist = Table::new("Release history (newest first)", &["Crate", "Version", "Date", "Method", "Publisher", "CI run / account created"]);
        let mut data = Vec::new();
        let mut failed = Vec::new();
        let mut last_err = None;
        let (mut n_trusted_latest, mut n_token_latest) = (0usize, 0usize);
        for (name, version) in &targets {
            let info = match fetch(ctx, name) {
                Ok(i) => i,
                Err(e) => {
                    failed.push(format!("{name}: {e}"));
                    last_err = Some(e);
                    continue;
                }
            };
            if info.releases.is_empty() {
                failed.push(format!("{name}: crates.io returned no versions"));
                continue;
            }
            let events = analyze(&info, cutoff, new_days);
            let selected = version.as_deref().and_then(|v| info.releases.iter().find(|r| r.num == v));
            let latest = info.releases.iter().rev().find(|r| !r.yanked).unwrap_or(info.releases.last().unwrap_or(&info.releases[0]));
            match latest.method {
                Method::Trusted => n_trusted_latest += 1,
                Method::Token => n_token_latest += 1,
                Method::Unknown => {}
            }
            let recent: Vec<&Release> = info.releases.iter().filter(|r| r.created >= cutoff).collect();
            let recent_trusted = recent.iter().filter(|r| r.method == Method::Trusted).count();
            let publishers: BTreeSet<String> = info.releases.iter().filter(|r| r.created >= cutoff).map(|r| r.publisher_label()).collect();
            let shown = selected.unwrap_or(latest);
            overview.row([
                name.clone(),
                shown.num.clone(),
                util::format_date(shown.created),
                shown.via(),
                if selected.is_some_and(|s| s.num != latest.num) { format!("{} ({})", latest.via(), latest.num) } else { latest.via() },
                format!("{recent_trusted}/{}", recent.len()),
                publishers.len().to_string(),
                match info.trustpub_only {
                    Some(true) => "disabled".to_string(),
                    Some(false) => "allowed".to_string(),
                    None => "?".to_string(),
                },
            ]);
            if version.is_some() && selected.is_none() {
                rep.note(format!("{name}@{}: version not found in crates.io's release list", version.as_deref().unwrap_or("")));
            }
            for r in info.releases.iter().rev().take(history) {
                hist.row([
                    name.clone(),
                    if r.yanked { format!("{} (yanked)", r.num) } else { r.num.clone() },
                    util::format_date(r.created),
                    r.method.as_str().to_string(),
                    r.publisher_label(),
                    match r.method {
                        Method::Trusted => r.run_id.clone().map(|id| format!("run {id}")).unwrap_or_default(),
                        Method::Token => r.account_created.map(util::format_date).unwrap_or_default(),
                        Method::Unknown => String::new(),
                    },
                ]);
            }
            for e in &events {
                let mut f = Finding::new(e.severity, e.code, e.message.clone()).krate(name, Some(e.version.clone())).detail(e.detail.clone()).fix(e.fix.clone());
                if selected.is_some_and(|s| s.num == e.version) {
                    f.detail = Some(format!("{} (this is the version you use)", e.detail));
                }
                rep.finding(f);
            }
            if latest.method == Method::Trusted && info.trustpub_only == Some(false) {
                rep.finding(
                    Finding::new(
                        Severity::Info,
                        "trustpub/token-still-allowed",
                        format!("latest release {} used Trusted Publishing, but crates.io still accepts personal API tokens for {name}", latest.num),
                    )
                    .krate(name, Some(latest.num.clone()))
                    .detail("A leaked owner token can still publish a release that bypasses CI")
                    .fix("Owners can enable \"Trusted Publishing only\" in the crate's settings on crates.io"),
                );
            }
            data.push(json!({
                "crate": name,
                "version": shown.num,
                "selected": selected.map(|r| r.to_json()),
                "trustpub_only": info.trustpub_only,
                "latest": latest.to_json(),
                "releases": info.releases.iter().rev().map(|r| r.to_json()).collect::<Vec<_>>(),
                "recent_releases": recent.len(),
                "recent_trusted": recent_trusted,
                "publishers": publishers,
                "events": events.iter().map(|e| json!({"code": e.code, "severity": e.severity, "version": e.version, "date": util::format_date(e.date), "message": e.message})).collect::<Vec<_>>(),
            }));
        }
        if data.is_empty() {
            return Err(last_err.unwrap_or_else(|| Error::Network("no release data could be fetched from crates.io".into())));
        }
        for f in &failed {
            rep.note(format!("skipped {f}"));
        }
        let flagged: BTreeSet<&str> = rep.findings.iter().filter(|f| f.severity >= Severity::Medium).filter_map(|f| f.krate.as_deref()).collect();
        rep.summary(format!(
            "{} crate(s): latest release via Trusted Publishing for {n_trusted_latest}, via a personal token for {n_token_latest}; {} with publisher changes worth a look",
            data.len(),
            flagged.len()
        ));
        rep.table(overview);
        rep.table(hist);
        rep.note(if since <= 0 {
            "Changes are flagged over the whole release history.".to_string()
        } else {
            format!("Changes are flagged for releases in the last {since} days (--since 0 for the whole history); older releases count as history.")
        });
        rep.note("Trusted (recent) = releases published through Trusted Publishing / all releases in that window. Releases from before crates.io recorded publishers show as unknown.");
        rep.data = json!({"crates": data, "config": {"since_days": since, "new_account_days": new_days}});
        Ok(rep)
    }
}

/// Crates named on the command line, or the project's crates.io dependencies with locked versions.
fn select(ctx: &Ctx, args: &Args) -> Result<(String, Vec<(String, Option<String>)>, bool)> {
    if !args.positional.is_empty() {
        let mut v: Vec<(String, Option<String>)> = Vec::new();
        for p in &args.positional {
            let s = CrateSpec::parse(p)?;
            let ver = match s.version.as_deref() {
                None | Some("latest") => None,
                Some(_) => Some(s.resolve(ctx)?.vers),
            };
            if !v.iter().any(|(n, x)| *n == s.name && *x == ver) {
                v.push((s.name, ver));
            }
        }
        let label = v.iter().map(|(n, x)| x.as_ref().map(|x| format!("{n}@{x}")).unwrap_or_else(|| n.clone())).collect::<Vec<_>>().join(", ");
        return Ok((label, v, false));
    }
    let meta = Metadata::load(ctx, &MetaOpts::default())?;
    let mut set: BTreeSet<(String, String)> = BTreeSet::new();
    if args.flag("all") {
        for p in meta.registry_packages(false) {
            set.insert((p.name.clone(), p.version.clone()));
        }
    } else {
        let by_id = meta.by_id();
        for m in meta.members() {
            for d in meta.node(&m.id).map(|n| n.deps.clone()).unwrap_or_default() {
                if let Some(p) = by_id.get(d.pkg.as_str()).filter(|p| p.is_crates_io()) {
                    set.insert((p.name.clone(), p.version.clone()));
                }
            }
        }
    }
    let only: Vec<String> = args.list("only").iter().map(|s| util::normalize_crate_name(s)).collect();
    let v: Vec<(String, Option<String>)> =
        set.into_iter().filter(|(n, _)| only.is_empty() || only.contains(&util::normalize_crate_name(n))).map(|(n, v)| (n, Some(v))).collect();
    if v.is_empty() {
        return Err(Error::Usage("no crates.io dependencies to check (name crates: CRATE...)".into()));
    }
    let label = meta.members().iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
    Ok((format!("project {label} ({} dependencies)", v.len()), v, true))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Trusted,
    Token,
    Unknown,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Trusted => "trusted",
            Method::Token => "token",
            Method::Unknown => "unknown",
        }
    }
}

/// One published version and how it was published.
#[derive(Debug, Clone)]
pub struct Release {
    pub num: String,
    pub created: i64,
    pub yanked: bool,
    pub method: Method,
    /// crates.io login (token releases).
    pub user: Option<String>,
    /// Creation time of the publishing account (token releases).
    pub account_created: Option<i64>,
    /// CI provider (`github`, `gitlab`, ...) for trusted releases.
    pub provider: Option<String>,
    /// `owner/repo` (GitHub) or project path (GitLab) for trusted releases.
    pub repository: Option<String>,
    pub run_id: Option<String>,
    pub sha: Option<String>,
}

impl Release {
    pub fn from_json(v: &Value) -> Option<Release> {
        let num = v["num"].as_str()?.to_string();
        let created = v["created_at"].as_str().and_then(util::parse_time)?;
        let tp = &v["trustpub_data"];
        let pb = &v["published_by"];
        let s = |x: &Value| match x {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        };
        let mut r = Release {
            num,
            created,
            yanked: v["yanked"].as_bool().unwrap_or(false),
            method: Method::Unknown,
            user: None,
            account_created: None,
            provider: None,
            repository: None,
            run_id: None,
            sha: None,
        };
        if tp.is_object() {
            r.method = Method::Trusted;
            r.provider = s(&tp["provider"]).or(Some("ci".into()));
            r.repository = s(&tp["repository"]).or_else(|| s(&tp["project_path"])).or_else(|| s(&tp["namespace"]));
            r.run_id = s(&tp["run_id"]).or_else(|| s(&tp["job_id"])).or_else(|| s(&tp["pipeline_id"]));
            r.sha = s(&tp["sha"]);
        } else if let Some(login) = pb["login"].as_str() {
            r.method = Method::Token;
            r.user = Some(login.to_string());
            r.account_created = pb["created_at"].as_str().and_then(util::parse_time);
        }
        Some(r)
    }

    /// Who published it: `github:owner/repo` or the crates.io login.
    pub fn publisher_label(&self) -> String {
        match self.method {
            Method::Trusted => format!("{}:{}", self.provider.as_deref().unwrap_or("ci"), self.repository.as_deref().unwrap_or("?")),
            Method::Token => self.user.clone().unwrap_or_else(|| "?".into()),
            Method::Unknown => "unknown".into(),
        }
    }

    pub fn via(&self) -> String {
        match self.method {
            Method::Trusted => format!("trusted ({})", self.publisher_label()),
            Method::Token => format!("token ({})", self.publisher_label()),
            Method::Unknown => "unknown".into(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "version": self.num,
            "published_at": util::format_unix(self.created),
            "yanked": self.yanked,
            "method": self.method.as_str(),
            "publisher": self.publisher_label(),
            "user": self.user,
            "account_created_at": self.account_created.map(util::format_unix),
            "provider": self.provider,
            "repository": self.repository,
            "run_id": self.run_id,
            "sha": self.sha,
        })
    }
}

/// Release history of one crate.
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// Oldest first.
    pub releases: Vec<Release>,
    pub trustpub_only: Option<bool>,
}

pub fn parse_crate(k: &Value, versions: Option<&[Value]>) -> CrateInfo {
    let embedded: Vec<Value> = k["versions"].as_array().cloned().unwrap_or_default();
    let list: &[Value] = versions.unwrap_or(&embedded);
    let mut releases: Vec<Release> = list.iter().filter_map(Release::from_json).collect();
    releases.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| util::parse_version(&a.num).cmp(&util::parse_version(&b.num))));
    CrateInfo { releases, trustpub_only: k["crate"]["trustpub_only"].as_bool() }
}

fn fetch(ctx: &Ctx, name: &str) -> Result<CrateInfo> {
    let k = api::krate(ctx, name)?;
    let embedded = k["versions"].as_array().map(|v| v.len()).unwrap_or(0);
    let expected = k["crate"]["num_versions"].as_u64().map(|n| n as usize);
    // embedded version objects are complete for most crates; page through /versions otherwise
    let complete = embedded > 0 && expected.is_none_or(|n| embedded >= n) && k["versions"][0].is_object();
    if complete {
        return Ok(parse_crate(&k, None));
    }
    let vs = api::versions(ctx, name)?;
    Ok(parse_crate(&k, Some(&vs)))
}

/// One flagged change in a crate's publishing history.
#[derive(Debug, Clone)]
pub struct Event {
    pub code: &'static str,
    pub severity: Severity,
    pub version: String,
    pub date: i64,
    pub message: String,
    pub detail: String,
    pub fix: String,
}

/// Walk the releases in publication order and flag publisher changes for releases at or after `cutoff`.
pub fn analyze(info: &CrateInfo, cutoff: i64, new_account_days: i64) -> Vec<Event> {
    let mut out = Vec::new();
    let mut users: BTreeMap<String, usize> = BTreeMap::new();
    let mut recent_tokens: Vec<String> = Vec::new();
    let mut repos: BTreeSet<String> = BTreeSet::new();
    let mut prev_known: Option<&Release> = None;
    let mut trusted_seen: Option<&Release> = None;
    for (i, r) in info.releases.iter().enumerate() {
        let flag = r.created >= cutoff && i > 0;
        let date = util::format_date(r.created);
        match r.method {
            Method::Token => {
                let user = r.user.clone().unwrap_or_default();
                if flag {
                    if let (Some(p), Some(t)) = (prev_known, trusted_seen) {
                        if p.method == Method::Trusted {
                            let later_tokens = info.releases[i + 1..].iter().filter(|x| x.method == Method::Token).count();
                            out.push(Event {
                                code: "trustpub/regression",
                                severity: Severity::High,
                                version: r.num.clone(),
                                date: r.created,
                                message: format!(
                                    "{} was published with {user}'s personal API token on {date}, after {} had moved to Trusted Publishing ({})",
                                    r.num,
                                    p.num,
                                    p.publisher_label()
                                ),
                                detail: format!(
                                    "previous release {} came from {}; Trusted Publishing first used in {}; {later_tokens} later token release(s){}",
                                    p.num,
                                    p.publisher_label(),
                                    t.num,
                                    if info.trustpub_only == Some(true) { "; token publishing is now disabled for this crate" } else { "" }
                                ),
                                fix: format!("Confirm with the maintainers that {} was a deliberate manual release, and compare it with the repository (sm-crates srcverify)", r.num),
                            });
                        }
                    }
                    if let Some(ac) = r.account_created {
                        let age = (r.created - ac).div_euclid(86_400);
                        if (0..new_account_days).contains(&age) {
                            out.push(Event {
                                code: "trustpub/new-account",
                                severity: Severity::High,
                                version: r.num.clone(),
                                date: r.created,
                                message: format!("{} was published by account {user}, created only {age} day(s) earlier ({})", r.num, util::format_date(ac)),
                                detail: "Freshly created accounts publishing releases of established crates are typical of account takeover and hand-over attacks".into(),
                                fix: format!("Check who {user} is and how they became an owner (crates.io owners page, repository history)"),
                            });
                        }
                    }
                    if !users.contains_key(&user) && prev_known.is_some() {
                        let before: Vec<String> = users.keys().cloned().collect();
                        out.push(Event {
                            code: "trustpub/first-time-publisher",
                            severity: Severity::Medium,
                            version: r.num.clone(),
                            date: r.created,
                            message: format!("{} was published by {user}, who had never published {} before", r.num, if before.is_empty() { "a release of this crate with a token" } else { "this crate" }),
                            detail: if before.is_empty() {
                                format!("earlier releases came from {}", prev_known.map(|p| p.publisher_label()).unwrap_or_else(|| "unknown publishers".into()))
                            } else {
                                format!("earlier token publishers: {}", before.join(", "))
                            },
                            fix: format!("Verify that {user} is a legitimate maintainer (repository commits, release notes) before upgrading to {}", r.num),
                        });
                    } else if !recent_tokens.is_empty() && !recent_tokens.contains(&user) {
                        out.push(Event {
                            code: "trustpub/publisher-changed",
                            severity: Severity::Low,
                            version: r.num.clone(),
                            date: r.created,
                            message: format!("{} was published by {user}, not by the publishers of the previous releases ({})", r.num, recent_tokens.join(", ")),
                            detail: format!("{user} published {} earlier release(s) of this crate", users.get(&user).copied().unwrap_or(0)),
                            fix: "Usually a maintainer rotation; confirm in the repository if the release is unexpected".into(),
                        });
                    }
                }
                *users.entry(user.clone()).or_insert(0) += 1;
                recent_tokens.retain(|u| *u != user);
                recent_tokens.insert(0, user);
                recent_tokens.truncate(3);
                prev_known = Some(r);
            }
            Method::Trusted => {
                let repo = r.publisher_label();
                if flag && !repos.is_empty() && !repos.contains(&repo) {
                    out.push(Event {
                        code: "trustpub/repository-changed",
                        severity: Severity::Medium,
                        version: r.num.clone(),
                        date: r.created,
                        message: format!("{} was published by Trusted Publishing from {repo}, a repository not used for earlier releases", r.num),
                        detail: format!("earlier trusted releases came from {}", repos.iter().cloned().collect::<Vec<_>>().join(", ")),
                        fix: "Check that the repository move is genuine (crate homepage/repository field, announcement)".into(),
                    });
                }
                repos.insert(repo);
                trusted_seen.get_or_insert(r);
                prev_known = Some(r);
            }
            Method::Unknown => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(num: &str, date: &str, user: &str, acct: &str) -> Value {
        json!({"num": num, "created_at": format!("{date}T10:00:00Z"), "yanked": false, "trustpub_data": null,
               "published_by": {"login": user, "created_at": format!("{acct}T00:00:00Z")}})
    }
    fn tp(num: &str, date: &str, repo: &str) -> Value {
        json!({"num": num, "created_at": format!("{date}T10:00:00Z"), "yanked": false, "published_by": null,
               "trustpub_data": {"provider": "github", "repository": repo, "run_id": "1", "sha": "abc"}})
    }

    fn codes(vs: Vec<Value>) -> Vec<(&'static str, String)> {
        let info = parse_crate(&json!({"crate": {"trustpub_only": false}, "versions": vs}), None);
        analyze(&info, i64::MIN, 60).into_iter().map(|e| (e.code, e.version)).collect()
    }

    #[test]
    fn flags_regression_new_user_and_repo_change() {
        let got = codes(vec![
            tok("1.0.0", "2023-01-01", "alice", "2015-01-01"),
            tok("1.1.0", "2023-06-01", "bob", "2016-01-01"),
            tok("1.2.0", "2023-07-01", "alice", "2015-01-01"),
            tp("1.3.0", "2024-01-01", "acme/x"),
            tp("1.4.0", "2024-02-01", "evil/x"),
            tok("1.4.1", "2024-03-01", "mallory", "2024-02-20"),
        ]);
        assert_eq!(
            got,
            [
                ("trustpub/first-time-publisher", "1.1.0".to_string()),
                ("trustpub/repository-changed", "1.4.0".to_string()),
                ("trustpub/regression", "1.4.1".to_string()),
                ("trustpub/new-account", "1.4.1".to_string()),
                ("trustpub/first-time-publisher", "1.4.1".to_string()),
            ]
        );
    }

    #[test]
    fn rotation_and_order() {
        // API order is semver-descending; analysis uses publication time
        let got = codes(vec![
            tok("2.0.0", "2024-05-01", "a", "2010-01-01"),
            tok("1.0.0", "2024-01-01", "a", "2010-01-01"),
            json!({"num": "0.1.0", "created_at": "2015-01-01T00:00:00Z", "published_by": null, "trustpub_data": null}),
            tok("1.0.1", "2024-06-01", "b", "2010-01-01"),
            tok("1.0.2", "2024-07-01", "a", "2010-01-01"),
            tok("1.0.3", "2024-08-01", "c", "2010-01-01"),
            tok("1.0.4", "2024-09-01", "d", "2010-01-01"),
            tok("1.0.5", "2024-10-01", "e", "2010-01-01"),
            tok("1.0.6", "2024-11-01", "a", "2010-01-01"),
        ]);
        let pc: Vec<&str> = got.iter().filter(|g| g.0 == "trustpub/publisher-changed").map(|g| g.1.as_str()).collect();
        assert_eq!(pc, ["1.0.6"], "{got:?}");
        // b, c, d, e; the first recorded publisher after unknown history is not "new"
        assert_eq!(got.iter().filter(|g| g.0 == "trustpub/first-time-publisher").count(), 4, "{got:?}");
    }
}
