//! Published-vs-Repo Verifier: Diff the published .crate against the exact git commit it claims to come from.
//!
//! `cargo publish` records the commit it packaged in `.cargo_vcs_info.json`.
//! Nothing on crates.io checks that the uploaded files really come from that
//! commit, so a compromised publisher token or a dirty working tree can ship
//! code that is in no repository. This tool fetches the recorded commit with
//! git and compares every file byte for byte.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::common::{self, CrateRef, Select};
use crate::tools::supplychain_util::{self as su, git, git_error};
use crate::tools::unsafe_hotspots::par_map;
use crate::tools::{Group, Tool};
use crate::util;

pub struct SrcVerify;

const OPTS: &[Opt] = &[
    Opt::value("only", "A,B", "Only verify these dependencies (comma-separated names)"),
    Opt::value("limit", "N", "Verify at most N project dependencies (default 50; 0 = all)"),
    Opt::value("timeout", "SECS", "Time limit for each git fetch (default 300)"),
    Opt::flag("no-tags", "Skip the release-tag check (`git ls-remote --tags`)"),
];

impl Tool for SrcVerify {
    fn name(&self) -> &'static str {
        "srcverify"
    }
    fn title(&self) -> &'static str {
        "Published-vs-Repo Verifier"
    }
    fn group(&self) -> Group {
        Group::SupplyChain
    }
    fn summary(&self) -> &'static str {
        "Diff the published .crate against the exact git commit it claims to come from"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Proves (or disproves) that a published .crate matches its git repository. For each crate (named on
the command line, or the project's crates.io dependencies, at most --limit) the verified .crate is
unpacked and `.cargo_vcs_info.json` is read for the commit (git.sha1), the package directory in the
repo (path_in_vcs) and the dirty flag. The repository URL comes from Cargo.toml.orig / Cargo.toml
(`package.repository`; GitHub, GitLab, Codeberg, sr.ht and other git hosts; /tree/... suffixes are
stripped). The exact commit is fetched with the git CLI (`git fetch --depth 1 <url> <sha>`, falling
back to a full fetch) into the cache, keyed by repo and sha, and every file in the crate is compared
byte for byte with <repo>/<path_in_vcs>/<file>. Git submodules are fetched at their recorded commit.
Files cargo generates or rewrites are skipped (Cargo.toml, Cargo.lock, .cargo_vcs_info.json,
.cargo-ok); Cargo.toml.orig must equal the repo's Cargo.toml; README/license files that
cargo copies from outside the package (readme = \"../README.md\") are compared with their source.

Findings: Rust source in the crate but not in the repo (critical), other crate-only files and
byte-different files (high, with a diff excerpt), commit not fetchable from the repo, e.g. force-pushed
away or never pushed (high), crate published from a dirty tree, no .cargo_vcs_info.json (published with
--allow-dirty or by an old cargo), no repository URL, unreachable repository, a release tag (v1.2.3,
name-v1.2.3, ...) that points at a different commit (medium), line-ending-only differences (low). Files
in the repo but excluded from the crate are normal and only counted.

Limits: needs git and network access to the repository host; repositories that require
authentication are reported as unreachable. A matching commit proves the crate came from that commit,
not that the commit itself was reviewed."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates srcverify itoa@1.0.11",
            "sm-crates srcverify cfg-if@1.0.0 hex@0.4.3 --json",
            "sm-crates srcverify --limit 10",
            "sm-crates srcverify libgit2-sys@0.17.0+1.8.1",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crate downloads, git access to the repository hosts), git"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        su::require_git()?;
        let limit: usize = args.parse_or("limit", 50)?;
        let timeout = Duration::from_secs(args.parse_or("timeout", 300u64)?.max(10));
        let (subject, crates, _) = common::select(ctx, args, Select::default())?;
        let mut crates: Vec<CrateRef> = common::only(args, crates).into_iter().filter(|c| c.is_registry()).collect();
        let mut rep = Report::new("srcverify", subject);
        if args.positional.is_empty() && limit > 0 && crates.len() > limit {
            rep.note(format!(
                "{} of {} dependencies verified (--limit {limit}); pass --limit 0 to verify all",
                limit,
                crates.len()
            ));
            crates.truncate(limit);
        }
        common::non_empty(&crates)?;
        let state = State { tags: Mutex::new(HashMap::new()), locks: Mutex::new(HashMap::new()) };
        let opts = RunOpts { timeout, tags: !args.flag("no-tags") };
        let results = par_map(&crates, 4, |c| verify(ctx, c, &opts, &state));

        let mut t = Table::new(
            "Published crate vs repository",
            &["Crate", "Version", "Repository", "Commit", "Compared", "Only in crate", "Differing", "Verdict"],
        );
        let mut data = Vec::new();
        let (mut verified, mut mismatch, mut unverifiable) = (0, 0, 0);
        for (c, r) in crates.iter().zip(results) {
            let v = match r {
                Ok(v) => v,
                Err(e) => {
                    let mut v = Verification::new(c);
                    v.problem = Some(format!("source unavailable: {e}"));
                    v
                }
            };
            match v.verdict() {
                "verified" => verified += 1,
                "mismatch" => mismatch += 1,
                _ => unverifiable += 1,
            }
            t.row([
                c.name.clone(),
                c.version.clone(),
                v.repo.clone().unwrap_or_else(|| "-".into()),
                v.sha.as_deref().map(|s| s.chars().take(10).collect()).unwrap_or_else(|| "-".into()),
                v.compared.to_string(),
                v.only_in_crate.len().to_string(),
                v.differing.len().to_string(),
                v.verdict_label(),
            ]);
            for f in v.findings(c) {
                rep.finding(f);
            }
            data.push(v.to_json());
        }
        rep.table(t);
        rep.summary(format!(
            "{} crate(s): {verified} verified against their repository, {mismatch} mismatch, {unverifiable} unverifiable",
            crates.len()
        ));
        rep.note("Compared: every file in the .crate except Cargo.toml (rewritten by cargo), Cargo.lock (regenerated by cargo), .cargo_vcs_info.json and .cargo-ok.");
        rep.data = json!({ "crates": data });
        Ok(rep)
    }
}

struct RunOpts {
    timeout: Duration,
    tags: bool,
}

/// Shared between worker threads: `ls-remote` results per repo, and a lock per checkout directory.
struct State {
    tags: Mutex<HashMap<String, std::result::Result<Vec<(String, String)>, String>>>,
    locks: Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>,
}

#[derive(Debug, Default)]
struct Verification {
    name: String,
    version: String,
    repo: Option<String>,
    repo_raw: Option<String>,
    sha: Option<String>,
    path_in_vcs: String,
    vcs_info: bool,
    dirty: bool,
    compared: usize,
    only_in_crate: Vec<String>,
    differing: Vec<(String, String)>,
    eol_only: Vec<String>,
    excluded: usize,
    skipped: Vec<String>,
    /// Why the crate could not be verified (code, message, severity).
    blocker: Option<(&'static str, String, Severity)>,
    problem: Option<String>,
    tag: Option<(String, String, bool)>,
    submodules: Vec<String>,
}

impl Verification {
    fn new(c: &CrateRef) -> Verification {
        Verification { name: c.name.clone(), version: c.version.clone(), ..Default::default() }
    }

    fn verdict(&self) -> &'static str {
        if !self.only_in_crate.is_empty() || !self.differing.is_empty() {
            "mismatch"
        } else if self.blocker.is_some() || self.problem.is_some() || self.sha.is_none() {
            "unverifiable"
        } else {
            "verified"
        }
    }

    fn verdict_label(&self) -> String {
        let v = self.verdict();
        if v == "verified" && self.dirty {
            "verified (dirty)".into()
        } else if v == "verified" && !self.eol_only.is_empty() {
            "verified (line endings)".into()
        } else {
            v.into()
        }
    }

    fn findings(&self, c: &CrateRef) -> Vec<Finding> {
        let mut out = Vec::new();
        let k = |f: Finding| f.krate(&c.name, Some(&c.version));
        let repo = self.repo.clone().unwrap_or_default();
        let sha = self.sha.clone().unwrap_or_default();
        if let Some(p) = &self.problem {
            out.push(k(Finding::new(Severity::Medium, "srcverify/unavailable", format!("could not verify: {p}"))));
        }
        if let Some((code, msg, sev)) = &self.blocker {
            let fix = match *code {
                "srcverify/no-vcs-info" => "ask the maintainers to publish from a clean git checkout (no --allow-dirty) so cargo records the commit; review this version's source directly meanwhile",
                "srcverify/no-repository" => "ask the maintainers to set package.repository; review this version's source directly meanwhile",
                "srcverify/commit-missing" => "ask the maintainers which commit this release was built from; treat the published source as unreviewed until then",
                _ => "retry later or check the repository URL; until verified, review the published source directly",
            };
            out.push(k(Finding::new(*sev, *code, msg.clone()).fix(fix)));
        }
        if self.dirty {
            out.push(k(Finding::new(
                Severity::Medium,
                "srcverify/dirty",
                "published from a working tree with uncommitted changes (`git.dirty: true` in .cargo_vcs_info.json)",
            )
            .detail("cargo only sets this with --allow-dirty; the published files may contain edits that never reached the repository")
            .fix("diff the published files against the commit (see the table) and ask maintainers to publish from a clean tree")));
        }
        let rust: Vec<&String> = self.only_in_crate.iter().filter(|f| f.ends_with(".rs")).collect();
        let other: Vec<&String> = self.only_in_crate.iter().filter(|f| !f.ends_with(".rs")).collect();
        let list = |v: &[&String]| {
            let mut s: Vec<String> = v.iter().take(25).map(|x| x.to_string()).collect();
            if v.len() > 25 {
                s.push(format!("… and {} more", v.len() - 25));
            }
            s.join("\n")
        };
        if !rust.is_empty() {
            let build = rust.iter().any(|f| f.as_str() == "build.rs");
            out.push(
                k(Finding::new(
                    Severity::Critical,
                    "srcverify/file-not-in-repo",
                    format!(
                        "{} Rust source file(s){} in the published crate do not exist at {repo} commit {}",
                        rust.len(),
                        if build { " including build.rs" } else { "" },
                        short(&sha)
                    ),
                ))
                .detail(list(&rust))
                .at(rust[0].clone(), None)
                .fix("do not build this version until the maintainers explain the extra code; pin the previous verified version"),
            );
        }
        if !other.is_empty() {
            out.push(
                k(Finding::new(
                    Severity::High,
                    "srcverify/file-not-in-repo",
                    format!("{} file(s) in the published crate do not exist at {repo} commit {}", other.len(), short(&sha)),
                ))
                .detail(list(&other))
                .at(other[0].clone(), None)
                .fix("inspect these files (generated data, binaries, vendored code) before trusting this version"),
            );
        }
        if !self.differing.is_empty() {
            let mut d = String::new();
            for (f, snip) in self.differing.iter().take(3) {
                d.push_str(&format!("{f}:\n{snip}\n"));
            }
            if self.differing.len() > 3 {
                d.push_str(&format!(
                    "… also differ: {}",
                    self.differing.iter().skip(3).take(20).map(|x| x.0.clone()).collect::<Vec<_>>().join(", ")
                ));
            }
            out.push(
                k(Finding::new(
                    Severity::High,
                    "srcverify/file-differs",
                    format!(
                        "{} published file(s) differ from {repo} commit {}",
                        self.differing.len(),
                        short(&sha)
                    ),
                ))
                .detail(d.trim_end().to_string())
                .at(self.differing[0].0.clone(), None)
                .fix("review the differences; code that is not in the repository has not been through its review process"),
            );
        }
        if !self.eol_only.is_empty() {
            out.push(
                k(Finding::new(
                    Severity::Low,
                    "srcverify/line-endings",
                    format!("{} file(s) differ from the repository only in line endings", self.eol_only.len()),
                ))
                .detail(self.eol_only.iter().take(20).cloned().collect::<Vec<_>>().join("\n"))
                .fix("usually caused by publishing from a Windows checkout with core.autocrlf; harmless"),
            );
        }
        if let Some((tag, tsha, false)) = &self.tag {
            out.push(
                k(Finding::new(
                    Severity::Medium,
                    "srcverify/tag-mismatch",
                    format!("release tag {tag} points at {} but the crate was published from {}", short(tsha), short(&sha)),
                ))
                .fix("the tag was moved or the release was published from another commit; ask the maintainers which is authoritative"),
            );
        }
        out
    }

    fn to_json(&self) -> Value {
        json!({
            "crate": self.name, "version": self.version, "repository": self.repo, "repository_raw": self.repo_raw,
            "commit": self.sha, "path_in_vcs": self.path_in_vcs, "vcs_info": self.vcs_info, "dirty": self.dirty,
            "verdict": self.verdict(), "files_compared": self.compared,
            "only_in_crate": self.only_in_crate,
            "differing": self.differing.iter().map(|(f, s)| json!({"file": f, "diff": s})).collect::<Vec<_>>(),
            "line_endings_only": self.eol_only, "excluded_from_crate": self.excluded, "skipped": self.skipped,
            "submodules": self.submodules,
            "unverifiable_reason": self.blocker.as_ref().map(|b| json!({"code": b.0, "message": b.1})).or_else(|| self.problem.as_ref().map(|p| json!({"code": "srcverify/unavailable", "message": p}))),
            "tag": self.tag.as_ref().map(|(t, s, ok)| json!({"name": t, "commit": s, "matches": ok})),
        })
    }
}

fn short(sha: &str) -> String {
    sha.chars().take(10).collect()
}

fn verify(ctx: &Ctx, c: &CrateRef, opts: &RunOpts, st: &State) -> Result<Verification> {
    let mut v = Verification::new(c);
    let dir = c.source_dir(ctx)?;
    // .cargo_vcs_info.json
    let info: Option<Value> = std::fs::read(dir.join(".cargo_vcs_info.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let orig = std::fs::read_to_string(dir.join("Cargo.toml.orig")).ok().and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let norm = rustsrc_manifest(&dir);
    let repo_raw = [orig.as_ref(), norm.as_ref()]
        .into_iter()
        .flatten()
        .find_map(|m| m.get("package").and_then(|p| p.get("repository")).and_then(|r| r.as_str()).map(String::from));
    v.repo_raw = repo_raw.clone();
    v.repo = repo_raw.as_deref().and_then(su::normalize_repo_url);
    let Some(info) = info else {
        v.blocker = Some((
            "srcverify/no-vcs-info",
            "no .cargo_vcs_info.json: the crate does not record which commit it was published from".into(),
            Severity::Medium,
        ));
        return Ok(v);
    };
    v.vcs_info = true;
    v.dirty = info["git"]["dirty"].as_bool().unwrap_or(false);
    v.path_in_vcs = info["path_in_vcs"].as_str().unwrap_or("").trim_matches('/').to_string();
    let sha = info["git"]["sha1"].as_str().unwrap_or("").to_ascii_lowercase();
    if !(sha.len() == 40 || sha.len() == 64) || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        v.blocker = Some(("srcverify/no-vcs-info", ".cargo_vcs_info.json has no valid git.sha1".into(), Severity::Medium));
        return Ok(v);
    }
    v.sha = Some(sha.clone());
    let Some(repo) = v.repo.clone() else {
        v.blocker = Some((
            "srcverify/no-repository",
            match &repo_raw {
                Some(r) => format!("package.repository `{r}` is not a git URL this tool can fetch"),
                None => "no package.repository in Cargo.toml, so the recorded commit cannot be located".into(),
            },
            Severity::Medium,
        ));
        return Ok(v);
    };
    let checkout = match fetch_commit(ctx, &repo, &sha, opts.timeout, st) {
        Ok(p) => p,
        Err(FetchError::CommitMissing(m)) => {
            v.blocker = Some((
                "srcverify/commit-missing",
                format!("commit {} recorded in .cargo_vcs_info.json is not in {repo} ({m})", short(&sha)),
                Severity::High,
            ));
            return Ok(v);
        }
        Err(FetchError::Unreachable(m)) => {
            v.blocker = Some(("srcverify/repo-unreachable", format!("could not reach {repo}: {m}"), Severity::Medium));
            return Ok(v);
        }
        Err(FetchError::Other(e)) => return Err(e),
    };
    compare(ctx, &dir, &checkout, &mut v, orig.as_ref(), opts, st)?;
    if opts.tags && !ctx.offline {
        v.tag = tag_check(&repo, &c.name, &c.version, &sha, opts.timeout, st);
    }
    Ok(v)
}

fn rustsrc_manifest(dir: &Path) -> Option<toml::Value> {
    crate::rustsrc::manifest(dir)
}

enum FetchError {
    CommitMissing(String),
    Unreachable(String),
    Other(Error),
}

impl From<Error> for FetchError {
    fn from(e: Error) -> Self {
        FetchError::Other(e)
    }
}

impl From<std::io::Error> for FetchError {
    fn from(e: std::io::Error) -> Self {
        FetchError::Other(Error::Io(e))
    }
}

/// Fetch `sha` from `url` into a cached checkout (one directory per repo and commit).
fn fetch_commit(ctx: &Ctx, url: &str, sha: &str, timeout: Duration, st: &State) -> std::result::Result<PathBuf, FetchError> {
    let base = ctx.cache_subdir("srcverify")?.join(su::key(url));
    std::fs::create_dir_all(&base)?;
    let dest = base.join(sha);
    let marker = base.join(format!("{sha}.ok"));
    let lock = {
        let mut m = st.locks.lock().unwrap_or_else(|e| e.into_inner());
        m.entry(dest.clone()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    };
    let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
    if marker.is_file() && dest.is_dir() {
        return Ok(dest);
    }
    if ctx.offline {
        return Err(FetchError::Other(Error::Offline(format!("git commit {sha} of {url}"))));
    }
    let tmp = base.join(format!("{sha}.tmp{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let run = |args: &[&str]| git(Some(&tmp), args, timeout);
    let o = run(&["init", "-q"])?;
    if !o.success() {
        return Err(FetchError::Other(Error::Env(format!("git init failed: {}", git_error(&o)))));
    }
    run(&["remote", "add", "origin", url])?;
    let o = run(&["fetch", "-q", "--depth", "1", "--no-tags", "origin", sha])?;
    if !o.success() {
        let first = git_error(&o);
        // Is the repository reachable at all?
        let probe = run(&["ls-remote", "origin", "HEAD"])?;
        if !probe.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(FetchError::Unreachable(git_error(&probe)));
        }
        // Some servers refuse fetching an unadvertised sha: fetch everything (without blobs) and look.
        let all = run(&["fetch", "-q", "--no-tags", "--filter=blob:none", "origin", "+refs/heads/*:refs/remotes/origin/*", "+refs/tags/*:refs/tags/*"])?;
        let has = run(&["cat-file", "-e", &format!("{sha}^{{commit}}")])?;
        if !all.success() || !has.success() {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(FetchError::CommitMissing(format!("not reachable from any branch or tag; first fetch said: {first}")));
        }
    }
    let o = run(&["checkout", "-q", "--force", sha])?;
    if !o.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(FetchError::Other(Error::Env(format!("git checkout {sha} failed: {}", git_error(&o)))));
    }
    let _ = std::fs::remove_dir_all(&dest);
    std::fs::rename(&tmp, &dest)?;
    std::fs::write(&marker, b"")?;
    Ok(dest)
}

/// Lexically normalize `a/b/../c` (no filesystem access). `None` if it escapes the root.
fn normalize_rel(p: &str) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    for c in Path::new(p).components() {
        match c {
            Component::Normal(x) => out.push(x.to_string_lossy().into_owned()),
            Component::ParentDir => {
                out.pop()?;
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out.join("/"))
}

fn join_rel(a: &str, b: &str) -> Option<String> {
    if a.is_empty() { normalize_rel(b) } else { normalize_rel(&format!("{a}/{b}")) }
}

/// Files cargo copies into the package root from elsewhere (`readme`, `license-file`):
/// crate-relative name -> repo-relative source path.
fn copied_sources(checkout: &Path, path_in_vcs: &str, orig: Option<&toml::Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(pkg) = orig.and_then(|o| o.get("package")) else { return out };
    for key in ["readme", "license-file"] {
        let Some(val) = pkg.get(key) else { continue };
        let src = match val {
            toml::Value::String(s) => join_rel(path_in_vcs, s),
            toml::Value::Table(t) if t.get("workspace").and_then(|w| w.as_bool()) == Some(true) => {
                workspace_value(checkout, path_in_vcs, key)
            }
            _ => None,
        };
        if let Some(src) = src {
            if let Some(name) = Path::new(&src).file_name() {
                out.insert(name.to_string_lossy().into_owned(), src);
            }
        }
    }
    out
}

/// `[workspace.package] <key>` of the nearest enclosing workspace, as a repo-relative path.
fn workspace_value(checkout: &Path, path_in_vcs: &str, key: &str) -> Option<String> {
    let mut cur = PathBuf::from(path_in_vcs);
    loop {
        let parent = cur.parent().map(Path::to_path_buf);
        let Some(p) = parent else { return None };
        cur = p;
        let m = checkout.join(&cur).join("Cargo.toml");
        if let Ok(t) = std::fs::read_to_string(&m) {
            if let Ok(v) = toml::from_str::<toml::Value>(&t) {
                if let Some(s) = v.get("workspace").and_then(|w| w.get("package")).and_then(|p| p.get(key)).and_then(|x| x.as_str()) {
                    return join_rel(&cur.to_string_lossy().replace('\\', "/"), s);
                }
            }
        }
        if cur.as_os_str().is_empty() {
            return None;
        }
    }
}

/// Submodules declared in `.gitmodules`: (repo-relative path, url).
fn submodules(checkout: &Path) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(checkout.join(".gitmodules")) else { return vec![] };
    let mut out = Vec::new();
    let (mut path, mut url): (Option<String>, Option<String>) = (None, None);
    let flush = |p: &mut Option<String>, u: &mut Option<String>, out: &mut Vec<(String, String)>| {
        if let (Some(a), Some(b)) = (p.take(), u.take()) {
            out.push((a.trim_matches('/').to_string(), b));
        }
    };
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            flush(&mut path, &mut url, &mut out);
        } else if let Some((k, val)) = l.split_once('=') {
            match k.trim() {
                "path" => path = Some(val.trim().to_string()),
                "url" => url = Some(val.trim().to_string()),
                _ => {}
            }
        }
    }
    flush(&mut path, &mut url, &mut out);
    out
}

fn resolve_submodule_url(base: &str, rel: &str) -> String {
    if !(rel.starts_with("./") || rel.starts_with("../")) {
        return rel.to_string();
    }
    let mut parts: Vec<&str> = base.trim_end_matches('/').split('/').collect();
    for seg in rel.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

fn compare(
    ctx: &Ctx,
    crate_dir: &Path,
    checkout: &Path,
    v: &mut Verification,
    orig: Option<&toml::Value>,
    opts: &RunOpts,
    st: &State,
) -> Result<()> {
    let pkg_root = if v.path_in_vcs.is_empty() { checkout.to_path_buf() } else { checkout.join(&v.path_in_vcs) };
    let copied = copied_sources(checkout, &v.path_in_vcs, orig);
    // submodules overlapping the package, fetched lazily
    let subs = submodules(checkout);
    let mut sub_roots: HashMap<String, Option<(PathBuf, PathBuf)>> = HashMap::new();
    // files are only read inside the checkout: a symlink in the repository must not make
    // this tool read (and print a diff of) files elsewhere on this machine
    let checkout_canon = checkout.canonicalize()?;
    let sha = v.sha.clone().unwrap_or_default();
    let repo = v.repo.clone().unwrap_or_default();
    let mut seen_repo_rel: BTreeSet<String> = BTreeSet::new();
    for f in util::walk_files(crate_dir) {
        let rel = util::rel(crate_dir, &f);
        if matches!(rel.as_str(), ".sm-complete" | ".cargo_vcs_info.json" | ".cargo-ok" | "Cargo.toml") {
            if rel == "Cargo.toml" {
                v.skipped.push(rel);
            }
            continue;
        }
        let crate_bytes = std::fs::read(&f)?;
        let repo_rel_name = if rel == "Cargo.toml.orig" { "Cargo.toml".to_string() } else { rel.clone() };
        let Some(mut repo_rel) = join_rel(&v.path_in_vcs, &repo_rel_name) else { continue };
        let mut repo_file = checkout.join(&repo_rel);
        if !repo_file.is_file() {
            if let Some(src) = copied.get(&rel) {
                if checkout.join(src).is_file() {
                    repo_rel = src.clone();
                    repo_file = checkout.join(src);
                }
            }
        }
        // inside a submodule?
        let mut root_canon = checkout_canon.clone();
        if let Some((sp, surl)) = subs.iter().find(|(p, _)| repo_rel.starts_with(&format!("{p}/"))) {
            let root = sub_roots
                .entry(sp.clone())
                .or_insert_with(|| {
                    let o = git(Some(checkout), &["ls-tree", &sha, "--", sp], opts.timeout).ok()?;
                    let line = o.stdout.lines().next()?.to_string();
                    let mut it = line.split_whitespace();
                    let (_mode, kind, ssha) = (it.next()?, it.next()?, it.next()?);
                    if kind != "commit" {
                        return None;
                    }
                    // the URL comes from the (untrusted) repository: only plain git URLs, and no
                    // local file:// repositories unless the package itself came from one
                    let url = su::normalize_repo_url(&resolve_submodule_url(&repo, surl))
                        .filter(|u| !u.starts_with("file:") || repo.starts_with("file:"));
                    let Some(url) = url else {
                        v.submodules.push(format!("{sp} -> {surl} (not fetched: unsupported URL)"));
                        return None;
                    };
                    v.submodules.push(format!("{sp} -> {url}@{}", short(ssha)));
                    let root = fetch_commit(ctx, &url, ssha, opts.timeout, st).ok()?;
                    let canon = root.canonicalize().ok()?;
                    Some((root, canon))
                })
                .clone();
            if let Some((r, rc)) = root {
                repo_file = r.join(&repo_rel[sp.len() + 1..]);
                root_canon = rc;
            }
        }
        // `cargo package` regenerates Cargo.lock for the package alone (for a workspace member it
        // never equals the workspace's lock file), so it is not a copy of any repository file
        if rel == "Cargo.lock" {
            v.skipped.push(rel);
            continue;
        }
        v.compared += 1;
        seen_repo_rel.insert(repo_rel.clone());
        // symlinks inside the checkout are followed (cargo packages the target's content),
        // symlinks that leave it are not
        let resolved = repo_file.canonicalize();
        if let Ok(r) = &resolved {
            if !r.starts_with(&root_canon) {
                let target = std::fs::read_link(&repo_file).map(|t| t.display().to_string()).unwrap_or_else(|_| "outside".into());
                v.differing.push((rel, format!("the repository has a symlink here that points outside the repository ({target}); not followed")));
                continue;
            }
        }
        match resolved.and_then(std::fs::read) {
            Err(_) => v.only_in_crate.push(rel),
            Ok(repo_bytes) => {
                if repo_bytes == crate_bytes {
                    continue;
                }
                let strip = |b: &[u8]| -> Vec<u8> { b.iter().copied().filter(|&c| c != b'\r').collect() };
                if strip(&repo_bytes) == strip(&crate_bytes) {
                    v.eol_only.push(rel);
                    continue;
                }
                let snippet = if su::is_binary(&crate_bytes) || su::is_binary(&repo_bytes) {
                    format!(
                        "binary file differs (crate {} sha256 {}, repo {} sha256 {})",
                        util::human_bytes(crate_bytes.len() as u64),
                        &util::sha256_hex(&crate_bytes)[..16],
                        util::human_bytes(repo_bytes.len() as u64),
                        &util::sha256_hex(&repo_bytes)[..16]
                    )
                } else {
                    su::diff_snippet(
                        &String::from_utf8_lossy(&repo_bytes),
                        &String::from_utf8_lossy(&crate_bytes),
                        &format!("repo/{repo_rel}"),
                        &format!("crate/{rel}"),
                        6,
                    )
                };
                v.differing.push((rel, snippet));
            }
        }
    }
    // files in the repo package directory that cargo left out (normal: tests, CI config, ...)
    if pkg_root.is_dir() {
        v.excluded = util::walk_files(&pkg_root)
            .iter()
            .filter(|p| {
                let r = util::rel(checkout, p);
                !seen_repo_rel.contains(&r)
            })
            .count();
    }
    Ok(())
}

/// Find a release tag for this version and whether it points at `sha`.
fn tag_check(repo: &str, name: &str, version: &str, sha: &str, timeout: Duration, st: &State) -> Option<(String, String, bool)> {
    let refs = {
        let mut m = st.tags.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = m.get(repo) {
            r.clone()
        } else {
            drop(m);
            let r = match git(None, &["ls-remote", "--tags", repo], timeout) {
                Ok(o) if o.success() => Ok(parse_ls_remote(&o.stdout)),
                Ok(o) => Err(git_error(&o)),
                Err(e) => Err(e.to_string()),
            };
            m = st.tags.lock().unwrap_or_else(|e| e.into_inner());
            m.insert(repo.to_string(), r.clone());
            r
        }
    };
    let refs = refs.ok()?;
    let candidates =
        // crate-specific tags first: in a multi-crate repository `v1.2.3` may belong to another crate
        [format!("{name}-v{version}"), format!("{name}-{version}"), format!("{name}@{version}"), format!("{name}/v{version}"), format!("{name}_v{version}"), format!("v{version}"), version.to_string()];
    for cand in candidates {
        if let Some((_, tsha)) = refs.iter().find(|(t, _)| *t == cand) {
            return Some((cand, tsha.clone(), tsha.eq_ignore_ascii_case(sha)));
        }
    }
    None
}

/// `(tag name, commit)` pairs; annotated tags use their peeled (`^{}`) commit.
fn parse_ls_remote(out: &str) -> Vec<(String, String)> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut peeled: BTreeMap<String, String> = BTreeMap::new();
    for line in out.lines() {
        let mut it = line.split_whitespace();
        let (Some(sha), Some(r)) = (it.next(), it.next()) else { continue };
        let Some(name) = r.strip_prefix("refs/tags/") else { continue };
        if let Some(base) = name.strip_suffix("^{}") {
            peeled.insert(base.to_string(), sha.to_string());
        } else {
            map.insert(name.to_string(), sha.to_string());
        }
    }
    for (k, v) in peeled {
        map.insert(k, v);
    }
    map.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_tags() {
        assert_eq!(normalize_rel("a/b/../README.md").as_deref(), Some("a/README.md"));
        assert_eq!(join_rel("crates/x", "../../README.md").as_deref(), Some("README.md"));
        assert_eq!(join_rel("", "../x"), None);
        assert_eq!(resolve_submodule_url("https://github.com/o/r", "../libgit2.git"), "https://github.com/o/libgit2.git");
        let tags = parse_ls_remote("aaa\trefs/tags/v1.0.0\nbbb\trefs/tags/v1.0.0^{}\nccc\trefs/tags/x-v2\n");
        assert_eq!(tags, vec![("v1.0.0".to_string(), "bbb".to_string()), ("x-v2".to_string(), "ccc".to_string())]);
    }
}
