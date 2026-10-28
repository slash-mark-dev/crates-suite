//! Verification Coverage: Which dependencies are fuzzed, Kani-proven, Miri-tested, loom-tested or property-tested.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::{self, Kind, LoadOpts, items};
use crate::tools::common::{self, CrateRef, Select};
use crate::tools::unsafe_hotspots::{analyze, library_files, par_map};
use crate::tools::{Group, Tool};

pub struct Assurance;

const OPTS: &[Opt] = &[
    Opt::value("only", "A,B", "Only check these dependencies (comma-separated names)"),
    Opt::flag("no-repo", "Skip GitHub and OSS-Fuzz lookups; use only the published package"),
];

/// Workflow names probed on raw.githubusercontent.com when the GitHub API cannot list them.
const GUESS_WORKFLOWS: &[&str] =
    &["ci.yml", "ci.yaml", "CI.yml", "main.yml", "rust.yml", "test.yml", "tests.yml", "build.yml", "check.yml", "miri.yml", "fuzz.yml"];

impl Tool for Assurance {
    fn name(&self) -> &'static str {
        "assurance"
    }
    fn title(&self) -> &'static str {
        "Verification Coverage"
    }
    fn group(&self) -> Group {
        Group::Soundness
    }
    fn summary(&self) -> &'static str {
        "Which dependencies are fuzzed, Kani-proven, Miri-tested, loom-tested or property-tested"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Collects evidence that a crate's unsafe code is verified beyond ordinary tests. From the published
package: #[kani::proof] harnesses, cfg(miri)/cfg_attr(miri) (Miri-aware tests), loom (dependency or
cfg(loom)), proptest/quickcheck/arbitrary/bolero dependencies, fuzz targets (fuzz/ directory or
libfuzzer-sys/afl/honggfuzz in any Cargo.toml), #![forbid(unsafe_code)], unsafe_op_in_unsafe_fn and
clippy::undocumented_unsafe_blocks lint settings, and the number of #[test] functions. From the
repository (Cargo.toml `repository` on GitHub): OSS-Fuzz enrollment (google/oss-fuzz
projects/<name>/project.yaml for the crate and repo names, with and without a rust- prefix, and only
when its main_repo matches), and CI workflows (listed with the GitHub API, else common workflow file
names probed on raw.githubusercontent.com) searched for miri, cargo fuzz, kani, loom, sanitizers,
valgrind and cargo careful. Score weights (sum 100): fuzz targets 15, OSS-Fuzz 15, Kani 15, Miri in
source 10, Miri in CI 10, loom 10, property tests 10, sanitizers/valgrind/careful in CI 5, unsafe
lints 5, tests present 5. #![forbid(unsafe_code)] scores 100 (no unsafe to verify). Levels: none (no
verification evidence), basic, strong (score >= 45). Crates with unsafe code and no evidence get a
medium finding. Limits: evidence of a tool is not evidence it covers the unsafe code; monorepo CI
and OSS-Fuzz projects are credited to every crate of that repository; GitHub API calls are rate
limited without GITHUB_TOKEN."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates assurance",
            "sm-crates assurance smallvec bytes crossbeam-channel itoa",
            "sm-crates assurance --only hashbrown,memchr --json",
            "sm-crates assurance regex --no-repo",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crates.io, GitHub, OSS-Fuzz)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let (subject, crates, _) = common::select(ctx, args, Select::default())?;
        let crates = common::only(args, crates);
        common::non_empty(&crates)?;
        let no_repo = args.flag("no-repo");
        let results = par_map(&crates, 4, |c| -> Result<Evidence> {
            let dir = c.source_dir(ctx)?;
            let mut e = package_evidence(&dir);
            if !no_repo {
                repo_evidence(ctx, &c.name, &mut e);
            }
            e.score();
            Ok(e)
        });
        let mut rep = Report::new("assurance", subject);
        let mut rows: Vec<(&CrateRef, Evidence)> = Vec::new();
        for (c, r) in crates.iter().zip(results) {
            match r {
                Ok(e) => rows.push((c, e)),
                Err(err) => rep.note(format!("{}: could not check: {err}", c.spec())),
            }
        }
        if rows.is_empty() {
            return Err(Error::Network("no crate could be downloaded and checked".into()));
        }
        rows.sort_by(|a, b| b.1.unsafe_blocks.cmp(&a.1.unsafe_blocks).then(a.1.score.cmp(&b.1.score)).then(a.0.name.cmp(&b.0.name)));
        let mut t = Table::new("Verification evidence", &["Crate", "Version", "Unsafe blocks", "Fuzz", "Miri", "Kani", "Loom", "Proptest", "OSS-Fuzz", "Score"]);
        let mut data = Vec::new();
        let mut api_failed = false;
        for (c, e) in &rows {
            let src_ci = |src: bool, ci: bool| match (src, ci) {
                (true, true) => "src+ci",
                (true, false) => "src",
                (false, true) => "ci",
                _ => "-",
            };
            t.row([
                c.name.clone(),
                c.version.clone(),
                if e.forbid_unsafe { "forbid".to_string() } else { e.unsafe_blocks.to_string() },
                src_ci(e.fuzz_pkg, e.ci.fuzz).to_string(),
                src_ci(e.miri_src > 0, e.ci.miri).to_string(),
                src_ci(e.kani_proofs > 0, e.ci.kani).to_string(),
                src_ci(e.loom_src, e.ci.loom).to_string(),
                if e.proptest.is_empty() { "-".into() } else { e.proptest.iter().cloned().collect::<Vec<_>>().join(",") },
                if e.oss_fuzz.is_some() { "yes".into() } else { "-".into() },
                format!("{} {}", e.score, e.level),
            ]);
            api_failed |= e.ci_source == "guessed" || e.ci_source == "unknown";
            if e.uses_unsafe && !e.forbid_unsafe && !e.has_verification() {
                let ci = match e.ci_source.as_str() {
                    "api" => "CI workflows checked".to_string(),
                    "guessed" => format!("CI checked via common workflow names ({})", e.ci_files.join(", ")),
                    "none" => "no GitHub repository to check".to_string(),
                    _ => "CI could not be checked".to_string(),
                };
                rep.finding(
                    Finding::new(
                        Severity::Medium,
                        "assurance/unsafe-unverified",
                        format!("{} unsafe block(s), {} unsafe fn(s), {} unsafe impl(s) with no fuzzing, Miri, Kani, loom or property tests", e.unsafe_blocks, e.unsafe_fns, e.unsafe_impls),
                    )
                    .krate(&c.name, Some(&c.version))
                    .detail(format!("{} #[test] fn(s); {ci}", e.tests))
                    .fix(format!("Run `sm-crates miri {}@{}` and `sm-crates unsafe {}` to review it; suggest Miri in CI upstream", c.name, c.version, c.name)),
                );
            }
            let mut d = e.to_json();
            d["crate"] = json!(c.name);
            d["version"] = json!(c.version);
            data.push(d);
        }
        rep.table(t);
        let strong = rows.iter().filter(|(_, e)| e.level == "strong").count();
        let unverified = rep.findings.len();
        rep.summary(format!("{} crate(s): {strong} strong, {unverified} with unsafe code and no verification evidence", rows.len()));
        rep.note("Columns: src = evidence in the published package, ci = found in GitHub workflow files.");
        if api_failed && !no_repo {
            rep.note("The GitHub API could not list workflows (blocked or rate-limited); common workflow file names were probed instead. Set GITHUB_TOKEN to raise the API limit.");
        }
        rep.data = json!({"crates": data});
        Ok(rep)
    }
}

#[derive(Debug, Clone, Default)]
struct CiEvidence {
    miri: bool,
    fuzz: bool,
    kani: bool,
    loom: bool,
    sanitizers: bool,
}

#[derive(Debug, Clone, Default)]
struct Evidence {
    unsafe_blocks: usize,
    unsafe_fns: usize,
    unsafe_impls: usize,
    uses_unsafe: bool,
    forbid_unsafe: bool,
    kani_proofs: usize,
    miri_src: usize,
    loom_src: bool,
    proptest: BTreeSet<String>,
    fuzz_pkg: bool,
    fuzz_detail: Vec<String>,
    unsafe_lints: Vec<String>,
    tests: usize,
    repository: Option<String>,
    oss_fuzz: Option<String>,
    oss_fuzz_note: Option<String>,
    ci: CiEvidence,
    /// "api", "guessed", "unknown", "none"
    ci_source: String,
    ci_files: Vec<String>,
    score: u32,
    level: &'static str,
}

impl Evidence {
    fn has_verification(&self) -> bool {
        self.fuzz_pkg
            || self.oss_fuzz.is_some()
            || self.miri_src > 0
            || self.kani_proofs > 0
            || self.loom_src
            || !self.proptest.is_empty()
            || self.ci.miri
            || self.ci.fuzz
            || self.ci.kani
            || self.ci.loom
            || self.ci.sanitizers
    }

    fn score(&mut self) {
        if self.forbid_unsafe {
            self.score = 100;
            self.level = "strong";
            return;
        }
        let mut s = 0;
        if self.fuzz_pkg || self.ci.fuzz {
            s += 15;
        }
        if self.oss_fuzz.is_some() {
            s += 15;
        }
        if self.kani_proofs > 0 || self.ci.kani {
            s += 15;
        }
        if self.miri_src > 0 {
            s += 10;
        }
        if self.ci.miri {
            s += 10;
        }
        if self.loom_src || self.ci.loom {
            s += 10;
        }
        if !self.proptest.is_empty() {
            s += 10;
        }
        if self.ci.sanitizers {
            s += 5;
        }
        if !self.unsafe_lints.is_empty() {
            s += 5;
        }
        if self.tests > 0 {
            s += 5;
        }
        self.score = s;
        self.level = if !self.has_verification() {
            "none"
        } else if s >= 45 {
            "strong"
        } else {
            "basic"
        };
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "unsafe_blocks": self.unsafe_blocks, "unsafe_fns": self.unsafe_fns, "unsafe_impls": self.unsafe_impls,
            "forbid_unsafe_code": self.forbid_unsafe, "kani_proofs": self.kani_proofs, "miri_cfg_uses": self.miri_src,
            "loom": self.loom_src, "property_testing": self.proptest, "fuzz_targets": self.fuzz_pkg, "fuzz_evidence": self.fuzz_detail,
            "unsafe_lints": self.unsafe_lints, "tests": self.tests, "repository": self.repository,
            "oss_fuzz": self.oss_fuzz, "oss_fuzz_note": self.oss_fuzz_note,
            "ci": {"source": self.ci_source, "files": self.ci_files, "miri": self.ci.miri, "fuzz": self.ci.fuzz, "kani": self.ci.kani, "loom": self.ci.loom, "sanitizers": self.ci.sanitizers},
            "score": self.score, "level": self.level,
        })
    }
}

const PROPTEST: &[&str] = &["proptest", "quickcheck", "arbitrary", "bolero", "proptest-derive", "quickcheck_macros", "test-strategy"];
const FUZZ: &[&str] = &["libfuzzer-sys", "afl", "honggfuzz", "cargo-fuzz", "bolero"];

/// Dependency names from every dependency table of a manifest (including target-specific ones).
fn manifest_deps(m: &toml::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut tables: Vec<(&str, &toml::Value)> = Vec::new();
    for sec in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = m.get(sec) {
            tables.push((sec, t));
        }
    }
    if let Some(targets) = m.get("target").and_then(|t| t.as_table()) {
        for (_, tv) in targets {
            for sec in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(t) = tv.get(sec) {
                    tables.push((sec, t));
                }
            }
        }
    }
    for (sec, t) in tables {
        for (k, v) in t.as_table().into_iter().flatten() {
            let name = v.get("package").and_then(|p| p.as_str()).unwrap_or(k);
            out.push((sec.to_string(), name.to_string()));
        }
    }
    out
}

fn package_evidence(dir: &Path) -> Evidence {
    let mut e = Evidence::default();
    let u = analyze(&library_files(dir));
    e.unsafe_blocks = u.blocks;
    e.unsafe_fns = u.unsafe_fns;
    e.unsafe_impls = u.unsafe_impls;
    e.uses_unsafe = u.uses_unsafe();
    // manifests: the package's and any nested one (fuzz/Cargo.toml)
    for f in crate::util::walk_files(dir) {
        let rel = crate::util::rel(dir, &f);
        if rel.starts_with("fuzz/") && !e.fuzz_pkg {
            e.fuzz_pkg = true;
            e.fuzz_detail.push("fuzz/ directory".into());
        }
        if f.file_name().is_some_and(|n| n == "Cargo.toml") {
            let Some(m) = std::fs::read_to_string(&f).ok().and_then(|t| toml::from_str::<toml::Value>(&t).ok()) else { continue };
            for (sec, d) in manifest_deps(&m) {
                // a normal (often optional) `arbitrary`/`proptest` dependency only provides impls for
                // users; it is evidence of property testing only as a dev-dependency or in a test crate
                if PROPTEST.contains(&d.as_str()) && (sec == "dev-dependencies" || rel != "Cargo.toml") {
                    e.proptest.insert(d.clone());
                }
                if FUZZ.contains(&d.as_str()) {
                    e.fuzz_pkg = true;
                    e.fuzz_detail.push(format!("{d} in {rel}"));
                }
                if d == "loom" {
                    e.loom_src = true;
                }
            }
            if m.get("package").and_then(|p| p.get("metadata")).and_then(|x| x.get("cargo-fuzz")).is_some() {
                e.fuzz_pkg = true;
                e.fuzz_detail.push(format!("cargo-fuzz metadata in {rel}"));
            }
            if rel == "Cargo.toml" {
                if let Some(lints) = m.get("lints") {
                    let level = |t: &str, l: &str| lints.get(t).and_then(|x| x.get(l)).map(|v| v.as_str().map(String::from).or_else(|| v.get("level").and_then(|x| x.as_str()).map(String::from)).unwrap_or_default());
                    if level("rust", "unsafe_code").as_deref() == Some("forbid") {
                        e.forbid_unsafe = true;
                    }
                    if let Some(l) = level("rust", "unsafe_op_in_unsafe_fn").filter(|l| l != "allow") {
                        e.unsafe_lints.push(format!("unsafe_op_in_unsafe_fn = {l}"));
                    }
                    if let Some(l) = level("clippy", "undocumented_unsafe_blocks").filter(|l| l != "allow") {
                        e.unsafe_lints.push(format!("clippy::undocumented_unsafe_blocks = {l}"));
                    }
                }
                e.repository = m.get("package").and_then(|p| p.get("repository")).and_then(|r| r.as_str()).map(String::from);
            }
        }
    }
    // sources, including tests/ and benches/
    for f in rustsrc::load_crate(dir, LoadOpts { auxiliary: true, build_script: true }) {
        let c = &f.code;
        for i in 0..c.len() {
            let t = &c[i];
            if t.kind != Kind::Ident {
                continue;
            }
            match t.text.as_str() {
                "kani" if c.get(i + 1).is_some_and(|x| x.punct("::")) && c.get(i + 2).is_some_and(|x| x.text.starts_with("proof")) => e.kani_proofs += 1,
                "miri" | "loom" => {
                    let near_cfg = c[i.saturating_sub(6)..i].iter().any(|x| x.ident("cfg") || x.ident("cfg_attr"));
                    if near_cfg {
                        if t.text == "miri" {
                            e.miri_src += 1;
                        } else {
                            e.loom_src = true;
                        }
                    }
                }
                "test" if i >= 2 && c[i - 1].punct("[") && c[i - 2].punct("#") && c.get(i + 1).is_some_and(|x| x.punct("]")) => e.tests += 1,
                "test" if i >= 3 && c[i - 1].punct("::") && c.get(i + 1).is_some_and(|x| x.punct("]") || x.punct("(")) && c[..i].iter().rev().take(6).any(|x| x.punct("#")) => e.tests += 1,
                _ => {}
            }
        }
    }
    if let Some(root) = rustsrc::lib_root(dir) {
        if let Ok(f) = rustsrc::SourceFile::load(dir, &root) {
            for a in items::inner_attrs(&f.code) {
                let compact: String = a.chars().filter(|c| !c.is_whitespace()).collect();
                if compact.starts_with("forbid(") && compact.contains("unsafe_code") {
                    e.forbid_unsafe = true;
                }
                for (lint, label) in [("unsafe_op_in_unsafe_fn", "unsafe_op_in_unsafe_fn"), ("clippy::undocumented_unsafe_blocks", "clippy::undocumented_unsafe_blocks")] {
                    if compact.contains(lint) && !compact.starts_with("allow(") {
                        e.unsafe_lints.push(format!("{label} via #![{}(..)]", compact.split('(').next().unwrap_or("")));
                    }
                }
            }
        }
    }
    e
}

/// `(owner, repo)` of a GitHub repository URL.
fn github_repo(url: &str) -> Option<(String, String)> {
    let u = url.trim().trim_end_matches('/');
    let rest = u.split("github.com/").nth(1)?;
    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.trim_end_matches(".git").to_string();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

fn norm_repo(u: &str) -> String {
    github_repo(u).map(|(o, r)| format!("{}/{}", o.to_ascii_lowercase(), r.to_ascii_lowercase())).unwrap_or_else(|| u.trim().to_ascii_lowercase())
}

/// Minimal parse of an OSS-Fuzz project.yaml: (language, main_repo).
fn parse_project_yaml(text: &str) -> (Option<String>, Option<String>) {
    let mut lang = None;
    let mut main = None;
    for l in text.lines() {
        let val = |k: &str| l.strip_prefix(k).map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string());
        if let Some(v) = val("language:") {
            lang = Some(v);
        }
        if let Some(v) = val("main_repo:") {
            main = Some(v);
        }
    }
    (lang, main)
}

fn repo_evidence(ctx: &Ctx, name: &str, e: &mut Evidence) {
    let gh = e.repository.as_deref().and_then(github_repo);
    // OSS-Fuzz
    let mut cands: Vec<String> = vec![name.to_ascii_lowercase()];
    if let Some((_, r)) = &gh {
        let r = r.to_ascii_lowercase();
        cands.push(r.clone());
        if let Some(stripped) = r.strip_prefix("rust-") {
            cands.push(stripped.to_string());
        }
        cands.push(format!("rust-{r}"));
    }
    cands.push(format!("rust-{}", name.to_ascii_lowercase()));
    let mut seen = BTreeSet::new();
    cands.retain(|c| seen.insert(c.clone()));
    let urls: Vec<String> = cands.iter().map(|c| format!("{}/google/oss-fuzz/master/projects/{c}/project.yaml", ctx.endpoints.github_raw)).collect();
    for (c, r) in cands.iter().zip(ctx.http.get_many(&urls, Ttl::DAY, 6)) {
        let Ok(r) = r else { continue };
        if !r.ok() {
            continue;
        }
        let (lang, main) = parse_project_yaml(&r.text());
        let matches = match (&main, &e.repository) {
            (Some(m), Some(repo)) => norm_repo(m) == norm_repo(repo),
            (_, None) => c == &name.to_ascii_lowercase() && lang.as_deref() == Some("rust"),
            _ => false,
        };
        if matches {
            e.oss_fuzz = Some(c.clone());
            break;
        } else if e.oss_fuzz_note.is_none() {
            e.oss_fuzz_note = Some(format!("OSS-Fuzz project `{c}` exists but its main_repo ({}) is not this crate's repository", main.unwrap_or_default()));
        }
    }
    // CI workflows
    let Some((owner, repo)) = gh else {
        e.ci_source = "none".into();
        return;
    };
    let api = format!("{}/repos/{owner}/{repo}/contents/.github/workflows", ctx.endpoints.github_api);
    let listed: Option<Vec<String>> = ctx.http.get(&api, Ttl::DAY).ok().and_then(|r| {
        if r.status == 404 {
            return Some(vec![]);
        }
        let v = r.json().ok().filter(|_| r.ok())?;
        Some(
            v.as_array()?
                .iter()
                .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
                .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
                .map(String::from)
                .collect(),
        )
    });
    let (names, source): (Vec<String>, &str) = match listed {
        Some(n) => (n, "api"),
        None => (GUESS_WORKFLOWS.iter().map(|s| s.to_string()).collect(), "guessed"),
    };
    let urls: Vec<String> = names.iter().map(|n| format!("{}/{owner}/{repo}/HEAD/.github/workflows/{n}", ctx.endpoints.github_raw)).collect();
    let mut found = Vec::new();
    for (n, r) in names.iter().zip(ctx.http.get_many(&urls, Ttl::DAY, 6)) {
        let Ok(r) = r else { continue };
        if !r.ok() {
            continue;
        }
        found.push(n.clone());
        let t = r.text().to_ascii_lowercase();
        e.ci.miri |= t.contains("miri");
        e.ci.fuzz |= t.contains("cargo fuzz") || t.contains("cargo-fuzz") || t.contains("cargo +nightly fuzz");
        e.ci.kani |= t.contains("kani");
        e.ci.loom |= t.contains("loom");
        e.ci.sanitizers |= t.contains("sanitizer") || t.contains("valgrind") || t.contains("cargo careful") || t.contains("cargo-careful");
    }
    e.ci_source = if source == "guessed" && found.is_empty() { "unknown".into() } else { source.into() };
    e.ci_files = found;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls() {
        assert_eq!(github_repo("https://github.com/tokio-rs/bytes"), Some(("tokio-rs".into(), "bytes".into())));
        assert_eq!(github_repo("https://github.com/servo/rust-smallvec.git/"), Some(("servo".into(), "rust-smallvec".into())));
        assert_eq!(github_repo("https://github.com/crossbeam-rs/crossbeam/tree/master/crossbeam-channel"), Some(("crossbeam-rs".into(), "crossbeam".into())));
        assert_eq!(github_repo("https://gitlab.com/x/y"), None);
        assert_eq!(norm_repo("https://github.com/Rust-Lang/regex.git"), "rust-lang/regex");
    }

    #[test]
    fn oss_fuzz_yaml() {
        let (l, m) = parse_project_yaml("homepage: \"https://github.com/rust-lang/regex\"\nmain_repo: \"https://github.com/rust-lang/regex\"\nlanguage: rust\n");
        assert_eq!(l.as_deref(), Some("rust"));
        assert_eq!(m.as_deref(), Some("https://github.com/rust-lang/regex"));
    }

    #[test]
    fn scoring_levels() {
        let mut e = Evidence { tests: 3, uses_unsafe: true, ..Default::default() };
        e.score();
        assert_eq!((e.score, e.level), (5, "none"));
        let mut e = Evidence { tests: 3, miri_src: 2, oss_fuzz: Some("x".into()), fuzz_pkg: true, ..Default::default() };
        e.ci.miri = true;
        e.score();
        assert_eq!((e.score, e.level), (55, "strong"));
        let mut e = Evidence { proptest: ["proptest".to_string()].into(), ..Default::default() };
        e.score();
        assert_eq!((e.score, e.level), (10, "basic"));
        let mut e = Evidence { forbid_unsafe: true, ..Default::default() };
        e.score();
        assert_eq!((e.score, e.level), (100, "strong"));
    }

    #[test]
    fn package_scan() {
        let d = crate::util::temp_dir("assure").unwrap();
        let w = |p: &str, c: &str| {
            let f = d.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        };
        w("Cargo.toml", "[package]\nname = \"x\"\nversion = \"1.0.0\"\nrepository = \"https://github.com/o/x\"\n[dev-dependencies]\nproptest = \"1\"\n[target.'cfg(loom)'.dependencies]\nloom = \"0.7\"\n[lints.rust]\nunsafe_op_in_unsafe_fn = \"deny\"\n");
        w("src/lib.rs", "#![deny(clippy::undocumented_unsafe_blocks)]\npub fn a(p: *const u8) -> u8 { unsafe { *p } }\n#[cfg(kani)]\nmod proofs { #[kani::proof] fn p() {} }\n#[cfg(test)]\nmod t { #[test] #[cfg_attr(miri, ignore)] fn big() {} #[tokio::test] async fn b() {} }\n");
        w("fuzz/Cargo.toml", "[package]\nname = \"x-fuzz\"\nversion = \"0.0.0\"\n[dependencies]\nlibfuzzer-sys = \"0.4\"\n");
        let e = package_evidence(&d);
        assert_eq!(e.unsafe_blocks, 1);
        assert_eq!(e.kani_proofs, 1);
        assert_eq!(e.miri_src, 1);
        assert!(e.loom_src && e.fuzz_pkg);
        assert_eq!(e.proptest.iter().collect::<Vec<_>>(), ["proptest"]);
        assert_eq!(e.tests, 2);
        assert_eq!(e.unsafe_lints.len(), 2, "{:?}", e.unsafe_lints);
        assert_eq!(e.repository.as_deref(), Some("https://github.com/o/x"));
        assert!(!e.forbid_unsafe);
        let _ = std::fs::remove_dir_all(d);
    }
}
