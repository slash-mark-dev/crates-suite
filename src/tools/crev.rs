//! crev Trust Graph: Score dependencies by signed cargo-crev reviews from a web of trust.
//!
//! cargo-crev reviews are YAML documents signed with ed25519 keys and kept in
//! ordinary git repositories ("proof repos"). Each author also publishes trust
//! proofs naming other authors' ids and repos. Starting from root repos, this
//! tool walks the trust graph, verifies every signature, and scores each
//! dependency by the reviews of the people reachable through trust.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
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

pub struct Crev;

const DEFAULT_ROOT: &str = "https://github.com/dpc/crev-proofs";

const OPTS: &[Opt] = &[
    Opt::value("root", "URL", "Proof repository to start the web of trust from (repeatable; default https://github.com/dpc/crev-proofs)"),
    Opt::value("depth", "N", "How many trust hops to follow from the roots (default 2)"),
    Opt::value("max-repos", "N", "Fetch at most N proof repositories (default 50)"),
    Opt::value("only", "A,B", "Only score these dependencies (comma-separated names)"),
    Opt::flag("no-local", "Ignore local cargo-crev ids and proofs ($CREV_DIR, ~/.config/crev, ~/.local/share/crev)"),
];

impl Tool for Crev {
    fn name(&self) -> &'static str {
        "crev"
    }
    fn title(&self) -> &'static str {
        "crev Trust Graph"
    }
    fn group(&self) -> Group {
        Group::SupplyChain
    }
    fn summary(&self) -> &'static str {
        "Score dependencies by signed cargo-crev reviews from a web of trust"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Scores dependencies with cargo-crev reviews, without installing cargo-crev. Proof repositories are git
repos of signed YAML proofs (<id>/reviews/*.crev, <id>/trust/*.crev). Starting from the --root repos
(default: https://github.com/dpc/crev-proofs) plus your own local crev ids and proofs if present
($CREV_DIR, ~/.config/crev, ~/.local/share/crev), each repo is shallow-cloned into the cache (refreshed
daily), every proof's ed25519 signature is checked against its author id (forged or unverifiable
proofs are ignored and counted), and trust proofs are followed breadth-first up to --depth hops,
fetching each trusted author's repo (at most --max-repos). Trust weight is the product of the levels
along the path (high 1.0, medium 0.5, low 0.25, none 0); an id distrusted by anyone in the graph is
excluded. The newest proof per author and subject wins.

For each dependency (project crates.io dependencies, or CRATE@VERSION named) the package reviews by
trusted authors are matched by name and version: reviews of the exact version, of other versions,
the best reviewer trust and a trust-weighted rating. A dangerous rating of the exact version is
critical, a negative one high; a crev advisory published in a review of a newer version whose range
(all / major / minor) covers this version is high (critical for high-severity advisories); issues
reported against the exact version are medium or high. Unreviewed dependencies are counted (info).

Limits: reviews are matched by crate name and version; the recursive source digest in each review is
not recomputed. The web of trust only covers what its members reviewed, so most crates are
unreviewed: absence of reviews is not evidence of a problem."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates crev",
            "sm-crates crev once_cell@1.0.1 log@0.4.8 --depth 1",
            "sm-crates crev --root https://github.com/dpc/crev-proofs --max-repos 10 --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (git access to proof repositories), git"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        su::require_git()?;
        let depth: usize = args.parse_or("depth", 2)?;
        let max_repos: usize = args.parse_or("max-repos", 50)?;
        let roots: Vec<String> = {
            let r = args.list("root");
            if r.is_empty() { vec![DEFAULT_ROOT.to_string()] } else { r }
        };
        let (subject, crates, _) = common::select(ctx, args, Select { dev: true, ..Default::default() })?;
        let crates: Vec<CrateRef> = common::only(args, crates).into_iter().filter(|c| c.is_registry()).collect();
        common::non_empty(&crates)?;
        let mut rep = Report::new("crev", subject);

        let mut g = Graph::default();
        // Local ids and proofs.
        if !args.flag("no-local") {
            let (ids, dirs) = local_crev();
            for d in &dirs {
                let n = g.add_dir(d, "local");
                rep.note(format!("loaded {n} local proof(s) from {}", d.display()));
            }
            for id in ids {
                g.root_ids.insert(id);
            }
        }
        // Root repos.
        let fetched = par_map(&roots, 4, |u| fetch_repo(ctx, u, args.flag("refresh")));
        for (u, r) in roots.iter().zip(fetched) {
            g.repos_tried += 1;
            match r {
                Ok((dir, note)) => {
                    if let Some(n) = note {
                        rep.note(n);
                    }
                    g.add_dir(&dir, u);
                    let ids = g.repo_owner_ids(u);
                    if ids.is_empty() {
                        rep.note(format!("root {u}: no validly signed proofs found"));
                    }
                    g.root_ids.extend(ids);
                    g.repo_status.insert(norm(u), "fetched".into());
                }
                Err(e) => {
                    rep.note(format!("root {u}: {e}"));
                    g.repo_status.insert(norm(u), format!("failed: {e}"));
                }
            }
        }
        if g.root_ids.is_empty() {
            return Err(Error::Network("no root proof repository could be loaded (check --root and network access)".into()));
        }
        // Walk the web of trust.
        g.walk(ctx, depth, max_repos, args.flag("refresh"), &mut rep);

        // Score dependencies.
        let mut t = Table::new("crev reviews", &["Crate", "Version", "Reviews (exact / other)", "Best reviewer trust", "Rating", "Verdict"]);
        let mut unreviewed = Vec::new();
        let mut data = Vec::new();
        let mut positive = 0;
        for c in &crates {
            let s = g.score(c);
            t.row([
                c.name.clone(),
                c.version.clone(),
                format!("{} / {}", s.exact.len(), s.other.len()),
                if s.best_trust > 0.0 { format!("{:.2}", s.best_trust) } else { "-".into() },
                s.rating.map(|r| format!("{r:+.2}")).unwrap_or_else(|| "-".into()),
                s.verdict.clone(),
            ]);
            if s.exact.is_empty() && s.other.is_empty() {
                unreviewed.push(c.spec());
            }
            if s.verdict.starts_with("positive") {
                positive += 1;
            }
            for f in s.findings.iter().cloned() {
                rep.finding(f.krate(&c.name, Some(&c.version)));
            }
            data.push(s.to_json(c, &g));
        }
        rep.table(t);
        if !unreviewed.is_empty() {
            let mut d: Vec<String> = unreviewed.iter().take(40).cloned().collect();
            if unreviewed.len() > 40 {
                d.push(format!("… and {} more", unreviewed.len() - 40));
            }
            rep.finding(
                Finding::new(
                    Severity::Info,
                    "crev/unreviewed",
                    format!("{} of {} dependencies have no review from anyone in the web of trust", unreviewed.len(), crates.len()),
                )
                .detail(d.join("\n"))
                .fix("review them with `cargo crev crate review` and publish your proofs, or add --root repos of people who review your stack"),
            );
        }
        let mut tg = Table::new("Web of trust", &["Id", "Repository", "Depth", "Trust", "Reviews"]);
        let mut ids: Vec<(&String, &Node)> = g.nodes.iter().filter(|(id, _)| !g.distrusted.contains(*id)).collect();
        ids.sort_by(|a, b| a.1.depth.cmp(&b.1.depth).then(b.1.weight.total_cmp(&a.1.weight)).then(a.0.cmp(b.0)));
        for (id, n) in ids.iter().take(60) {
            tg.row([
                id.chars().take(12).collect::<String>(),
                n.url.clone().unwrap_or_else(|| "-".into()),
                n.depth.to_string(),
                format!("{:.2}", n.weight),
                g.reviews_by(id).to_string(),
            ]);
        }
        rep.table(tg);
        rep.summary(format!(
            "{} trusted reviewer(s) in {} proof repo(s); {} of {} dependencies reviewed by them ({} positive), {} unreviewed",
            g.nodes.len() - g.nodes.keys().filter(|k| g.distrusted.contains(*k)).count(),
            g.repos_fetched,
            crates.len() - unreviewed.len(),
            crates.len(),
            positive,
            unreviewed.len()
        ));
        rep.note(format!(
            "{} proof(s) read, {} rejected (bad or missing signature); trust depth {depth}, {} distrusted id(s)",
            g.proofs_total, g.proofs_invalid, g.distrusted.len()
        ));
        rep.note("Reviews are matched by crate name and version; crev's recursive source digest is not recomputed.");
        rep.data = json!({
            "roots": roots,
            "proofs": {"total": g.proofs_total, "rejected": g.proofs_invalid},
            "repos": g.repo_status,
            "trust": g.nodes.iter().map(|(id, n)| json!({"id": id, "url": n.url, "depth": n.depth, "weight": n.weight, "distrusted": g.distrusted.contains(id)})).collect::<Vec<_>>(),
            "crates": data,
        });
        Ok(rep)
    }
}

// ---------------------------------------------------------------- YAML subset

/// The YAML subset cargo-crev writes: block maps, block lists (of maps or
/// scalars), plain/quoted scalars, `|`/`>` block scalars and `[a, b]` flow lists.
#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    Null,
    Str(String),
    List(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    pub fn get(&self, k: &str) -> &Yaml {
        static NULL: Yaml = Yaml::Null;
        match self {
            Yaml::Map(m) => m.iter().find(|(x, _)| x == k).map(|(_, v)| v).unwrap_or(&NULL),
            _ => &NULL,
        }
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Yaml::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn list(&self) -> &[Yaml] {
        match self {
            Yaml::List(l) => l,
            _ => &[],
        }
    }
}

struct Line {
    indent: usize,
    text: String,
    raw: String,
}

pub fn parse_yaml(src: &str) -> Yaml {
    let mut lines: Vec<Line> = src
        .lines()
        .map(|raw| {
            let raw = raw.trim_end_matches('\r').to_string();
            let indent = raw.len() - raw.trim_start_matches(' ').len();
            Line { indent, text: raw.trim().to_string(), raw }
        })
        .collect();
    let mut i = 0;
    skip_blank(&lines, &mut i);
    if i >= lines.len() {
        return Yaml::Null;
    }
    let ind = lines[i].indent;
    parse_block(&mut lines, &mut i, ind, 0)
}

fn skip_blank(lines: &[Line], i: &mut usize) {
    while *i < lines.len() && (lines[*i].text.is_empty() || lines[*i].text.starts_with('#') || lines[*i].text == "---") {
        *i += 1;
    }
}

fn is_item(t: &str) -> bool {
    t == "-" || t.starts_with("- ")
}

fn parse_block(lines: &mut [Line], i: &mut usize, indent: usize, depth: usize) -> Yaml {
    if depth > 64 {
        return Yaml::Null;
    }
    skip_blank(lines, i);
    if *i >= lines.len() {
        return Yaml::Null;
    }
    if is_item(&lines[*i].text) { parse_list(lines, i, indent, depth) } else { parse_map(lines, i, indent, depth) }
}

fn parse_list(lines: &mut [Line], i: &mut usize, indent: usize, depth: usize) -> Yaml {
    let mut out = Vec::new();
    loop {
        skip_blank(lines, i);
        if *i >= lines.len() || lines[*i].indent != indent || !is_item(&lines[*i].text) {
            break;
        }
        let rest = lines[*i].text[1..].trim_start().to_string();
        let off = lines[*i].text.len() - lines[*i].text[1..].trim_start().len();
        if rest.is_empty() {
            *i += 1;
            skip_blank(lines, i);
            if *i < lines.len() && lines[*i].indent > indent {
                let ind = lines[*i].indent;
                out.push(parse_block(lines, i, ind, depth + 1));
            } else {
                out.push(Yaml::Null);
            }
        } else if split_key(&rest).is_some() || is_item(&rest) {
            // `- key: value` starts a map (or `- - x` a nested list) indented at the content column
            lines[*i].indent = indent + off;
            lines[*i].text = rest;
            let ind = indent + off;
            out.push(parse_block(lines, i, ind, depth + 1));
        } else {
            out.push(scalar(&rest));
            *i += 1;
        }
    }
    Yaml::List(out)
}

/// `key: value` -> (key, value) for the first `: ` (or trailing `:`) outside quotes.
fn split_key(t: &str) -> Option<(String, String)> {
    if t.starts_with('"') || t.starts_with('\'') || t.starts_with('[') || t.starts_with('{') {
        // quoted keys are not used by crev; treat as scalar
        if !t.starts_with('"') {
            return None;
        }
    }
    let b = t.as_bytes();
    let mut q: Option<u8> = None;
    for (idx, &c) in b.iter().enumerate() {
        match q {
            Some(x) if c == x => q = None,
            Some(_) => {}
            None if c == b'"' || c == b'\'' => q = Some(c),
            None if c == b':' && (idx + 1 == b.len() || b[idx + 1] == b' ') => {
                let k = t[..idx].trim().trim_matches('"').to_string();
                if k.is_empty() || k.contains(' ') && !t.starts_with('"') {
                    return None;
                }
                return Some((k, t[idx + 1..].trim().to_string()));
            }
            None => {}
        }
    }
    None
}

fn parse_map(lines: &mut [Line], i: &mut usize, indent: usize, depth: usize) -> Yaml {
    let mut out = Vec::new();
    loop {
        skip_blank(lines, i);
        if *i >= lines.len() || lines[*i].indent != indent || is_item(&lines[*i].text) {
            break;
        }
        let Some((k, v)) = split_key(&lines[*i].text) else {
            *i += 1;
            continue;
        };
        *i += 1;
        let val = if v.starts_with('|') || v.starts_with('>') {
            block_scalar(lines, i, indent, &v)
        } else if v.is_empty() {
            skip_blank(lines, i);
            if *i < lines.len() && (lines[*i].indent > indent || (lines[*i].indent == indent && is_item(&lines[*i].text))) {
                let ind = lines[*i].indent;
                parse_block(lines, i, ind, depth + 1)
            } else {
                Yaml::Null
            }
        } else {
            scalar(&v)
        };
        out.push((k, val));
    }
    Yaml::Map(out)
}

fn block_scalar(lines: &[Line], i: &mut usize, indent: usize, head: &str) -> Yaml {
    let mut body: Vec<&str> = Vec::new();
    let mut bi: Option<usize> = None;
    while *i < lines.len() {
        let l = &lines[*i];
        if l.text.is_empty() {
            body.push("");
            *i += 1;
            continue;
        }
        if l.indent <= indent {
            break;
        }
        let b = *bi.get_or_insert(l.indent);
        body.push(if l.raw.len() >= b { &l.raw[b.min(l.indent)..] } else { l.text.as_str() });
        *i += 1;
    }
    while body.last() == Some(&"") {
        body.pop();
    }
    let mut s = if head.starts_with('>') { body.join(" ") } else { body.join("\n") };
    if !head.contains('-') && !s.is_empty() {
        s.push('\n');
    }
    Yaml::Str(s)
}

fn scalar(v: &str) -> Yaml {
    let v = v.trim();
    if let Some(inner) = v.strip_prefix('"') {
        let inner = inner.rfind('"').map(|e| &inner[..e]).unwrap_or(inner);
        let mut s = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                s.push(c);
                continue;
            }
            match it.next() {
                Some('n') => s.push('\n'),
                Some('t') => s.push('\t'),
                Some('r') => s.push('\r'),
                Some('0') => s.push('\0'),
                Some('u') => {
                    let h: String = it.by_ref().take(4).collect();
                    if let Some(ch) = u32::from_str_radix(&h, 16).ok().and_then(char::from_u32) {
                        s.push(ch);
                    }
                }
                Some(o) => s.push(o),
                None => {}
            }
        }
        return Yaml::Str(s);
    }
    if let Some(inner) = v.strip_prefix('\'') {
        let inner = inner.strip_suffix('\'').unwrap_or(inner);
        return Yaml::Str(inner.replace("''", "'"));
    }
    if v == "[]" {
        return Yaml::List(vec![]);
    }
    if v == "{}" {
        return Yaml::Map(vec![]);
    }
    if let Some(inner) = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        return Yaml::List(inner.split(',').map(str::trim).filter(|x| !x.is_empty()).map(scalar).collect());
    }
    let v = match v.find(" #") {
        Some(p) => v[..p].trim_end(),
        None => v,
    };
    if v == "~" || v == "null" {
        return Yaml::Null;
    }
    Yaml::Str(v.to_string())
}

// ---------------------------------------------------------------- proofs

#[derive(Debug, Clone)]
pub struct RawProof {
    /// Proof type from the armor line (`TRUST`, `PACKAGE REVIEW`, `PROOF`).
    pub armor: String,
    pub body: String,
    pub signature: String,
}

/// Split a `.crev` file into armored proofs. Both the current format
/// (`----- BEGIN CREV PROOF -----` / `----- SIGN CREV PROOF -----` / `----- END CREV PROOF -----`)
/// and the legacy one (`-----BEGIN CREV TRUST -----` / `-----BEGIN CREV TRUST SIGNATURE-----` /
/// `-----END CREV TRUST-----`) are accepted.
pub fn split_proofs(text: &str) -> Vec<RawProof> {
    enum St {
        Out,
        Body(String, String),
        Sig(String, String, String),
    }
    let mut st = St::Out;
    let mut out = Vec::new();
    for line in text.split_inclusive('\n') {
        let t = line.trim();
        let armor = (t.starts_with("-----") && t.ends_with("-----")).then(|| t.trim_matches('-').trim().to_string());
        st = match (st, armor) {
            (St::Out, Some(a)) if a.starts_with("BEGIN CREV ") && !a.ends_with(" SIGNATURE") => {
                St::Body(a["BEGIN CREV ".len()..].trim().to_string(), String::new())
            }
            (St::Out, _) => St::Out,
            (St::Body(kind, body), Some(a)) if a.starts_with("SIGN CREV ") || (a.starts_with("BEGIN CREV ") && a.ends_with(" SIGNATURE")) => {
                St::Sig(kind, body, String::new())
            }
            (St::Body(_, _), Some(a)) if a.starts_with("BEGIN CREV ") => St::Body(a["BEGIN CREV ".len()..].trim().to_string(), String::new()),
            (St::Body(kind, mut body), _) => {
                body.push_str(line);
                St::Body(kind, body)
            }
            (St::Sig(kind, body, sig), Some(a)) if a.starts_with("END CREV ") => {
                out.push(RawProof { armor: kind, body, signature: sig.trim().to_string() });
                St::Out
            }
            (St::Sig(kind, body, mut sig), _) => {
                sig.push_str(t);
                St::Sig(kind, body, sig)
            }
        };
    }
    out
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s).ok())
}

/// Verify an ed25519 signature (base64url) over `body` by the crev id (base64url public key).
pub fn verify_signature(body: &str, signature: &str, id: &str) -> bool {
    use ed25519_dalek::Verifier;
    let (Some(pk), Some(sig)) = (b64(id), b64(signature)) else { return false };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), <[u8; 64]>::try_from(sig.as_slice())) else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    vk.verify(body.as_bytes(), &sig).is_ok() || (body.contains('\r') && vk.verify(body.replace('\r', "").as_bytes(), &sig).is_ok())
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Level {
    Trust(f64),
    Distrust,
}

#[derive(Debug, Clone)]
struct TrustProof {
    from: String,
    to: Vec<(String, Option<String>)>,
    level: Level,
    date: i64,
}

#[derive(Debug, Clone)]
struct Review {
    from: String,
    name: String,
    version: String,
    rating: String,
    thoroughness: String,
    understanding: String,
    issues: Vec<(String, String, String)>,
    advisories: Vec<Advisory>,
    comment: String,
    date: i64,
}

#[derive(Debug, Clone)]
struct Advisory {
    ids: Vec<String>,
    severity: String,
    range: String,
    comment: String,
}

#[derive(Debug, Clone)]
struct Node {
    url: Option<String>,
    depth: usize,
    weight: f64,
}

#[derive(Default)]
struct Graph {
    trust: Vec<TrustProof>,
    reviews: Vec<Review>,
    /// author id -> repo URL seen in their own proofs, and which repo a proof was found in
    author_url: HashMap<String, String>,
    found_in: HashMap<String, BTreeSet<String>>,
    nodes: BTreeMap<String, Node>,
    root_ids: BTreeSet<String>,
    distrusted: BTreeSet<String>,
    repo_status: BTreeMap<String, String>,
    repos_tried: usize,
    repos_fetched: usize,
    proofs_total: usize,
    proofs_invalid: usize,
    seen_proofs: BTreeSet<String>,
}

fn norm(u: &str) -> String {
    su::normalize_repo_url(u).unwrap_or_else(|| u.trim_end_matches('/').to_string()).to_ascii_lowercase()
}

impl Graph {
    /// Load every `*.crev` file under `dir`; returns the number of valid proofs.
    fn add_dir(&mut self, dir: &Path, repo: &str) -> usize {
        let mut n = 0;
        for f in util::walk_files(dir) {
            if f.extension().and_then(|e| e.to_str()) != Some("crev") {
                continue;
            }
            if std::fs::metadata(&f).map(|m| m.len() > 8 * 1024 * 1024).unwrap_or(true) {
                continue;
            }
            let Ok(text) = util::read_to_string_lossy(&f) else { continue };
            for p in split_proofs(&text) {
                if self.add_proof(&p, repo) {
                    n += 1;
                }
            }
        }
        if dir.is_dir() {
            self.repos_fetched += 1;
        }
        n
    }

    fn add_proof(&mut self, p: &RawProof, repo: &str) -> bool {
        // the same proof can be mirrored in several repos
        let key = util::sha256_hex(p.signature.as_bytes());
        if self.seen_proofs.contains(&key) {
            return true;
        }
        self.proofs_total += 1;
        let y = parse_yaml(&p.body);
        let from = y.get("from").get("id").str().unwrap_or("").to_string();
        if from.is_empty() || !verify_signature(&p.body, &p.signature, &from) {
            self.proofs_invalid += 1;
            return false;
        }
        self.seen_proofs.insert(key);
        if let Some(u) = y.get("from").get("url").str() {
            self.author_url.entry(from.clone()).or_insert_with(|| u.to_string());
        }
        self.found_in.entry(norm(repo)).or_default().insert(from.clone());
        let date = y.get("date").str().and_then(util::parse_time).unwrap_or(0);
        let kind = match y.get("kind").str() {
            Some(k) => k.to_ascii_lowercase(),
            None => p.armor.to_ascii_lowercase(),
        };
        if kind.starts_with("trust") {
            let level = match y.get("trust").str().unwrap_or("none").to_ascii_lowercase().as_str() {
                "high" => Level::Trust(1.0),
                "medium" => Level::Trust(0.5),
                "low" => Level::Trust(0.25),
                "distrust" => Level::Distrust,
                _ => Level::Trust(0.0),
            };
            let to = y
                .get("ids")
                .list()
                .iter()
                .filter_map(|i| Some((i.get("id").str()?.to_string(), i.get("url").str().map(String::from))))
                .collect();
            self.trust.push(TrustProof { from, to, level, date });
        } else if kind.contains("package review") {
            let pkg = y.get("package");
            if pkg.get("source").str().is_some_and(|s| s.trim_end_matches('/') != "https://crates.io") {
                return true;
            }
            let (Some(name), Some(version)) = (pkg.get("name").str(), pkg.get("version").str()) else { return true };
            let r = y.get("review");
            let issues = y
                .get("issues")
                .list()
                .iter()
                .map(|i| {
                    (
                        i.get("id").str().unwrap_or("").to_string(),
                        i.get("severity").str().unwrap_or("medium").to_string(),
                        i.get("comment").str().unwrap_or("").trim().to_string(),
                    )
                })
                .collect();
            let advisories = y
                .get("advisories")
                .list()
                .iter()
                .map(|a| Advisory {
                    ids: a.get("ids").list().iter().filter_map(|x| x.str().map(String::from)).collect(),
                    severity: a.get("severity").str().unwrap_or("medium").to_string(),
                    range: a.get("range").str().unwrap_or("major").to_string(),
                    comment: a.get("comment").str().unwrap_or("").trim().to_string(),
                })
                .collect();
            self.reviews.push(Review {
                from,
                name: name.to_string(),
                version: version.to_string(),
                rating: r.get("rating").str().unwrap_or("neutral").to_ascii_lowercase(),
                thoroughness: r.get("thoroughness").str().unwrap_or("none").to_string(),
                understanding: r.get("understanding").str().unwrap_or("none").to_string(),
                issues,
                advisories,
                comment: y.get("comment").str().unwrap_or("").trim().to_string(),
                date,
            });
        }
        true
    }

    /// Ids that own a repo: proofs found there whose `from.url` is that repo (or every author found there).
    fn repo_owner_ids(&self, repo: &str) -> BTreeSet<String> {
        let r = norm(repo);
        let found = self.found_in.get(&r).cloned().unwrap_or_default();
        let owners: BTreeSet<String> = found.iter().filter(|id| self.author_url.get(*id).map(|u| norm(u)) == Some(r.clone())).cloned().collect();
        if owners.is_empty() { found } else { owners }
    }

    /// Newest trust proof per (from, to).
    fn latest_trust(&self) -> HashMap<(String, String), (Level, Option<String>, i64)> {
        let mut m: HashMap<(String, String), (Level, Option<String>, i64)> = HashMap::new();
        for t in &self.trust {
            for (to, url) in &t.to {
                let k = (t.from.clone(), to.clone());
                if m.get(&k).is_none_or(|e| t.date >= e.2) {
                    m.insert(k, (t.level, url.clone(), t.date));
                }
            }
        }
        m
    }

    fn walk(&mut self, ctx: &Ctx, depth: usize, max_repos: usize, refresh: bool, rep: &mut Report) {
        for id in self.root_ids.clone() {
            let url = self.author_url.get(&id).cloned();
            self.nodes.insert(id, Node { url, depth: 0, weight: 1.0 });
        }
        let mut frontier: Vec<String> = self.root_ids.iter().cloned().collect();
        let mut skipped = 0;
        for d in 0..depth {
            let trust = self.latest_trust();
            let mut next: Vec<(String, Option<String>)> = Vec::new();
            for from in &frontier {
                let w = self.nodes.get(from).map(|n| n.weight).unwrap_or(0.0);
                if w <= 0.0 || self.distrusted.contains(from) {
                    continue;
                }
                for ((f, to), (level, url, _)) in &trust {
                    if f != from || to == from {
                        continue;
                    }
                    match level {
                        Level::Distrust => {
                            self.distrusted.insert(to.clone());
                        }
                        Level::Trust(l) => {
                            let nw = w * l;
                            if nw <= 0.0 {
                                continue;
                            }
                            match self.nodes.get_mut(to) {
                                Some(n) => n.weight = n.weight.max(nw),
                                None => {
                                    self.nodes.insert(to.clone(), Node { url: url.clone(), depth: d + 1, weight: nw });
                                    next.push((to.clone(), url.clone()));
                                }
                            }
                        }
                    }
                }
            }
            // fetch the new ids' repos
            let mut urls: Vec<String> = Vec::new();
            for (_, u) in &next {
                if let Some(u) = u {
                    let n = norm(u);
                    if !self.repo_status.contains_key(&n) && !urls.iter().any(|x| norm(x) == n) {
                        if self.repos_tried + urls.len() >= max_repos {
                            skipped += 1;
                            continue;
                        }
                        urls.push(u.clone());
                    }
                }
            }
            let fetched = par_map(&urls, 4, |u| fetch_repo(ctx, u, refresh));
            for (u, r) in urls.iter().zip(fetched) {
                self.repos_tried += 1;
                match r {
                    Ok((dir, _)) => {
                        self.add_dir(&dir, u);
                        self.repo_status.insert(norm(u), "fetched".into());
                    }
                    Err(e) => {
                        self.repo_status.insert(norm(u), format!("failed: {e}"));
                    }
                }
            }
            frontier = next.into_iter().map(|(id, _)| id).collect();
            if frontier.is_empty() {
                break;
            }
        }
        for id in self.distrusted.clone() {
            if let Some(n) = self.nodes.get_mut(&id) {
                n.weight = 0.0;
            }
        }
        if skipped > 0 {
            rep.note(format!("{skipped} trusted proof repo(s) not fetched (--max-repos {max_repos})"));
        }
        let failed = self.repo_status.values().filter(|s| s.starts_with("failed")).count();
        if failed > 0 {
            rep.note(format!("{failed} proof repo(s) could not be fetched (see data.repos in --json)"));
        }
    }

    fn weight(&self, id: &str) -> f64 {
        if self.distrusted.contains(id) {
            return 0.0;
        }
        self.nodes.get(id).map(|n| n.weight).unwrap_or(0.0)
    }

    fn reviews_by(&self, id: &str) -> usize {
        self.reviews.iter().filter(|r| r.from == id).count()
    }

    fn score(&self, c: &CrateRef) -> Score {
        // newest review per (author, version) by trusted authors
        let mut latest: BTreeMap<(String, String), &Review> = BTreeMap::new();
        for r in self.reviews.iter().filter(|r| r.name == c.name && self.weight(&r.from) > 0.0) {
            let k = (r.from.clone(), r.version.clone());
            if latest.get(&k).is_none_or(|e| r.date >= e.date) {
                latest.insert(k, r);
            }
        }
        let mut s = Score::default();
        let ours = util::parse_version(&c.version);
        for r in latest.values() {
            if r.version == c.version || (ours.is_some() && util::parse_version(&r.version) == ours) {
                s.exact.push((*r).clone());
            } else {
                s.other.push((*r).clone());
            }
        }
        let (mut num, mut den) = (0.0, 0.0);
        for r in &s.exact {
            let w = self.weight(&r.from);
            s.best_trust = s.best_trust.max(w);
            num += w * rating_value(&r.rating);
            den += w;
            let who = short_id(&r.from);
            match r.rating.as_str() {
                "dangerous" => s.findings.push(
                    Finding::new(Severity::Critical, "crev/dangerous", format!("rated DANGEROUS by trusted reviewer {who} (trust {:.2})", w))
                        .detail(review_detail(r))
                        .fix("do not use this version; read the review and switch versions or crates"),
                ),
                "negative" => s.findings.push(
                    Finding::new(Severity::High, "crev/negative", format!("rated negative by trusted reviewer {who} (trust {:.2})", w))
                        .detail(review_detail(r))
                        .fix("read the review; prefer another version or crate"),
                ),
                _ => {}
            }
            for (id, sev, comment) in &r.issues {
                let sv = if matches!(sev.as_str(), "high" | "critical") { Severity::High } else { Severity::Medium };
                s.findings.push(
                    Finding::new(sv, "crev/issue", format!("issue {} ({sev}) reported against this version by {who}", if id.is_empty() { "-" } else { id }))
                        .detail(comment.clone())
                        .fix("check whether a newer version fixes it (a crev advisory or a positive review of a newer version)"),
                );
            }
        }
        if den > 0.0 {
            s.rating = Some(num / den);
        }
        // advisories from reviews of newer versions that cover ours
        if let Some(ours) = &ours {
            let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
            for r in s.exact.iter().chain(s.other.iter()) {
                let Some(fixed) = util::parse_version(&r.version) else { continue };
                for a in &r.advisories {
                    if advisory_affects(&a.range, &fixed, ours) && seen.insert((a.ids.join(","), r.version.clone())) {
                        let sv = if matches!(a.severity.as_str(), "high" | "critical") { Severity::Critical } else { Severity::High };
                        s.findings.push(
                            Finding::new(
                                sv,
                                "crev/advisory",
                                format!(
                                    "crev advisory {}({} severity) from {}: versions before {} are affected",
                                    if a.ids.is_empty() { String::new() } else { format!("{} ", a.ids.join(", ")) },
                                    a.severity,
                                    short_id(&r.from),
                                    r.version
                                ),
                            )
                            .detail(if a.comment.is_empty() { format!("range: {}", a.range) } else { format!("{} (range: {})", a.comment, a.range) })
                            .fix(format!("upgrade to {} or later", r.version)),
                        );
                        s.advisory = true;
                    }
                }
            }
        }
        s.verdict = if s.exact.iter().any(|r| r.rating == "dangerous") {
            "DANGEROUS".into()
        } else if s.exact.iter().any(|r| r.rating == "negative") {
            "negative".into()
        } else if s.advisory {
            "advisory".into()
        } else if !s.exact.is_empty() {
            match s.rating {
                Some(r) if r > 0.0 => format!("positive ({})", s.exact.len()),
                _ => "neutral".into(),
            }
        } else if !s.other.is_empty() {
            "other versions only".into()
        } else {
            "unreviewed".into()
        };
        if s.exact.is_empty() {
            for r in &s.other {
                s.best_trust = s.best_trust.max(self.weight(&r.from));
            }
        }
        s
    }
}

fn advisory_affects(range: &str, fixed: &semver::Version, ours: &semver::Version) -> bool {
    if ours >= fixed {
        return false;
    }
    match range {
        "all" => true,
        "minor" => ours.major == fixed.major && ours.minor == fixed.minor,
        _ => ours.major == fixed.major,
    }
}

fn rating_value(r: &str) -> f64 {
    match r {
        "strong" => 2.0,
        "positive" => 1.0,
        "negative" => -1.0,
        "dangerous" => -2.0,
        _ => 0.0,
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(12).collect()
}

fn review_detail(r: &Review) -> String {
    let mut d = format!("thoroughness {}, understanding {}, rating {}", r.thoroughness, r.understanding, r.rating);
    if !r.comment.is_empty() {
        d.push_str(&format!("\n{}", r.comment.chars().take(600).collect::<String>()));
    }
    d
}

#[derive(Default)]
struct Score {
    exact: Vec<Review>,
    other: Vec<Review>,
    best_trust: f64,
    rating: Option<f64>,
    verdict: String,
    advisory: bool,
    findings: Vec<Finding>,
}

impl Score {
    fn to_json(&self, c: &CrateRef, g: &Graph) -> Value {
        let rv = |r: &Review| {
            json!({"from": r.from, "trust": g.weight(&r.from), "version": r.version, "rating": r.rating, "thoroughness": r.thoroughness,
                   "understanding": r.understanding, "date": util::format_unix(r.date), "comment": r.comment,
                   "issues": r.issues.iter().map(|i| json!({"id": i.0, "severity": i.1, "comment": i.2})).collect::<Vec<_>>(),
                   "advisories": r.advisories.iter().map(|a| json!({"ids": a.ids, "severity": a.severity, "range": a.range, "comment": a.comment})).collect::<Vec<_>>()})
        };
        json!({
            "crate": c.name, "version": c.version, "verdict": self.verdict, "best_trust": self.best_trust, "weighted_rating": self.rating,
            "exact": self.exact.iter().map(rv).collect::<Vec<_>>(),
            "other_versions": self.other.iter().map(rv).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------- repos

/// Shallow-clone (or refresh daily) a proof repo into the cache. Returns the
/// checkout and an optional note (e.g. stale copy used).
fn fetch_repo(ctx: &Ctx, url: &str, refresh: bool) -> Result<(PathBuf, Option<String>)> {
    // URLs come from (untrusted) trust proofs: only fetch what normalizes to a plain git URL,
    // never pass an arbitrary string (e.g. `--upload-pack=...` or `ext::...`) to git
    let Some(fetch_url) = su::normalize_repo_url(url) else {
        return Err(Error::Parse(format!("not a git repository URL: {url}")));
    };
    let base = ctx.cache_subdir("crev")?;
    let dir = base.join(su::key(&norm(url)));
    let marker = base.join(format!("{}.fetched", su::key(&norm(url))));
    let timeout = Duration::from_secs(300);
    if dir.join(".git").is_dir() {
        if ctx.offline || (!refresh && su::fresh(&marker, 86_400)) {
            return Ok((dir, None));
        }
        let f = git(Some(&dir), &["fetch", "-q", "--depth", "1", "origin", "HEAD"], timeout)?;
        if f.success() {
            let r = git(Some(&dir), &["reset", "-q", "--hard", "FETCH_HEAD"], timeout)?;
            if r.success() {
                let _ = std::fs::write(&marker, b"");
                return Ok((dir, None));
            }
        }
        return Ok((dir, Some(format!("{url}: refresh failed ({}); using the cached copy", git_error(&f)))));
    }
    if ctx.offline {
        return Err(Error::Offline(format!("crev proof repo {url}")));
    }
    let tmp = base.join(format!("{}.tmp{}", su::key(&norm(url)), std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let tmp_s = tmp.to_string_lossy().into_owned();
    let o = git(None, &["clone", "-q", "--depth", "1", "--no-tags", "--", &fetch_url, &tmp_s], timeout)?;
    if !o.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Network(format!("git clone {fetch_url}: {}", git_error(&o))));
    }
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&tmp, &dir)?;
    let _ = std::fs::write(&marker, b"");
    Ok((dir, None))
}

/// The user's own crev ids and local proof directories.
fn local_crev() -> (Vec<String>, Vec<PathBuf>) {
    let mut bases: Vec<PathBuf> = Vec::new();
    if let Some(d) = std::env::var_os("CREV_DIR").filter(|d| !d.is_empty()) {
        bases.push(PathBuf::from(d));
    } else if let Some(h) = su::home_dir() {
        bases.push(h.join(".config").join("crev"));
        bases.push(h.join(".local").join("share").join("crev"));
        if cfg!(target_os = "macos") {
            bases.push(h.join("Library").join("Application Support").join("crev"));
        }
        if let Some(a) = std::env::var_os("APPDATA") {
            bases.push(PathBuf::from(a).join("crev"));
        }
    }
    let mut ids = Vec::new();
    let mut dirs = Vec::new();
    for b in bases {
        if let Ok(rd) = std::fs::read_dir(b.join("ids")) {
            for e in rd.flatten() {
                if let Ok(t) = std::fs::read_to_string(e.path()) {
                    let y = parse_yaml(&t);
                    if let Some(id) = y.get("public-key").str().or_else(|| y.get("id").str()) {
                        ids.push(id.to_string());
                    }
                }
            }
        }
        let p = b.join("proofs");
        if p.is_dir() {
            dirs.push(p);
        }
    }
    (ids, dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVIEW: &str = r#"kind: package review
version: -1
date: "2020-03-07T23:41:54.402563700-08:00"
from:
  id-type: crev
  id: FYlr8YoYGVvDwHQxqEIs89reKKDy-oWisoO0qXXEfHE
  url: "https://github.com/dpc/crev-proofs"
package:
  source: "https://crates.io"
  name: log
  version: 0.4.8
  digest: abc
review:
  thoroughness: low
  understanding: medium
  rating: positive
issues:
  - id: X-1
    severity: high
    comment: |-
      line one
      line two
advisories:
  - ids:
      - RUSTSEC-2019-0018
    severity: medium
    range: all
  - ids: [A, B]
    comment: ""
comment: |
  multi
    indented
"#;

    #[test]
    fn yaml_subset() {
        let y = parse_yaml(REVIEW);
        assert_eq!(y.get("kind").str(), Some("package review"));
        assert_eq!(y.get("from").get("url").str(), Some("https://github.com/dpc/crev-proofs"));
        assert_eq!(y.get("package").get("version").str(), Some("0.4.8"));
        assert_eq!(y.get("review").get("rating").str(), Some("positive"));
        assert_eq!(y.get("issues").list()[0].get("comment").str(), Some("line one\nline two"));
        assert_eq!(y.get("advisories").list()[0].get("ids").list()[0].str(), Some("RUSTSEC-2019-0018"));
        assert_eq!(y.get("advisories").list()[1].get("ids").list().len(), 2);
        assert_eq!(y.get("comment").str(), Some("multi\n  indented\n"));
        let t = parse_yaml("ids:\n- id-type: crev\n  id: AAA\n  url: \"u\"\ntrust: high\n");
        assert_eq!(t.get("ids").list()[0].get("id").str(), Some("AAA"));
        assert_eq!(t.get("trust").str(), Some("high"));
    }

    #[test]
    fn armor_and_signatures() {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().as_bytes());
        let body = format!("kind: trust\nfrom:\n  id: {id}\ntrust: high\n");
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(body.as_bytes()).to_bytes());
        let new = format!("----- BEGIN CREV PROOF -----\n{body}----- SIGN CREV PROOF -----\n{sig}\n----- END CREV PROOF -----\n");
        let legacy = format!("-----BEGIN CREV TRUST -----\n{body}-----BEGIN CREV TRUST SIGNATURE-----\n{sig}\n-----END CREV TRUST-----\n\n");
        for text in [new, legacy] {
            let p = split_proofs(&text);
            assert_eq!(p.len(), 1, "{text}");
            assert_eq!(p[0].body, body);
            assert!(verify_signature(&p[0].body, &p[0].signature, &id));
            assert!(!verify_signature(&p[0].body.replace("high", "low"), &p[0].signature, &id));
        }
    }

    #[test]
    fn advisory_ranges() {
        let v = |s: &str| semver::Version::parse(s).unwrap();
        assert!(advisory_affects("major", &v("1.2.0"), &v("1.1.9")));
        assert!(!advisory_affects("major", &v("1.2.0"), &v("0.9.0")));
        assert!(advisory_affects("all", &v("1.2.0"), &v("0.9.0")));
        assert!(!advisory_affects("minor", &v("1.2.0"), &v("1.1.0")));
        assert!(!advisory_affects("all", &v("1.2.0"), &v("1.2.0")));
    }
}
