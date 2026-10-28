//! Helpers shared by the compile-time supply-chain tools (buildtrace, csys,
//! srcverify, vet, crev): running git, normalizing repository URLs, reading
//! `.crate` archives in memory and cheap line diffs.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::util;

/// How to install git, for error messages.
pub const GIT_INSTALL: &str = "install git (https://git-scm.com/downloads; e.g. `apt install git`, `brew install git`, `winget install Git.Git`)";

/// A `git` command that never prompts for credentials, never runs LFS smudge
/// filters and never rewrites line endings.
pub fn git_command() -> Command {
    let mut c = Command::new(std::env::var("SM_CRATES_GIT").unwrap_or_else(|_| "git".into()));
    c.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_SSH_COMMAND", "ssh -oBatchMode=yes")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .args(["-c", "core.autocrlf=false", "-c", "core.eol=lf", "-c", "advice.detachedHead=false", "-c", "init.defaultBranch=main"]);
    c
}

/// Fail with an install hint when git is missing.
pub fn require_git() -> Result<()> {
    match util::run(git_command().arg("--version"), Duration::from_secs(30)) {
        Ok(o) if o.success() => Ok(()),
        _ => Err(Error::Env(format!("git is required but was not found or does not run; {GIT_INSTALL}"))),
    }
}

/// Run git (optionally in `dir`) with a timeout.
pub fn git(dir: Option<&Path>, args: &[&str], timeout: Duration) -> Result<util::Output> {
    let mut c = git_command();
    if let Some(d) = dir {
        c.current_dir(d);
    }
    c.args(args);
    util::run(&mut c, timeout)
}

/// The last meaningful line of git's stderr, for messages.
pub fn git_error(o: &util::Output) -> String {
    if o.timed_out {
        return "timed out".into();
    }
    o.stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.trim_start_matches("fatal: ").trim_start_matches("error: ").to_string())
        .unwrap_or_else(|| format!("exit code {:?}", o.code))
}

/// Normalize a repository URL from a manifest into something `git fetch` accepts:
/// strips `/tree/<ref>/...`, `/blob/...`, `/-/tree/...`, `#fragment`, `?query`, a trailing
/// `/` or `.git`, and turns `git@host:o/r` and `git+https://` into https.
/// Returns `None` for values that are clearly not repositories.
pub fn normalize_repo_url(url: &str) -> Option<String> {
    let mut u = url.trim().to_string();
    if u.is_empty() {
        return None;
    }
    if let Some(rest) = u.strip_prefix("git+") {
        u = rest.to_string();
    }
    if let Some(rest) = u.strip_prefix("git@") {
        // git@github.com:owner/repo.git
        let (host, path) = rest.split_once(':')?;
        u = format!("https://{host}/{path}");
    }
    if u.starts_with("http://") && !u.starts_with("http://127.") && !u.starts_with("http://localhost") {
        u = format!("https://{}", &u["http://".len()..]);
    }
    if let Some(i) = u.find(['#', '?']) {
        u.truncate(i);
    }
    let lower = u.to_ascii_lowercase();
    if lower.starts_with("file://") {
        return Some(u.trim_end_matches('/').to_string());
    }
    if !(lower.starts_with("https://") || lower.starts_with("ssh://") || lower.starts_with("git://") || lower.starts_with("http://")) {
        return None;
    }
    let (scheme, rest) = u.split_once("://")?;
    let mut parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    let host = parts[0].to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
    let two_level = ["github.com", "codeberg.org", "bitbucket.org", "gitea.com"];
    if two_level.contains(&host.as_str()) {
        parts.truncate(3);
    } else if host == "git.sr.ht" {
        // git.sr.ht/~user/repo/tree/...
        parts.truncate(3);
    } else if host.contains("gitlab") {
        // gitlab groups can nest; cut at `/-/`
        if let Some(i) = parts.iter().position(|p| *p == "-") {
            parts.truncate(i);
        }
        if let Some(i) = parts.iter().position(|p| *p == "tree" || *p == "blob") {
            parts.truncate(i);
        }
    } else if let Some(i) = parts.iter().position(|p| *p == "tree" || *p == "blob" || *p == "src") {
        if i >= 3 {
            parts.truncate(i);
        }
    }
    if parts.len() < 2 {
        return None;
    }
    parts[0] = &host;
    let mut out = format!("{scheme}://{}", parts.join("/"));
    while out.ends_with(".git") || out.ends_with('/') {
        out.truncate(out.len() - if out.ends_with('/') { 1 } else { 4 });
    }
    Some(out)
}

/// Short stable key for cache directory names.
pub fn key(s: &str) -> String {
    util::sha256_hex(s.as_bytes())[..16].to_string()
}

/// Read every regular file in a `.crate` (gzip'd tar) into memory, stripping
/// the `name-version/` prefix. Stops at `max_total` bytes.
pub fn crate_files(data: &[u8], max_total: u64) -> Result<Vec<(String, Vec<u8>)>> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut ar = tar::Archive::new(gz);
    let mut out = Vec::new();
    let mut total = 0u64;
    for e in ar.entries().map_err(|e| Error::Parse(format!("bad crate archive: {e}")))? {
        let mut e = e.map_err(|e| Error::Parse(format!("bad crate archive: {e}")))?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        let p = e.path().map_err(|e| Error::Parse(e.to_string()))?.to_string_lossy().replace('\\', "/");
        let rel = match p.split_once('/') {
            Some((_, r)) if !r.is_empty() => r.to_string(),
            _ => continue,
        };
        if rel.split('/').any(|c| c == "..") {
            continue;
        }
        total += e.header().size().unwrap_or(0);
        if total > max_total {
            return Err(Error::Parse(format!("crate archive larger than {}", util::human_bytes(max_total))));
        }
        let mut buf = Vec::new();
        e.read_to_end(&mut buf)?;
        out.push((rel, buf));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Heuristic binary check: NUL byte in the first 8 KiB.
pub fn is_binary(b: &[u8]) -> bool {
    b.iter().take(8192).any(|&c| c == 0)
}

/// Lines added and removed between two texts, matching lines as a multiset
/// (order-insensitive). Approximate but fast, and never under-counts a pure
/// insertion or deletion.
pub fn line_delta(old: &str, new: &str) -> (usize, usize) {
    let mut counts: HashMap<&str, isize> = HashMap::new();
    for l in old.lines() {
        *counts.entry(l.trim_end()).or_default() += 1;
    }
    let mut added = 0usize;
    for l in new.lines() {
        let c = counts.entry(l.trim_end()).or_default();
        if *c > 0 {
            *c -= 1;
        } else {
            added += 1;
        }
    }
    let removed = counts.values().filter(|&&c| c > 0).map(|&c| c as usize).sum();
    (added, removed)
}

/// A short unified-diff-like excerpt around the first differing line.
pub fn diff_snippet(a: &str, b: &str, label_a: &str, label_b: &str, max: usize) -> String {
    let al: Vec<&str> = a.lines().collect();
    let bl: Vec<&str> = b.lines().collect();
    let first = al.iter().zip(bl.iter()).position(|(x, y)| x != y).unwrap_or(al.len().min(bl.len()));
    // common suffix, to show only the changed middle
    let mut sa = al.len();
    let mut sb = bl.len();
    while sa > first && sb > first && al[sa - 1] == bl[sb - 1] {
        sa -= 1;
        sb -= 1;
    }
    let mut out = format!("--- {label_a}\n+++ {label_b}\n@@ line {} @@\n", first + 1);
    let mut n = 0;
    let clip = |s: &str| -> String {
        let t: String = s.chars().take(160).collect();
        if s.chars().count() > 160 { format!("{t}…") } else { t }
    };
    if first > 0 {
        out.push_str(&format!(" {}\n", clip(al[first - 1])));
    }
    for l in &al[first..sa] {
        if n >= max {
            break;
        }
        out.push_str(&format!("-{}\n", clip(l)));
        n += 1;
    }
    for l in &bl[first..sb] {
        if n >= max * 2 {
            break;
        }
        out.push_str(&format!("+{}\n", clip(l)));
        n += 1;
    }
    let hidden = (sa - first) + (sb - first);
    if hidden > n {
        out.push_str(&format!("… {} more changed line(s)\n", hidden - n));
    }
    out.trim_end().to_string()
}

/// The user's home directory.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// `CARGO_HOME` or `~/.cargo`.
pub fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| home_dir().map(|h| h.join(".cargo")))
}

/// Whether a cache marker file is younger than `secs`.
pub fn fresh(marker: &Path, secs: u64) -> bool {
    std::fs::metadata(marker)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() < secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls() {
        let n = |s: &str| normalize_repo_url(s);
        assert_eq!(n("https://github.com/serde-rs/serde").as_deref(), Some("https://github.com/serde-rs/serde"));
        assert_eq!(n("https://github.com/serde-rs/serde.git").as_deref(), Some("https://github.com/serde-rs/serde"));
        assert_eq!(n("https://github.com/rust-lang/cargo/tree/master/crates/home").as_deref(), Some("https://github.com/rust-lang/cargo"));
        assert_eq!(n("http://www.github.com/a/b/").as_deref(), Some("https://github.com/a/b"));
        assert_eq!(n("git@github.com:a/b.git").as_deref(), Some("https://github.com/a/b"));
        assert_eq!(n("https://gitlab.com/g/sub/r/-/tree/main").as_deref(), Some("https://gitlab.com/g/sub/r"));
        assert_eq!(n("https://git.sr.ht/~u/r/tree/main/item/x").as_deref(), Some("https://git.sr.ht/~u/r"));
        assert_eq!(n("https://codeberg.org/o/r/src/branch/main").as_deref(), Some("https://codeberg.org/o/r"));
        assert_eq!(n("file:///tmp/x/").as_deref(), Some("file:///tmp/x"));
        assert_eq!(n("https://docs.rs"), None);
        assert_eq!(n("not a url"), None);
    }

    #[test]
    fn deltas_and_snippets() {
        assert_eq!(line_delta("a\nb\nc\n", "a\nc\nd\ne\n"), (2, 1));
        assert_eq!(line_delta("", "x\ny"), (2, 0));
        let s = diff_snippet("a\nb\nc\n", "a\nB\nc\n", "crate/x", "repo/x", 5);
        assert!(s.contains("-b") && s.contains("+B") && s.contains("@@ line 2 @@"), "{s}");
        assert!(is_binary(b"\x7fELF\0\0"));
        assert!(!is_binary(b"fn main() {}"));
    }
}
