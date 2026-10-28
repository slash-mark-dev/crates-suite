//! srcverify against a local git repository (file:// URL) and crates published to the mock.
mod common;
use common::*;
use serde_json::json;
use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

const LIB: &str = "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n";

/// A repo with the package in `crates/demo`, a workspace README, and a tag.
fn repo() -> (std::path::PathBuf, String, String) {
    let dir = temp_dir("upstream");
    let orig = "[package]\nname = \"demo\"\nversion = \"0.2.0\"\nedition = \"2021\"\nreadme = \"../../README.md\"\nrepository = \"__URL__\"\n";
    let url = format!("file://{}", dir.display());
    write_files(
        &dir,
        &[
            ("README.md", "# demo\n"),
            ("crates/demo/Cargo.toml", &orig.replace("__URL__", &url)),
            ("crates/demo/src/lib.rs", LIB),
            ("crates/demo/tests/t.rs", "#[test] fn t() {}\n"),
            ("crates/demo/Cargo.lock", "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.2.0\"\n\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\n"),
        ],
    );
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-qm", "release"]);
    let sha = git(&dir, &["rev-parse", "HEAD"]);
    // a later commit, and a tag v0.2.0 that points at it instead of the release commit
    write_files(&dir, &[("CHANGELOG.md", "later\n")]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-qm", "later"]);
    git(&dir, &["tag", "-a", "v0.2.0", "-m", "v0.2.0"]);
    (dir, url, sha)
}

fn publish(m: &Mock, name: &str, version: &str, url: &str, sha: &str, dirty: bool, extra: &[(&str, &str)], lib: &str) {
    let orig = format!(
        "[package]\nname = \"demo\"\nversion = \"0.2.0\"\nedition = \"2021\"\nreadme = \"../../README.md\"\nrepository = \"{url}\"\n"
    );
    let vcs = json!({"git": {"sha1": sha, "dirty": dirty}, "path_in_vcs": "crates/demo"}).to_string();
    let manifest = format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\nreadme = \"README.md\"\nrepository = \"{url}\"\n");
    let mut files: Vec<(&str, &str)> =
        vec![("Cargo.toml", &manifest), ("Cargo.toml.orig", &orig), (".cargo_vcs_info.json", &vcs), ("src/lib.rs", lib), ("README.md", "# demo\n")];
    files.extend_from_slice(extra);
    m.publish(name, version, &files, json!({}));
}

#[test]
fn verifies_matching_crate_and_flags_tag_mismatch() {
    let (_dir, url, sha) = repo();
    let m = Mock::start();
    // cargo regenerates Cargo.lock for the package; the workspace's lock file differs
    publish(&m, "demo", "0.2.0", &url, &sha, false, &[("Cargo.lock", "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"0.2.0\"\n")], LIB);
    let o = sm(&m, &["srcverify", "demo@0.2.0", "--json"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let c = &v["data"]["crates"][0];
    assert_eq!(c["verdict"], "verified", "{c}");
    assert_eq!(c["commit"], sha);
    // Cargo.toml.orig, src/lib.rs and README.md (copied from the workspace root) were compared
    assert_eq!(c["files_compared"], 3, "{c}");
    assert_eq!(c["excluded_from_crate"], 2, "tests/t.rs and the repo Cargo.lock are not in the crate: {c}");
    assert!(c["skipped"].as_array().unwrap().iter().any(|f| f == "Cargo.lock"), "{c}");
    assert_eq!(c["tag"]["name"], "v0.2.0");
    assert_eq!(c["tag"]["matches"], false);
    assert_eq!(o.codes(), vec!["srcverify/tag-mismatch"]);
    assert_eq!(v["findings"][0]["severity"], "medium");
}

#[test]
fn injected_and_modified_files_are_reported() {
    let (_dir, url, sha) = repo();
    let m = Mock::start();
    publish(&m, "demo", "0.2.0", &url, &sha, false, &[("src/evil.rs", "pub fn steal() {}\n"), ("data.bin", "\0\x01")], LIB);
    publish(&m, "demo2", "0.2.0", &url, &sha, true, &[], "pub fn add(a: u32, b: u32) -> u32 {\n    std::process::exit(0)\n}\n");
    let o = sm(&m, &["srcverify", "demo@0.2.0", "demo2@0.2.0", "--json", "--no-tags"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let fs = v["findings"].as_array().unwrap();
    let rust = fs.iter().find(|f| f["code"] == "srcverify/file-not-in-repo" && f["severity"] == "critical").unwrap();
    assert_eq!(rust["crate"], "demo");
    assert!(rust["detail"].as_str().unwrap().contains("src/evil.rs"));
    let bin = fs.iter().find(|f| f["code"] == "srcverify/file-not-in-repo" && f["severity"] == "high").unwrap();
    assert!(bin["detail"].as_str().unwrap().contains("data.bin"));
    let diff = fs.iter().find(|f| f["code"] == "srcverify/file-differs").unwrap();
    assert_eq!(diff["crate"], "demo2");
    assert_eq!(diff["severity"], "high");
    let d = diff["detail"].as_str().unwrap();
    assert!(d.contains("-    a + b") && d.contains("+    std::process::exit(0)"), "{d}");
    assert!(fs.iter().any(|f| f["code"] == "srcverify/dirty" && f["crate"] == "demo2"));
    let crates = v["data"]["crates"].as_array().unwrap();
    assert!(crates.iter().all(|c| c["verdict"] == "mismatch"));
    assert_eq!(sm(&m, &["srcverify", "demo@0.2.0", "--fail-on", "none", "--no-tags"]).code, 0);
}

#[test]
fn unverifiable_cases() {
    let (_dir, url, _sha) = repo();
    let m = Mock::start();
    publish(&m, "ghost", "1.0.0", &url, "0123456789abcdef0123456789abcdef01234567", false, &[], LIB);
    m.publish("novcs", "1.0.0", &[("src/lib.rs", LIB)], json!({}));
    let o = sm(&m, &["srcverify", "ghost@1.0.0", "novcs@1.0.0", "--json"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let codes = o.codes();
    assert!(codes.contains(&"srcverify/commit-missing".to_string()), "{codes:?}");
    assert!(codes.contains(&"srcverify/no-vcs-info".to_string()), "{codes:?}");
    let v = o.json();
    assert!(v["data"]["crates"].as_array().unwrap().iter().all(|c| c["verdict"] == "unverifiable"));
    let text = sm(&m, &["srcverify", "novcs@1.0.0"]);
    assert!(text.stdout.contains("unverifiable"), "{}", text.stdout);
}

#[test]
fn symlinks_leaving_the_repository_are_not_followed() {
    // The repository's src/notes.txt is a symlink to a file outside the repository: following
    // it would print a diff of a local file (e.g. ~/.cargo/credentials.toml) in the report.
    let outside = temp_dir("outside").join("credentials.toml");
    std::fs::write(&outside, "token = \"SECRET-LOCAL-TOKEN\"\n").unwrap();
    let dir = temp_dir("upstream-link");
    let url = format!("file://{}", dir.display());
    let orig = format!("[package]\nname = \"demo\"\nversion = \"0.2.0\"\nedition = \"2021\"\nreadme = \"../../README.md\"\nrepository = \"{url}\"\n");
    write_files(&dir, &[("README.md", "# demo\n"), ("crates/demo/Cargo.toml", &orig), ("crates/demo/src/lib.rs", LIB)]);
    std::os::unix::fs::symlink(&outside, dir.join("crates/demo/src/notes.txt")).unwrap();
    git(&dir, &["init", "-q"]);
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-qm", "release"]);
    let sha = git(&dir, &["rev-parse", "HEAD"]);
    let m = Mock::start();
    publish(&m, "demo", "0.2.0", &url, &sha, false, &[("src/notes.txt", "token = \"published\"\n")], LIB);
    let o = sm(&m, &["srcverify", "demo@0.2.0", "--json", "--no-tags"]);
    assert!(!o.stdout.contains("SECRET-LOCAL-TOKEN"), "local file content leaked into the report:\n{}", o.stdout);
    let v = o.json();
    let c = &v["data"]["crates"][0];
    assert_eq!(c["verdict"], "mismatch", "{c}");
    assert!(c["differing"][0]["diff"].as_str().unwrap().contains("points outside the repository"), "{c}");
}
