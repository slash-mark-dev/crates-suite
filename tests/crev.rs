//! crev with signed proofs in local git proof repos (file:// URLs).
//!
//! Proofs use cargo-crev's armored format: `----- BEGIN CREV PROOF -----`, a
//! YAML body (kind, version, date, from{id-type,id,url}, package{source,name,
//! version,digest}, review{thoroughness,understanding,rating}, issues,
//! advisories / ids + trust), `----- SIGN CREV PROOF -----`, the base64url
//! ed25519 signature of the body, `----- END CREV PROOF -----`.
mod common;
use base64::Engine;
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

struct Who {
    key: SigningKey,
    id: String,
    url: String,
    dir: PathBuf,
}

fn who(seed: u8) -> Who {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = b64(key.verifying_key().as_bytes());
    let dir = temp_dir("proofs");
    Who { key, id, url: format!("file://{}", dir.display()), dir }
}

fn from(w: &Who) -> String {
    format!("from:\n  id-type: crev\n  id: {}\n  url: \"{}\"\n", w.id, w.url)
}

fn armor(body: &str, signer: &SigningKey) -> String {
    let sig = b64(&signer.sign(body.as_bytes()).to_bytes());
    format!("----- BEGIN CREV PROOF -----\n{body}----- SIGN CREV PROOF -----\n{sig}\n----- END CREV PROOF -----\n\n")
}

fn review(w: &Who, name: &str, version: &str, rating: &str, extra: &str) -> String {
    format!(
        "kind: package review\nversion: -1\ndate: \"2024-05-01T10:00:00.000000000+00:00\"\n{}package:\n  source: \"https://crates.io\"\n  name: {name}\n  version: {version}\n  digest: x\nreview:\n  thoroughness: medium\n  understanding: high\n  rating: {rating}\n{extra}comment: \"\"\n",
        from(w)
    )
}

fn trust(w: &Who, to: &Who, level: &str) -> String {
    format!(
        "kind: trust\nversion: -1\ndate: \"2024-04-01T10:00:00+00:00\"\n{}ids:\n  - id-type: crev\n    id: {}\n    url: \"{}\"\ntrust: {level}\ncomment: \"\"\n",
        from(w),
        to.id,
        to.url
    )
}

fn commit(dir: &Path, files: &[(&str, &str)]) {
    write_files(dir, files);
    for args in [vec!["init", "-q"], vec!["add", "."], vec!["commit", "-qm", "proofs"]] {
        let o = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"])
            .args(&args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
}

fn setup() -> (Mock, Who) {
    let m = Mock::start();
    for (n, v) in [("goodcrate", "1.0.0"), ("badcrate", "2.0.0"), ("oldcrate", "1.0.0"), ("nocrate", "0.1.0")] {
        m.publish(n, v, &[("src/lib.rs", "pub fn f() {}\n")], json!({}));
    }
    let a = who(1);
    let b = who(2);
    let mallory = who(3);
    // Root repo (A): trusts B highly, reviews goodcrate positively, and carries a
    // forged "dangerous" review that claims to come from B but is signed by Mallory.
    let a_trust = armor(&trust(&a, &b, "high"), &a.key);
    let a_reviews = armor(&review(&a, "goodcrate", "1.0.0", "positive", ""), &a.key)
        + &armor(&review(&b, "goodcrate", "1.0.0", "dangerous", ""), &mallory.key);
    commit(
        &a.dir,
        &[(&format!("{}/trust/2024-04-x.proof.crev", a.id), &a_trust), (&format!("{}/reviews/2024-05-x.proof.crev", a.id), &a_reviews)],
    );
    // B's repo: a dangerous review of badcrate and an advisory in a review of oldcrate 1.1.0.
    let adv = "advisories:\n  - ids:\n      - CREV-TEST-1\n    severity: high\n    range: major\n    comment: \"use-after-free in parse\"\n";
    let b_reviews = armor(&review(&b, "badcrate", "2.0.0", "dangerous", ""), &b.key) + &armor(&review(&b, "oldcrate", "1.1.0", "positive", adv), &b.key);
    commit(&b.dir, &[(&format!("{}/reviews/2024-05-y.proof.crev", b.id), &b_reviews)]);
    (m, a)
}

fn crev(m: &Mock, args: &[&str]) -> Out {
    let empty = temp_dir("crevdir");
    let mut c = m.cmd();
    c.env("CREV_DIR", &empty).arg("crev").args(args);
    run(c)
}

#[test]
fn web_of_trust_flags_dangerous_and_advisories_and_ignores_forgeries() {
    let (m, a) = setup();
    let o = crev(&m, &["goodcrate@1.0.0", "badcrate@2.0.0", "oldcrate@1.0.0", "nocrate@0.1.0", "--root", &a.url, "--json"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["proofs"]["rejected"], 1, "the forged proof must be rejected");
    let by = |n: &str| v["data"]["crates"].as_array().unwrap().iter().find(|c| c["crate"] == n).unwrap().clone();
    let good = by("goodcrate");
    assert_eq!(good["verdict"], "positive (1)", "{good}");
    assert_eq!(good["exact"].as_array().unwrap().len(), 1);
    assert_eq!(by("badcrate")["verdict"], "DANGEROUS");
    assert_eq!(by("badcrate")["best_trust"], 1.0);
    assert_eq!(by("oldcrate")["verdict"], "advisory");
    assert_eq!(by("nocrate")["verdict"], "unreviewed");
    let fs = v["findings"].as_array().unwrap();
    let dangerous: Vec<_> = fs.iter().filter(|f| f["code"] == "crev/dangerous").collect();
    assert_eq!(dangerous.len(), 1, "{fs:?}");
    assert_eq!(dangerous[0]["crate"], "badcrate");
    assert_eq!(dangerous[0]["severity"], "critical");
    let adv = fs.iter().find(|f| f["code"] == "crev/advisory").unwrap();
    assert_eq!(adv["crate"], "oldcrate");
    assert_eq!(adv["severity"], "critical");
    assert!(adv["message"].as_str().unwrap().contains("CREV-TEST-1"));
    assert_eq!(adv["fix"], "upgrade to 1.1.0 or later");
    let un = fs.iter().find(|f| f["code"] == "crev/unreviewed").unwrap();
    assert_eq!(un["severity"], "info");
    assert!(un["detail"].as_str().unwrap().contains("nocrate@0.1.0"));
    let trust = v["data"]["trust"].as_array().unwrap();
    assert_eq!(trust.len(), 2);
}

#[test]
fn depth_zero_only_trusts_the_root() {
    let (m, a) = setup();
    let o = crev(&m, &["badcrate@2.0.0", "goodcrate@1.0.0", "--root", &a.url, "--depth", "0"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("unreviewed"), "{}", o.stdout);
    assert!(o.stdout.contains("positive (1)"), "{}", o.stdout);
    // the cached clone is reused offline
    let off = crev(&m, &["goodcrate@1.0.0", "--root", &a.url, "--offline", "--json"]);
    assert_eq!(off.code, 0, "{}", off.stderr);
    assert_eq!(off.json()["data"]["crates"][0]["verdict"], "positive (1)");
}

#[test]
fn unreachable_root_is_an_error() {
    let m = Mock::start();
    m.publish("goodcrate", "1.0.0", &[("src/lib.rs", "")], json!({}));
    let o = crev(&m, &["goodcrate@1.0.0", "--root", "file:///nonexistent/crev-proofs"]);
    assert_eq!(o.code, 3, "{}\n{}", o.stdout, o.stderr);
    assert!(o.stderr.contains("no root proof repository"), "{}", o.stderr);
}

#[test]
fn trust_proof_urls_are_never_passed_to_git_as_options() {
    // A (the root) trusts an id whose proof repo "URL" is a git option: cloning it
    // verbatim would run the command through --upload-pack.
    let m = Mock::start();
    m.publish("goodcrate", "1.0.0", &[("src/lib.rs", "")], json!({}));
    let a = who(11);
    let mut evil = who(12);
    let marker = temp_dir("marker").join("pwned");
    evil.url = format!("--upload-pack=touch {}", marker.display());
    commit(&a.dir, &[(&format!("{}/trust/x.proof.crev", a.id), &armor(&trust(&a, &evil, "high"), &a.key))]);
    let o = crev(&m, &["goodcrate@1.0.0", "--root", &a.url, "--json"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    assert!(!marker.exists(), "a URL from a trust proof was executed as a git option");
    let repos = o.json()["data"]["repos"].clone();
    assert!(repos.as_object().unwrap().iter().any(|(k, v)| k.contains("upload-pack") && v.as_str().unwrap().contains("not a git repository URL")), "{repos}");
}
