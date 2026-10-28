//! vet against mock cargo-vet audit sets.
//!
//! Shapes mirror the real sources: `registry.toml` from mozilla/cargo-vet
//! (`[registry.<name>] url = "..."`), cargo-vet `audits.toml` files
//! (`[[audits.<crate>]]` with who/criteria/version|delta|violation,
//! `[[trusted.<crate>]]` with user-id/start/end, `[criteria.<name>] implies`), and
//! the crates.io API `GET /api/v1/crates/<name>/versions` (`versions[].num`,
//! `created_at`, `published_by.id/login`, `meta.next_page`).
mod common;
use common::*;
use serde_json::json;

fn setup() -> (Mock, std::path::PathBuf) {
    let m = Mock::start();
    let u = &m.url;
    m.route(
        "/raw/mozilla/cargo-vet/main/registry.toml",
        200,
        format!(
            "[registry.orga]\nurl = \"{u}/raw/orga/supply-chain/main/audits.toml\"\n\n[registry.orgb]\nurl = [\"{u}/raw/orgb/audits.toml\"]\n\n[registry.broken]\nurl = \"{u}/raw/missing/audits.toml\"\n"
        ),
    );
    m.route(
        "/raw/orga/supply-chain/main/audits.toml",
        200,
        r#"
[criteria.reviewed-deeply]
description = "Deep review"
implies = "safe-to-deploy"

[[audits.alpha]]
who = "Ann <ann@example.com>"
criteria = "reviewed-deeply"
version = "1.0.0"

[[audits.beta]]
who = "Ann <ann@example.com>"
criteria = "safe-to-deploy"
version = "1.0.0"

[[audits.gamma]]
who = "Ann <ann@example.com>"
criteria = "safe-to-deploy"
version = "2.0.0"

[[audits.bad]]
who = "Ann <ann@example.com>"
criteria = "safe-to-deploy"
violation = ">=0.3.0, <0.3.2"
notes = "phones home from build.rs"

[[trusted.trusty]]
criteria = "safe-to-deploy"
user-id = 42 # Alice
start = "2023-01-01"
end = "2024-01-01"
"#,
    );
    m.route(
        "/raw/orgb/audits.toml",
        200,
        r#"
[[audits.beta]]
who = "Bob"
criteria = ["safe-to-deploy"]
delta = "1.0.0 -> 1.1.0"

[[audits.devonly]]
who = "Bob"
criteria = "safe-to-run"
version = "0.5.0"
"#,
    );
    m.json(
        "/api/v1/crates/trusty/versions",
        &json!({"versions": [{"num": "3.0.0", "created_at": "2023-05-01T10:00:00.000000+00:00", "published_by": {"id": 42, "login": "alice", "name": "Alice"}}], "meta": {"total": 1, "next_page": null}}),
    );
    // an older gamma that the uncovered version can be diffed against
    let gamma_old = "pub fn g() -> u32 {\n    1\n}\n// a\n// b\n// c\n// d\n// e\n// f\n// g\n// h\n";
    m.publish("gamma", "2.0.0", &[("src/lib.rs", gamma_old)], json!({}));
    let gamma_new = format!("{gamma_old}pub fn h() -> u32 {{\n    2\n}}\n");
    let lib = "pub fn f() {}\n";
    let dir = project(
        &m,
        &[
            (
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nalpha = \"1\"\nbeta = \"1\"\ngamma = \"2\"\nbad = \"0.3\"\ntrusty = \"3\"\n\n[dev-dependencies]\ndevonly = \"0.5\"\n",
            ),
            ("src/main.rs", "fn main() {}\n"),
        ],
        &[
            Vendored { name: "alpha", version: "1.0.0", manifest: manifest("alpha", "1.0.0", ""), files: vec![("src/lib.rs", lib)] },
            Vendored { name: "beta", version: "1.1.0", manifest: manifest("beta", "1.1.0", ""), files: vec![("src/lib.rs", lib)] },
            Vendored { name: "gamma", version: "2.0.1", manifest: manifest("gamma", "2.0.1", ""), files: vec![("src/lib.rs", Box::leak(gamma_new.into_boxed_str()))] },
            Vendored { name: "bad", version: "0.3.1", manifest: manifest("bad", "0.3.1", ""), files: vec![("src/lib.rs", lib)] },
            Vendored { name: "trusty", version: "3.0.0", manifest: manifest("trusty", "3.0.0", ""), files: vec![("src/lib.rs", lib)] },
            Vendored { name: "devonly", version: "0.5.0", manifest: manifest("devonly", "0.5.0", ""), files: vec![("src/lib.rs", lib)] },
        ],
    );
    (m, dir)
}

fn run_in(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

#[test]
fn coverage_deltas_trust_violation_and_suggestions() {
    let (m, dir) = setup();
    let o = run_in(&m, &dir, &["vet", "--json"]);
    assert_eq!(o.code, 1, "violation is critical\n{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let by = |n: &str| v["data"]["crates"].as_array().unwrap().iter().find(|c| c["crate"] == n).unwrap().clone();
    assert_eq!(by("alpha")["status"], "full", "custom criteria implies safe-to-deploy");
    let beta = by("beta");
    assert_eq!(beta["status"], "delta");
    assert_eq!(beta["path"], json!(["full 1.0.0 (orga)", "1.0.0 -> 1.1.0 (orgb)"]));
    // cargo-vet never imports another organization's `trusted` entries: only a hint
    let trusty = by("trusty");
    assert_eq!(trusty["status"], "uncovered", "{trusty}");
    assert!(trusty["trust_hint"].as_str().unwrap().contains("orga trusts publisher 42 (alice)"), "{trusty}");
    assert_eq!(by("bad")["status"], "violation");
    let dev = by("devonly");
    assert_eq!(dev["dev_only"], true);
    assert_eq!(dev["criteria"], "safe-to-run");
    assert_eq!(dev["status"], "full");
    let gamma = by("gamma");
    assert_eq!(gamma["status"], "uncovered");
    let s = &gamma["suggestions"][0];
    assert_eq!(s["command"], "cargo vet diff gamma 2.0.0 2.0.1", "{gamma}");
    // 3 new lines in src/lib.rs, plus the version line and a blank line in Cargo.toml
    assert_eq!(s["added"], 5, "{s}");
    assert_eq!(s["removed"], 1, "{s}");
    assert_eq!(gamma["suggestions"][1]["command"], "cargo vet inspect gamma 2.0.1");
    assert!(gamma["suggestions"][1]["lines"].as_u64().unwrap() > 6);

    let fs = v["findings"].as_array().unwrap();
    assert_eq!(fs[0]["code"], "vet/violation");
    assert_eq!(fs[0]["severity"], "critical");
    assert!(fs[0]["detail"].as_str().unwrap().contains("phones home"));
    let un = fs.iter().find(|f| f["code"] == "vet/uncovered" && f["crate"] == "gamma").unwrap();
    assert_eq!(un["severity"], "medium");
    assert!(un["fix"].as_str().unwrap().contains("cargo vet diff gamma 2.0.0 2.0.1"));
    assert_eq!(v["data"]["covered"], 3);
    assert_eq!(v["data"]["uncovered"], 2);
    let srcs = v["data"]["sources"].as_array().unwrap();
    assert!(srcs.iter().any(|s| s["name"] == "broken" && s["loaded"] == false));
    assert_eq!(run_in(&m, &dir, &["vet", "--fail-on", "none"]).code, 0);
}

#[test]
fn import_filter_local_audits_and_exemptions() {
    let (m, dir) = setup();
    write_files(
        &dir,
        &[
            (
                "supply-chain/audits.toml",
                "[[audits.gamma]]\nwho = \"me\"\ncriteria = \"safe-to-deploy\"\ndelta = \"2.0.0 -> 2.0.1\"\n\n[[trusted.trusty]]\ncriteria = \"safe-to-deploy\"\nuser-id = 42\nstart = \"2023-01-01\"\nend = \"2024-01-01\"\n",
            ),
            (
                "supply-chain/config.toml",
                "[policy.app]\ncriteria = \"safe-to-deploy\"\n\n[[exemptions.beta]]\nversion = \"1.1.0\"\ncriteria = \"safe-to-deploy\"\n",
            ),
        ],
    );
    // only orga: beta loses its delta (from orgb) but is exempted; gamma is covered via the local delta
    let o = run_in(&m, &dir, &["vet", "--import", "orga", "--only", "beta,gamma,devonly,trusty", "--json"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let by = |n: &str| v["data"]["crates"].as_array().unwrap().iter().find(|c| c["crate"] == n).unwrap().clone();
    assert_eq!(by("beta")["status"], "exempted");
    assert_eq!(by("gamma")["status"], "delta");
    assert_eq!(by("gamma")["certified_by"], json!(["local", "orga"]));
    assert_eq!(by("devonly")["status"], "uncovered");
    assert_eq!(by("trusty")["status"], "trusted", "a trusted entry in the project's own audits.toml certifies");
    assert!(!m.requests().iter().any(|r| r.contains("/raw/orgb/")), "orgb must not be fetched with --import orga");
    // text output
    let t = run_in(&m, &dir, &["vet", "--import", "orga", "--no-suggest"]);
    assert!(t.stdout.contains("Audit coverage") && t.stdout.contains("exempted"), "{}", t.stdout);
}

#[test]
fn crates_on_the_command_line() {
    let (m, _dir) = setup();
    let o = sm(&m, &["vet", "gamma@2.0.0", "beta@1.1.0", "--criteria", "safe-to-run", "--json"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["criteria"], "safe-to-run");
    assert!(v["data"]["crates"].as_array().unwrap().iter().all(|c| c["status"] == "full" || c["status"] == "delta"));
}
