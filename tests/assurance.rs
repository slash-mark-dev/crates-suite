mod common;
use common::*;
use serde_json::json;

fn toml(name: &str, extra: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\nedition = \"2021\"\nrepository = \"https://github.com/acme/{name}\"\n{extra}")
}

const UNSAFE_LIB: &str = "pub fn read(p: *const u8) -> u8 { unsafe { *p } }\n#[cfg(test)]\nmod t { #[test] fn a() {} }\n";

#[test]
fn credits_ci_oss_fuzz_and_package_evidence() {
    let m = Mock::start();
    m.publish(
        "fuzzed",
        "1.0.0",
        &[
            ("Cargo.toml", &toml("fuzzed", "[dev-dependencies]\nproptest = \"1\"\n")),
            ("src/lib.rs", &format!("{UNSAFE_LIB}#[cfg(kani)]\nmod proofs {{ #[kani::proof] fn p() {{}} }}\n")),
        ],
        json!({}),
    );
    m.json("/gh/repos/acme/fuzzed/contents/.github/workflows", &json!([
        {"name": "ci.yml", "path": ".github/workflows/ci.yml", "type": "file"},
        {"name": "README.md", "path": ".github/workflows/README.md", "type": "file"}
    ]));
    m.route("/raw/acme/fuzzed/HEAD/.github/workflows/ci.yml", 200, "jobs:\n  miri:\n    steps:\n      - run: cargo miri test\n  fuzz:\n    steps:\n      - run: cargo fuzz build\n");
    m.route("/raw/google/oss-fuzz/master/projects/fuzzed/project.yaml", 200, "homepage: \"https://github.com/acme/fuzzed\"\nlanguage: rust\nmain_repo: \"https://github.com/acme/fuzzed.git\"\n");
    let o = sm(&m, &["assurance", "fuzzed", "--json", "--fail-on", "low"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let c = &v["data"]["crates"][0];
    assert_eq!(c["oss_fuzz"], "fuzzed");
    assert_eq!(c["ci"]["source"], "api");
    assert_eq!(c["ci"]["files"], json!(["ci.yml"]));
    assert_eq!(c["ci"]["miri"], true);
    assert_eq!(c["ci"]["fuzz"], true);
    assert_eq!(c["kani_proofs"], 1);
    assert_eq!(c["property_testing"], json!(["proptest"]));
    assert_eq!(c["unsafe_blocks"], 1);
    // fuzz 15 + oss-fuzz 15 + kani 15 + miri ci 10 + proptest 10 + tests 5
    assert_eq!(c["score"], 70);
    assert_eq!(c["level"], "strong");
    let row = &v["tables"][0]["rows"][0];
    assert_eq!(row[0], "fuzzed");
    assert_eq!(row[4], "ci");
    assert_eq!(row[8], "yes");
    assert!(!m.requests().iter().any(|r| r.contains("README.md")), "only workflow files are fetched");
}

#[test]
fn unsafe_without_evidence_is_flagged() {
    let m = Mock::start();
    m.publish("rawptr", "1.0.0", &[("Cargo.toml", &toml("rawptr", "")), ("src/lib.rs", UNSAFE_LIB)], json!({}));
    m.route("/gh/repos/acme/rawptr/contents/.github/workflows", 403, "{\"message\":\"API rate limit exceeded\"}");
    // an OSS-Fuzz project with the same name but another repository is not credited
    m.route("/raw/google/oss-fuzz/master/projects/rawptr/project.yaml", 200, "language: rust\nmain_repo: 'https://github.com/someone-else/rawptr'\n");
    let o = sm(&m, &["assurance", "rawptr", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let v = o.json();
    let f = &v["findings"][0];
    assert_eq!(f["code"], "assurance/unsafe-unverified");
    assert_eq!(f["severity"], "medium");
    assert_eq!(f["crate"], "rawptr");
    assert_eq!(f["version"], "1.0.0");
    let c = &v["data"]["crates"][0];
    assert_eq!(c["ci"]["source"], "unknown");
    assert!(c["oss_fuzz"].is_null());
    assert!(c["oss_fuzz_note"].as_str().unwrap().contains("someone-else"));
    assert_eq!(c["level"], "none");
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("GITHUB_TOKEN")));
    // guessed workflow names were probed on raw
    assert!(m.requests().iter().any(|r| r.ends_with("/raw/acme/rawptr/HEAD/.github/workflows/ci.yml")));
    assert_eq!(sm(&m, &["assurance", "rawptr", "--fail-on", "none"]).code, 0);
}

#[test]
fn forbid_unsafe_and_no_repo() {
    let m = Mock::start();
    m.publish("safe", "1.0.0", &[("Cargo.toml", &toml("safe", "")), ("src/lib.rs", "#![forbid(unsafe_code)]\npub fn f() {}\n")], json!({}));
    let o = sm(&m, &["assurance", "safe", "--no-repo"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("forbid") && o.stdout.contains("100 strong"), "{}", o.stdout);
    assert!(!m.requests().iter().any(|r| r.contains("/gh/") || r.contains("/raw/")), "{:?}", m.requests());
}

#[test]
fn project_dependencies_and_errors() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nrawdep = \"1\"\n"), ("src/main.rs", "fn main() {}\n")],
        &[Vendored { name: "rawdep", version: "1.0.0", manifest: manifest("rawdep", "1.0.0", ""), files: vec![("src/lib.rs", UNSAFE_LIB)] }],
    );
    let mut c = m.cmd();
    c.current_dir(&dir).args(["assurance", "--json", "--fail-on", "none"]);
    let o = run(c);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["crates"][0]["crate"], "rawdep");
    assert_eq!(v["data"]["crates"][0]["ci"]["source"], "none", "no repository field");
    assert_eq!(v["findings"][0]["code"], "assurance/unsafe-unverified");
    assert_eq!(sm(&m, &["assurance", "missing-crate"]).code, 3);
}
