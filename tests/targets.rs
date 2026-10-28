mod common;
use common::*;
use serde_json::{Value, json};

fn crates() -> Vec<Vendored<'static>> {
    vec![
        Vendored {
            name: "getrandom",
            version: "0.2.0",
            manifest: manifest("getrandom", "0.2.0", "[features]\njs = []\n"),
            files: vec![("src/lib.rs", "#![no_std]\npub fn fill() {}\n")],
        },
        Vendored { name: "stdonly", version: "1.0.0", manifest: manifest("stdonly", "1.0.0", ""), files: vec![("src/lib.rs", "pub fn f() {}\n")] },
        Vendored {
            name: "nativ",
            version: "1.0.0",
            manifest: "[package]\nname = \"nativ\"\nversion = \"1.0.0\"\nedition = \"2021\"\nlinks = \"foo\"\nbuild = \"build.rs\"\n\n[build-dependencies]\ncc = \"1\"\n".to_string(),
            files: vec![("src/lib.rs", "#![no_std]\n"), ("build.rs", "fn main() {}\n")],
        },
        Vendored { name: "cc", version: "1.0.0", manifest: manifest("cc", "1.0.0", ""), files: vec![("src/lib.rs", "")] },
        Vendored {
            name: "linksonly",
            version: "1.0.0",
            manifest: "[package]\nname = \"linksonly\"\nversion = \"1.0.0\"\nedition = \"2021\"\nlinks = \"bar\"\nbuild = \"build.rs\"\n".to_string(),
            files: vec![("src/lib.rs", "#![no_std]\n"), ("build.rs", "fn main() {}\n")],
        },
        Vendored {
            name: "docsy",
            version: "1.0.0",
            manifest: manifest("docsy", "1.0.0", "[package.metadata.docs.rs]\ntargets = [\"thumbv7em-none-eabihf\"]\n"),
            files: vec![("src/lib.rs", "#![no_std]\n")],
        },
        Vendored { name: "purelib", version: "1.0.0", manifest: manifest("purelib", "1.0.0", ""), files: vec![("src/lib.rs", "#![no_std]\npub fn f() {}\n")] },
    ]
}

fn platforms(m: &Mock, name: &str, version: &str, targets: &[&str]) {
    m.json(&format!("/docsrs/crate/{name}/{version}/status.json"), &json!({"doc_status": true, "version": version}));
    let html: String = targets
        .iter()
        .map(|t| format!("<li class=\"pure-menu-item\"><a href=\"/crate/{name}/{version}/target-redirect/{t}/{name}/\" class=\"pure-menu-link\" data-fragment=\"retain\" rel=\"nofollow\">{t}</a></li>\n"))
        .collect();
    m.route(&format!("/docsrs/crate/{name}/{version}/menus/platforms/"), 200, html);
}

fn app(deps: &str) -> String {
    format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{deps}")
}

fn run_in(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

fn cell<'a>(v: &'a Value, krate: &str, target: &str) -> &'a Value {
    v["data"]["matrix"].as_array().unwrap().iter().find(|c| c["crate"] == krate && c["target"] == target).unwrap_or_else(|| panic!("no cell {krate} {target}"))
}

fn findings<'a>(v: &'a Value, code: &str, krate: &str) -> Vec<&'a Value> {
    v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == code && f["crate"] == krate).collect()
}

const TARGETS: &str = "wasm32-unknown-unknown,thumbv7em-none-eabihf";

#[test]
fn wasm_and_embedded_problems_with_docsrs_evidence() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[("Cargo.toml", &app("getrandom = \"0.2\"\nstdonly = \"1\"\nnativ = \"1\"\ndocsy = \"1\"\npurelib = \"1\"\nlinksonly = \"1\"\n")), ("src/lib.rs", "#![no_std]\n")],
        &crates(),
    );
    platforms(&m, "getrandom", "0.2.0", &["x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"]);
    platforms(&m, "docsy", "1.0.0", &["x86_64-unknown-linux-gnu"]);
    platforms(&m, "purelib", "1.0.0", &["x86_64-unknown-linux-gnu", "thumbv7em-none-eabihf"]);
    m.json("/docsrs/crate/nativ/1.0.0/status.json", &json!({"doc_status": false, "version": "1.0.0"}));
    let o = run_in(&m, &dir, &["targets", "--target", TARGETS, "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["tool"], "targets");
    assert_eq!(v["data"]["targets"], json!(["wasm32-unknown-unknown", "thumbv7em-none-eabihf"]));
    assert_eq!(v["data"]["docsrs"]["used"], true);
    // getrandom 0.2 without `js` on wasm
    let g = findings(&v, "targets/getrandom-wasm", "getrandom");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0]["severity"], "high");
    assert!(g[0]["message"].as_str().unwrap().ends_with("on wasm32-unknown-unknown"));
    assert_eq!(cell(&v, "getrandom", "wasm32-unknown-unknown")["status"], "x");
    assert_eq!(cell(&v, "getrandom", "wasm32-unknown-unknown")["docsrs"], "built");
    // std-only crate on a target without std
    let s = findings(&v, "targets/needs-std", "stdonly");
    assert_eq!(s.len(), 1);
    assert!(s[0]["message"].as_str().unwrap().ends_with("on thumbv7em-none-eabihf"), "{}", s[0]);
    assert_eq!(cell(&v, "stdonly", "wasm32-unknown-unknown")["status"], "ok");
    assert_eq!(cell(&v, "stdonly", "wasm32-unknown-unknown")["docsrs"], "unknown");
    // native C library on wasm
    let n = findings(&v, "targets/native-build", "nativ");
    assert_eq!(n[0]["severity"], "medium");
    assert_eq!(n[0]["message"], "build script compiles native code with `cc` (links `foo`); there is no C toolchain or system library on wasm32-unknown-unknown");
    // a `links` key without a C build is fine
    assert_eq!(cell(&v, "linksonly", "wasm32-unknown-unknown")["status"], "ok");
    assert_eq!(cell(&v, "nativ", "wasm32-unknown-unknown")["docsrs"], "build-failed");
    // docs.rs was asked for thumbv7em but has no build for it
    let d = findings(&v, "targets/docsrs-missing", "docsy");
    assert_eq!(d.len(), 1, "{}", v["findings"]);
    assert_eq!(d[0]["severity"], "low");
    assert_eq!(cell(&v, "docsy", "thumbv7em-none-eabihf")["status"], "?");
    assert_eq!(cell(&v, "docsy", "wasm32-unknown-unknown")["docsrs"], "not-requested");
    assert_eq!(cell(&v, "purelib", "thumbv7em-none-eabihf")["docsrs"], "built");
    assert_eq!(cell(&v, "purelib", "thumbv7em-none-eabihf")["status"], "ok");
    // no real check: targets not installed, nothing is claimed to fail to build
    assert!(v["findings"].as_array().unwrap().iter().all(|f| f["code"] != "targets/build-fails"));
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("rustup target add wasm32-unknown-unknown")));
    let txt = run_in(&m, &dir, &["targets", "--target", TARGETS, "--all", "--fail-on", "none"]);
    assert_eq!(txt.code, 0);
    assert!(txt.stdout.contains("ok (docs.rs)"), "{}", txt.stdout);
}

#[test]
fn docsrs_unreachable_degrades_gracefully() {
    let m = Mock::start();
    let dir = project(&m, &[("Cargo.toml", &app("purelib = \"1\"\ndocsy = \"1\"\n")), ("src/lib.rs", "#![no_std]\n")], &crates());
    let mut c = m.cmd();
    c.current_dir(&dir).env("SM_DOCSRS_URL", "http://127.0.0.1:9").args(["targets", "--target", "thumbv7em-none-eabihf", "--json", "--fail-on", "low"]);
    let o = run(c);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert!(v["findings"].as_array().unwrap().is_empty(), "{}", v["findings"]);
    assert_eq!(v["data"]["docsrs"]["used"], false);
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("docs.rs build results unavailable")), "{}", v["notes"]);
    assert_eq!(cell(&v, "docsy", "thumbv7em-none-eabihf")["docsrs"], "not-checked");
}

#[test]
fn clean_project_and_bad_target() {
    let m = Mock::start();
    let dir = project(&m, &[("Cargo.toml", &app("purelib = \"1\"\n")), ("src/lib.rs", "#![no_std]\n")], &crates());
    platforms(&m, "purelib", "1.0.0", &["thumbv7em-none-eabihf"]);
    let o = run_in(&m, &dir, &["targets", "--target", TARGETS, "--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert!(v["findings"].as_array().unwrap().is_empty(), "{}", v["findings"]);
    assert!(v["tables"][0]["rows"].as_array().unwrap().is_empty(), "only problematic packages are listed");
    assert_eq!(v["data"]["target_cfg"][1]["has_std"], false);
    let before = m.requests().len();
    let o = run_in(&m, &dir, &["targets", "--target", TARGETS, "--no-docsrs", "--json"]);
    assert_eq!(o.json()["data"]["docsrs"]["used"], false);
    assert_eq!(m.requests().len(), before, "--no-docsrs makes no requests");
    assert_eq!(run_in(&m, &dir, &["targets", "--target", "nonsense-target"]).code, 2);
}
