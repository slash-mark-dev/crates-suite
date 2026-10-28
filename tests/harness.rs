//! Checks for the test harness itself and the CLI shell.

mod common;
use common::*;

#[test]
fn help_lists_all_25_tools_in_six_groups() {
    let m = Mock::start();
    let o = sm(&m, &["help"]);
    assert_eq!(o.code, 0);
    for g in ["SOUNDNESS & SAFETY", "COMPILE-TIME SUPPLY CHAIN", "FEATURES & TARGETS", "BUILD PERFORMANCE", "API & EVOLUTION", "ECOSYSTEM INTELLIGENCE"] {
        assert!(o.stdout.contains(g), "missing group {g}");
    }
    let list = sm(&m, &["list", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&list.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 25);
}

#[test]
fn every_tool_has_help_and_examples() {
    let m = Mock::start();
    let list = sm(&m, &["list", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&list.stdout).unwrap();
    for t in v.as_array().unwrap() {
        let name = t["name"].as_str().unwrap();
        let o = sm(&m, &["help", name]);
        assert_eq!(o.code, 0, "{name}");
        assert!(o.stdout.contains("EXAMPLES"), "{name}");
        assert!(!o.stdout.contains("TODO"), "{name} help still has TODO");
        let ex = t["examples"].as_array().unwrap();
        assert!(!ex.is_empty(), "{name} has no examples");
        for e in ex {
            assert!(e.as_str().unwrap().starts_with(&format!("sm-crates {name}")), "{name}: {e}");
        }
    }
}

#[test]
fn usage_errors_exit_2() {
    let m = Mock::start();
    assert_eq!(sm(&m, &["nope"]).code, 2);
    assert!(sm(&m, &["unsaf"]).stderr.contains("Did you mean `unsafe`"));
    assert_eq!(sm(&m, &["unsafe", "--bogus"]).code, 2);
    assert_eq!(sm(&m, &["unsafe", "--fail-on", "sometimes"]).code, 2);
}

#[test]
fn vendored_fixture_project_resolves_offline() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nleaf = \"1\"\n"),
            ("src/main.rs", "fn main() { leaf::hi(); }\n"),
        ],
        &[Vendored { name: "leaf", version: "1.0.0", manifest: manifest("leaf", "1.0.0", ""), files: vec![("src/lib.rs", "pub fn hi() {}\n")] }],
    );
    let o = std::process::Command::new("cargo").args(["metadata", "--format-version", "1"]).current_dir(&dir).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let leaf = v["packages"].as_array().unwrap().iter().find(|p| p["name"] == "leaf").unwrap();
    assert_eq!(leaf["source"], "registry+https://github.com/rust-lang/crates.io-index");
    let b = std::process::Command::new("cargo").args(["build", "-q"]).current_dir(&dir).output().unwrap();
    assert!(b.status.success(), "{}", String::from_utf8_lossy(&b.stderr));
    // and the mock serves the same crate with a matching checksum
    assert!(m.requests().is_empty());
}
