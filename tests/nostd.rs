mod common;
use common::*;
use serde_json::{Value, json};

fn crates() -> Vec<Vendored<'static>> {
    vec![
        Vendored {
            name: "stdy",
            version: "1.0.0",
            manifest: manifest("stdy", "1.0.0", ""),
            files: vec![("src/lib.rs", "pub fn f() -> std::string::String { String::new() }\n")],
        },
        Vendored {
            name: "nos",
            version: "1.0.0",
            manifest: manifest("nos", "1.0.0", "[features]\ndefault = [\"std\"]\nstd = []\nfast = []\n"),
            files: vec![("src/lib.rs", "#![cfg_attr(not(feature = \"std\"), no_std)]\npub fn f() {}\n")],
        },
        Vendored {
            name: "allocy",
            version: "1.0.0",
            manifest: manifest("allocy", "1.0.0", ""),
            files: vec![("src/lib.rs", "#![no_std]\nextern crate alloc;\npub fn f() -> alloc::vec::Vec<u8> { alloc::vec::Vec::new() }\n")],
        },
    ]
}

fn root(deps: &str) -> String {
    format!("[package]\nname = \"fw\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{deps}")
}

fn run_in(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

fn dep<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["data"]["dependencies"].as_array().unwrap().iter().find(|d| d["crate"] == name).unwrap_or_else(|| panic!("{name} missing: {v}"))
}

#[test]
fn blocking_dependencies_with_fixes() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[("Cargo.toml", &root("stdy = \"1\"\nnos = { version = \"1\", features = [\"fast\"] }\nallocy = \"1\"\n")), ("src/lib.rs", "#![no_std]\npub fn x() {}\n")],
        &crates(),
    );
    // a newer stdy has a `std` feature
    m.publish("stdy", "1.2.0", &[("src/lib.rs", "")], json!({"features": {"std": []}, "rust_version": "1.70"}));
    let o = run_in(&m, &dir, &["nostd", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["tool"], "nostd");
    assert_eq!(v["data"]["root"]["declares_no_std"], true);
    let blocking: Vec<&Value> = v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == "nostd/blocking-dep").collect();
    assert_eq!(blocking.len(), 2, "{}", v["findings"]);
    assert!(blocking.iter().all(|f| f["severity"] == "high"));
    let nos = dep(&v, "nos");
    assert_eq!(nos["status"], "std via feature std");
    assert_eq!(nos["blocking"], true);
    assert!(nos["enabled_by"].as_str().unwrap().contains("fw@0.1.0 (default features on)"), "{nos}");
    assert_eq!(nos["fix"], "nos = { version = \"1\", default-features = false, features = [\"fast\"] }");
    let stdy = dep(&v, "stdy");
    assert_eq!(stdy["status"], "always std");
    assert!(stdy["fix"].as_str().unwrap().contains("stdy@1.2.0 has a `std` feature"), "{stdy}");
    assert!(stdy["fix"].as_str().unwrap().contains("rust-version 1.70"), "{stdy}");
    let allocy = dep(&v, "allocy");
    assert_eq!(allocy["blocking"], false);
    assert_eq!(allocy["needs_alloc"], true);
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["code"] == "nostd/needs-alloc" && f["severity"] == "info"));
    assert_eq!(run_in(&m, &dir, &["nostd", "--fail-on", "critical"]).code, 0);
}

#[test]
fn clean_no_std_build_and_uninstalled_target() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &root("nos = { version = \"1\", default-features = false }\n\n[features]\nstd = [\"nos/std\"]\n")),
            ("src/lib.rs", "#![cfg_attr(not(feature = \"std\"), no_std)]\npub fn x() {}\n"),
        ],
        &crates(),
    );
    let o = run_in(&m, &dir, &["nostd", "--target", "thumbv7em-none-eabihf", "--all", "--json", "--fail-on", "low"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert!(v["findings"].as_array().unwrap().is_empty(), "{}", v["findings"]);
    assert_eq!(v["data"]["target"], "thumbv7em-none-eabihf");
    assert_eq!(v["data"]["target_has_std"], false);
    assert_eq!(dep(&v, "nos")["status"], "no_std");
    assert_eq!(v["tables"][0]["rows"][0][0], "nos");
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("rustup target add thumbv7em-none-eabihf")), "{}", v["notes"]);

    // the root's own std feature turns nos/std on: fix is to build without it
    let o = run_in(&m, &dir, &["nostd", "--features", "std", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let v = o.json();
    let nos = dep(&v, "nos");
    assert_eq!(nos["status"], "std via feature std");
    assert!(nos["fix"].as_str().unwrap().starts_with("turn off fw's feature `std`"), "{nos}");
    assert_eq!(v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "nostd/blocking-dep").unwrap()["severity"], "medium");

    assert_eq!(run_in(&m, &dir, &["nostd", "--target", "not-a-target"]).code, 2);
}
