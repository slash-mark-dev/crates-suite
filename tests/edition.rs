//! `sm-crates edition`: a real `cargo check` with the rust-20xx-compatibility lint groups,
//! and `cargo fix --edition` in a temporary copy, on fixture workspaces.

mod common;
use common::*;
use serde_json::Value;

fn edition(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.arg("edition").arg("--project").arg(dir).args(args);
    run(c)
}

fn member<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["data"]["members"].as_array().unwrap().iter().find(|p| p["name"] == name).unwrap_or_else(|| panic!("no member {name}: {v:#}"))
}

/// `core_a` needs a manual fix (static mut reference) and an automatic one (`gen` keyword);
/// `cli_b` depends on it and is clean; `done_c` is already on 2024.
fn workspace(m: &Mock) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"cli_b\", \"core_a\", \"done_c\"]\nresolver = \"2\"\n"),
            ("core_a/Cargo.toml", "[package]\nname = \"core_a\"\nversion = \"0.1.0\"\nedition = \"2021\"\nrust-version = \"1.80\"\n"),
            ("core_a/src/lib.rs", "static mut N: u32 = 0;\npub fn gen() -> u32 { 1 }\npub fn peek() -> u32 { let r = unsafe { &N }; *r }\n"),
            ("cli_b/Cargo.toml", "[package]\nname = \"cli_b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore_a = { path = \"../core_a\" }\n"),
            ("cli_b/src/main.rs", "fn main() { println!(\"{}\", core_a::peek()); }\n"),
            ("done_c/Cargo.toml", "[package]\nname = \"done_c\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"),
            ("done_c/src/lib.rs", "pub fn x() {}\n"),
        ],
        &[],
    )
}

#[test]
fn plans_members_leaves_first_with_lints() {
    let m = Mock::start();
    let dir = workspace(&m);
    let o = edition(&m, &dir, &["--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let order: Vec<&str> = v["data"]["members"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    let pos = |n: &str| order.iter().position(|x| *x == n).unwrap();
    assert!(pos("core_a") < pos("cli_b"), "core_a is migrated before the member that depends on it: {order:?}");
    let a = member(&v, "core_a");
    assert_eq!(a["target"], "2024");
    assert_eq!(a["needs_migration"], true);
    let lints: Vec<&str> = a["lints"].as_array().unwrap().iter().map(|l| l["lint"].as_str().unwrap()).collect();
    assert!(lints.contains(&"keyword_idents_2024") && lints.contains(&"static_mut_refs"), "{lints:?}");
    assert!(a["auto_fixable"].as_u64().unwrap() >= 1 && a["manual"].as_u64().unwrap() >= 1, "{a:#}");
    let b = member(&v, "cli_b");
    assert_eq!(b["lints"], serde_json::json!([]));
    assert_eq!(member(&v, "done_c")["needs_migration"], false);
    let fs = v["findings"].as_array().unwrap();
    let manual = fs.iter().find(|f| f["code"] == "edition/manual-fix").unwrap_or_else(|| panic!("{v:#}"));
    assert_eq!(manual["crate"], "core_a");
    assert_eq!(manual["severity"], "medium");
    assert!(manual["location"]["file"].as_str().unwrap().ends_with("src/lib.rs"));
    let rv = fs.iter().find(|f| f["code"] == "edition/rust-version-too-low").unwrap();
    assert_eq!(rv["severity"], "high");
    assert!(rv["message"].as_str().unwrap().contains("needs 1.85"));
    assert!(fs.iter().any(|f| f["code"] == "edition/no-rust-version" && f["crate"] == "cli_b"));
    // high finding: the default --fail-on fails
    assert_eq!(edition(&m, &dir, &[]).code, 1);
    // --package narrows the plan
    let only = edition(&m, &dir, &["--package", "cli_b", "--json", "--fail-on", "none"]).json();
    assert_eq!(only["data"]["members"].as_array().unwrap().len(), 1);
    assert!(!dir.join("target").exists(), "the private target dir is under the cache");
}

#[test]
fn dry_run_fix_compiles_in_a_copy() {
    let m = Mock::start();
    let src = "pub fn gen() -> u32 { 1 }\npub fn call() -> u32 { gen() }\nextern \"C\" { pub fn abs(x: i32) -> i32; }\n";
    let dir = project(&m, &[("Cargo.toml", "[package]\nname = \"fixme\"\nversion = \"0.1.0\"\nedition = \"2021\"\nrust-version = \"1.85\"\n"), ("src/lib.rs", src)], &[]);
    let o = edition(&m, &dir, &["--dry-run-fix", "--json", "--fail-on", "low"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let a = member(&v, "fixme");
    assert_eq!(a["manual"], 0, "{a:#}");
    assert!(a["auto_fixable"].as_u64().unwrap() >= 2);
    let dr = &v["data"]["dry_run"];
    assert_eq!(dr["fix_ok"], true, "{dr:#}");
    assert_eq!(dr["compiles"], true, "{dr:#}");
    let changed: Vec<&str> = dr["files_changed"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert!(changed.contains(&"src/lib.rs") && changed.contains(&"Cargo.toml"), "{changed:?}");
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["code"] == "edition/dry-run-ok"));
    // the real tree is untouched
    assert_eq!(std::fs::read_to_string(dir.join("src/lib.rs")).unwrap(), src);
    assert!(std::fs::read_to_string(dir.join("Cargo.toml")).unwrap().contains("edition = \"2021\""));
}

#[test]
fn already_migrated_and_errors() {
    let m = Mock::start();
    let dir = project(&m, &[("Cargo.toml", "[package]\nname = \"new\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"), ("src/lib.rs", "pub fn x() {}\n")], &[]);
    let o = edition(&m, &dir, &["--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    assert!(v["summary"].as_str().unwrap().starts_with("nothing to migrate"));
    for k in ["tool", "subject", "summary", "counts", "findings", "tables", "notes", "data"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(edition(&m, &dir, &["--to", "2027"]).code, 2);
    assert_eq!(edition(&m, &dir, &["--package", "missing"]).code, 2);
    assert_eq!(edition(&m, &temp_dir("none"), &[]).code, 3);
}

#[test]
fn older_member_only_gets_its_own_edition_step() {
    // a 2018 member moving to 2021 must not be charged with 2024 lints that the
    // 2021 member's step turns on for the whole check
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"old\", \"mid\"]\nresolver = \"2\"\n"),
            ("old/Cargo.toml", "[package]\nname = \"old\"\nversion = \"0.1.0\"\nedition = \"2018\"\n"),
            ("old/src/lib.rs", "pub fn gen() -> u32 { 1 }\n"),
            ("mid/Cargo.toml", "[package]\nname = \"mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
            ("mid/src/lib.rs", "pub fn gen() -> u32 { 1 }\n"),
        ],
        &[],
    );
    let v = edition(&m, &dir, &["--json", "--fail-on", "none"]).json();
    assert_eq!(member(&v, "old")["target"], "2021");
    assert_eq!(member(&v, "old")["lints"], serde_json::json!([]), "{v:#}");
    assert_eq!(member(&v, "mid")["lints"][0]["lint"], "keyword_idents_2024");
}

#[test]
fn dry_run_raises_a_too_low_rust_version_in_the_copy() {
    // cargo refuses a manifest whose rust-version predates its edition; the dry run must
    // raise it in the copy instead of reporting "failed to load manifest" as a code problem
    let m = Mock::start();
    let manifest = "[package]\nname = \"oldmsrv\"\nversion = \"0.1.0\"\nedition = \"2021\"\nrust-version = \"1.70\"\n";
    let dir = project(&m, &[("Cargo.toml", manifest), ("src/lib.rs", "pub fn gen() -> u32 { 1 }\n")], &[]);
    let v = edition(&m, &dir, &["--dry-run-fix", "--json", "--fail-on", "none"]).json();
    let dr = &v["data"]["dry_run"];
    assert_eq!(dr["compiles"], true, "{v:#}");
    assert_eq!(dr["rust_version_raised"], serde_json::json!(["oldmsrv 1.70 → 1.85"]), "{dr:#}");
    assert!(!v["findings"].as_array().unwrap().iter().any(|f| f["code"] == "edition/fix-breaks-build"), "{v:#}");
    assert!(v["findings"].as_array().unwrap().iter().any(|f| f["code"] == "edition/rust-version-too-low"));
    assert_eq!(std::fs::read_to_string(dir.join("Cargo.toml")).unwrap(), manifest);
}
