//! `sm-crates futurecompat`: a real `cargo check --future-incompat-report` on fixture
//! projects with a vendored dependency, crates.io index and crater results from the mock.

mod common;
use common::*;
use serde_json::json;

/// Code that rustc 1.85+ reports as future-incompatible (semicolon in a macro used as an
/// expression, and never-type fallback that breaks in Rust 2024).
const FCW_LIB: &str = "macro_rules! one { () => { 1; } }\npub fn a() -> i32 { let x = one!(); x }\nfn foo<T: Default>() -> Result<T, ()> { Ok(T::default()) }\npub fn bar() -> Result<(), ()> { foo()?; Ok(()) }\n";

fn app(m: &Mock, dep: &str, lib: &'static str) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", &format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{dep} = \"1\"\nleaf = \"1\"\n")),
            ("src/main.rs", "fn main() {}\n"),
        ],
        &[
            Vendored { name: dep, version: "1.0.0", manifest: manifest(dep, "1.0.0", ""), files: vec![("src/lib.rs", lib)] },
            Vendored { name: "leaf", version: "1.0.0", manifest: manifest("leaf", "1.0.0", ""), files: vec![("src/lib.rs", "pub fn hi() {}\n")] },
        ],
    )
}

fn fc(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.env("SM_CRATER_URL", format!("{}/crater", m.url)).arg("futurecompat").arg("--project").arg(dir).args(args);
    run(c)
}

#[test]
fn dependency_warnings_updates_and_crater() {
    let m = Mock::start();
    let dir = app(&m, "fcdep", FCW_LIB);
    // a compatible fix release exists on the (mock) index
    m.publish("fcdep", "1.0.1", &[("src/lib.rs", "pub fn a() -> i32 { 1 }\n")], json!({}));
    m.route("/crater/beta-1.99-1/retry-regressed-list.txt", 200, "leaf\nsomething-else\nrust-lang/regex\n");
    let o = fc(&m, &dir, &["--crater", "beta-1.99-1", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let items = v["data"]["items"].as_array().unwrap();
    let lints: Vec<&str> = items.iter().filter_map(|i| i["lint"].as_str()).collect();
    assert!(lints.contains(&"semicolon_in_expressions_from_macros"), "{v:#}");
    assert!(lints.contains(&"dependency_on_unit_never_type_fallback"), "{v:#}");
    for i in items {
        assert_eq!(i["package"], "fcdep");
        assert_eq!(i["own_code"], false);
        assert_eq!(i["update"], json!({"kind": "compatible", "version": "1.0.1"}));
    }
    let fs = v["findings"].as_array().unwrap();
    let dep: Vec<&serde_json::Value> = fs.iter().filter(|f| f["code"] == "futurecompat/dependency").collect();
    assert_eq!(dep.len(), 2, "{v:#}");
    // "in Rust 2024 and in a future release" names an edition: high; the other one: medium
    assert!(dep.iter().any(|f| f["severity"] == "high"));
    assert!(dep.iter().any(|f| f["severity"] == "medium"));
    assert!(dep[0]["fix"].as_str().unwrap().contains("cargo update -p fcdep@1.0.0"));
    // crater: leaf is locked at its newest version, so the regression applies as-is
    let cr: Vec<&serde_json::Value> = fs.iter().filter(|f| f["code"] == "futurecompat/crater-regression").collect();
    assert_eq!(cr.len(), 1, "{v:#}");
    assert_eq!(cr[0]["crate"], "leaf");
    assert_eq!(cr[0]["severity"], "medium");
    assert_eq!(v["data"]["crater"]["status"], "ok");
    assert_eq!(v["data"]["crater"]["regressed_total"], 2);
    assert!(v["summary"].as_str().unwrap().contains("1 dependency(ies) regressed in crater run beta-1.99-1"), "{}", v["summary"]);
    // Rust release data comes from the (mock) dist server, which has nothing: a note, not an error
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("channel data unavailable")));
    assert!(m.requests().iter().any(|r| r.contains("/index/fc/de/fcdep")));

    // --fail-on decides the exit code; the cached second run still sees the report
    assert_eq!(fc(&m, &dir, &["--crater", "beta-1.99-1", "--fail-on", "high"]).code, 1);
    let txt = fc(&m, &dir, &["--crater", "beta-1.99-1", "--no-crater", "--fail-on", "critical"]);
    assert_eq!(txt.code, 0, "{}", txt.stderr);
    assert!(txt.stdout.contains("Future-incompatibility warnings") && txt.stdout.contains("cargo update → 1.0.1"), "{}", txt.stdout);
    assert!(!txt.stdout.contains("Crater regressions"));
    // the project's own tree is untouched
    assert!(!dir.join("target").exists());
}

#[test]
fn verify_runs_in_a_copy() {
    let m = Mock::start();
    // both releases are vendored; the lock file pins the broken 1.0.0
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nfcdep = \"1\"\n"),
            ("src/main.rs", "fn main() {}\n"),
        ],
        &[
            Vendored { name: "fcdep", version: "1.0.0", manifest: manifest("fcdep", "1.0.0", ""), files: vec![("src/lib.rs", FCW_LIB)] },
            Vendored { name: "fcdep", version: "1.0.1", manifest: manifest("fcdep", "1.0.1", ""), files: vec![("src/lib.rs", "pub fn a() -> i32 { 1 }\n")] },
        ],
    );
    let g = std::process::Command::new("cargo").args(["generate-lockfile", "--offline"]).current_dir(&dir).output().unwrap();
    assert!(g.status.success(), "{}", String::from_utf8_lossy(&g.stderr));
    let ck = |v: &str| -> String {
        let t = std::fs::read_to_string(dir.join(format!("vendor/fcdep-{v}/.cargo-checksum.json"))).unwrap();
        serde_json::from_str::<serde_json::Value>(&t).unwrap()["package"].as_str().unwrap().to_string()
    };
    let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap().replace("version = \"1.0.1\"", "version = \"1.0.0\"").replace(&ck("1.0.1"), &ck("1.0.0"));
    std::fs::write(dir.join("Cargo.lock"), lock).unwrap();
    let lock_before = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap();
    assert!(lock_before.contains("version = \"1.0.0\""), "{lock_before}");
    let o = fc(&m, &dir, &["--verify", "--no-crater", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    let it = &v["data"]["items"][0];
    assert_eq!(it["update"], json!({"kind": "compatible", "version": "1.0.1"}), "{v:#}");
    assert_eq!(it["verified"], json!({"result": "fixed", "version": "1.0.1"}), "{v:#}");
    assert!(v["findings"][0]["detail"].as_str().unwrap().contains("the warning is gone"));
    // the update happened in a temporary copy only
    assert_eq!(std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(), lock_before);
}

#[test]
fn clean_project_and_crater_not_published() {
    let m = Mock::start();
    let dir = app(&m, "okdep", "pub fn a() -> i32 { 1 }\n");
    let o = fc(&m, &dir, &["--crater", "beta-1.99-1", "--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0, "{v:#}");
    assert_eq!(v["data"]["items"], json!([]));
    assert_eq!(v["data"]["crater"]["status"], "not-found");
    assert!(v["summary"].as_str().unwrap().contains("nothing in the build is known to break"));
    assert!(v["summary"].as_str().unwrap().contains("crater results could not be checked"), "{}", v["summary"]);
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("no report published for beta-1.99-1")));
    // JSON shape shared by every tool
    for k in ["tool", "subject", "summary", "counts", "findings", "tables", "notes", "data"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(v["tool"], "futurecompat");
}

#[test]
fn own_code_and_no_project() {
    let m = Mock::start();
    let dir = project(&m, &[("Cargo.toml", "[package]\nname = \"mine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"), ("src/lib.rs", FCW_LIB)], &[]);
    let o = fc(&m, &dir, &["--no-crater", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let own: Vec<&serde_json::Value> = v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == "futurecompat/own-code").collect();
    assert!(own.len() >= 2, "{v:#}");
    assert!(own.iter().all(|f| f["severity"] == "high" && f["crate"] == "mine"));
    assert!(own.iter().any(|f| f["location"]["file"] == "src/lib.rs"));
    // these lints are deny-by-default in your own code, so the build itself fails
    assert_eq!(v["data"]["build_success"], false);
    assert!(v["summary"].as_str().unwrap().contains("cargo check failed"), "{}", v["summary"]);
    let empty = temp_dir("empty");
    assert_eq!(fc(&m, &empty, &[]).code, 3);
}

#[test]
fn dependency_that_no_longer_builds_is_a_finding() {
    // a dependency that fails on the current stable compiler is the end state of a
    // future-incompatibility warning: it must not come out as "no findings"
    let m = Mock::start();
    let dir = app(&m, "brokendep", "pub fn a() -> u32 { \"not a number\" }\n");
    let o = fc(&m, &dir, &["--no-crater", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let f: Vec<&serde_json::Value> = v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == "futurecompat/build-fails").collect();
    assert_eq!(f.len(), 1, "{v:#}");
    assert_eq!(f[0]["crate"], "brokendep");
    assert!(f[0]["detail"].as_str().unwrap().contains("E0308"), "{v:#}");
    assert!(v["summary"].as_str().unwrap().contains("cargo check failed"));
}

#[test]
fn verify_copies_the_whole_workspace_for_a_member_project() {
    // --project pointing at a workspace member: the copy must hold the workspace root
    // (its Cargo.lock and [workspace]), not just the member directory
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n\n[workspace.package]\nedition = \"2021\"\n"),
            ("app/Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition.workspace = true\n\n[dependencies]\nfcdep = \"1\"\n"),
            ("app/src/main.rs", "fn main() {}\n"),
        ],
        &[
            Vendored { name: "fcdep", version: "1.0.0", manifest: manifest("fcdep", "1.0.0", ""), files: vec![("src/lib.rs", FCW_LIB)] },
            Vendored { name: "fcdep", version: "1.0.1", manifest: manifest("fcdep", "1.0.1", ""), files: vec![("src/lib.rs", "pub fn a() -> i32 { 1 }\n")] },
        ],
    );
    let g = std::process::Command::new("cargo").args(["generate-lockfile", "--offline"]).current_dir(&dir).env_remove("CARGO_TARGET_DIR").output().unwrap();
    assert!(g.status.success(), "{}", String::from_utf8_lossy(&g.stderr));
    let ck = |v: &str| -> String {
        let t = std::fs::read_to_string(dir.join(format!("vendor/fcdep-{v}/.cargo-checksum.json"))).unwrap();
        serde_json::from_str::<serde_json::Value>(&t).unwrap()["package"].as_str().unwrap().to_string()
    };
    let lock = std::fs::read_to_string(dir.join("Cargo.lock")).unwrap().replace("version = \"1.0.1\"", "version = \"1.0.0\"").replace(&ck("1.0.1"), &ck("1.0.0"));
    std::fs::write(dir.join("Cargo.lock"), &lock).unwrap();
    let o = fc(&m, &dir.join("app"), &["--verify", "--no-crater", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["items"][0]["verified"], json!({"result": "fixed", "version": "1.0.1"}), "{v:#}");
    assert_eq!(std::fs::read_to_string(dir.join("Cargo.lock")).unwrap(), lock);
}
