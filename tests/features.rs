mod common;
use common::*;
use serde_json::{Value, json};

fn app(edition: &str, deps: &str) -> String {
    format!("[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"{edition}\"\n\n{deps}")
}

fn vendored() -> Vec<Vendored<'static>> {
    vec![
        Vendored {
            name: "lib1",
            version: "1.0.0",
            manifest: manifest("lib1", "1.0.0", "[features]\nextra = []\n"),
            files: vec![("src/lib.rs", "pub fn f() {}\n#[cfg(feature = \"extra\")]\npub fn g() {}\n")],
        },
        Vendored {
            name: "fat",
            version: "2.0.0",
            manifest: manifest("fat", "2.0.0", "[dependencies]\nleafx = { version = \"1\", optional = true }\n\n[features]\ndefault = [\"std\", \"heavy\"]\nstd = []\nheavy = [\"dep:leafx\"]\n"),
            files: vec![("src/lib.rs", "pub fn f() {}\n")],
        },
        Vendored { name: "leafx", version: "1.0.0", manifest: manifest("leafx", "1.0.0", ""), files: vec![("src/lib.rs", "pub fn l() {}\n")] },
    ]
}

fn run_in(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

fn find<'a>(v: &'a Value, code: &str) -> Vec<&'a Value> {
    v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == code).collect()
}

#[test]
fn resolver_1_dev_dependency_bleeds_into_release() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &app("2018", "[dependencies]\nlib1 = \"1\"\n\n[dev-dependencies]\nlib1 = { version = \"1\", features = [\"extra\"] }\n")),
            ("src/lib.rs", "pub fn x() { lib1::f() }\n"),
        ],
        &vendored(),
    );
    let o = run_in(&m, &dir, &["features", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["tool"], "features");
    assert_eq!(v["data"]["resolver"], "1");
    assert!(v["data"]["resolver_reason"].as_str().unwrap().contains("edition 2018"));
    let r1 = find(&v, "features/resolver-v1");
    assert_eq!(r1.len(), 1);
    assert_eq!(r1[0]["severity"], "high");
    assert!(r1[0]["detail"].as_str().unwrap().contains("lib1 (dev)"), "{}", r1[0]);
    let bleed = find(&v, "features/bleed");
    assert_eq!(bleed.len(), 1, "{}", v["findings"]);
    assert_eq!(bleed[0]["crate"], "lib1");
    assert_eq!(bleed[0]["severity"], "high");
    assert!(bleed[0]["message"].as_str().unwrap().contains("`extra`") && bleed[0]["message"].as_str().unwrap().contains("dev-dependency"));
    assert!(bleed[0]["detail"].as_str().unwrap().contains("app@0.1.0 (dev)"), "{}", bleed[0]);
    assert_eq!(v["data"]["bleed"][0]["package"], "lib1@1.0.0");
    // --why explains the chain
    let w = run_in(&m, &dir, &["features", "--why", "lib1/extra", "--json", "--fail-on", "none"]);
    assert_eq!(w.code, 0, "{}", w.stderr);
    let wv = w.json();
    let chain = &wv["data"]["chains"][0];
    assert_eq!(chain["by"], "app@0.1.0");
    assert_eq!(chain["kind"], "dev");
    assert!(chain["how"].as_str().unwrap().contains("features = [\"extra\"]"), "{chain}");
    assert_eq!(run_in(&m, &dir, &["features", "--why", "nothere"]).code, 2);
}

#[test]
fn resolver_2_test_only_features_and_droppable_defaults() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &app("2021", "[dependencies]\nlib1 = \"1\"\nfat = \"2\"\n\n[dev-dependencies]\nlib1 = { version = \"1\", features = [\"extra\"] }\n")),
            ("src/lib.rs", "pub fn x() { lib1::f(); fat::f() }\n"),
        ],
        &vendored(),
    );
    let o = run_in(&m, &dir, &["features", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["resolver"], "2");
    assert!(find(&v, "features/resolver-v1").is_empty());
    assert!(find(&v, "features/bleed").is_empty(), "{}", v["findings"]);
    let t = find(&v, "features/test-only");
    assert_eq!(t.len(), 1, "{}", v["findings"]);
    assert_eq!(t[0]["crate"], "lib1");
    assert_eq!(t[0]["severity"], "low");
    let d = find(&v, "features/droppable-default");
    assert_eq!(d.len(), 1, "{}", v["findings"]);
    assert!(d[0]["message"].as_str().unwrap().contains("leafx@1.0.0"), "{}", d[0]);
    assert_eq!(v["data"]["droppable_defaults"][0]["suggestion"], "fat = { version = \"2\", default-features = false, features = [\"std\"] }");
    let lib1 = v["data"]["packages"].as_array().unwrap().iter().find(|p| p["package"] == "lib1@1.0.0").unwrap();
    assert_eq!(lib1["release"], json!([]));
    assert_eq!(lib1["test_only"], json!(["extra"]));
    assert_eq!(run_in(&m, &dir, &["features", "--fail-on", "low"]).code, 1);
}

#[test]
fn clean_project_and_virtual_workspace() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[("Cargo.toml", &app("2021", "[dependencies]\nlib1 = { version = \"1\", features = [\"extra\"] }\n")), ("src/lib.rs", "pub fn x() {}\n")],
        &vendored(),
    );
    let o = run_in(&m, &dir, &["features", "--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    assert!(o.json()["findings"].as_array().unwrap().is_empty());
    let txt = run_in(&m, &dir, &["features", "--all"]);
    assert!(txt.stdout.contains("lib1@1.0.0") && txt.stdout.contains("No findings."), "{}", txt.stdout);

    // a virtual workspace without `resolver` uses resolver 1, even with nothing to leak yet
    let ws = project(
        &m,
        &[("Cargo.toml", "[workspace]\nmembers = [\"a\"]\n"), ("a/Cargo.toml", &app("2021", "")), ("a/src/lib.rs", "")],
        &[],
    );
    let o = run_in(&m, &ws, &["features", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["resolver"], "1");
    let r1 = find(&v, "features/resolver-v1");
    assert_eq!(r1[0]["severity"], "low");
    assert_eq!(r1[0]["location"]["file"], "Cargo.toml");
}

#[test]
fn features_enabled_by_a_bleeding_feature_are_not_unexplained() {
    let m = Mock::start();
    // resolver 1: the dev-dependency turns `default` on, and `default` turns on `std` and `heavy`
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &app("2018", "[dependencies]\nfat = { version = \"2\", default-features = false }\n\n[dev-dependencies]\nfat = \"2\"\n")),
            ("src/lib.rs", "pub fn x() { fat::f() }\n"),
        ],
        &vendored(),
    );
    let o = run_in(&m, &dir, &["features", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let bleed = find(&v, "features/bleed");
    assert_eq!(bleed.len(), 1, "{}", v["findings"]);
    assert!(bleed[0]["message"].as_str().unwrap().contains("`default`"), "{}", bleed[0]);
    let notes: Vec<&str> = v["notes"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
    assert!(notes.iter().any(|n| n.contains("only because a bleeding feature enables them") && n.contains("fat@2.0.0[std]") && n.contains("fat@2.0.0[heavy]")), "{notes:?}");
    assert!(!notes.iter().any(|n| n.contains("could not be attributed")), "{notes:?}");
}
