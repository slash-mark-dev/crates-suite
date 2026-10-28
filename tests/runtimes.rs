mod common;
use common::*;
use serde_json::Value;

const TOKIO_FEATURES: &str = "[features]\nrt = []\nnet = []\nsync = []\nmacros = []\n";

fn crates() -> Vec<Vendored<'static>> {
    vec![
        Vendored { name: "tokio", version: "1.40.0", manifest: manifest("tokio", "1.40.0", TOKIO_FEATURES), files: vec![("src/lib.rs", "")] },
        Vendored { name: "tokio", version: "0.2.25", manifest: manifest("tokio", "0.2.25", ""), files: vec![("src/lib.rs", "")] },
        Vendored { name: "oldhttp", version: "0.1.0", manifest: manifest("oldhttp", "0.1.0", "[dependencies]\ntokio = \"0.2\"\n"), files: vec![("src/lib.rs", "")] },
        Vendored { name: "async-std", version: "1.13.0", manifest: manifest("async-std", "1.13.0", ""), files: vec![("src/lib.rs", "")] },
        Vendored { name: "smol", version: "2.0.0", manifest: manifest("smol", "2.0.0", ""), files: vec![("src/lib.rs", "")] },
    ]
}

fn app(deps: &str, dev: &str) -> String {
    format!("[package]\nname = \"svc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{deps}\n[dev-dependencies]\n{dev}")
}

const BLOCKING: &str = r#"use std::sync::Mutex;
pub async fn handler(m: &Mutex<u8>) {
    std::thread::sleep(std::time::Duration::from_millis(5));
    let g = m.lock().unwrap();
    tick().await;
}
async fn tick() {}
pub fn sync_ok() { std::thread::sleep(std::time::Duration::from_millis(5)); }
"#;

fn run_in(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

fn codes(v: &Value) -> Vec<String> {
    v["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect()
}

#[test]
fn mixed_runtimes_tokio_majors_and_blocking_calls() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &app("tokio = { version = \"1\", features = [\"rt\"] }\noldhttp = \"0.1\"\nasync-std = \"1\"\n", "smol = \"2\"\n")),
            ("src/lib.rs", BLOCKING),
        ],
        &crates(),
    );
    let o = run_in(&m, &dir, &["runtimes", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["tool"], "runtimes");
    let c = codes(&v);
    for want in ["runtimes/mixed", "runtimes/tokio-majors", "runtimes/dev-only", "runtimes/blocking-in-async"] {
        assert!(c.iter().any(|x| x == want), "missing {want}: {c:?}");
    }
    let f = |code: &str| v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == code).cloned().collect::<Vec<Value>>();
    let mixed = &f("runtimes/mixed")[0];
    assert_eq!(mixed["severity"], "high");
    assert!(mixed["message"].as_str().unwrap().contains("async-std, tokio"), "{mixed}");
    let majors = &f("runtimes/tokio-majors")[0];
    assert!(majors["message"].as_str().unwrap().contains("tokio 0.2, tokio 1"), "{majors}");
    assert!(majors["detail"].as_str().unwrap().contains("svc@0.1.0 -> oldhttp@0.1.0 -> tokio@0.2.25"), "{majors}");
    let dev = &f("runtimes/dev-only")[0];
    assert_eq!(dev["crate"], "smol");
    assert_eq!(dev["severity"], "info");
    let blocking = f("runtimes/blocking-in-async");
    assert_eq!(blocking.len(), 2, "{blocking:?}");
    assert_eq!(blocking[0]["location"]["line"], 3);
    assert_eq!(blocking[1]["location"]["line"], 4);
    assert!(blocking[1]["message"].as_str().unwrap().contains("Mutex guard `g` is held across `.await` (line 5)"));
    assert_eq!(v["data"]["families"], serde_json::json!(["async-std", "tokio"]));
    assert_eq!(v["data"]["blocking"][0]["kind"], "thread-sleep");
    let tokio1 = v["data"]["runtimes"].as_array().unwrap().iter().find(|r| r["version"] == "1.40.0").unwrap();
    assert_eq!(tokio1["release"], true);
    assert_eq!(tokio1["executor_only"], false);
    // --no-scan skips the source scan; findings below high do not fail
    let o = run_in(&m, &dir, &["runtimes", "--no-scan", "--json", "--fail-on", "critical"]);
    assert_eq!(o.code, 0);
    assert!(!codes(&o.json()).iter().any(|c| c == "runtimes/blocking-in-async"));
}

#[test]
fn single_runtime_and_utility_tokio_are_clean() {
    let m = Mock::start();
    // tokio with only `sync` is runtime-agnostic: no conflict with async-std
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &app("tokio = { version = \"1\", features = [\"sync\"] }\nasync-std = \"1\"\n", "")),
            ("src/lib.rs", "pub async fn f() { let _ = tokio_like().await; }\nasync fn tokio_like() {}\n"),
        ],
        &crates(),
    );
    let o = run_in(&m, &dir, &["runtimes", "--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert!(v["findings"].as_array().unwrap().is_empty(), "{}", v["findings"]);
    assert_eq!(v["data"]["families"], serde_json::json!(["async-std"]));
    let t = run_in(&m, &dir, &["runtimes"]);
    assert!(t.stdout.contains("tokio 1 (utilities only, no runtime features)"), "{}", t.stdout);
    assert!(t.stdout.contains("No findings."));

    let none = project(&m, &[("Cargo.toml", &app("", "")), ("src/lib.rs", "")], &[]);
    let o = run_in(&m, &none, &["runtimes", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("no async runtime"), "{}", o.stdout);
}

#[test]
fn dev_only_tokio_features_do_not_make_release_tokio_a_runtime() {
    let m = Mock::start();
    // release: tokio with `sync` only; tests turn on `rt`. Resolver 2 keeps `rt` out of the release build.
    let dir = project(
        &m,
        &[
            ("Cargo.toml", &app("tokio = { version = \"1\", features = [\"sync\"] }\nasync-std = \"1\"\n", "tokio = { version = \"1\", features = [\"rt\"] }\n")),
            ("src/lib.rs", ""),
        ],
        &crates(),
    );
    let o = run_in(&m, &dir, &["runtimes", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert!(!codes(&v).iter().any(|c| c == "runtimes/mixed"), "{}", v["findings"]);
    assert_eq!(v["data"]["families"], serde_json::json!(["async-std"]));
}
