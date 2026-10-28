//! `sm-crates timings`: a real `cargo build --timings` on a fixture project, and
//! reports in both the current (cargo 1.97: `unblocked_*`, `sections`) and the
//! older (`unlocked_*`, `rmeta_time`) layouts.

mod common;
use common::*;

fn app(m: &Mock) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nleaf = \"1\"\n"),
            ("src/main.rs", "fn main() { println!(\"{}\", leaf::hi()); }\n"),
        ],
        &[Vendored {
            name: "leaf",
            version: "1.0.0",
            manifest: manifest("leaf", "1.0.0", ""),
            files: vec![("src/lib.rs", "pub fn hi() -> u32 { (1..10u32).map(|x| x * 2).sum() }\n"), ("build.rs", "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n")],
        }],
    )
}

#[test]
fn real_clean_build_critical_path() {
    let m = Mock::start();
    let dir = app(&m);
    let o = sm(&m, &["timings", "--clean", "--json", "--project", dir.to_str().unwrap()]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let d = &v["data"];
    assert!(d["units"].as_u64().unwrap() >= 4, "{d}"); // build script compile + run, leaf, app
    let path = d["critical_path"].as_array().unwrap();
    assert_eq!(path.last().unwrap()["name"], "app", "{d}");
    assert!(path.iter().any(|s| s["name"] == "leaf"), "leaf blocks app: {d}");
    assert!(d["wall_secs"].as_f64().unwrap() > 0.0);
    assert!(v["summary"].as_str().unwrap().contains("critical path"));
    // the private target dir is under the cache, the project's target/ is untouched
    assert!(!dir.join("target").exists());
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains(m.cache.to_str().unwrap())));
}

const CURRENT: &str = r#"<html><script>
const UNIT_DATA = [
  {"i": 0, "name": "proc-macro2", "version": "1.0.0", "mode": "todo", "target": "", "features": [], "start": 0.3, "duration": 1.6,
   "unblocked_units": [], "unblocked_rmeta_units": [1], "sections": [["frontend", {"start": 0.0, "end": 1.1}], ["codegen", {"start": 1.1, "end": 1.6}]]},
  {"i": 1, "name": "syn", "version": "2.0.0", "mode": "todo", "target": "", "features": [], "start": 1.5, "duration": 4.0,
   "unblocked_units": [2], "unblocked_rmeta_units": [], "sections": [["frontend", {"start": 0.0, "end": 3.0}], ["codegen", {"start": 3.0, "end": 4.0}]]},
  {"i": 2, "name": "serde_derive", "version": "1.0.0", "mode": "todo", "target": "", "features": [], "start": 5.5, "duration": 3.0,
   "unblocked_units": [3], "unblocked_rmeta_units": [], "sections": null},
  {"i": 3, "name": "app", "version": "0.1.0", "mode": "todo", "target": " app \"bin\"", "features": [], "start": 8.5, "duration": 1.5,
   "unblocked_units": [], "unblocked_rmeta_units": [], "sections": null},
  {"i": 4, "name": "ring", "version": "0.17.0", "mode": "run-custom-build", "target": " build-script (run)", "features": [], "start": 0.0, "duration": 2.0,
   "unblocked_units": [], "unblocked_rmeta_units": [], "sections": null}
];
const CONCURRENCY_DATA = [{"t": 0.0, "active": 2, "waiting": 0, "inactive": 3}, {"t": 10.0, "active": 0, "waiting": 0, "inactive": 0}];
</script></html>"#;

#[test]
fn analyzes_an_existing_report() {
    let m = Mock::start();
    let d = temp_dir("timing");
    let f = d.join("cargo-timing.html");
    std::fs::write(&f, CURRENT).unwrap();
    let o = sm(&m, &["timings", "--file", f.to_str().unwrap(), "--json", "--top", "2"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    let names: Vec<&str> = v["data"]["critical_path"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["proc-macro2", "syn", "serde_derive", "app"]);
    assert_eq!(v["data"]["critical_path"][0]["rmeta_only"], true);
    assert_eq!(v["data"]["longest"].as_array().unwrap().len(), 2);
    assert_eq!(v["data"]["parallelism"], 2.0);
    let codes = o.codes();
    assert!(codes.contains(&"timings/proc-macro-on-path".to_string()), "{codes:?}");
    assert!(codes.contains(&"timings/dominant-crate".to_string()), "{codes:?}"); // syn: 40% of 10s
    // medium findings only, so the default --fail-on high passes and --fail-on medium fails
    assert_eq!(sm(&m, &["timings", "--file", f.to_str().unwrap(), "--fail-on", "medium"]).code, 1);
    let txt = sm(&m, &["timings", "--file", f.to_str().unwrap()]).stdout;
    assert!(txt.contains("Critical path") && txt.contains("metadata only (pipelined)"), "{txt}");
}

#[test]
fn older_layout_and_bad_input() {
    let m = Mock::start();
    let d = temp_dir("timing");
    let old = d.join("old.html");
    std::fs::write(&old, r#"const UNIT_DATA = [{"i":0,"name":"a","version":"1.0.0","mode":"todo","target":"","start":0.0,"duration":1.0,"rmeta_time":0.4,"unlocked_units":[],"unlocked_rmeta_units":[1]},{"i":1,"name":"b","version":"1.0.0","mode":"todo","target":"","start":0.5,"duration":1.0,"rmeta_time":0.9,"unlocked_units":[],"unlocked_rmeta_units":[]}];"#).unwrap();
    let o = sm(&m, &["timings", "--file", old.to_str().unwrap(), "--json"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let p = o.json()["data"]["critical_path"].as_array().unwrap().clone();
    assert_eq!(p.len(), 2);
    assert_eq!(p[0]["name"], "a");
    let bad = d.join("bad.html");
    std::fs::write(&bad, "<html>not a timing report</html>").unwrap();
    let o = sm(&m, &["timings", "--file", bad.to_str().unwrap()]);
    assert_eq!(o.code, 3);
    assert!(o.stderr.contains("UNIT_DATA"), "{}", o.stderr);
    assert_eq!(sm(&m, &["timings", "--file", d.join("missing.html").to_str().unwrap()]).code, 3);
}

#[test]
fn fresh_build_has_nothing_to_measure() {
    let m = Mock::start();
    let dir = app(&m);
    let first = sm(&m, &["timings", "--project", dir.to_str().unwrap(), "--json", "--fail-on", "none"]);
    assert_eq!(first.code, 0, "{}", first.stderr);
    // without --clean the project's own target/ is used
    assert!(dir.join("target/cargo-timings").is_dir());
    let o = sm(&m, &["timings", "--project", dir.to_str().unwrap(), "--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["units"], 0, "{v:#}\n{}", o.stderr);
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    assert!(v["summary"].as_str().unwrap().contains("nothing was compiled"));
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("--clean")));
    for k in ["tool", "subject", "summary", "counts", "findings", "tables", "notes", "data"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    // no project and no --file: a clear error
    assert_eq!(sm(&m, &["timings", "--project", temp_dir("none").to_str().unwrap()]).code, 3);
}

#[test]
fn own_crate_dominating_the_path_is_a_split_candidate() {
    // `app` is a workspace member and is most of the build in this report
    let m = Mock::start();
    let dir = app(&m);
    let f = dir.join("report.html");
    std::fs::write(
        &f,
        r#"const UNIT_DATA = [
  {"i": 0, "name": "leaf", "version": "1.0.0", "mode": "todo", "target": "", "start": 0.0, "duration": 1.0, "unblocked_units": [], "unblocked_rmeta_units": [1], "sections": [["frontend", {"start": 0.0, "end": 0.5}]]},
  {"i": 1, "name": "app", "version": "0.1.0", "mode": "todo", "target": " app \"bin\"", "start": 0.5, "duration": 8.0, "unblocked_units": [], "unblocked_rmeta_units": [], "sections": [["frontend", {"start": 0.0, "end": 2.0}]]}
];"#,
    )
    .unwrap();
    let o = sm(&m, &["timings", "--file", f.to_str().unwrap(), "--project", dir.to_str().unwrap(), "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let v = o.json();
    let split: Vec<&serde_json::Value> = v["findings"].as_array().unwrap().iter().filter(|f| f["code"] == "timings/split-candidate").collect();
    assert_eq!(split.len(), 1, "{v:#}");
    assert_eq!(split[0]["crate"], "app");
    assert!(split[0]["fix"].as_str().unwrap().contains("sm-crates mono"), "codegen-heavy: {}", split[0]["fix"]);
}
