//! `sm-crates profile`: real release builds of a tiny fixture binary, limited to a
//! couple of profile variants with --variants so the tests stay fast.

mod common;
use common::*;

fn bin_project(m: &Mock, main: &str) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", "[package]\nname = \"tool\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nleaf = \"1\"\n\n[profile.release]\ndebug = false\n"),
            ("src/main.rs", main),
        ],
        &[Vendored { name: "leaf", version: "1.0.0", manifest: manifest("leaf", "1.0.0", ""), files: vec![("src/lib.rs", "pub fn hi() -> u64 { (1..100u64).sum() }\n")] }],
    )
}

fn profile(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.arg("profile").arg("--project").arg(dir).args(args);
    run(c)
}

#[test]
fn strip_is_measured_and_recommended() {
    let m = Mock::start();
    let dir = bin_project(&m, "fn main() { println!(\"{}\", leaf::hi()); }\n");
    let o = profile(&m, &dir, &["--variants", "strip", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let vs = v["data"]["variants"].as_array().unwrap();
    let names: Vec<&str> = vs.iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["baseline", "strip"], "baseline is always measured first");
    let size = |i: usize| vs[i]["size_bytes"].as_u64().unwrap();
    assert!(size(1) < size(0), "stripping symbols shrinks the binary: {vs:?}");
    assert!(vs.iter().all(|x| x["rebuild_secs"].as_f64().unwrap() > 0.0 && x["error"].is_null()));
    assert_eq!(vs[1]["settings"]["strip"], "symbols");
    assert_eq!(v["data"]["smallest"], "strip");
    assert_eq!(v["data"]["recommended"], "strip");
    let snip = v["data"]["snippet"].as_str().unwrap();
    assert!(snip.contains("[profile.release]") && snip.contains("debug = false") && snip.contains("strip = \"symbols\""), "{snip}");
    let rec = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "profile/recommendation").unwrap();
    assert_eq!(rec["severity"], "info");
    // the default --fail-on high passes, the user's target/ and Cargo.toml are untouched
    assert!(!dir.join("target").exists());
    assert!(std::fs::read_to_string(dir.join("Cargo.toml")).unwrap().contains("debug = false\n"));
    for k in ["tool", "subject", "summary", "counts", "findings", "tables", "notes", "data"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
}

#[test]
fn panic_abort_warns_about_catch_unwind_and_benchmarks_run() {
    let m = Mock::start();
    let dir = bin_project(&m, "fn main() { let r = std::panic::catch_unwind(|| leaf::hi()); println!(\"{:?}\", r.is_ok()); }\n");
    let o = profile(&m, &dir, &["--variants", "panic-abort", "--bench-cmd", "{bin} --flag", "--runs", "2", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let f = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "profile/abort-breaks-catch-unwind").unwrap_or_else(|| panic!("{v:#}"));
    assert_eq!(f["severity"], "medium");
    assert_eq!(f["location"]["file"], "src/main.rs");
    assert_eq!(f["location"]["line"], 1);
    for x in v["data"]["variants"].as_array().unwrap() {
        assert!(x["runtime_secs"].as_f64().is_some(), "benchmark ran for {}: {x}", x["name"]);
    }
    assert!(v["data"]["recommended"] != "panic-abort", "abort is never recommended when the code catches panics");
    assert!(v["tables"][0]["headers"].as_array().unwrap().iter().any(|h| h == "Runtime (median)"));
}

#[test]
fn usage_errors() {
    let m = Mock::start();
    let dir = bin_project(&m, "fn main() {}\n");
    assert_eq!(profile(&m, &dir, &["--variants", "nope"]).code, 2);
    assert_eq!(profile(&m, &dir, &["--bin", "other"]).code, 2);
    let lib = project(&m, &[("Cargo.toml", "[package]\nname = \"l\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"), ("src/lib.rs", "")], &[]);
    let o = profile(&m, &lib, &["--quick"]);
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("no binary target"), "{}", o.stderr);
}
