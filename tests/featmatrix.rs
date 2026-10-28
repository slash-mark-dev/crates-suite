mod common;
use common::*;
use serde_json::{Value, json};

fn lib_project(m: &Mock, features: &str, lib: &str) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", &format!("[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[features]\n{features}")),
            ("src/lib.rs", lib),
        ],
        &[],
    )
}

fn run_in(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

fn combo<'a>(v: &'a Value, label: &str) -> &'a Value {
    v["data"]["combinations"].as_array().unwrap().iter().find(|c| c["combination"] == label).unwrap_or_else(|| panic!("no combination {label}: {v}"))
}

const BROKEN: &str = r#"
#[cfg(feature = "a")]
pub fn a_only() -> u8 { 1 }
#[cfg(feature = "b")]
pub fn needs_a() -> u8 { a_only() + 1 }
#[cfg(not(feature = "fast"))]
pub fn slow_path() -> u8 { 2 }
#[cfg(not(feature = "std"))]
pub fn now() -> u8 { 0 }
#[cfg(feature = "std")]
pub fn now() -> u8 { 1 }
"#;

#[test]
fn finds_broken_combination_and_non_additive_feature() {
    let m = Mock::start();
    let dir = lib_project(&m, "default = [\"std\"]\na = []\nb = []\nfast = []\nstd = []\n", BROKEN);
    let o = run_in(&m, &dir, &["featmatrix", "--json", "--fail-on", "high"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["tool"], "featmatrix");
    assert_eq!(v["data"]["features"], json!(["a", "b", "fast", "std"]));
    assert_eq!(v["data"]["strategy"], "each");
    // b alone does not compile: a_only is missing
    let b = combo(&v, "b");
    assert_eq!(b["status"]["kind"], "fail", "{b}");
    assert!(b["status"]["error"].as_str().unwrap().contains("a_only"), "{b}");
    assert_eq!(b["status"]["file"], "src/lib.rs");
    assert_eq!(combo(&v, "a")["status"]["kind"], "pass");
    assert_eq!(combo(&v, "(no default features)")["status"]["kind"], "pass");
    assert_eq!(combo(&v, "--all-features")["status"]["kind"], "pass");
    let codes = o.codes();
    assert_eq!(codes.iter().filter(|c| *c == "featmatrix/combo-fails").count(), 1, "{codes:?}");
    // `fast` removes the public slow_path; `now` is swapped, not removed
    let na = v["data"]["non_additive"].as_array().unwrap();
    assert_eq!(na.len(), 1, "{na:?}");
    assert_eq!(na[0]["feature"], "fast");
    assert_eq!(na[0]["name"], "slow_path");
    assert_eq!(na[0]["line"], 7);
    let f = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "featmatrix/non-additive").unwrap();
    assert_eq!(f["severity"], "high");
    assert_eq!(f["crate"], "fx");
    assert_eq!(f["location"]["file"], "src/lib.rs");
    let fail = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "featmatrix/combo-fails").unwrap();
    assert!(fail["fix"].as_str().unwrap().contains("cargo check --no-default-features --features b"), "{fail}");
    // text output
    let t = run_in(&m, &dir, &["featmatrix", "--static", "--fail-on", "none"]);
    assert_eq!(t.code, 0, "{}", t.stderr);
    assert!(t.stdout.contains("enabling feature `fast` removes public fn `slow_path`"), "{}", t.stdout);
}

#[test]
fn clean_crate_powerset_max_exclusive_and_guards() {
    let m = Mock::start();
    let lib = r#"
#[cfg(feature = "a")]
pub fn a() {}
#[cfg(feature = "b")]
pub fn b() {}
#[cfg(all(feature = "x", feature = "y"))]
compile_error!("x and y are exclusive");
"#;
    let dir = lib_project(&m, "a = []\nb = [\"a\"]\nx = []\ny = []\n", lib);
    let o = run_in(&m, &dir, &["featmatrix", "--strategy", "powerset", "--depth", "2", "--max", "5", "--exclusive", "a,y", "--json", "--fail-on", "low"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert!(v["findings"].as_array().unwrap().is_empty(), "{}", v["findings"]);
    let reason = |l: &str| combo(&v, l)["status"]["reason"].as_str().unwrap_or("").to_string();
    assert!(reason("x,y").starts_with("compile_error! guard"), "{}", reason("x,y"));
    assert_eq!(reason("a,y"), "--exclusive a,y");
    // b already enables a
    assert_eq!(reason("a,b"), "same features as b");
    let ran = v["data"]["combinations"].as_array().unwrap().iter().filter(|c| c["status"]["kind"] == "pass").count();
    assert_eq!(ran, 5);
    // combinations beyond --max are not listed one by one; the note counts them
    assert!(!v["data"]["combinations"].as_array().unwrap().iter().any(|c| c["status"]["kind"] == "not-run"));
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("only the first 5 were checked (raise --max)")), "{}", v["notes"]);
    assert_eq!(v["data"]["compile_error_guards"][0]["message"], "x and y are exclusive");
}

#[test]
fn named_crate_and_usage_errors() {
    let m = Mock::start();
    m.publish(
        "negf",
        "1.0.0",
        &[
            ("Cargo.toml", "[package]\nname = \"negf\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[features]\nlite = []\n"),
            ("src/lib.rs", "#[cfg(not(feature = \"lite\"))]\nfn heavy() {}\n"),
        ],
        json!({"features": {"lite": []}}),
    );
    let o = sm(&m, &["featmatrix", "negf", "--static", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["subject"], "negf@1.0.0");
    assert_eq!(o.codes(), ["featmatrix/negative-feature"]);
    assert_eq!(v["findings"][0]["severity"], "medium");
    assert_eq!(sm(&m, &["featmatrix", "negf", "--static", "--fail-on", "high"]).code, 0);
    assert_eq!(sm(&m, &["featmatrix", "negf", "--strategy", "random"]).code, 2);
    assert_eq!(sm(&m, &["featmatrix", "negf", "--exclusive", "lite"]).code, 2);
    assert_eq!(sm(&m, &["featmatrix", "negf", "--exclusive", "lite,nope"]).code, 2);
}

#[test]
fn deep_powerset_is_bounded_and_static_mode_says_listed() {
    let m = Mock::start();
    let feats: String = (0..24).map(|i| format!("f{i} = []\n")).collect();
    let dir = lib_project(&m, &feats, "pub fn x() {}\n");
    // 2^24 combinations: generation must stop early, and only --max rows are listed
    let o = run_in(&m, &dir, &["featmatrix", "--strategy", "powerset", "--depth", "24", "--static", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["combinations"].as_array().unwrap().len(), 40);
    let notes: Vec<&str> = v["notes"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
    assert!(notes.iter().any(|n| n.contains("more than 10000 combinations")), "{notes:?}");
    assert!(notes.iter().any(|n| n.contains("only the first 40 were listed")), "{notes:?}");
}
