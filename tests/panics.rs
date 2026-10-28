mod common;
use common::*;
use serde_json::json;

const APP_LIB: &str = r#"#![deny(clippy::unwrap_used)]
pub fn load(s: &str) -> u32 {
    parse_inner(s)
}

fn parse_inner(s: &str) -> u32 {
    if s.is_empty() {
        todo!("empty input")
    }
    s.len() as u32
}

fn dead() {
    panic!("unreachable from the API");
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() { None::<u8>.unwrap(); }
}
"#;

const DEP_LIB: &str = r#"
pub fn first(v: &[u8]) -> Option<u8> {
    let x = v.first().copied().unwrap();
    Some(x + v[1])
}
"#;

fn fixture(m: &Mock) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.3.0\"\nedition = \"2021\"\n\n[dependencies]\ndep = \"1\"\n"),
            ("src/lib.rs", APP_LIB),
        ],
        &[Vendored { name: "dep", version: "1.0.0", manifest: manifest("dep", "1.0.0", ""), files: vec![("src/lib.rs", DEP_LIB)] }],
    )
}

fn in_dir(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.current_dir(dir).args(args);
    run(c)
}

#[test]
fn workspace_members_by_default() {
    let m = Mock::start();
    let dir = fixture(&m);
    let o = in_dir(&m, &dir, &["panics", "--json"]);
    assert_eq!(o.code, 0, "medium is below the default --fail-on high: {}", o.stderr);
    let v = o.json();
    let crates = v["data"]["crates"].as_array().unwrap();
    assert_eq!(crates.len(), 1);
    assert_eq!(crates[0]["crate"], "app");
    assert_eq!(crates[0]["sites"]["todo"], 1);
    assert_eq!(crates[0]["sites"]["panic"], 1);
    assert_eq!(crates[0]["reachable_sites"]["todo"], 1);
    assert!(crates[0]["reachable_sites"].get("panic").is_none(), "dead() is not reachable");
    assert!(crates[0]["sites"].get("unwrap").is_none(), "test code excluded");
    let f = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "panics/todo-in-api").expect("todo finding");
    assert_eq!(f["severity"], "medium");
    assert_eq!(f["location"]["file"], "src/lib.rs");
    assert_eq!(f["location"]["line"], 8);
    assert!(f["detail"].as_str().unwrap().contains("load -> parse_inner"), "{f}");
    assert_eq!(crates[0]["top_functions"][0]["function"], "load");
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().contains("clippy::unwrap_used")));
    assert_eq!(in_dir(&m, &dir, &["panics", "--fail-on", "medium"]).code, 1);
}

#[test]
fn deps_flag_analyzes_dependencies() {
    let m = Mock::start();
    let dir = fixture(&m);
    let o = in_dir(&m, &dir, &["panics", "--deps", "--json", "--fail-on", "low"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["crates"][0]["crate"], "dep");
    let f = &v["findings"][0];
    assert_eq!(f["code"], "panics/unwrap-in-fallible-api");
    assert_eq!(f["severity"], "low");
    assert_eq!(f["crate"], "dep");
    assert_eq!(f["version"], "1.0.0");
}

#[test]
fn published_crate_text_output() {
    let m = Mock::start();
    m.publish("dep", "1.0.0", &[("src/lib.rs", DEP_LIB)], json!({}));
    let o = sm(&m, &["panics", "dep"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("2 of 2 panic site(s) are reachable"), "{}", o.stdout);
    assert!(o.stdout.contains("[panics/unwrap-in-fallible-api]"), "{}", o.stdout);
    assert!(o.stdout.contains("name-based"), "{}", o.stdout);
    let clean = Mock::start();
    clean.publish("calm", "0.1.0", &[("src/lib.rs", "pub fn add(a: u8, b: u8) -> Option<u8> { a.checked_add(b) }\n")], json!({}));
    let o = sm(&clean, &["panics", "calm", "--fail-on", "info"]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("No findings."), "{}", o.stdout);
}

#[test]
fn max_findings_caps_output() {
    let m = Mock::start();
    let mut src = String::new();
    for i in 0..5 {
        src.push_str(&format!("pub fn f{i}(v: &[u8]) -> u8 {{ v[{i}] }}\n"));
    }
    m.publish("many", "1.0.0", &[("src/lib.rs", &src)], json!({}));
    let o = sm(&m, &["panics", "many", "--max-findings", "2", "--json"]);
    let v = o.json();
    assert_eq!(v["findings"].as_array().unwrap().len(), 2);
    assert!(v["notes"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().starts_with("3 more")));
}

#[test]
fn missing_crate_exits_3() {
    let m = Mock::start();
    assert_eq!(sm(&m, &["panics", "no-such-crate"]).code, 3);
    assert_eq!(sm(&m, &["panics", "--max-findings", "x", "a"]).code, 2);
}
