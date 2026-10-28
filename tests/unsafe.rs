mod common;
use common::*;
use serde_json::json;

const RISKY: &str = r#"
pub struct Wrapper<T>(*mut T);

unsafe impl<T> Send for Wrapper<T> {}

pub fn grow(v: &mut Vec<u8>, n: usize) {
    v.reserve(n);
    unsafe { v.set_len(n); }
}

pub fn doc(x: &[u8]) -> u8 {
    // SAFETY: x is non-empty, checked by the caller
    unsafe { *x.as_ptr() }
}

#[cfg(test)]
mod tests {
    #[test]
    fn t() { let mut v = Vec::<u8>::new(); unsafe { v.set_len(0) } }
}
"#;

const CLEAN: &str = r#"
pub fn first(x: &[u8]) -> Option<u8> {
    if x.is_empty() { return None; }
    // SAFETY: checked non-empty above
    Some(unsafe { *x.get_unchecked(0) })
}
"#;

#[test]
fn flags_hotspots_with_locations() {
    let m = Mock::start();
    m.publish("risky", "1.0.0", &[("src/lib.rs", RISKY), ("tests/it.rs", "fn x() { unsafe { std::mem::uninitialized::<u8>(); } }")], json!({}));
    let o = sm(&m, &["unsafe", "risky", "--json"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let v = o.json();
    let codes = o.codes();
    assert!(codes.contains(&"unsafe/set-len-before-init".to_string()), "{codes:?}");
    assert!(codes.contains(&"unsafe/send-sync-unbounded".to_string()), "{codes:?}");
    assert!(!codes.iter().any(|c| c == "unsafe/mem-uninitialized"), "tests/ must be ignored: {codes:?}");
    let f = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "unsafe/set-len-before-init").unwrap();
    assert_eq!(f["severity"], "high");
    assert_eq!(f["crate"], "risky");
    assert_eq!(f["version"], "1.0.0");
    assert_eq!(f["location"]["file"], "src/lib.rs");
    assert_eq!(f["location"]["line"], 8);
    assert!(f["detail"].as_str().unwrap().contains("v.set_len(n)"));
    let c = &v["data"]["crates"][0];
    assert_eq!(c["unsafe_blocks"], 2, "test-module block excluded: {c}");
    assert_eq!(c["without_safety_comment"], 1);
    assert_eq!(c["unsafe_impls"], 1);
    assert_eq!(v["tables"][0]["rows"][0][0], "risky");
    // --fail-on none
    assert_eq!(sm(&m, &["unsafe", "risky", "--fail-on", "none"]).code, 0);
}

#[test]
fn clean_crate_and_text_output() {
    let m = Mock::start();
    m.publish("clean", "0.2.0", &[("src/lib.rs", CLEAN)], json!({}));
    let o = sm(&m, &["unsafe", "clean@0.2.0"]);
    assert_eq!(o.code, 0, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("1 unsafe block(s), 0 without a SAFETY comment, 0 hotspot(s)"), "{}", o.stdout);
    assert!(o.stdout.contains("No findings."), "{}", o.stdout);
}

#[test]
fn diff_reports_only_added_hotspots() {
    let m = Mock::start();
    m.publish("evolving", "1.0.0", &[("src/lib.rs", RISKY)], json!({}));
    let newer = format!("{RISKY}\npub fn make<T>() -> T {{ unsafe {{ std::mem::zeroed::<T>() }} }}\n");
    m.publish("evolving", "1.1.0", &[("src/lib.rs", &newer)], json!({}));
    let o = sm(&m, &["unsafe", "evolving", "--diff", "1.0.0", "--json"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    let codes = o.codes();
    assert!(codes.contains(&"unsafe/new-zeroed-generic".to_string()), "{codes:?}");
    assert!(codes.contains(&"unsafe/new-unsafe-blocks".to_string()), "{codes:?}");
    assert!(!codes.iter().any(|c| c == "unsafe/new-set-len-before-init"), "{codes:?}");
    let v = o.json();
    assert_eq!(v["data"]["old"]["version"], "1.0.0");
    assert_eq!(v["data"]["new"]["version"], "1.1.0");
    // --diff needs exactly one crate
    assert_eq!(sm(&m, &["unsafe", "--diff", "1.0.0"]).code, 2);
}

#[test]
fn scans_project_dependencies() {
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nrisky = \"1\"\n"),
            ("src/main.rs", "fn main() { unsafe { let _ = 1; } }\n"),
        ],
        &[Vendored { name: "risky", version: "1.0.0", manifest: manifest("risky", "1.0.0", ""), files: vec![("src/lib.rs", RISKY)] }],
    );
    // run inside the project so cargo picks up its vendored-source config
    let in_dir = |args: &[&str]| {
        let mut c = m.cmd();
        c.current_dir(&dir).args(args);
        run(c)
    };
    let o = in_dir(&["unsafe", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = o.json();
    let crates = v["data"]["crates"].as_array().unwrap();
    assert_eq!(crates.len(), 1, "members excluded by default: {crates:?}");
    assert_eq!(crates[0]["crate"], "risky");
    assert_eq!(crates[0]["via"][0], "app@0.1.0");
    let o = in_dir(&["unsafe", "--members", "--json", "--fail-on", "none"]);
    assert_eq!(o.json()["data"]["crates"].as_array().unwrap().len(), 2);
    let o = in_dir(&["unsafe", "--members", "--only", "app", "--json", "--fail-on", "none"]);
    let v = o.json();
    assert_eq!(v["data"]["crates"][0]["crate"], "app");
    assert_eq!(v["data"]["crates"][0]["unsafe_blocks"], 1, "binary-only member scans src/main.rs");
}

#[test]
fn missing_crate_exits_3() {
    let m = Mock::start();
    let o = sm(&m, &["unsafe", "does-not-exist"]);
    assert_eq!(o.code, 3, "{}", o.stderr);
    assert!(o.stderr.contains("not on crates.io"), "{}", o.stderr);
}
