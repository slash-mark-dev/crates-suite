#![cfg(unix)]
mod common;
use common::*;
use serde_json::json;
use std::io::Write;
use std::path::{Path, PathBuf};

const V1: &str = r#"
pub struct Handle { id: u32 }
pub struct Stable(pub u8);
pub struct Wrap<T>(T);
pub struct OldThing;
impl Handle { pub fn id(&self) -> u32 { self.id } }
"#;

const V2: &str = r#"
use std::rc::Rc;
pub struct Handle { id: u32, shared: Rc<u8> }
pub struct Stable(pub u8);
pub struct Wrap<T>(T);
impl Handle { pub fn id(&self) -> u32 { self.id + *self.shared as u32 } }
"#;

/// `cargo` wrapper that drops `+nightly` and enables unstable rustdoc flags on stable.
fn fake_nightly(dir: &Path) -> PathBuf {
    let p = dir.join("cargo-nightly");
    std::fs::write(&p, "#!/bin/sh\nif [ \"$1\" = \"+nightly\" ]; then shift; fi\nRUSTC_BOOTSTRAP=1 exec cargo \"$@\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn crate_toml(v: &str) -> String {
    format!("[package]\nname = \"leaky\"\nversion = \"{v}\"\nedition = \"2021\"\n")
}

/// Real rustdoc JSON for a fixture version, gzipped like docs.rs serves it.
fn rustdoc_json_gz(src: &str, version: &str) -> Vec<u8> {
    let dir = temp_dir("rdj");
    write_files(&dir, &[("Cargo.toml", &format!("{}\n[workspace]\n", crate_toml(version))), ("src/lib.rs", src)]);
    let o = std::process::Command::new("cargo")
        .args(["rustdoc", "-q", "--lib", "--", "-Zunstable-options", "--output-format", "json"])
        .env("RUSTC_BOOTSTRAP", "1")
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let json = std::fs::read(dir.join("target/doc/leaky.json")).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&json).unwrap();
    gz.finish().unwrap()
}

fn setup() -> Mock {
    let m = Mock::start();
    for (v, src) in [("1.0.0", V1), ("1.1.0", V2)] {
        m.publish("leaky", v, &[("src/lib.rs", src), ("Cargo.toml", &crate_toml(v))], json!({}));
    }
    m
}

fn check_lost_send(o: &Out) {
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let f: Vec<(String, String)> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["code"].as_str().unwrap().to_string(), f["severity"].as_str().unwrap().to_string()))
        .collect();
    assert!(f.contains(&("autotraits/lost-send".into(), "high".into())), "{f:?}");
    assert!(f.contains(&("autotraits/lost-sync".into(), "high".into())), "{f:?}");
    assert!(f.contains(&("autotraits/type-removed".into(), "info".into())), "{f:?}");
    let changes = v["data"]["changes"].as_array().unwrap();
    assert!(changes.iter().all(|c| !c["type"].as_str().unwrap().ends_with("Stable") && !c["type"].as_str().unwrap().ends_with("Wrap")), "{changes:?}");
    let send = changes.iter().find(|c| c["code"] == "autotraits/lost-send").unwrap();
    assert_eq!(send["type"], "leaky::Handle");
    assert_eq!(send["old"], "yes");
    assert_eq!(send["new"], "no");
    assert_eq!(v["data"]["old"], "1.0.0");
    assert_eq!(v["data"]["new"], "1.1.0");
}

#[test]
fn docsrs_json_detects_lost_send_and_sync() {
    let m = setup();
    m.route("/docsrs/crate/leaky/1.0.0/json.gz", 200, rustdoc_json_gz(V1, "1.0.0"));
    m.route("/docsrs/crate/leaky/1.1.0/json.gz", 200, rustdoc_json_gz(V2, "1.1.0"));
    check_lost_send(&sm(&m, &["autotraits", "leaky", "1.0.0", "1.1.0", "--json"]));
    // bare name: previous release vs latest
    let o = sm(&m, &["autotraits", "leaky", "--json"]);
    check_lost_send(&o);
    // text and --fail-on none
    let o = sm(&m, &["autotraits", "leaky@1.0.0", "1.1.0", "--fail-on", "none"]);
    assert_eq!(o.code, 0);
    assert!(o.stdout.contains("`leaky::Handle` is no longer Send"), "{}", o.stdout);
    // same version twice is a usage error
    assert_eq!(sm(&m, &["autotraits", "leaky", "1.1.0", "1.1.0"]).code, 2);
}

#[test]
fn local_build_with_nightly_wrapper() {
    let m = setup();
    let bin = temp_dir("bin");
    let cargo = fake_nightly(&bin);
    let mut c = m.cmd();
    c.env("SM_CRATES_CARGO", &cargo).args(["autotraits", "leaky@1.0.0", "1.1.0", "--local", "--json"]);
    let o = run(c);
    check_lost_send(&o);
    assert_eq!(o.json()["data"]["source"], "local");
    assert!(!m.cache.join("src/leaky-1.0.0/Cargo.lock").exists(), "cache must not be modified");
}

#[test]
fn missing_docsrs_json_suggests_local() {
    let m = setup();
    let o = sm(&m, &["autotraits", "leaky", "1.0.0", "1.1.0"]);
    assert_eq!(o.code, 3);
    assert!(o.stderr.contains("docs.rs has no rustdoc JSON for leaky@1.0.0"), "{}", o.stderr);
    assert!(o.stderr.contains("--local"), "{}", o.stderr);
    assert_eq!(sm(&m, &["autotraits"]).code, 2);
    assert_eq!(sm(&m, &["autotraits", "nope-crate"]).code, 3);
}
