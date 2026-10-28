#![cfg(unix)]
mod common;
use common::*;
use serde_json::json;
use std::path::{Path, PathBuf};

/// A fake `cargo` that answers `+nightly miri ...` with real Miri output formats and
/// forwards everything else (e.g. `cargo metadata`) to the real cargo.
fn fake_cargo(dir: &Path, miri_installed: bool) -> PathBuf {
    let script = String::from(
        r#"#!/bin/sh
LOG="__LOG__"
if [ "$1" = "+nightly" ]; then
  if [ "__INSTALLED__" != "yes" ]; then
    echo "error: toolchain 'nightly-x86_64-unknown-linux-gnu' is not installed" >&2
    exit 1
  fi
  if [ "$2" = "miri" ] && [ "$3" = "--version" ]; then echo "miri 0.1.0 (1a2b3c4 2026-10-01)"; exit 0; fi
  if [ "$2" = "miri" ] && [ "$3" = "test" ]; then
    echo "$MIRIFLAGS" > "$LOG/miriflags"
    pwd > "$LOG/cwd"
    echo "$@" > "$LOG/args"
    echo "$CARGO_TARGET_DIR" > "$LOG/target"
    touch Cargo.lock
    name=$(grep '^name' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
    case "$name" in
      ubcrate)
        echo "running 2 tests"
        echo "test tests::fine ... ok"
        printf 'test tests::reads_freed ... '
        cat >&2 <<'EOF'
   Compiling ubcrate v0.1.0 (/tmp/x)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.31s
     Running unittests src/lib.rs (target/miri/x86_64-unknown-linux-gnu/debug/deps/ubcrate-1234)
error: Undefined Behavior: memory access failed: alloc211 has been freed, so this pointer is dangling
  --> src/lib.rs:7:14
   |
7  |     unsafe { *p }
   |              ^^ Undefined Behavior occurred here
   |
   = help: this indicates a bug in the program: it performed an invalid operation, and caused Undefined Behavior
   = help: see https://doc.rust-lang.org/nightly/reference/behavior-considered-undefined.html for further information
   = note: BACKTRACE (of the first span) on thread `tests::reads_freed`:
   = note: inside `read_freed` at src/lib.rs:7:14: 7:16

error: aborting due to 1 previous error

error: test failed, to rerun pass `--lib`
EOF
        exit 101 ;;
      ffi)
        echo "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.20s"
        cat >&2 <<'EOF'
error: unsupported operation: can't call foreign function `deflateInit2_` on OS `linux`
  --> src/zlib.rs:42:9
   |
42 |         deflateInit2_(strm, level, 8, bits, 9, 0, ver, size)
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ unsupported operation occurred here
   |
   = help: this means the program tried to do something Miri does not support; it does not indicate a bug in the program
EOF
        exit 101 ;;
      *)
        echo "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s"
        exit 0 ;;
    esac
  fi
  echo "unexpected: $@" >&2
  exit 2
fi
exec cargo "$@"
"#,
    )
    .replace("__LOG__", &dir.display().to_string())
    .replace("__INSTALLED__", if miri_installed { "yes" } else { "no" });
    let p = dir.join("fake-cargo");
    std::fs::write(&p, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn sm_with(m: &Mock, cargo: &Path, cwd: Option<&Path>, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.env("SM_CRATES_CARGO", cargo).env_remove("MIRIFLAGS").args(args);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    run(c)
}

const UB_LIB: &str = "pub fn read_freed() -> u8 {\n    let b = Box::new(1u8);\n    let p = &*b as *const u8;\n    drop(b);\n    // SAFETY: none, this is the bug\n    unsafe { *p }\n}\n";

#[test]
fn reports_undefined_behavior_from_a_scratch_copy() {
    let m = Mock::start();
    m.publish("ubcrate", "0.1.0", &[("src/lib.rs", UB_LIB)], json!({}));
    let log = temp_dir("mirilog");
    let cargo = fake_cargo(&log, true);
    let o = sm_with(&m, &cargo, None, &["miri", "ubcrate", "--many-seeds", "--miriflags", "-Zmiri-strict-provenance", "--json"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let f = &v["findings"][0];
    assert_eq!(f["code"], "miri/undefined-behavior");
    assert_eq!(f["severity"], "critical");
    assert_eq!(f["crate"], "ubcrate");
    assert_eq!(f["location"]["file"], "src/lib.rs");
    assert_eq!(f["location"]["line"], 7);
    assert!(f["message"].as_str().unwrap().contains("alloc211 has been freed"), "{f}");
    assert!(f["detail"].as_str().unwrap().contains("test: tests::reads_freed"), "{f}");
    assert_eq!(v["data"]["results"][0]["result"], "UNDEFINED BEHAVIOR");
    // flags, args, scratch copy, shared target dir
    let flags = std::fs::read_to_string(log.join("miriflags")).unwrap();
    assert_eq!(flags.trim(), "-Zmiri-strict-provenance -Zmiri-many-seeds=0..4");
    assert!(std::fs::read_to_string(log.join("args")).unwrap().contains("--no-fail-fast"));
    let cwd = std::fs::read_to_string(log.join("cwd")).unwrap();
    assert!(!cwd.starts_with(m.cache.to_str().unwrap()), "must not run inside the cache: {cwd}");
    assert!(std::fs::read_to_string(log.join("target")).unwrap().trim().ends_with("miri-target"));
    let cached = m.cache.join("src").join("ubcrate-0.1.0");
    assert!(cached.join("src/lib.rs").is_file());
    assert!(!cached.join("Cargo.lock").exists(), "cache copy was modified");
    assert_eq!(sm_with(&m, &cargo, None, &["miri", "ubcrate", "--fail-on", "none"]).code, 0);
}

#[test]
fn clean_and_unsupported_runs() {
    let m = Mock::start();
    m.publish("okcrate", "1.0.0", &[("src/lib.rs", "pub fn f() -> u8 { 1 }\n")], json!({}));
    m.publish("ffi", "2.0.0", &[("src/lib.rs", "extern \"C\" { fn deflateInit2_(); }\n")], json!({}));
    let log = temp_dir("mirilog");
    let cargo = fake_cargo(&log, true);
    let o = sm_with(&m, &cargo, None, &["miri", "okcrate", "ffi", "--lib"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("okcrate") && o.stdout.contains("3 passed"), "{}", o.stdout);
    assert!(o.stdout.contains("partly unsupported"), "{}", o.stdout);
    assert!(o.stdout.contains("[miri/unsupported]"), "{}", o.stdout);
    assert!(std::fs::read_to_string(log.join("args")).unwrap().contains("--lib"));
}

#[test]
fn missing_toolchain_gives_install_commands() {
    let m = Mock::start();
    m.publish("okcrate", "1.0.0", &[("src/lib.rs", "pub fn f() {}\n")], json!({}));
    let log = temp_dir("mirilog");
    let cargo = fake_cargo(&log, false);
    let o = sm_with(&m, &cargo, None, &["miri", "okcrate"]);
    assert_eq!(o.code, 3);
    assert!(o.stderr.contains("rustup toolchain install nightly --component miri"), "{}", o.stderr);
    assert!(o.stderr.contains("cargo +nightly miri setup"), "{}", o.stderr);
}

#[test]
fn plan_ranks_project_deps_by_unsafe_code() {
    let m = Mock::start();
    let unsafe_lib = "pub fn a(p: *const u8) -> u8 { unsafe { *p } }\npub fn b(p: *const u8) -> u8 { unsafe { *p } }\n";
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsafe-dep = \"1\"\nraw-dep = \"1\"\nraw-two = \"1\"\n"),
            ("src/main.rs", "fn main() {}\n"),
        ],
        &[
            Vendored { name: "safe-dep", version: "1.0.0", manifest: manifest("safe-dep", "1.0.0", ""), files: vec![("src/lib.rs", "pub fn s() {}\n")] },
            Vendored { name: "raw-dep", version: "1.0.0", manifest: manifest("raw-dep", "1.0.0", ""), files: vec![("src/lib.rs", unsafe_lib)] },
            Vendored { name: "raw-two", version: "1.2.0", manifest: manifest("raw-two", "1.2.0", ""), files: vec![("src/lib.rs", "pub fn a(p: *const u8) -> u8 { unsafe { *p } }\n")] },
        ],
    );
    let log = temp_dir("mirilog");
    let cargo = fake_cargo(&log, false); // --plan must not need Miri
    let o = sm_with(&m, &cargo, Some(&dir), &["miri", "--plan", "--max", "1", "--json"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let plan = o.json()["data"]["plan"].as_array().unwrap().clone();
    let sel: Vec<&str> = plan.iter().filter(|p| p["selected"] == true).map(|p| p["crate"].as_str().unwrap()).collect();
    assert_eq!(sel, ["raw-dep"]);
    assert_eq!(plan[0]["unsafe_blocks"], 2);
    assert!(plan.iter().any(|p| p["crate"] == "safe-dep" && p["reason"] == "no unsafe code in library sources"));
    assert!(plan.iter().any(|p| p["crate"] == "raw-two" && p["reason"].as_str().unwrap().contains("beyond --max 1")));
    assert!(!log.join("args").exists(), "plan must not run miri");
}

#[test]
fn missing_crate_exits_3() {
    let m = Mock::start();
    let log = temp_dir("mirilog");
    let cargo = fake_cargo(&log, true);
    assert_eq!(sm_with(&m, &cargo, None, &["miri", "nope-crate"]).code, 3);
}
