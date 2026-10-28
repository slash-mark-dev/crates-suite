//! `sm-crates mono`: real `cargo rustc --emit=llvm-ir` (and `-Zunpretty=expanded` for
//! --macros) on fixture projects with vendored dependencies.

mod common;
use common::*;
use serde_json::Value;

/// A dependency with one generic function that the app instantiates for many types.
const GEN_LIB: &str = "pub fn heavy<T: core::fmt::Debug>(x: T) -> String {\n    let mut s = String::new();\n    for i in 0..3 {\n        s.push_str(&format!(\"{:?}-{}\", x, i));\n    }\n    s\n}\n";

const APP_LIB: &str = "pub fn all() -> usize {\n    let v = [gen::heavy(1u8), gen::heavy(2u16), gen::heavy(3u32), gen::heavy(4u64), gen::heavy(5i8), gen::heavy(6i16), gen::heavy(7i32), gen::heavy(8i64), gen::heavy('c'), gen::heavy(\"s\"), gen::heavy(true), gen::heavy(1.5f32), gen::heavy(2.5f64), gen::heavy((1u8, 2u8))];\n    v.iter().map(|s| s.len()).sum()\n}\n";

fn app(m: &Mock, lib: &str) -> std::path::PathBuf {
    project(
        m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ngen = \"1\"\n"),
            ("src/lib.rs", lib),
        ],
        &[Vendored { name: "gen", version: "1.0.0", manifest: manifest("gen", "1.0.0", ""), files: vec![("src/lib.rs", GEN_LIB)] }],
    )
}

fn mono(m: &Mock, dir: &std::path::Path, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.arg("mono").arg("--project").arg(dir).args(args);
    run(c)
}

#[test]
fn generic_dependency_code_is_attributed_and_flagged() {
    let m = Mock::start();
    let dir = app(&m, APP_LIB);
    let o = mono(&m, &dir, &["--copies", "10", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let d = &v["data"];
    assert_eq!(d["crate"], "app");
    let heavy = d["top"].as_array().unwrap().iter().find(|f| f["function"] == "gen::heavy").unwrap_or_else(|| panic!("{d:#}"));
    assert_eq!(heavy["copies"], 14, "one instantiation per argument type");
    assert_eq!(heavy["crate"], "gen");
    let per: Vec<&str> = d["per_crate"].as_array().unwrap().iter().map(|c| c["crate"].as_str().unwrap()).collect();
    assert!(per.contains(&"gen") && per.contains(&"app") && per.contains(&"std"), "{per:?}");
    let fs = v["findings"].as_array().unwrap();
    let bloat = fs.iter().find(|f| f["code"] == "mono/generic-bloat" && f["crate"] == "gen").unwrap_or_else(|| panic!("{v:#}"));
    assert_eq!(bloat["severity"], "medium");
    assert!(bloat["message"].as_str().unwrap().starts_with("gen::heavy is instantiated 14 times"));
    assert!(v["subject"].as_str().unwrap().contains("app (lib app, dev)"));
    for k in ["tool", "subject", "summary", "counts", "findings", "tables", "notes", "data"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    // the project's own target/ is never used
    assert!(!dir.join("target").exists());
    assert_eq!(mono(&m, &dir, &["--copies", "10", "--fail-on", "medium"]).code, 1);
    let txt = mono(&m, &dir, &["--copies", "10", "--top", "3"]).stdout;
    assert!(txt.contains("Top 3 functions by LLVM IR lines") && txt.contains("LLVM IR by defining crate"), "{txt}");
}

#[test]
fn small_non_generic_crate_is_clean() {
    let m = Mock::start();
    let dir = app(&m, "pub fn one() -> i32 { 1 }\n");
    let o = mono(&m, &dir, &["--json", "--fail-on", "info"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["findings"].as_array().unwrap().len(), 0, "{v:#}");
    assert_eq!(v["data"]["top"][0]["function"], "app::one");
    // usage errors
    assert_eq!(mono(&m, &dir, &["--bin", "nope"]).code, 2);
    assert_eq!(mono(&m, &temp_dir("empty"), &[]).code, 3);
}

#[test]
fn macros_attribute_derived_code_to_crates() {
    let m = Mock::start();
    let derive = "extern crate proc_macro;\nuse proc_macro::TokenStream;\n#[proc_macro_derive(Hello)]\npub fn derive(input: TokenStream) -> TokenStream {\n    let s = input.to_string();\n    let name = s.split(\"struct\").nth(1).unwrap().split_whitespace().next().unwrap().trim_end_matches(';').to_string();\n    format!(\"#[automatically_derived] impl hello::Hello for {name} {{\\n fn hi() -> &'static str {{\\n \\\"{name}\\\"\\n }}\\n }}\").parse().unwrap()\n}\n";
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nhello = \"1\"\nhello_derive = \"1\"\n"),
            ("src/lib.rs", "use hello_derive::Hello;\n#[derive(Hello, Debug, Clone)]\npub struct A;\n#[derive(Hello)]\npub struct B;\nmod inner {\n    #[derive(Debug)]\n    pub struct C;\n}\npub fn names() -> String { use hello::Hello; format!(\"{} {} {:?} {:?}\", A::hi(), B::hi(), A.clone(), inner::C) }\n"),
        ],
        &[
            Vendored { name: "hello", version: "1.0.0", manifest: manifest("hello", "1.0.0", ""), files: vec![("src/lib.rs", "pub trait Hello { fn hi() -> &'static str; }\n")] },
            Vendored { name: "hello_derive", version: "1.0.0", manifest: manifest("hello_derive", "1.0.0", "[lib]\nproc-macro = true\n"), files: vec![("src/lib.rs", derive)] },
        ],
    );
    let o = mono(&m, &dir, &["--macros", "--json", "--fail-on", "none"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    let mac = &v["data"]["macros"];
    assert!(mac.is_object(), "{v:#}");
    let derives = mac["derives"].as_array().unwrap();
    let get = |c: &str| derives.iter().find(|d| d["crate"] == c).cloned().unwrap_or(Value::Null);
    assert_eq!(get("hello")["impls"], 2, "{mac:#}");
    assert_eq!(get("std")["impls"], 3, "{mac:#}");
    assert!(mac["expanded_lines"].as_u64().unwrap() > mac["source_lines"].as_u64().unwrap());
    assert_eq!(mac["modules"][0]["module"], "inner");
    // without nightly this ran on stable with RUSTC_BOOTSTRAP for the one crate (or on nightly if installed)
    assert!(mac["toolchain"] == "stable" || mac["toolchain"] == "nightly");
    assert!(v["tables"].as_array().unwrap().iter().any(|t| t["title"] == "Derive-generated code by crate"));
}

#[test]
fn analyzes_an_existing_ir_file() {
    let m = Mock::start();
    let d = temp_dir("ll");
    let f = d.join("mycrate-0123abcd.ll");
    // two instantiations of mycrate::f (v0 mangling) and one std function
    let ll = "; ModuleID = 'x'\ndefine void @_RINvCsjepkqm0F1Pt_7mycrate1fhEB2_() {\nstart:\n  ret void\n}\ndefine void @_RINvCsjepkqm0F1Pt_7mycrate1ftEB2_() {\nstart:\n  %a = add i64 1, 2\n  %b = add i64 1, 2\n  ret void\n}\ndefine void @_ZN4core3ptr13drop_in_place17h0123456789abcdefE() {\n  ret void\n}\n";
    std::fs::write(&f, ll).unwrap();
    let o = sm(&m, &["mono", "--file", f.to_str().unwrap(), "--copies", "1", "--json", "--fail-on", "medium"]);
    assert_eq!(o.code, 1, "{}\n{}", o.stdout, o.stderr);
    let v = o.json();
    assert_eq!(v["data"]["crate"], "mycrate");
    assert_eq!(v["data"]["top"][0]["function"], "mycrate::f");
    assert_eq!(v["data"]["top"][0]["copies"], 2);
    assert_eq!(v["findings"][0]["code"], "mono/generic-bloat");
    assert!(v["findings"][0]["fix"].as_str().unwrap().contains("non-generic inner function"), "your own code gets the inner-function advice");
    assert_eq!(sm(&m, &["mono", "--file", d.join("missing.ll").to_str().unwrap()]).code, 3);
}

#[test]
fn member_directory_and_relative_project_path() {
    // run for one member of a multi-member workspace, with --project given relative to the cwd:
    // the member is picked without --package, and cargo metadata finds the manifest
    let m = Mock::start();
    let dir = project(
        &m,
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"one\", \"two\"]\nresolver = \"2\"\n"),
            ("one/Cargo.toml", "[package]\nname = \"one\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
            ("one/src/lib.rs", "pub fn f(x: u32) -> u32 { x + 1 }\n"),
            ("two/Cargo.toml", "[package]\nname = \"two\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
            ("two/src/lib.rs", "pub fn g() {}\n"),
        ],
        &[],
    );
    let mut c = m.cmd();
    c.current_dir(&dir).args(["mono", "--project", "two", "--json", "--fail-on", "none"]);
    let o = run(c);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    assert!(o.json()["subject"].as_str().unwrap().starts_with("two (lib two"), "{}", o.stdout);
    // from the workspace root, a multi-member workspace still asks for --package
    let o = mono(&m, &dir, &[]);
    assert_eq!(o.code, 2, "{}", o.stderr);
    assert!(o.stderr.contains("--package"), "{}", o.stderr);
}
