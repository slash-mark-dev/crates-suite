//! Reading Rust source trees: lexing files and locating crate roots.

pub mod items;
pub mod lexer;

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::util;

pub use lexer::{Kind, Token, lex};

/// One lexed source file.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    /// Path relative to the crate root, forward slashes.
    pub rel: String,
    pub text: String,
    /// All tokens including comments.
    pub tokens: Vec<Token>,
    /// Tokens without comments.
    pub code: Vec<Token>,
}

impl SourceFile {
    pub fn load(root: &Path, path: &Path) -> Result<SourceFile> {
        let text = util::read_to_string_lossy(path)?;
        Ok(SourceFile::from_text(root, path, text))
    }

    pub fn from_text(root: &Path, path: &Path, text: String) -> SourceFile {
        let tokens = lex(&text);
        let code = items::code_only(&tokens);
        SourceFile { path: path.to_path_buf(), rel: util::rel(root, path), text, tokens, code }
    }

    /// Whether this file is test/example/bench code rather than library code.
    pub fn is_auxiliary(&self) -> bool {
        let r = &self.rel;
        r.starts_with("tests/") || r.starts_with("examples/") || r.starts_with("benches/") || r.starts_with("fuzz/")
    }

    /// The source text of one line (1-based).
    pub fn line_text(&self, line: usize) -> &str {
        self.text.lines().nth(line.saturating_sub(1)).unwrap_or("")
    }
}

/// Which files to load.
#[derive(Debug, Clone, Copy)]
pub struct LoadOpts {
    /// Include `tests/`, `examples/`, `benches/`.
    pub auxiliary: bool,
    /// Include `build.rs`.
    pub build_script: bool,
}

impl Default for LoadOpts {
    fn default() -> Self {
        LoadOpts { auxiliary: false, build_script: true }
    }
}

/// Lex every `.rs` file under a crate root. Files over 4 MiB are skipped
/// (generated tables), as are `target/` and `.git/`.
pub fn load_crate(root: &Path, opts: LoadOpts) -> Vec<SourceFile> {
    let mut out = Vec::new();
    for p in util::walk_files(root) {
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if std::fs::metadata(&p).map(|m| m.len() > 4 * 1024 * 1024).unwrap_or(true) {
            continue;
        }
        let rel = util::rel(root, &p);
        if !opts.build_script && rel == "build.rs" {
            continue;
        }
        let aux = rel.starts_with("tests/") || rel.starts_with("examples/") || rel.starts_with("benches/") || rel.starts_with("fuzz/");
        if aux && !opts.auxiliary {
            continue;
        }
        if let Ok(f) = SourceFile::load(root, &p) {
            out.push(f);
        }
    }
    out
}

/// Parse a crate's `Cargo.toml` as a generic TOML value.
pub fn manifest(root: &Path) -> Option<toml::Value> {
    let t = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    toml::from_str(&t).ok()
}

/// The library entry file (`[lib] path` or `src/lib.rs`).
pub fn lib_root(root: &Path) -> Option<PathBuf> {
    let m = manifest(root);
    if let Some(p) = m.as_ref().and_then(|m| m.get("lib")).and_then(|l| l.get("path")).and_then(|p| p.as_str()) {
        let p = root.join(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let p = root.join("src/lib.rs");
    p.is_file().then_some(p)
}

/// The build script path if the crate has one.
pub fn build_script(root: &Path) -> Option<PathBuf> {
    let m = manifest(root);
    match m.as_ref().and_then(|m| m.get("package")).and_then(|p| p.get("build")) {
        Some(toml::Value::Boolean(false)) => return None,
        Some(toml::Value::String(s)) => {
            let p = root.join(s);
            return p.is_file().then_some(p);
        }
        _ => {}
    }
    let p = root.join("build.rs");
    p.is_file().then_some(p)
}

/// Whether the crate is a proc-macro crate.
pub fn is_proc_macro(root: &Path) -> bool {
    manifest(root)
        .and_then(|m| m.get("lib").and_then(|l| l.get("proc-macro").or_else(|| l.get("proc_macro"))).and_then(|v| v.as_bool()))
        .unwrap_or(false)
}
