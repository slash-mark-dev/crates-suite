//! A small, fast Rust lexer.
//!
//! It knows exactly enough Rust to never mistake text inside strings, raw
//! strings, chars or comments for code: nested block comments, raw strings
//! with any number of `#`, byte/C strings, char literals versus lifetimes,
//! and raw identifiers. It does not need the code to compile.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ident,
    Lifetime,
    Str,
    Char,
    Num,
    Punct,
    LineComment,
    BlockComment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    pub text: String,
    /// 1-based line of the first character.
    pub line: usize,
    /// Byte offset in the source.
    pub start: usize,
    /// Doc comment (`///`, `//!`, `/** */`, `/*! */`).
    pub doc: bool,
}

impl Token {
    pub fn is(&self, kind: Kind, text: &str) -> bool {
        self.kind == kind && self.text == text
    }
    pub fn ident(&self, text: &str) -> bool {
        self.is(Kind::Ident, text)
    }
    pub fn punct(&self, text: &str) -> bool {
        self.is(Kind::Punct, text)
    }
    pub fn is_comment(&self) -> bool {
        matches!(self.kind, Kind::LineComment | Kind::BlockComment)
    }
}

/// Multi-character punctuation the lexer joins (longest first).
const PUNCTS: &[&str] = &[
    "..=", "...", "<<=", ">>=", "::", "->", "=>", "..", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=",
    "%=", "^=", "&=", "|=", "<<", ">>",
];

pub fn lex(src: &str) -> Vec<Token> {
    let b = src.as_bytes();
    let n = b.len();
    let mut i = 0;
    let mut line = 1;
    let mut out = Vec::new();
    let count_lines = |s: &[u8]| s.iter().filter(|&&c| c == b'\n').count();

    while i < n {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let start_line = line;
        // Comments
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            let mut j = i;
            while j < n && b[j] != b'\n' {
                j += 1;
            }
            let text = &src[i..j];
            let doc = (text.starts_with("///") && !text.starts_with("////")) || text.starts_with("//!");
            out.push(Token { kind: Kind::LineComment, text: text.to_string(), line, start, doc });
            i = j;
            continue;
        }
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            let mut depth = 1;
            let mut j = i + 2;
            while j < n && depth > 0 {
                if b[j] == b'/' && j + 1 < n && b[j + 1] == b'*' {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && j + 1 < n && b[j + 1] == b'/' {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            let text = &src[i..j.min(n)];
            let doc = (text.starts_with("/**") && !text.starts_with("/***") && text != "/**/") || text.starts_with("/*!");
            line += count_lines(text.as_bytes());
            out.push(Token { kind: Kind::BlockComment, text: text.to_string(), line: start_line, start, doc });
            i = j.min(n);
            continue;
        }
        // Raw strings / byte strings / C strings / raw identifiers
        if c == b'r' || c == b'b' || c == b'c' {
            let mut j = i;
            if (c == b'b' || c == b'c') && j + 1 < n && b[j + 1] == b'r' {
                j += 1;
            }
            if b[j] == b'r' && j + 1 < n && (b[j + 1] == b'#' || b[j + 1] == b'"') {
                // raw string r"..." / r#"..."# , or raw identifier r#ident
                let mut k = j + 1;
                let mut hashes = 0;
                while k < n && b[k] == b'#' {
                    hashes += 1;
                    k += 1;
                }
                if k < n && b[k] == b'"' {
                    k += 1;
                    'scan: while k < n {
                        if b[k] == b'"' {
                            let mut h = 0;
                            while h < hashes && k + 1 + h < n && b[k + 1 + h] == b'#' {
                                h += 1;
                            }
                            if h == hashes {
                                k += 1 + hashes;
                                break 'scan;
                            }
                        }
                        k += 1;
                    }
                    let text = &src[i..k.min(n)];
                    line += count_lines(text.as_bytes());
                    out.push(Token { kind: Kind::Str, text: text.to_string(), line: start_line, start, doc: false });
                    i = k.min(n);
                    continue;
                } else if hashes == 1 && c == b'r' && j == i && k < n && is_ident_start(b[k]) {
                    let mut m = k;
                    while m < n && is_ident_continue(b[m]) {
                        m += 1;
                    }
                    out.push(Token { kind: Kind::Ident, text: src[k..m].to_string(), line, start, doc: false });
                    i = m;
                    continue;
                }
            }
            if (c == b'b' || c == b'c') && i + 1 < n && b[i + 1] == b'"' {
                let k = scan_quoted(b, i + 1, b'"');
                let text = &src[i..k];
                line += count_lines(text.as_bytes());
                out.push(Token { kind: Kind::Str, text: text.to_string(), line: start_line, start, doc: false });
                i = k;
                continue;
            }
            if c == b'b' && i + 1 < n && b[i + 1] == b'\'' {
                let k = scan_quoted(b, i + 1, b'\'');
                out.push(Token { kind: Kind::Char, text: src[i..k].to_string(), line, start, doc: false });
                i = k;
                continue;
            }
        }
        if c == b'"' {
            let k = scan_quoted(b, i, b'"');
            let text = &src[i..k];
            line += count_lines(text.as_bytes());
            out.push(Token { kind: Kind::Str, text: text.to_string(), line: start_line, start, doc: false });
            i = k;
            continue;
        }
        if c == b'\'' {
            // char literal or lifetime/label
            if i + 1 < n && b[i + 1] == b'\\' {
                let k = scan_quoted(b, i, b'\'');
                out.push(Token { kind: Kind::Char, text: src[i..k].to_string(), line, start, doc: false });
                i = k;
                continue;
            }
            // next full UTF-8 char
            let rest = &src[i + 1..];
            if let Some(ch) = rest.chars().next() {
                let after = i + 1 + ch.len_utf8();
                if after < n && b[after] == b'\'' {
                    out.push(Token { kind: Kind::Char, text: src[i..after + 1].to_string(), line, start, doc: false });
                    i = after + 1;
                    continue;
                }
                if ch == '_' || ch.is_alphabetic() {
                    let mut m = i + 1;
                    while m < n && (is_ident_continue(b[m]) || b[m] >= 0x80) {
                        m += 1;
                    }
                    out.push(Token { kind: Kind::Lifetime, text: src[i..m].to_string(), line, start, doc: false });
                    i = m;
                    continue;
                }
            }
            out.push(Token { kind: Kind::Punct, text: "'".into(), line, start, doc: false });
            i += 1;
            continue;
        }
        if is_ident_start(c) || c >= 0x80 {
            let mut j = i;
            while j < n && (is_ident_continue(b[j]) || b[j] >= 0x80) {
                j += 1;
            }
            if j == i {
                j = i + src[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            }
            out.push(Token { kind: Kind::Ident, text: src[i..j].to_string(), line, start, doc: false });
            i = j;
            continue;
        }
        if c.is_ascii_digit() {
            let mut j = i;
            while j < n {
                let d = b[j];
                if d.is_ascii_alphanumeric() || d == b'_' {
                    j += 1;
                } else if d == b'.' && j + 1 < n && b[j + 1].is_ascii_digit() && !src[i..j].contains('.') {
                    j += 1;
                } else {
                    break;
                }
            }
            out.push(Token { kind: Kind::Num, text: src[i..j].to_string(), line, start, doc: false });
            i = j;
            continue;
        }
        let mut matched = false;
        for p in PUNCTS {
            if src[i..].starts_with(p) {
                out.push(Token { kind: Kind::Punct, text: (*p).to_string(), line, start, doc: false });
                i += p.len();
                matched = true;
                break;
            }
        }
        if !matched {
            let ch_len = src[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            out.push(Token { kind: Kind::Punct, text: src[i..i + ch_len].to_string(), line, start, doc: false });
            i += ch_len;
        }
    }
    out
}

fn scan_quoted(b: &[u8], open: usize, q: u8) -> usize {
    let mut k = open + 1;
    while k < b.len() {
        if b[k] == b'\\' {
            k += 2;
            continue;
        }
        if b[k] == q {
            return k + 1;
        }
        k += 1;
    }
    b.len()
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}

fn is_ident_continue(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<(Kind, String)> {
        lex(src).into_iter().map(|t| (t.kind, t.text)).collect()
    }

    #[test]
    fn strings_hide_code() {
        let t = lex(r##"let s = "unsafe { x }"; let r = r#"a "unsafe" b"#; unsafe { y }"##);
        let unsafes: Vec<_> = t.iter().filter(|t| t.ident("unsafe")).collect();
        assert_eq!(unsafes.len(), 1);
    }

    #[test]
    fn comments_nested_and_doc() {
        let t = lex("/* a /* b */ unsafe */ /// doc\n//// not doc\n//! inner\nfn x() {}");
        assert_eq!(t[0].kind, Kind::BlockComment);
        assert!(t[1].doc && t[1].kind == Kind::LineComment);
        assert!(!t[2].doc);
        assert!(t[3].doc);
        assert!(t.iter().all(|t| !t.ident("unsafe")));
        assert_eq!(t[4].line, 4);
    }

    #[test]
    fn chars_vs_lifetimes() {
        let k = kinds("fn f<'a>(x: &'a u8) -> char { 'x' } let c = '\\''; let u = '\\u{1F600}'; let e = 'é'; 'outer: loop {}");
        assert!(k.contains(&(Kind::Lifetime, "'a".into())));
        assert!(k.contains(&(Kind::Char, "'x'".into())));
        assert!(k.contains(&(Kind::Char, "'\\''".into())));
        assert!(k.contains(&(Kind::Char, "'\\u{1F600}'".into())));
        assert!(k.contains(&(Kind::Char, "'é'".into())));
        assert!(k.contains(&(Kind::Lifetime, "'outer".into())));
    }

    #[test]
    fn raw_idents_bytes_numbers() {
        let k = kinds(r#"r#type b"bytes" br"raw" c"cstr" b'x' 1.5e3 0x_FF 1..2 x.0.1 a::b ->"#);
        assert_eq!(k[0], (Kind::Ident, "type".into()));
        assert_eq!(k[1].0, Kind::Str);
        assert_eq!(k[2].0, Kind::Str);
        assert_eq!(k[3].0, Kind::Str);
        assert_eq!(k[4].0, Kind::Char);
        assert_eq!(k[5], (Kind::Num, "1.5e3".into()));
        assert!(k.contains(&(Kind::Punct, "..".into())));
        assert!(k.contains(&(Kind::Punct, "::".into())));
        assert!(k.contains(&(Kind::Punct, "->".into())));
    }

    #[test]
    fn multiline_string_lines() {
        let t = lex("let a = \"x\ny\nz\";\nfoo");
        assert_eq!(t.last().unwrap().line, 4);
    }
}

#[cfg(test)]
mod corpus {
    /// Lex every .rs file in cargo's registry cache and check that brackets balance.
    /// Run with: SM_LEX_CORPUS=~/.cargo/registry/src cargo test corpus -- --ignored --nocapture
    #[test]
    #[ignore]
    fn balanced_on_real_code() {
        let Some(root) = std::env::var_os("SM_LEX_CORPUS") else { return };
        let files = crate::util::walk_files(std::path::Path::new(&root));
        let mut checked = 0;
        let mut bad = Vec::new();
        for f in files.iter().filter(|p| p.extension().is_some_and(|e| e == "rs")) {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            checked += 1;
            let toks = super::lex(&text);
            let mut depth = [0i64; 3];
            for t in toks.iter().filter(|t| t.kind == super::Kind::Punct) {
                match t.text.as_str() {
                    "{" => depth[0] += 1,
                    "}" => depth[0] -= 1,
                    "(" => depth[1] += 1,
                    ")" => depth[1] -= 1,
                    "[" => depth[2] += 1,
                    "]" => depth[2] -= 1,
                    _ => {}
                }
            }
            if depth != [0, 0, 0] {
                bad.push(format!("{} {:?}", f.display(), depth));
            }
        }
        println!("checked {checked} files, {} unbalanced", bad.len());
        for b in bad.iter().take(30) {
            println!("  {b}");
        }
        assert!(bad.is_empty());
    }
}
