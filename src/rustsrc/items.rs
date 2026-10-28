//! Item-level structure on top of the lexer: functions, impl blocks,
//! attributes and test-only regions.

use super::lexer::{Kind, Token};

/// Index of the token that closes the bracket opened at `open`
/// (`(`, `[` or `{`), in a comment-free token list.
pub fn matching(code: &[Token], open: usize) -> Option<usize> {
    let (o, c) = match code.get(open)?.text.as_str() {
        "(" => ("(", ")"),
        "[" => ("[", "]"),
        "{" => ("{", "}"),
        _ => return None,
    };
    let mut depth = 0i32;
    for (i, t) in code.iter().enumerate().skip(open) {
        if t.kind != Kind::Punct {
            continue;
        }
        if t.text == o {
            depth += 1;
        } else if t.text == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// A function or method.
#[derive(Debug, Clone)]
pub struct FnItem {
    pub name: String,
    /// `pub` with no restriction.
    pub is_pub: bool,
    pub is_async: bool,
    pub is_unsafe: bool,
    pub is_const: bool,
    /// Token index of the first qualifier/`fn` keyword.
    pub decl: usize,
    /// Line of the `fn` keyword.
    pub line: usize,
    /// Token indices of the body braces `{` and `}`; `None` for declarations without a body.
    pub body: Option<(usize, usize)>,
    /// Attributes written directly on the function, e.g. `#[test]`, `#[cfg(test)]`.
    pub attrs: Vec<String>,
    /// Index into [`impls`] result if this is a method.
    pub impl_idx: Option<usize>,
}

/// An `impl` block.
#[derive(Debug, Clone)]
pub struct ImplBlock {
    pub is_unsafe: bool,
    /// `Some("Send")` for `impl Send for X`.
    pub trait_name: Option<String>,
    /// Text of the implementing type (`X<T>`).
    pub self_ty: String,
    /// Generics text after `impl` (`<T: Send>`), empty when none.
    pub generics: String,
    /// `where` clause text, empty when none.
    pub where_clause: String,
    pub line: usize,
    /// Token index of the `impl` keyword.
    pub start: usize,
    /// Body braces.
    pub body: (usize, usize),
}

/// Remove comments.
pub fn code_only(tokens: &[Token]) -> Vec<Token> {
    tokens.iter().filter(|t| !t.is_comment()).cloned().collect()
}

/// Join token texts with sensible spacing (for displaying types and attributes).
pub fn join(code: &[Token]) -> String {
    let mut s = String::new();
    for (i, t) in code.iter().enumerate() {
        if i > 0 {
            let prev = &code[i - 1];
            let tight = matches!(t.text.as_str(), "," | ";" | ")" | "]" | ">" | "::" | "." | "?" | ":")
                || matches!(prev.text.as_str(), "(" | "[" | "<" | "::" | "&" | "." | "#" | "!")
                || (t.text == "(" && prev.kind == Kind::Ident)
                || (t.text == "<" && prev.kind == Kind::Ident)
                || (t.text == "!" && prev.kind == Kind::Ident);
            if !tight {
                s.push(' ');
            }
        }
        s.push_str(&t.text);
    }
    s
}

/// Attributes (`#[...]`, not `#![...]`) immediately before token `idx`, outermost first.
pub fn attrs_before(code: &[Token], idx: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = idx;
    // skip visibility/qualifiers so callers can pass the `fn`/`struct` keyword index
    while i > 0 {
        let p = &code[i - 1];
        if p.kind == Kind::Ident && matches!(p.text.as_str(), "pub" | "const" | "async" | "unsafe" | "extern" | "default")
            || p.kind == Kind::Str
        {
            i -= 1;
            continue;
        }
        if p.punct(")") {
            // pub(crate)
            let mut depth = 0;
            let mut j = i - 1;
            loop {
                if code[j].punct(")") {
                    depth += 1;
                } else if code[j].punct("(") {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                if j == 0 {
                    break;
                }
                j -= 1;
            }
            if j > 0 && code[j - 1].ident("pub") {
                i = j - 1;
                continue;
            }
        }
        break;
    }
    while i >= 2 && code[i - 1].punct("]") {
        // find matching '['
        let mut depth = 0;
        let mut j = i - 1;
        let mut found = None;
        loop {
            if code[j].punct("]") {
                depth += 1;
            } else if code[j].punct("[") {
                depth -= 1;
                if depth == 0 {
                    found = Some(j);
                    break;
                }
            }
            if j == 0 {
                break;
            }
            j -= 1;
        }
        let Some(open) = found else { break };
        if open == 0 || !code[open - 1].punct("#") {
            break;
        }
        out.push(join(&code[open + 1..i - 1]));
        i = open - 1;
    }
    out.reverse();
    out
}

/// All `impl` blocks.
pub fn impls(code: &[Token]) -> Vec<ImplBlock> {
    let mut out = Vec::new();
    for i in 0..code.len() {
        if !code[i].ident("impl") {
            continue;
        }
        // `impl Trait` in type position is followed by a path, not part of an item; items are
        // preceded by start-of-file, `}`, `;`, `]` (attribute), `unsafe`, `default` or `{`.
        let prev_ok = i == 0
            || matches!(code[i - 1].text.as_str(), "}" | ";" | "]" | "{" | "unsafe" | "default" | "pub")
            || code[i - 1].kind == Kind::LineComment;
        if !prev_ok {
            continue;
        }
        let is_unsafe = i > 0 && code[i - 1].ident("unsafe");
        // generics
        let mut j = i + 1;
        let mut generics = String::new();
        if code.get(j).is_some_and(|t| t.punct("<")) {
            let start = j;
            let mut depth = 0;
            while j < code.len() {
                match code[j].text.as_str() {
                    "<" | "<<" => depth += code[j].text.len() as i32,
                    ">" | ">>" => depth -= code[j].text.len() as i32,
                    "->" => {}
                    _ => {}
                }
                j += 1;
                if depth <= 0 {
                    break;
                }
            }
            generics = join(&code[start..j]);
        }
        // header until `{` at depth 0
        let head_start = j;
        let mut depth = 0i32;
        let mut brace = None;
        while j < code.len() {
            let t = &code[j];
            match t.text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                "{" if depth == 0 => {
                    brace = Some(j);
                    break;
                }
                ";" if depth == 0 => break,
                _ => {}
            }
            j += 1;
        }
        let Some(open) = brace else { continue };
        let Some(close) = matching(code, open) else { continue };
        let head = &code[head_start..open];
        let where_pos = head.iter().position(|t| t.ident("where"));
        let head_main = &head[..where_pos.unwrap_or(head.len())];
        let where_clause = where_pos.map(|w| join(&head[w + 1..])).unwrap_or_default();
        // split on top-level `for`
        let mut angle = 0i32;
        let mut for_pos = None;
        for (k, t) in head_main.iter().enumerate() {
            match t.text.as_str() {
                "<" => angle += 1,
                ">" => angle -= 1,
                "for" if angle == 0 && k > 0 => {
                    for_pos = Some(k);
                    break;
                }
                _ => {}
            }
        }
        let (trait_name, self_ty) = match for_pos {
            Some(f) => {
                let tr = &head_main[..f];
                // trait name = last ident before generics, skipping a leading `!`
                let name = tr.iter().filter(|t| t.kind == Kind::Ident).take_while(|_| true).last().map(|t| t.text.clone());
                let base = tr
                    .iter()
                    .position(|t| t.punct("<"))
                    .map(|p| &tr[..p])
                    .unwrap_or(tr)
                    .iter()
                    .filter(|t| t.kind == Kind::Ident)
                    .last()
                    .map(|t| t.text.clone());
                let neg = tr.first().is_some_and(|t| t.punct("!"));
                let tname = base.or(name).map(|n| if neg { format!("!{n}") } else { n });
                (tname, join(&head_main[f + 1..]))
            }
            None => (None, join(head_main)),
        };
        out.push(ImplBlock {
            is_unsafe,
            trait_name,
            self_ty,
            generics,
            where_clause,
            line: code[i].line,
            start: i,
            body: (open, close),
        });
    }
    out
}

/// All functions with bodies or declarations.
pub fn fns(code: &[Token]) -> Vec<FnItem> {
    let impl_blocks = impls(code);
    let mut out = Vec::new();
    for i in 0..code.len() {
        if !code[i].ident("fn") {
            continue;
        }
        let Some(name_tok) = code.get(i + 1) else { continue };
        if name_tok.kind != Kind::Ident {
            continue; // `fn(` pointer type
        }
        // qualifiers backwards
        let mut decl = i;
        let (mut is_pub, mut is_async, mut is_unsafe, mut is_const) = (false, false, false, false);
        let mut k = i;
        while k > 0 {
            let p = &code[k - 1];
            match (p.kind, p.text.as_str()) {
                (Kind::Ident, "async") => is_async = true,
                (Kind::Ident, "unsafe") => is_unsafe = true,
                (Kind::Ident, "const") => is_const = true,
                (Kind::Ident, "extern") | (Kind::Ident, "default") | (Kind::Str, _) => {}
                (Kind::Ident, "pub") => is_pub = true,
                (Kind::Punct, ")") => {
                    // pub(crate) / pub(super) / pub(in path)
                    let mut j = k - 1;
                    while j > 0 && !code[j].punct("(") {
                        j -= 1;
                    }
                    if j > 0 && code[j - 1].ident("pub") {
                        decl = j - 1;
                        k = j - 1;
                        continue;
                    }
                    break;
                }
                _ => break,
            }
            k -= 1;
            decl = k;
        }
        // body
        let mut j = i + 2;
        let mut depth = 0i32;
        let mut body = None;
        while j < code.len() {
            let t = &code[j];
            match t.text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                "{" if depth == 0 => {
                    body = matching(code, j).map(|c| (j, c));
                    break;
                }
                ";" if depth == 0 => break,
                "}" if depth == 0 => break,
                _ => {}
            }
            j += 1;
        }
        let attrs = attrs_before(code, decl);
        let impl_idx = impl_blocks.iter().enumerate().filter(|(_, b)| b.body.0 < i && i < b.body.1).map(|(n, _)| n).last();
        out.push(FnItem {
            name: name_tok.text.clone(),
            is_pub,
            is_async,
            is_unsafe,
            is_const,
            decl,
            line: code[i].line,
            body,
            attrs,
            impl_idx,
        });
    }
    out
}

/// Token ranges that only exist in tests: `#[cfg(test)]` items and `#[test]`-like functions.
pub fn test_ranges(code: &[Token]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..code.len() {
        if !code[i].punct("#") || !code.get(i + 1).is_some_and(|t| t.punct("[")) {
            continue;
        }
        let Some(close) = matching(code, i + 1) else { continue };
        let attr = join(&code[i + 2..close]);
        let compact: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
        let is_test = compact == "cfg(test)"
            || compact == "test"
            || compact.ends_with("::test")
            || compact.starts_with("test(")
            || compact.contains("::test(")
            || compact == "bench"
            || compact.starts_with("cfg(all(test")
            || compact.starts_with("cfg(any(test");
        if !is_test {
            continue;
        }
        // the item after this (and any further attributes): find next `{` or `;` at depth 0
        let mut j = close + 1;
        let mut depth = 0i32;
        while j < code.len() {
            match code[j].text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                "{" if depth == 0 => {
                    if let Some(c) = matching(code, j) {
                        out.push((i, c));
                    }
                    break;
                }
                ";" if depth == 0 => {
                    out.push((i, j));
                    break;
                }
                _ => {}
            }
            j += 1;
        }
    }
    out
}

pub fn in_ranges(ranges: &[(usize, usize)], idx: usize) -> bool {
    ranges.iter().any(|(a, b)| *a <= idx && idx <= *b)
}

/// The innermost function whose body contains token `idx`.
pub fn enclosing_fn(fns: &[FnItem], idx: usize) -> Option<&FnItem> {
    fns.iter()
        .filter(|f| f.body.is_some_and(|(a, b)| a < idx && idx < b))
        .min_by_key(|f| f.body.map(|(a, b)| b - a).unwrap_or(usize::MAX))
}

/// Whether the file declares `#![no_std]` (possibly behind `cfg_attr`) at crate level,
/// returning the raw attribute text.
pub fn inner_attrs(code: &[Token]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < code.len() {
        if code[i].punct("#") && code[i + 1].punct("!") && code[i + 2].punct("[") {
            if let Some(c) = matching(code, i + 2) {
                out.push(join(&code[i + 3..c]));
                i = c + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::lexer::lex;
    use super::*;

    const SRC: &str = r#"
//! crate docs
#![cfg_attr(not(feature = "std"), no_std)]

pub struct W<T>(T);

/// Doc
#[inline]
pub fn public(x: &[u8]) -> u8 { helper(x) }

fn helper(x: &[u8]) -> u8 { x[0] }

pub(crate) async unsafe fn crate_only() {}

unsafe impl<T> Send for W<T> {}
unsafe impl<T: Sync> Sync for W<T> where T: Send {}

impl<T: Clone> W<T> {
    pub fn get(&self) -> T { self.0.clone() }
}

impl !Unpin for Other {}

extern "C" { fn ext(); }

type F = fn(u8) -> u8;

#[cfg(test)]
mod tests {
    #[test]
    fn t() { super::helper(&[1]); }
}

#[tokio::test]
async fn async_test() {}
"#;

    #[test]
    fn finds_functions() {
        let code = code_only(&lex(SRC));
        let f = fns(&code);
        let names: Vec<&str> = f.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["public", "helper", "crate_only", "get", "ext", "t", "async_test"]);
        let public = &f[0];
        assert!(public.is_pub && public.body.is_some());
        assert_eq!(public.attrs, ["inline"]);
        assert!(!f[1].is_pub);
        assert!(!f[2].is_pub && f[2].is_async && f[2].is_unsafe);
        assert!(f[3].is_pub && f[3].impl_idx.is_some());
        assert!(f[4].body.is_none());
    }

    #[test]
    fn finds_impls() {
        let code = code_only(&lex(SRC));
        let im = impls(&code);
        assert_eq!(im.len(), 4);
        assert!(im[0].is_unsafe);
        assert_eq!(im[0].trait_name.as_deref(), Some("Send"));
        assert_eq!(im[0].generics, "<T>");
        assert_eq!(im[0].self_ty, "W<T>");
        assert_eq!(im[1].where_clause, "T: Send");
        assert_eq!(im[1].generics, "<T: Sync>");
        assert_eq!(im[2].trait_name, None);
        assert_eq!(im[3].trait_name.as_deref(), Some("!Unpin"));
    }

    #[test]
    fn test_regions() {
        let code = code_only(&lex(SRC));
        let r = test_ranges(&code);
        let f = fns(&code);
        let t = f.iter().find(|f| f.name == "t").unwrap();
        let a = f.iter().find(|f| f.name == "async_test").unwrap();
        let h = f.iter().find(|f| f.name == "helper").unwrap();
        assert!(in_ranges(&r, t.decl));
        assert!(in_ranges(&r, a.decl));
        assert!(!in_ranges(&r, h.decl));
    }

    #[test]
    fn inner_and_enclosing() {
        let code = code_only(&lex(SRC));
        assert_eq!(inner_attrs(&code), [r#"cfg_attr(not(feature = "std"), no_std)"#]);
        let f = fns(&code);
        let idx = code.iter().rposition(|t| t.ident("x") && t.line == 11).unwrap();
        assert_eq!(enclosing_fn(&f, idx).unwrap().name, "helper");
    }
}
