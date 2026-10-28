//! Monomorphization & Macro Bloat: Generic instantiations and LLVM IR lines generated per crate and per function.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::json;

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata, Package};
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::{self, Kind};
use crate::tools::perf_util as pu;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Mono;

const OPTS: &[Opt] = &[
    Opt::value("package", "NAME", "Workspace package to analyze (default: the root or only package)"),
    Opt::flag("lib", "Analyze the library target (default when the package has one)"),
    Opt::value("bin", "NAME", "Analyze this binary target instead of the library"),
    Opt::flag("release", "Use the release profile (default: dev, like cargo-llvm-lines)"),
    Opt::value("features", "LIST", "Features to enable (comma-separated)"),
    Opt::flag("all-features", "Enable all features"),
    Opt::flag("no-default-features", "Disable default features"),
    Opt::value("top", "N", "Functions to list (default 30)"),
    Opt::value("copies", "N", "Flag generic functions instantiated more than N times (default 20)"),
    Opt::flag("macros", "Also measure macro expansion per module and derive-generated lines per crate"),
    Opt::value("file", "LL", "Analyze an existing LLVM IR (.ll) file instead of building"),
    Opt::value("timeout", "SECS", "Time limit for the build (default 1800)"),
];

impl Tool for Mono {
    fn name(&self) -> &'static str {
        "mono"
    }
    fn title(&self) -> &'static str {
        "Monomorphization & Macro Bloat"
    }
    fn group(&self) -> Group {
        Group::Performance
    }
    fn summary(&self) -> &'static str {
        "Generic instantiations and LLVM IR lines generated per crate and per function"
    }
    fn usage(&self) -> &'static str {
        "[OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Measures how much LLVM IR your crate makes the compiler generate, the same way cargo-llvm-lines
does: builds one target with `cargo rustc -- --emit=llvm-ir -C codegen-units=1` in a private target
directory under the cache, reads the .ll file and counts the lines of every function body. Symbols
are demangled and generic arguments are stripped, so all instantiations of one generic function
are grouped: lines and copies per function show where monomorphization cost goes. Each function is
attributed to the crate that defines it (for `<Type as Trait>::f`, the crate of Type; std, core and
alloc are grouped as std), giving 'your code' versus each dependency's generic code instantiated
in your crate. Findings: one generic function with more than 5% of all lines or more than --copies
instantiations, and a dependency contributing more than 25% of the IR. IR lines are a proxy for
codegen time, not a measurement of it; inlined and optimized-away code differs between dev and
--release. --macros adds the macro side: it expands the crate with `-Zunpretty=expanded` (with the
nightly toolchain if installed, otherwise stable rustc with RUSTC_BOOTSTRAP set for this one crate),
compares expanded lines per module with the source, and attributes every #[automatically_derived]
impl to the crate whose trait it implements (serde, std, ...), so you see how many lines each
dependency's derive macros generate; a dependency's derives above 25% of the expansion are flagged."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &["sm-crates mono", "sm-crates mono --release --top 15", "sm-crates mono --copies 10 --json", "sm-crates mono --macros"]
    }
    fn requires(&self) -> &'static str {
        "cargo (no network unless dependencies must be downloaded)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let top: usize = args.parse_or("top", 30)?;
        let copies_limit: usize = args.parse_or("copies", 20)?;
        let (ll, crate_name, subject, pkg) = match args.value("file") {
            Some(f) => {
                let p = PathBuf::from(f);
                let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                let name = stem.split('-').next().unwrap_or(&stem).to_string();
                (p, name, format!("LLVM IR {f}"), None)
            }
            None => {
                let b = build(ctx, args)?;
                (b.ll, b.crate_name, b.subject, Some(b.package))
            }
        };
        let text = util::read_to_string_lossy(&ll).map_err(|e| Error::Env(format!("cannot read {}: {e}", ll.display())))?;
        let funcs = parse_ll(&text);
        let mut rep = Report::new("mono", subject);
        let file_lines = text.lines().count();
        analyze(&funcs, &crate_name, file_lines, top, copies_limit, &mut rep);
        if args.flag("macros") {
            match &pkg {
                Some(p) => macros(ctx, args, p, &mut rep)?,
                None => rep.note("--macros needs a project (it cannot be used with --file)"),
            }
        }
        rep.note(format!("LLVM IR: {}", ll.display()));
        Ok(rep)
    }
}

struct Built {
    ll: PathBuf,
    crate_name: String,
    subject: String,
    package: PackageTarget,
}

/// The package and target being analyzed.
#[derive(Debug, Clone)]
struct PackageTarget {
    name: String,
    dir: PathBuf,
    /// `--lib` or `--bin NAME`
    target_args: Vec<String>,
    target_name: String,
}

/// Pick the package: --package, else the member whose directory is the project directory
/// (the root package, or a member when run inside it), else the only member.
pub(crate) fn pick_package<'a>(meta: &'a Metadata, wanted: Option<&str>, here: &Path) -> Result<&'a Package> {
    let members = meta.members();
    if let Some(w) = wanted {
        return members
            .into_iter()
            .find(|p| p.name == w || util::normalize_crate_name(&p.name) == util::normalize_crate_name(w))
            .ok_or_else(|| Error::Usage(format!("no workspace package named `{w}`")));
    }
    // `resolve` is absent with --no-deps, so match the member by its directory
    let canon = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let here = canon(here);
    if let Some(p) = members.iter().find(|p| canon(&p.dir()) == here) {
        return Ok(p);
    }
    let root = meta.resolve.as_ref().and_then(|r| r.root.clone());
    if let Some(r) = root.and_then(|id| meta.package(&id)) {
        return Ok(r);
    }
    match members.as_slice() {
        [one] => Ok(one),
        _ => Err(Error::Usage(format!(
            "this is a workspace with {} packages; choose one with --package ({})",
            members.len(),
            members.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

fn pick_target(pkg: &Package, args: &Args) -> Result<PackageTarget> {
    let bins: Vec<&str> = pkg.targets.iter().filter(|t| t.kind.iter().any(|k| k == "bin")).map(|t| t.name.as_str()).collect();
    let lib = pkg.lib_target();
    let (target_args, target_name) = if let Some(b) = args.value("bin") {
        if !bins.contains(&b) {
            return Err(Error::Usage(format!("package `{}` has no binary `{b}` (binaries: {})", pkg.name, if bins.is_empty() { "none".into() } else { bins.join(", ") })));
        }
        (vec!["--bin".to_string(), b.to_string()], b.to_string())
    } else if let Some(l) = lib {
        (vec!["--lib".to_string()], l.name.clone())
    } else if args.flag("lib") {
        return Err(Error::Usage(format!("package `{}` has no library target", pkg.name)));
    } else if let Some(b) = bins.first() {
        (vec!["--bin".to_string(), b.to_string()], b.to_string())
    } else {
        return Err(Error::Usage(format!("package `{}` has no library or binary target", pkg.name)));
    };
    Ok(PackageTarget { name: pkg.name.clone(), dir: pkg.dir(), target_args, target_name })
}

fn build(ctx: &Ctx, args: &Args) -> Result<Built> {
    pu::require_manifest(ctx)?;
    let meta = Metadata::load(ctx, &MetaOpts { no_deps: true, ..Default::default() })?;
    let pkg = pick_package(&meta, args.value("package"), ctx.project_root())?;
    let pt = pick_target(pkg, args)?;
    let timeout = pu::timeout(args, 1800)?;
    let target_dir = pu::target_dir(ctx, "mono", None)?;
    let release = args.flag("release");
    // Remove this package's old artifacts in the private target dir so the .ll is regenerated.
    let mut clean = pu::cargo(ctx);
    clean.args(["clean", "-p", &pt.name]).env("CARGO_TARGET_DIR", &target_dir);
    if release {
        clean.arg("--release");
    }
    pu::offline_flag(ctx, &mut clean);
    let _ = util::run(&mut clean, Duration::from_secs(120));

    let mut cmd = pu::cargo(ctx);
    cmd.args(["rustc", "-p", &pt.name]).args(&pt.target_args);
    let mut shown = format!("cargo rustc -p {} {}", pt.name, pt.target_args.join(" "));
    if release {
        cmd.arg("--release");
        shown.push_str(" --release");
    }
    for a in pu::feature_args(args) {
        shown.push(' ');
        shown.push_str(&a);
        cmd.arg(a);
    }
    pu::offline_flag(ctx, &mut cmd);
    cmd.args(["--", "--emit=llvm-ir", "-C", "codegen-units=1"]);
    shown.push_str(" -- --emit=llvm-ir -C codegen-units=1");
    cmd.env("CARGO_TARGET_DIR", &target_dir).env("CARGO_INCREMENTAL", "0");
    pu::progress(args, &format!("running {shown}"));
    let out = util::run(&mut cmd, timeout)?;
    if out.timed_out {
        return Err(Error::Env(format!("{shown} did not finish within {}s (raise --timeout)", timeout.as_secs())));
    }
    if !out.success() {
        return Err(Error::Env(format!("{shown} failed: {}", pu::first_error(&out.stderr))));
    }
    let crate_name = pt.target_name.replace('-', "_");
    let deps = target_dir.join(if release { "release" } else { "debug" }).join("deps");
    let ll = newest_ll(&deps, &crate_name).ok_or_else(|| Error::Env(format!("{shown} succeeded but no {crate_name}-*.ll was written to {}", deps.display())))?;
    let subject = format!("{} ({} {}, {})", pt.name, if pt.target_args[0] == "--lib" { "lib" } else { "bin" }, pt.target_name, if release { "release" } else { "dev" });
    Ok(Built { ll, crate_name, subject, package: pt })
}

fn newest_ll(deps: &Path, crate_name: &str) -> Option<PathBuf> {
    let prefix = format!("{crate_name}-");
    std::fs::read_dir(deps)
        .ok()?
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(&prefix) && n.ends_with(".ll") && !n[prefix.len()..n.len() - 3].contains('-')
        })
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH))
        .map(|e| e.path())
}

/// One function body in the IR.
#[derive(Debug, Clone, PartialEq)]
pub struct IrFn {
    /// Demangled name without hash.
    pub name: String,
    pub lines: usize,
}

/// Every `define ... @sym(...) ... { ... }` in an .ll file with its line count.
pub fn parse_ll(text: &str) -> Vec<IrFn> {
    let mut out = Vec::new();
    let mut cur: Option<(String, usize)> = None;
    for line in text.lines() {
        if let Some((_, n)) = cur.as_mut() {
            *n += 1;
            if line.starts_with('}') {
                if let Some((name, n)) = cur.take() {
                    out.push(IrFn { name, lines: n });
                }
            }
            continue;
        }
        if line.starts_with("define ") {
            if let Some(sym) = symbol_of(line) {
                let name = demangle(&sym);
                if line.trim_end().ends_with('}') {
                    out.push(IrFn { name, lines: 1 });
                } else {
                    cur = Some((name, 1));
                }
            }
        }
    }
    out
}

fn symbol_of(define: &str) -> Option<String> {
    let at = define.find(" @")? + 2;
    let rest = &define[at..];
    if let Some(q) = rest.strip_prefix('"') {
        let end = q.find('"')?;
        return Some(q[..end].to_string());
    }
    let end = rest.find('(')?;
    Some(rest[..end].to_string())
}

fn demangle(sym: &str) -> String {
    match rustc_demangle::try_demangle(sym) {
        Ok(d) => format!("{d:#}"),
        Err(_) => sym.to_string(),
    }
}

/// Strip generic arguments: `<alloc::vec::Vec<u8> as core::ops::drop::Drop>::drop` →
/// `<alloc::vec::Vec as core::ops::drop::Drop>::drop`; `a::f::<u8>::{closure#0}` → `a::f::{closure#0}`;
/// `<core::option::Option<u8>>::map` → `core::option::Option::map`.
pub fn generic_key(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '<' {
            let prev = out.chars().last();
            let generic_args = matches!(prev, Some(p) if p.is_alphanumeric() || p == '_' || p == '>' || p == ':');
            if generic_args {
                // skip to the matching '>' (ignoring the '>' of '->')
                let mut depth = 0usize;
                while i < chars.len() {
                    match chars[i] {
                        '<' => depth += 1,
                        '>' if i > 0 && chars[i - 1] == '-' => {}
                        '>' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                if out.ends_with("::") {
                    out.truncate(out.len() - 2);
                }
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    if out.starts_with('<') {
        if let Some(end) = matching_close(&out, 0) {
            let inner = &out[1..end];
            let rest = &out[end + 1..];
            match split_as(inner) {
                // `<u8 as Trait>::f`, `<&str as Trait>::f`: the self type has no path, so in
                // your crate this can only be a generic (blanket) impl instantiated per type
                Some(k) if first_crate(&inner[..k]).is_none() => return format!("<_ as {}>{rest}", &inner[k + 4..]),
                Some(_) => {}
                // `<Type>::f` (inherent impl) -> `Type::f`
                None if inner.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') && first_crate(inner).is_some() => {
                    return format!("{inner}{rest}");
                }
                // inherent impls on primitives (`<[u8]>::to_vec`, `<*const ()>::cast`) are generic over the element
                None if inner.starts_with('[') => return format!("<[T]>{rest}"),
                None if inner.starts_with("*const ") => return format!("<*const T>{rest}"),
                None if inner.starts_with("*mut ") => return format!("<*mut T>{rest}"),
                None => {}
            }
        }
    }
    out
}

/// Byte offset of the top-level ` as ` in a qualified path's inside.
fn split_as(inner: &str) -> Option<usize> {
    let b = inner.as_bytes();
    let mut depth = 0i32;
    for k in 0..b.len() {
        match b[k] {
            b'<' | b'[' | b'(' => depth += 1,
            b'>' if k > 0 && b[k - 1] == b'-' => {}
            b'>' | b']' | b')' => depth -= 1,
            b' ' if depth == 0 && inner[k..].starts_with(" as ") => return Some(k),
            _ => {}
        }
    }
    None
}

fn matching_close(s: &str, open: usize) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0usize;
    for (k, &c) in b.iter().enumerate().skip(open) {
        match c {
            b'<' => depth += 1,
            b'>' if k > 0 && b[k - 1] == b'-' => {}
            b'>' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

/// First path segment of a type expression such as `&mut alloc::vec::Vec<u8>` (None for primitives).
fn first_crate(ty: &str) -> Option<String> {
    let t = ty.trim().trim_start_matches(['&', '*', '[', '(', ' ']);
    let t = t.strip_prefix("mut ").or_else(|| t.strip_prefix("const ")).or_else(|| t.strip_prefix("dyn ")).unwrap_or(t).trim_start_matches(['&', '*', '[', '(', ' ']);
    if t.starts_with('<') {
        return crate_of(t);
    }
    let seg: String = t.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if seg.is_empty() || !t[seg.len()..].starts_with("::") {
        return None;
    }
    Some(seg)
}

/// Crate that defines a (generic-stripped or full) function path.
pub fn crate_of(key: &str) -> Option<String> {
    if key.starts_with('<') {
        let end = matching_close(key, 0)?;
        let inner = &key[1..end];
        return match split_as(inner) {
            Some(k) => first_crate(&inner[..k]).or_else(|| first_crate(&inner[k + 4..])),
            // inherent impls on primitive types only exist in core/alloc/std
            None => first_crate(inner).or_else(|| Some("core".into())),
        };
    }
    first_crate(key)
}

fn crate_group(c: Option<String>) -> String {
    match c.as_deref() {
        Some("core" | "alloc" | "std" | "proc_macro" | "test" | "panic_unwind" | "panic_abort" | "compiler_builtins") => "std".into(),
        Some(c) => c.to_string(),
        None => "(other)".into(),
    }
}

#[derive(Debug, Clone, Default)]
struct FnGroup {
    lines: usize,
    copies: usize,
    krate: String,
}

fn analyze(funcs: &[IrFn], local: &str, file_lines: usize, top: usize, copies_limit: usize, rep: &mut Report) {
    let total: usize = funcs.iter().map(|f| f.lines).sum();
    if funcs.is_empty() || total == 0 {
        rep.summary("no function bodies in the LLVM IR (empty crate, or everything was inlined)");
        rep.data = json!({"total_lines": 0, "functions": []});
        return;
    }
    let mut groups: HashMap<String, FnGroup> = HashMap::new();
    for f in funcs {
        let key = generic_key(&f.name);
        let g = groups.entry(key.clone()).or_default();
        g.lines += f.lines;
        g.copies += 1;
        if g.krate.is_empty() {
            g.krate = crate_group(crate_of(&key));
        }
    }
    let mut sorted: Vec<(&String, &FnGroup)> = groups.iter().collect();
    sorted.sort_by(|a, b| b.1.lines.cmp(&a.1.lines).then(a.0.cmp(b.0)));
    let pct = |n: usize| n as f64 / total as f64 * 100.0;
    let who = |k: &str| if k == local { format!("{k} (your code)") } else { k.to_string() };

    let mut t = Table::new(format!("Top {} functions by LLVM IR lines", top.min(sorted.len())), &["Lines", "%", "Copies", "Function", "Crate"]);
    for (k, g) in sorted.iter().take(top) {
        t.row([g.lines.to_string(), format!("{:.1}%", pct(g.lines)), g.copies.to_string(), k.to_string(), who(&g.krate)]);
    }
    rep.table(t);

    let mut per_crate: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for g in groups.values() {
        let e = per_crate.entry(g.krate.clone()).or_default();
        e.0 += g.lines;
        e.1 += 1;
        e.2 += g.copies;
    }
    let mut pc: Vec<(&String, &(usize, usize, usize))> = per_crate.iter().collect();
    pc.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    let mut t2 = Table::new("LLVM IR by defining crate", &["Crate", "Lines", "%", "Functions", "Instantiations"]);
    for (c, (l, f, n)) in &pc {
        t2.row([who(c), l.to_string(), format!("{:.1}%", pct(*l)), f.to_string(), n.to_string()]);
    }
    rep.table(t2);

    // findings
    let mut flagged = 0;
    for (k, g) in &sorted {
        if g.copies < 2 || flagged >= 10 {
            continue;
        }
        let big = pct(g.lines) > 5.0;
        let many = g.copies > copies_limit;
        if !(big || many) {
            continue;
        }
        flagged += 1;
        let is_std = g.krate == "std";
        let sev = if is_std { Severity::Low } else { Severity::Medium };
        let mut f = Finding::new(sev, "mono/generic-bloat", format!("{k} is instantiated {} times: {} IR lines ({:.1}% of the crate)", g.copies, g.lines, pct(g.lines)));
        if g.krate != local && g.krate != "std" && g.krate != "(other)" {
            f = f.krate(&g.krate, None::<String>);
        }
        f = if is_std {
            f.fix("Instantiated for many of your types: pass fewer distinct types (e.g. convert to one type at the boundary, use `&dyn Trait` or `Box<dyn Trait>` where performance allows), and avoid deep generic wrappers that multiply drop_in_place/clone glue")
        } else if g.krate == local {
            f.fix("Move the body into a non-generic inner function and keep only a thin generic shim (`fn f<P: AsRef<Path>>(p: P) { fn inner(p: &Path) { .. } inner(p.as_ref()) }`), take `&dyn Trait` instead of `impl Trait` where the call is not hot, or factor the type-independent part into `#[inline(never)]` helpers")
        } else {
            f.fix(format!("This is {}'s generic code compiled into your crate: call it with fewer distinct type parameters, wrap it once behind a non-generic function of your own, or use its non-generic/`dyn` API if it has one", g.krate))
        };
        rep.finding(f);
    }
    for (c, (l, _, n)) in &pc {
        if c.as_str() != local && c.as_str() != "std" && c.as_str() != "(other)" && pct(*l) > 25.0 {
            rep.finding(
                Finding::new(Severity::Medium, "mono/dependency-bloat", format!("Generic code from {c} is {:.0}% of your crate's LLVM IR ({l} lines, {n} instantiations)", pct(*l)))
                    .krate(c.as_str(), None::<String>)
                    .fix(format!("Each use of {c}'s generic API with a new type is compiled again in your crate. Funnel calls through a few non-generic wrapper functions, reduce the number of types you use it with, or check whether {c} offers a less generic API (e.g. `serde_json::to_value` once instead of many `to_string::<T>`)")),
            );
        }
    }
    let local_lines = per_crate.get(local).map(|x| x.0).unwrap_or(0);
    let instantiations: usize = groups.values().map(|g| g.copies).sum();
    rep.summary(format!(
        "{} LLVM IR lines in {} function bodies ({} distinct functions); your code {:.0}%, std {:.0}%, other crates {:.0}%",
        util::human_count(total as u64),
        instantiations,
        groups.len(),
        pct(local_lines),
        pct(per_crate.get("std").map(|x| x.0).unwrap_or(0)),
        pct(total - local_lines - per_crate.get("std").map(|x| x.0).unwrap_or(0))
    ));
    rep.note("Lines are LLVM IR function-body lines (codegen-units=1), grouped by generic definition; they approximate codegen work, not time.");
    rep.data = json!({
        "total_lines": total,
        "file_lines": file_lines,
        "functions_total": instantiations,
        "distinct_functions": groups.len(),
        "crate": local,
        "top": sorted.iter().take(top).map(|(k, g)| json!({"function": k, "lines": g.lines, "copies": g.copies, "crate": g.krate})).collect::<Vec<_>>(),
        "per_crate": pc.iter().map(|(c, (l, f, n))| json!({"crate": c, "lines": l, "functions": f, "instantiations": n})).collect::<Vec<_>>(),
    });
}

/// `--macros`: expanded source per module and derive-generated code per crate, from
/// `-Zunpretty=expanded` (nightly if installed, else stable with RUSTC_BOOTSTRAP for this crate only).
fn macros(ctx: &Ctx, args: &Args, pt: &PackageTarget, rep: &mut Report) -> Result<()> {
    let nightly = pu::has_toolchain("nightly");
    let crate_name = pt.target_name.replace('-', "_");
    let target_dir = pu::target_dir(ctx, if nightly { "mono-nightly" } else { "mono-expand" }, None)?;
    let mut cmd = pu::cargo(ctx);
    if nightly {
        cmd.arg("+nightly");
    }
    cmd.args(["rustc", "-p", &pt.name]).args(&pt.target_args).args(["--profile", "check"]).args(pu::feature_args(args));
    pu::offline_flag(ctx, &mut cmd);
    cmd.args(["--", "-Zunpretty=expanded"]).env("CARGO_TARGET_DIR", &target_dir);
    if !nightly {
        // unstable flags for this one crate only; dependencies still build as plain stable
        cmd.env("RUSTC_BOOTSTRAP", &crate_name);
    }
    let how = if nightly { "cargo +nightly rustc -- -Zunpretty=expanded" } else { "cargo rustc -- -Zunpretty=expanded (stable, RUSTC_BOOTSTRAP for this crate)" };
    pu::progress(args, &format!("running {how}"));
    let out = util::run(&mut cmd, pu::timeout(args, 1800)?)?;
    if !out.success() || out.stdout.trim().is_empty() {
        rep.note(format!("--macros: macro expansion failed ({how}): {}", pu::first_error(&out.stderr)));
        return Ok(());
    }
    let src_lines: usize = rustsrc::load_crate(&pt.dir, rustsrc::LoadOpts { auxiliary: false, build_script: false }).iter().map(|f| f.text.lines().count()).sum();
    let st = expansion_stats(&out.stdout);
    let ratio = st.total as f64 / src_lines.max(1) as f64;
    let mut t = Table::new("Macro expansion by module", &["Module", "Expanded lines"]);
    t.row(["(crate total)".to_string(), format!("{} (source: {src_lines}, ×{ratio:.1})", st.total)]);
    for (m, n) in st.modules.iter().take(20) {
        t.row([m.clone(), n.to_string()]);
    }
    rep.table(t);
    let derived_lines: usize = st.derives.values().map(|d| d.1).sum();
    let mut dt = Table::new("Derive-generated code by crate", &["Crate (trait)", "Derived impls", "Lines", "% of expanded"]);
    let mut by_lines: Vec<(&String, &(usize, usize))> = st.derives.iter().collect();
    by_lines.sort_by(|a, b| b.1.1.cmp(&a.1.1).then(a.0.cmp(b.0)));
    for (c, (n, l)) in &by_lines {
        dt.row([c.to_string(), n.to_string(), l.to_string(), format!("{:.1}%", *l as f64 / st.total.max(1) as f64 * 100.0)]);
    }
    rep.table(dt);
    for (c, (n, l)) in &by_lines {
        let share = *l as f64 / st.total.max(1) as f64 * 100.0;
        if c.as_str() != "std" && *l >= 500 && share >= 25.0 {
            rep.finding(
                Finding::new(Severity::Low, "mono/derive-bloat", format!("Derives of {c} traits generate {l} lines ({share:.0}% of the expanded crate) in {n} impls"))
                    .krate(c.as_str(), None::<String>)
                    .fix(format!("Derive {c} traits only on the types that need them, use field attributes that shrink the generated code (e.g. serde's `#[serde(transparent)]`/`remote`), or gate test-only derives with `cfg_attr(test, derive(..))`")),
            );
        }
    }
    if src_lines > 0 && st.total > src_lines * 5 && st.total > 2000 {
        rep.finding(
            Finding::new(Severity::Low, "mono/macro-expansion", format!("Macros expand {src_lines} source lines into {} lines (×{ratio:.1}); {} derived impls", st.total, st.derived))
                .fix("Look at the largest modules above: derive only the traits you use, prefer functions over large macro_rules expansions, and gate test-only derives with cfg_attr"),
        );
    }
    if !nightly {
        rep.note("--macros: no nightly toolchain installed, so the expansion used stable rustc with RUSTC_BOOTSTRAP set for this crate only");
    }
    rep.data["macros"] = json!({
        "expanded_lines": st.total, "source_lines": src_lines, "derived_impls": st.derived, "derived_lines": derived_lines, "toolchain": if nightly { "nightly" } else { "stable" },
        "modules": st.modules.iter().map(|(m, n)| json!({"module": m, "lines": n})).collect::<Vec<_>>(),
        "derives": by_lines.iter().map(|(c, (n, l))| json!({"crate": c, "impls": n, "lines": l})).collect::<Vec<_>>(),
    });
    Ok(())
}

/// What `-Zunpretty=expanded` output contains.
#[derive(Debug, Default, PartialEq)]
struct Expansion {
    total: usize,
    /// Top-level `mod NAME { .. }` line counts, largest first.
    modules: Vec<(String, usize)>,
    /// `#[automatically_derived]` impls.
    derived: usize,
    /// Crate of the derived trait (std for core/alloc/std) -> (impls, lines).
    derives: BTreeMap<String, (usize, usize)>,
}

fn expansion_stats(expanded: &str) -> Expansion {
    let total = expanded.lines().count();
    let toks = rustsrc::lex(expanded);
    let code: Vec<_> = toks.into_iter().filter(|t| !t.is_comment()).collect();
    // `extern crate serde as _serde;` (how derives name their crate)
    let mut alias: HashMap<String, String> = HashMap::new();
    for w in code.windows(5) {
        if w[0].ident("extern") && w[1].ident("crate") && w[2].kind == Kind::Ident && w[3].ident("as") && w[4].kind == Kind::Ident {
            alias.insert(w[4].text.clone(), w[2].text.clone());
        }
    }
    let mut derives: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut derived = 0;
    let mut covered_until = 0;
    for k in 0..code.len().saturating_sub(1) {
        if !(code[k].punct("[") && code[k + 1].ident("automatically_derived")) {
            continue;
        }
        derived += 1;
        // the next `impl` within a few tokens (other attributes may sit in between)
        let Some(imp) = (k + 2..code.len().min(k + 60)).find(|&j| code[j].ident("impl")) else { continue };
        let mut j = imp + 1;
        if code.get(j).is_some_and(|t| t.punct("<")) {
            let mut depth = 0i32;
            while j < code.len() {
                if code[j].punct("<") {
                    depth += 1;
                } else if code[j].punct(">") {
                    depth -= 1;
                } else if code[j].punct(">>") {
                    depth -= 2;
                }
                j += 1;
                if depth <= 0 {
                    break;
                }
            }
        }
        while code.get(j).is_some_and(|t| t.punct("::")) {
            j += 1;
        }
        let first = code.get(j).filter(|t| t.kind == Kind::Ident).map(|t| t.text.clone()).unwrap_or_default();
        let krate = alias.get(&first).cloned().unwrap_or(first);
        let krate = match krate.as_str() {
            "core" | "alloc" | "std" => "std".to_string(),
            "" => "(other)".to_string(),
            c => c.to_string(),
        };
        let Some(open) = (j..code.len()).find(|&x| code[x].punct("{")) else { continue };
        let close = rustsrc::items::matching(&code, open);
        // impls nested in an impl already counted (serde's visitors) add no lines of their own
        let lines = match close {
            _ if k < covered_until => 0,
            Some(c) => {
                covered_until = c;
                code[c].line.saturating_sub(code[k].line) + 1
            }
            None => 1,
        };
        let e = derives.entry(krate).or_default();
        e.0 += 1;
        e.1 += lines;
    }
    let mut modules = Vec::new();
    let mut depth = 0usize;
    let mut k = 0;
    while k < code.len() {
        let t = &code[k];
        if t.punct("{") {
            depth += 1;
        } else if t.punct("}") {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && t.ident("mod") && k + 2 < code.len() && code[k + 1].kind == Kind::Ident && code[k + 2].punct("{") {
            if let Some(close) = rustsrc::items::matching(&code, k + 2) {
                modules.push((code[k + 1].text.clone(), code[close].line.saturating_sub(t.line) + 1));
                k = close + 1;
                continue;
            }
        }
        k += 1;
    }
    modules.sort_by(|a, b| b.1.cmp(&a.1));
    Expansion { total, modules, derived, derives }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_strip_generics() {
        assert_eq!(generic_key("gen::heavy::<alloc::string::String>"), "gen::heavy");
        assert_eq!(generic_key("<alloc::vec::Vec<u8> as core::ops::drop::Drop>::drop"), "<alloc::vec::Vec as core::ops::drop::Drop>::drop");
        assert_eq!(generic_key("<core::option::Option<&str>>::map_or_else::<alloc::string::String, F>"), "core::option::Option::map_or_else");
        assert_eq!(generic_key("core::ptr::drop_in_place::<alloc::vec::Vec<u8>>"), "core::ptr::drop_in_place");
        assert_eq!(generic_key("a::f::<fn() -> u8>::{closure#0}"), "a::f::{closure#0}");
        assert_eq!(generic_key("<[u8]>::to_vec"), "<[T]>::to_vec");
        assert_eq!(generic_key("<*const ()>::is_aligned_to"), "<*const T>::is_aligned_to");
        assert_eq!(generic_key("<u8 as <[_]>::to_vec_in::ConvertVec>::to_vec"), "<_ as <[_]>::to_vec_in::ConvertVec>::to_vec");
        assert_eq!(crate_of("<_ as <[_]>::to_vec_in::ConvertVec>::to_vec").as_deref(), Some("core"));
        assert_eq!(generic_key("main"), "main");
    }

    #[test]
    fn crates() {
        assert_eq!(crate_of("<alloc::vec::Vec as core::ops::drop::Drop>::drop").as_deref(), Some("alloc"));
        assert_eq!(crate_of("<mycrate::Foo as serde::ser::Serialize>::serialize").as_deref(), Some("mycrate"));
        assert_eq!(crate_of("<u8 as mycrate::Tr>::f").as_deref(), Some("mycrate"));
        assert_eq!(crate_of("<&mut serde_json::ser::Serializer as serde::Serializer>::x").as_deref(), Some("serde_json"));
        assert_eq!(crate_of("gen::heavy").as_deref(), Some("gen"));
        assert_eq!(crate_of("main"), None);
        assert_eq!(crate_group(Some("core".into())), "std");
    }

    const LL: &str = r#"; ModuleID = 'x'
define void @_RINvCsjepkqm0F1Pt_3gen5heavyhEB2_(ptr %_0) unnamed_addr #0 {
start:
  ret void
}
define void @_RINvCsjepkqm0F1Pt_3gen5heavytEB2_(ptr %_0) unnamed_addr #0 {
start:
  %x = add i64 1, 2
  ret void
}
define internal void @"weird name"() {
  ret void
}
declare void @ext()
"#;

    #[test]
    fn parses_ir() {
        let f = parse_ll(LL);
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].name, "gen::heavy::<u8>");
        assert_eq!(f[0].lines, 4);
        assert_eq!(f[1].name, "gen::heavy::<u16>");
        assert_eq!(f[1].lines, 5);
        assert_eq!(f[2].name, "weird name");
        let mut rep = Report::new("mono", "x");
        analyze(&f, "gen", 14, 30, 1, &mut rep);
        assert_eq!(rep.data["top"][0]["function"], "gen::heavy");
        assert_eq!(rep.data["top"][0]["copies"], 2);
        assert!(rep.findings.iter().any(|x| x.code == "mono/generic-bloat" && x.severity == Severity::Medium));
    }

    #[test]
    fn expansion() {
        let e = "#![feature(prelude_import)]\nmod a {\n    #[automatically_derived]\n    impl ::core::fmt::Debug for Y {\n        fn fmt(&self) {}\n    }\n}\n#[doc(hidden)]\nconst _: () = {\n    extern crate serde as _serde;\n    #[automatically_derived]\n    impl<'a, T: X<u8>> _serde::Serialize for Z<'a, T> {\n        fn serialize(&self) {\n            1\n        }\n    }\n};\nfn main() {}\n";
        let st = expansion_stats(e);
        assert_eq!(st.total, 18);
        assert_eq!(st.modules, vec![("a".to_string(), 6)]);
        assert_eq!(st.derived, 2);
        assert_eq!(st.derives.get("std"), Some(&(1, 4)));
        assert_eq!(st.derives.get("serde"), Some(&(1, 6)));
        let nested = "#[automatically_derived]\nimpl serde::Deserialize for A {\n    fn d() {\n        #[automatically_derived]\n        impl serde::de::Visitor for V {}\n    }\n}\n";
        assert_eq!(expansion_stats(nested).derives.get("serde"), Some(&(2, 7)));
    }
}
