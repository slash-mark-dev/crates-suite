//! Feature Matrix Tester: Compile feature combinations to find broken ones, and features that remove API instead of adding it.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::report::{Finding, Report, Severity, Table};
use crate::rustsrc::Kind;
use crate::rustsrc::items::test_ranges;
use crate::tools::features_util::{self as fu, CfgSpan, Env, ModFile};
use crate::tools::{Group, Tool};
use crate::util;

pub struct FeatMatrix;

const OPTS: &[Opt] = &[
    Opt::value("strategy", "each|powerset", "each (default): no-default, each feature alone, default, all-features; powerset: every combination up to --depth features"),
    Opt::value("depth", "N", "powerset: largest combination size (default 2)"),
    Opt::value("max", "N", "Check at most N combinations (default 40)"),
    Opt::value("exclusive", "A,B", "Never combine features A and B (pairs; repeat the option for more pairs)"),
    Opt::value("package", "NAME", "Workspace member to test (default: the root package)"),
    Opt::flag("include-deps", "Also treat optional dependencies' implicit features as features"),
    Opt::value("timeout", "SECS", "Time limit per combination (default 300)"),
    Opt::flag("static", "Only run the static non-additivity analysis; do not run cargo check"),
];

impl Tool for FeatMatrix {
    fn name(&self) -> &'static str {
        "featmatrix"
    }
    fn title(&self) -> &'static str {
        "Feature Matrix Tester"
    }
    fn group(&self) -> Group {
        Group::Features
    }
    fn summary(&self) -> &'static str {
        "Compile feature combinations to find broken ones, and features that remove API instead of adding it"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Builds a package under many feature combinations and checks that features are additive.
Target: the local package (--project DIR, --package NAME in a workspace) or a crate named on the
command line, which is downloaded from crates.io, copied to a scratch directory with its own
[workspace] table and checked there (cargo fetches its dependencies).
Combinations come from the [features] table reported by `cargo metadata`. --strategy each runs
no-default-features, each feature alone (with --no-default-features), the default set and
--all-features; --strategy powerset runs every combination of up to --depth features. Implicit
features of optional dependencies are skipped unless --include-deps. Combinations that pair
--exclusive features, or that would trigger a `compile_error!` guarded by
#[cfg(all(feature = \"a\", feature = \"b\"))] (found by the lexer), are skipped, and duplicates
(same effective feature set) run once. Each combination runs `cargo check --message-format json
--no-default-features --features LIST` with a shared CARGO_TARGET_DIR in the cache, so
dependencies compile once; a failure is a high finding with the first error and a reproduce command.
Static analysis (no compiling): the crate's module tree is lexed and every #[cfg(...)] is evaluated
with and without each feature. A public item that disappears when a feature is enabled is high
(non-additive: feature unification by any other crate breaks your users); other items under
cfg(not(feature = ...)) are medium, unless an alternative under the positive cfg defines the same name.
Limits: target-specific cfgs are treated as unknown (never counted as removals); macros that
generate items are not expanded; only the host target is compiled."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates featmatrix",
            "sm-crates featmatrix itoa@1.0.15",
            "sm-crates featmatrix semver@1.0.26 --strategy powerset --depth 2",
            "sm-crates featmatrix memchr@2.7.4 --static",
        ]
    }
    fn requires(&self) -> &'static str {
        "cargo (network for named crates)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let strategy = args.value("strategy").unwrap_or("each");
        if !matches!(strategy, "each" | "powerset") {
            return Err(Error::Usage(format!("--strategy must be each or powerset, not `{strategy}`")));
        }
        let depth: usize = args.parse_or("depth", 2)?;
        let max: usize = args.parse_or("max", 40)?;
        let timeout: u64 = args.parse_or("timeout", 300)?;
        let excl = args.list("exclusive");
        if excl.len() % 2 != 0 {
            return Err(Error::Usage("--exclusive takes pairs of features: --exclusive a,b [--exclusive c,d]".into()));
        }
        let exclusive: Vec<(String, String)> = excl.chunks(2).map(|c| (c[0].clone(), c[1].clone())).collect();

        let subj = fu::subject(ctx, args, "featmatrix")?;
        let pkg = subj.package().ok_or_else(|| Error::Env("package not found in cargo metadata".into()))?.clone();
        let mut rep = Report::new("featmatrix", subj.label.clone());
        let table = &pkg.features;
        let mut features: Vec<String> = table
            .keys()
            .filter(|f| *f != "default")
            .filter(|f| args.flag("include-deps") || !fu::is_dep_feature(&pkg, f))
            .cloned()
            .collect();
        features.sort();
        let dep_feats = table.keys().filter(|f| fu::is_dep_feature(&pkg, f)).count();
        if dep_feats > 0 && !args.flag("include-deps") {
            rep.note(format!("{dep_feats} implicit optional-dependency feature(s) left out of the combinations (use --include-deps)"));
        }
        for (a, b) in &exclusive {
            for f in [a, b] {
                if !table.contains_key(f) {
                    return Err(Error::Usage(format!("--exclusive: `{f}` is not a feature of {}", pkg.name)));
                }
            }
        }

        // ---- sources
        let dir = pkg.dir();
        let files = match fu::crate_root(&dir) {
            Some(root) => fu::module_tree(&dir, &root),
            None => vec![],
        };
        let guards = fu::compile_errors(&files);

        // ---- static analysis
        let stat = static_analysis(&files, table, &features);
        for r in &stat.removed {
            rep.finding(
                Finding::new(Severity::High, "featmatrix/non-additive", format!("enabling feature `{}` removes public {} `{}`", r.feature, r.kind, r.name))
                    .krate(&pkg.name, Some(&pkg.version))
                    .at(&r.file, Some(r.line))
                    .detail(format!("gated by #[cfg({})]; any crate in a build that turns `{}` on (feature unification) breaks code using `{}`", r.cfg, r.feature, r.name))
                    .fix(format!("make the item exist in both configurations (gate only its implementation), or replace `{}` with an opt-out-free design such as a positive feature", r.feature)),
            );
        }
        for n in &stat.negative {
            rep.finding(
                Finding::new(Severity::Medium, "featmatrix/negative-feature", format!("{} under cfg(not(feature = \"{}\")): enabling `{}` removes code", n.what, n.feature, n.feature))
                    .krate(&pkg.name, Some(&pkg.version))
                    .at(&n.file, Some(n.line))
                    .detail(format!("#[cfg({})]", n.cfg))
                    .fix(format!("express the behaviour as an additive feature, or provide the same item under cfg(feature = \"{}\")", n.feature)),
            );
        }
        if stat.swaps > 0 {
            rep.note(format!("{} cfg(not(feature)) item(s) have a same-named alternative under the positive cfg (implementation swaps) and were not reported", stat.swaps));
        }

        // ---- combinations
        let mut combos: Vec<Combo> = Vec::new();
        let mk = |label: String, feats: Vec<String>, default: bool, all: bool| Combo { label, features: feats, default, all, status: Status::Pending };
        match strategy {
            "each" => {
                combos.push(mk("(no default features)".into(), vec![], false, false));
                for f in &features {
                    combos.push(mk(f.clone(), vec![f.clone()], false, false));
                }
                combos.push(mk("default".into(), vec![], true, false));
                combos.push(mk("--all-features".into(), vec![], false, true));
            }
            _ => {
                'combos: for k in 0..=depth.min(features.len()) {
                    for c in combinations(&features, k, MAX_GENERATED - combos.len()) {
                        let label = if c.is_empty() { "(no default features)".to_string() } else { c.join(",") };
                        combos.push(mk(label, c, false, false));
                        if combos.len() >= MAX_GENERATED {
                            rep.note(format!("the powerset of {} features up to depth {depth} has more than {MAX_GENERATED} combinations; only the first {MAX_GENERATED} were considered (lower --depth)", features.len()));
                            break 'combos;
                        }
                    }
                }
            }
        }
        let all_keys: Vec<String> = table.keys().cloned().collect();
        let mut seen: BTreeMap<BTreeSet<String>, String> = BTreeMap::new();
        for c in &mut combos {
            let start: Vec<String> = if c.all {
                all_keys.clone()
            } else if c.default {
                vec!["default".to_string()]
            } else {
                c.features.clone()
            };
            let eff = fu::feature_closure(table, &start);
            if let Some((a, b)) = exclusive.iter().find(|(a, b)| eff.contains(a) && eff.contains(b)) {
                c.status = Status::Skipped(format!("--exclusive {a},{b}"));
                continue;
            }
            let env = Env { features: Some(&eff), target: None };
            if let Some(g) = guards.iter().find(|g| g.cfg.eval(&env) == Some(true)) {
                c.status = Status::Skipped(format!("compile_error! guard at {}:{}", g.file, g.line));
                continue;
            }
            if let Some(prev) = seen.get(&eff) {
                c.status = Status::Skipped(format!("same features as {prev}"));
                continue;
            }
            seen.insert(eff, c.label.clone());
        }
        let runnable = combos.iter().filter(|c| c.status == Status::Pending).count();
        if runnable > max {
            // combinations beyond --max, and duplicates found after that point, are dropped from
            // the table and the JSON (a powerset can have thousands); the note gives the count.
            // Combinations skipped for --exclusive or a compile_error! guard stay listed.
            let mut n = 0;
            let mut past = false;
            combos.retain(|c| {
                if c.status == Status::Pending {
                    n += 1;
                    past = n > max;
                    return !past;
                }
                !(past && matches!(&c.status, Status::Skipped(w) if w.starts_with("same features as")))
            });
            let verb = if args.flag("static") { "listed" } else { "checked" };
            rep.note(format!("{runnable} distinct combinations; only the first {max} were {verb} (raise --max)"));
        }

        let in_workspace = subj.scratch.is_none() && subj.meta.workspace_members.len() > 1;
        let base_cmd = |c: &Combo| -> Vec<String> {
            let mut v = Vec::new();
            if in_workspace {
                v.push("-p".to_string());
                v.push(pkg.spec());
            }
            if c.all {
                v.push("--all-features".into());
            } else if !c.default {
                v.push("--no-default-features".into());
                if !c.features.is_empty() {
                    v.push("--features".into());
                    v.push(c.features.join(","));
                }
            }
            v
        };
        let reproduce = |c: &Combo| -> String {
            let parts: Vec<String> = base_cmd(c).iter().map(|a| if a.contains(',') { format!("\"{a}\"") } else { a.clone() }).collect();
            let crate_note = if subj.scratch.is_some() { format!(" (in an unpacked copy of {})", subj.label) } else { String::new() };
            format!("cargo check {}{crate_note}", parts.join(" ")).trim_end().to_string()
        };

        if !args.flag("static") {
            let target_dir = ctx.cache_subdir("featmatrix-target")?;
            for c in &mut combos {
                if c.status != Status::Pending {
                    continue;
                }
                let r = fu::cargo_check(ctx, &subj.manifest, &base_cmd(c), &target_dir, Duration::from_secs(timeout))?;
                c.status = if r.timed_out {
                    Status::TimedOut(r.secs)
                } else if r.success {
                    Status::Pass(r.secs)
                } else {
                    // prefer the package's own error; a dependency error is still a failing combination
                    let own = r.errors.iter().find(|e| e.package == pkg.name).or(r.errors.first());
                    let (msg, file, line) = match own {
                        Some(e) => (e.message.clone(), e.file.clone(), e.line),
                        None => (r.stderr_error.clone().unwrap_or_else(|| "cargo check failed".into()), None, None),
                    };
                    Status::Fail { secs: r.secs, message: msg, file, line }
                };
            }
        } else {
            for c in &mut combos {
                if c.status == Status::Pending {
                    c.status = Status::Skipped("--static".into());
                }
            }
        }

        let mut t = Table::new(format!("Feature combinations of {}", pkg.spec()), &["Combination", "Result", "Time", "First error"]);
        let mut data = Vec::new();
        let (mut pass, mut fail) = (0, 0);
        for c in &combos {
            let (res, time, err) = match &c.status {
                Status::Pass(s) => {
                    pass += 1;
                    ("ok".to_string(), util::human_duration(*s), String::new())
                }
                Status::Fail { secs, message, file, line } => {
                    fail += 1;
                    let loc = match (file, line) {
                        (Some(f), Some(l)) => format!("{f}:{l}: "),
                        _ => String::new(),
                    };
                    let mut fnd = Finding::new(Severity::High, "featmatrix/combo-fails", format!("does not compile with {}", c.describe()))
                        .krate(&pkg.name, Some(&pkg.version))
                        .detail(message.clone())
                        .fix(format!("reproduce with `{}`; gate the code on the feature it needs, or make the feature enable it in [features]", reproduce(c)));
                    if let Some(f) = file {
                        fnd = fnd.at(f, *line);
                    }
                    rep.finding(fnd);
                    ("FAILED".to_string(), util::human_duration(*secs), format!("{loc}{message}"))
                }
                Status::TimedOut(s) => {
                    rep.note(format!("{} timed out after {} (raise --timeout); its result is unknown", c.describe(), util::human_duration(*s)));
                    ("timed out".to_string(), util::human_duration(*s), String::new())
                }
                Status::Skipped(why) => (format!("skipped: {why}"), String::new(), String::new()),
                Status::Pending => ("not run".to_string(), String::new(), String::new()),
            };
            t.row([c.label.clone(), res.clone(), time, err]);
            data.push(json!({"combination": c.label, "features": c.features, "default_features": c.default, "all_features": c.all, "result": res, "status": c.status.json()}));
        }
        rep.table(t);
        if !stat.removed.is_empty() {
            let mut t2 = Table::new("Public items removed by enabling a feature", &["Feature", "Item", "Location", "cfg"]);
            for r in &stat.removed {
                t2.row([r.feature.clone(), format!("{} {}", r.kind, r.name), format!("{}:{}", r.file, r.line), r.cfg.clone()]);
            }
            rep.table(t2);
        }
        let ran = pass + fail;
        rep.summary(if args.flag("static") {
            format!("{} feature(s); static analysis only: {} non-additive item(s), {} negative cfg(s)", features.len(), stat.removed.len(), stat.negative.len())
        } else {
            format!("{} feature(s), {ran} combination(s) checked: {pass} ok, {fail} failed; {} non-additive item(s)", features.len(), stat.removed.len())
        });
        if files.is_empty() {
            rep.note("no library or binary root found; static analysis skipped");
        }
        rep.data = json!({
            "package": pkg.name, "version": pkg.version, "features": features, "strategy": strategy,
            "combinations": data,
            "non_additive": stat.removed.iter().map(|r| json!({"feature": r.feature, "kind": r.kind, "name": r.name, "file": r.file, "line": r.line, "cfg": r.cfg})).collect::<Vec<_>>(),
            "negative": stat.negative.iter().map(|n| json!({"feature": n.feature, "item": n.what, "file": n.file, "line": n.line, "cfg": n.cfg})).collect::<Vec<_>>(),
            "compile_error_guards": guards.iter().map(|g| json!({"file": g.file, "line": g.line, "cfg": g.cfg.to_string(), "message": g.message})).collect::<Vec<_>>(),
        });
        Ok(rep)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Status {
    Pending,
    Pass(f64),
    Fail { secs: f64, message: String, file: Option<String>, line: Option<usize> },
    TimedOut(f64),
    Skipped(String),
}

impl Status {
    fn json(&self) -> Value {
        match self {
            Status::Pending => json!({"kind": "not-run"}),
            Status::Pass(s) => json!({"kind": "pass", "secs": round1(*s)}),
            Status::Fail { secs, message, file, line } => json!({"kind": "fail", "secs": round1(*secs), "error": message, "file": file, "line": line}),
            Status::TimedOut(s) => json!({"kind": "timeout", "secs": round1(*s)}),
            Status::Skipped(w) => json!({"kind": "skipped", "reason": w}),
        }
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

struct Combo {
    label: String,
    features: Vec<String>,
    default: bool,
    all: bool,
    status: Status,
}

impl Combo {
    fn describe(&self) -> String {
        if self.all {
            "--all-features".into()
        } else if self.default {
            "default features".into()
        } else if self.features.is_empty() {
            "--no-default-features".into()
        } else {
            format!("--no-default-features --features {}", self.features.join(","))
        }
    }
}

/// Upper bound on generated powerset combinations (before deduplication and --max).
const MAX_GENERATED: usize = 10_000;

/// The first `limit` k-element combinations, in order.
fn combinations(items: &[String], k: usize, limit: usize) -> Vec<Vec<String>> {
    let n = items.len();
    let mut out = Vec::new();
    if k > n || limit == 0 {
        return out;
    }
    let mut idx: Vec<usize> = (0..k).collect();
    loop {
        out.push(idx.iter().map(|&i| items[i].clone()).collect());
        if out.len() >= limit {
            return out;
        }
        // rightmost position that can still advance
        let Some(i) = (0..k).rev().find(|&i| idx[i] < n - k + i) else { return out };
        idx[i] += 1;
        for j in i + 1..k {
            idx[j] = idx[j - 1] + 1;
        }
    }
}

struct Removed {
    feature: String,
    kind: String,
    name: String,
    file: String,
    line: usize,
    cfg: String,
}

struct Negative {
    feature: String,
    what: String,
    file: String,
    line: usize,
    cfg: String,
}

struct Static {
    removed: Vec<Removed>,
    negative: Vec<Negative>,
    swaps: usize,
}

/// The item a cfg span gates: (keyword, name).
fn span_item(code: &[crate::rustsrc::Token], s: &CfgSpan) -> (String, String) {
    let mut j = s.start;
    while j + 1 < code.len() && code[j].punct("#") && code[j + 1].punct("[") {
        j = crate::rustsrc::items::matching(code, j + 1).map(|c| c + 1).unwrap_or(code.len());
    }
    let end = s.end.min(code.len().saturating_sub(1));
    let mut k = j;
    while k <= end {
        let t = &code[k];
        if t.kind == Kind::Ident {
            match t.text.as_str() {
                "fn" | "struct" | "enum" | "trait" | "type" | "const" | "static" | "mod" | "union" | "macro_rules" => {
                    let mut n = k + 1;
                    if code.get(n).is_some_and(|x| x.punct("!") || x.ident("mut")) {
                        n += 1;
                    }
                    let name = code.get(n).filter(|x| x.kind == Kind::Ident).map(|x| x.text.clone()).unwrap_or_default();
                    return (t.text.clone(), name);
                }
                "use" => {
                    let last = code[k..=end].iter().rev().find(|x| x.kind == Kind::Ident).map(|x| x.text.clone()).unwrap_or_default();
                    return ("use".into(), last);
                }
                "impl" => return ("impl".into(), String::new()),
                "pub" | "unsafe" | "async" | "extern" | "default" | "crate" | "super" | "in" | "self" => {}
                _ => {
                    // statement, field, variant or expression: name it by its first identifier
                    return ("code".into(), t.text.clone());
                }
            }
        } else if t.kind != Kind::Str && !t.punct("(") && !t.punct(")") {
            return ("code".into(), String::new());
        }
        k += 1;
    }
    ("code".into(), String::new())
}

fn static_analysis(files: &[ModFile], table: &BTreeMap<String, Vec<String>>, features: &[String]) -> Static {
    let empty = BTreeSet::new();
    let none_env = Env { features: Some(&empty), target: None };
    let mut removed = Vec::new();
    let mut seen_loc: BTreeSet<(String, usize)> = BTreeSet::new();
    let items = fu::pub_items(files);
    let named = fu::named_items(files);
    for f in features {
        let on = fu::feature_closure(table, std::slice::from_ref(f));
        let env = Env { features: Some(&on), target: None };
        for it in &items {
            if it.cfg.eval(&none_env) != Some(false) && it.cfg.eval(&env) == Some(false) {
                // an implementation swap: another definition or re-export of the name exists when `f`
                // is on (`#[cfg(f)] pub type T = ..; #[cfg(not(f))] pub enum T {}`, `pub use x::T`)
                let replaced = named.iter().any(|o| o.name == it.name && is_alternative(o, &it.file, it.line, &on));
                if replaced {
                    continue;
                }
                seen_loc.insert((it.file.clone(), it.line));
                removed.push(Removed {
                    feature: f.clone(),
                    kind: it.kind.clone(),
                    name: it.name.clone(),
                    file: it.file.clone(),
                    line: it.line,
                    cfg: simplify(&it.cfg),
                });
            }
        }
    }
    let mut negative = Vec::new();
    let mut swaps = 0;
    for mf in files {
        let code = &mf.file.code;
        let tests = test_ranges(code);
        // cfgs inside `macro_rules!` bodies are templates (e.g. `cfg_not_rt!`), not code of this build
        let macro_defs = fu::macro_rules_ranges(code);
        // names defined under a positive feature cfg, per feature
        let mut positive: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for s in &mf.spans {
            let (_, name) = span_item(code, s);
            let neg = s.cfg.has_negated_feature();
            for f in s.cfg.features() {
                if !neg.contains(&f) && !name.is_empty() {
                    positive.entry(f).or_default().insert(name.clone());
                }
            }
        }
        for s in &mf.spans {
            let negs = s.cfg.has_negated_feature();
            // cfg_if! else-branches always have a positive sibling: public removals are covered above
            if s.branch || negs.is_empty() || crate::rustsrc::items::in_ranges(&tests, s.start) || macro_defs.iter().any(|(a, b)| *a < s.start && s.start < *b) {
                continue;
            }
            let (kind, name) = span_item(code, s);
            let item_line = code.get(s.start).map(|t| t.line).unwrap_or(s.line);
            let extern_crate = code[s.start..=s.end.min(code.len() - 1)].windows(2).any(|w| w[0].ident("extern") && w[1].ident("crate"));
            if kind == "use" || extern_crate || code[s.start..=s.end.min(code.len() - 1)].iter().any(|t| t.ident("compile_error")) {
                continue;
            }
            for f in negs {
                if !features.contains(&f) && !table.contains_key(&f) {
                    continue;
                }
                // only a cfg that enabling `f` can switch off removes code: `not(all(tokio_unstable,
                // feature = "f"))` stays on, since custom cfgs are unset in a normal build
                let on = fu::feature_closure(table, std::slice::from_ref(&f));
                if s.cfg.eval(&Env { features: Some(&on), target: None }) == Some(true) {
                    continue;
                }
                // an adjacent sibling under the positive cfg (`#[cfg(f)] {..} #[cfg(not(f))] {..}`)
                let adjacent = mf.spans.iter().any(|o| {
                    (o.end + 1 == s.start || s.end + 1 == o.start) && o.cfg.features().contains(&f) && !o.cfg.has_negated_feature().contains(&f)
                });
                let elsewhere = kind != "code" && !name.is_empty() && named.iter().any(|o| o.name == name && is_alternative(o, &mf.file.rel, item_line, &on));
                if adjacent || elsewhere || !name.is_empty() && positive.get(&f).is_some_and(|p| p.contains(&name)) {
                    swaps += 1;
                    continue;
                }
                // covered by a non-additive public item finding?
                let covered = removed.iter().any(|r| r.file == mf.file.rel && r.feature == f && r.line >= item_line && r.line <= code.get(s.end).map(|t| t.line).unwrap_or(item_line));
                if covered || seen_loc.contains(&(mf.file.rel.clone(), item_line)) {
                    continue;
                }
                let what = match (kind.as_str(), name.as_str()) {
                    ("code", "") | ("impl", _) => if kind == "impl" { "impl block".to_string() } else { "code".to_string() },
                    ("code", n) => format!("`{n}`"),
                    (k, n) => format!("{k} `{n}`"),
                };
                negative.push(Negative { feature: f, what, file: mf.file.rel.clone(), line: item_line, cfg: s.cfg.to_string() });
            }
        }
    }
    Static { removed, negative, swaps }
}

/// Whether `o` (a definition or `use` of the same name) still provides the name when the
/// features `on` are enabled. Same-named items elsewhere only count when their cfg names one of
/// those features positively (a plain `pub use a::T` usually re-exports the removed item itself,
/// and an unrelated `Error` in another module is not a replacement).
fn is_alternative(o: &fu::PubItem, file: &str, line: usize, on: &BTreeSet<String>) -> bool {
    if o.file == file && o.line == line {
        return false;
    }
    if o.cfg.eval(&Env { features: Some(on), target: None }) == Some(false) {
        return false;
    }
    let neg = o.cfg.has_negated_feature();
    let positive = o.cfg.features().iter().any(|f| on.contains(f) && !neg.contains(f));
    positive || (o.file == file && o.kind != "use")
}

/// Drop the `all(...)` wrapper added when combining a single cfg.
fn simplify(c: &fu::Cfg) -> String {
    match c {
        fu::Cfg::All(v) if v.len() == 1 => simplify(&v[0]),
        fu::Cfg::All(v) => {
            let flat: Vec<String> = v.iter().map(simplify).collect();
            format!("all({})", flat.join(", "))
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn combos() {
        let f = s(&["a", "b", "c"]);
        assert_eq!(combinations(&f, 0, 10), vec![Vec::<String>::new()]);
        assert_eq!(combinations(&f, 2, 10), vec![s(&["a", "b"]), s(&["a", "c"]), s(&["b", "c"])]);
        assert_eq!(combinations(&f, 3, 10), vec![s(&["a", "b", "c"])]);
        assert!(combinations(&f, 4, 10).is_empty());
        assert_eq!(combinations(&f, 1, 10).len(), 3);
        assert_eq!(combinations(&f, 2, 2).len(), 2);
        // 40 features, depth 20 would be ~1.4e11 combinations: generation stops at the limit
        let many: Vec<String> = (0..40).map(|i| format!("f{i}")).collect();
        assert_eq!(combinations(&many, 20, 500).len(), 500);
    }

    #[test]
    fn non_additive_and_negative() {
        let src = "#[cfg(not(feature = \"fast\"))]\npub fn slow() {}\n#[cfg(not(feature = \"std\"))]\nfn imp() {}\n#[cfg(feature = \"std\")]\nfn imp() {}\n#[cfg(not(feature = \"fast\"))]\nfn helper() {}\n#[cfg(not(feature = \"fast\"))]\nuse core::fmt;\n#[cfg(not(feature = \"std\"))]\npub fn now() -> u8 { 0 }\n#[cfg(feature = \"std\")]\npub fn now() -> u8 { 1 }\n";
        let dir = std::env::temp_dir();
        let file = crate::rustsrc::SourceFile::from_text(&dir, &dir.join("src/lib.rs"), src.into());
        let spans = fu::cfg_spans(&file.code);
        let mf = ModFile { file, cfg: vec![], spans };
        let mut table = BTreeMap::new();
        table.insert("fast".to_string(), vec![]);
        table.insert("std".to_string(), vec![]);
        let st = static_analysis(&[mf], &table, &s(&["fast", "std"]));
        assert_eq!(st.removed.len(), 1);
        assert_eq!(st.removed[0].name, "slow");
        assert_eq!(st.removed[0].cfg, "not(feature = \"fast\")");
        assert_eq!(st.negative.len(), 1, "{:?}", st.negative.iter().map(|n| &n.what).collect::<Vec<_>>());
        assert_eq!(st.negative[0].what, "fn `helper`");
        // `imp` and the public `now` are implementation swaps, not removals
        assert_eq!(st.swaps, 2);
    }

    #[test]
    fn swaps_across_kinds_and_reexports_are_not_removals() {
        // hashbrown: `#[cfg(f)] pub type DefaultHashBuilder = ..; #[cfg(not(f))] pub enum DefaultHashBuilder {}`,
        // and an `Allocator` trait replaced by a re-export from a module gated on the feature
        let src = "#[cfg(feature = \"hasher\")]\npub type Builder = u8;\n#[cfg(not(feature = \"hasher\"))]\npub enum Builder {}\n#[cfg(feature = \"nightly\")]\nmod inner { pub use core::alloc::{Allocator, Global as G}; }\n#[cfg(not(feature = \"nightly\"))]\nmod inner { pub trait Allocator {} pub struct G; }\n#[cfg(not(feature = \"hasher\"))]\npub fn gone() {}\n";
        let dir = std::env::temp_dir();
        let file = crate::rustsrc::SourceFile::from_text(&dir, &dir.join("src/lib.rs"), src.into());
        let spans = fu::cfg_spans(&file.code);
        let mf = ModFile { file, cfg: vec![], spans };
        let mut table = BTreeMap::new();
        table.insert("hasher".to_string(), vec![]);
        table.insert("nightly".to_string(), vec![]);
        let st = static_analysis(&[mf], &table, &s(&["hasher", "nightly"]));
        let removed: Vec<(&str, &str)> = st.removed.iter().map(|r| (r.feature.as_str(), r.name.as_str())).collect();
        assert_eq!(removed, [("hasher", "gone")]);
        assert!(!removed.contains(&("hasher", "Builder")), "{removed:?}");
        assert!(!removed.contains(&("nightly", "Allocator")), "{removed:?}");
        assert!(!removed.contains(&("nightly", "G")), "{removed:?}");
    }

    #[test]
    fn negative_cfg_in_macro_templates_and_custom_cfgs_is_not_a_removal() {
        let src = "macro_rules! cfg_not_rt {\n    ($($item:item)*) => { $( #[cfg(not(feature = \"rt\"))] $item )* }\n}\npub fn f() {\n    #[cfg(not(all(tokio_unstable, feature = \"rt\")))]\n    let x = 1;\n    #[cfg(not(feature = \"rt\"))]\n    let y = 2;\n}\n";
        let dir = std::env::temp_dir();
        let file = crate::rustsrc::SourceFile::from_text(&dir, &dir.join("src/lib.rs"), src.into());
        let spans = fu::cfg_spans(&file.code);
        let mf = ModFile { file, cfg: vec![], spans };
        let mut table = BTreeMap::new();
        table.insert("rt".to_string(), vec![]);
        let st = static_analysis(&[mf], &table, &s(&["rt"]));
        let lines: Vec<usize> = st.negative.iter().map(|n| n.line).collect();
        assert_eq!(lines, [7], "{:?}", st.negative.iter().map(|n| (&n.what, n.line)).collect::<Vec<_>>());
    }
}
