//! Download Anomaly Detector: Sudden download spikes per version, an early signal of bot inflation or compromise.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata};
use crate::registry::{CrateSpec, api, index};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::apieco_util::{mad, median};
use crate::tools::{Group, Tool};
use crate::util;

pub struct Anomaly;

const OPTS: &[Opt] = &[
    Opt::value("days", "N", "Days of history to analyze (default 90, the most crates.io keeps)"),
    Opt::value("threshold", "Z", "Robust z-score for a daily spike (default 6)"),
    Opt::value("min-daily", "N", "Ignore excesses smaller than N downloads/day (default 100)"),
    Opt::value("limit", "N", "Analyze at most N project dependencies, smallest/youngest first"),
    Opt::flag("all", "Include transitive dependencies (default: direct dependencies only)"),
    Opt::value("only", "A,B", "Only analyze these dependencies"),
];

impl Tool for Anomaly {
    fn name(&self) -> &'static str {
        "anomaly"
    }
    fn title(&self) -> &'static str {
        "Download Anomaly Detector"
    }
    fn group(&self) -> Group {
        Group::Ecosystem
    }
    fn summary(&self) -> &'static str {
        "Sudden download spikes per version, an early signal of bot inflation or compromise"
    }
    fn usage(&self) -> &'static str {
        "[CRATE...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Looks for download patterns that organic use does not produce. Data: crates.io
`GET /api/v1/crates/{name}/downloads` (daily downloads for the last 90 days, per version for the
most recent versions plus an aggregate for the rest) and `GET /api/v1/crates/{name}` (version ids,
numbers, publication dates, yank state), at the crates.io limit of one request per second.

Checks, each explained with numbers and dates:
  1. daily spike (medium, anomaly/download-spike): robust z-score of the day's total against the
     median and MAD of the trailing 28 days of the same day type (weekdays vs weekends, so weekly
     seasonality never fires) above --threshold (default 6), at least 3x the median and at least
     --min-daily above it. Days of the crate's own releases (and the day after) are skipped. A jump
     that persists for the following week is reported as info anomaly/level-shift (organic adoption,
     e.g. a popular crate started depending on it), not as a spike.
  2. new-version burst (medium, anomaly/new-version-burst): a just-published version that within
     its first days gets at least 2x the crate's usual daily total while older versions do not drop
     (an organic release replaces old versions; an inflated one adds on top of them).
  3. old or yanked version growth (high, anomaly/yanked-version-growth or old-version-growth): a
     yanked version, or one superseded by a newer compatible release for 30+ days, whose last-7-day
     downloads are 5x its earlier level (someone pinning a yanked/vulnerable version, or mirrors
     pulling an old release). Growth of an old version that still stays below the latest version
     is medium.
  4. dormant then spike (high, anomaly/dormant-then-spike): a crate younger than 180 days with a
     near-zero history (median <= 5/day for 14+ days) followed by a day 50x higher, the pattern of
     typosquat and malware campaigns.

Crates: named on the command line, or the project's direct crates.io dependencies (--all for
transitive ones; --limit N keeps the N with the fewest published versions, a proxy for young and
small crates where inflation stands out). Limits: crates.io reports per-version history only for
its most recent versions, so old/yanked versions outside them are only seen in the aggregate;
download counts include CI and mirrors, so an anomaly is a lead to investigate, not proof."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &["sm-crates anomaly", "sm-crates anomaly serde tokio --days 60", "sm-crates anomaly --all --limit 20 --json", "sm-crates anomaly some-new-crate --threshold 4 --min-daily 50"]
    }
    fn requires(&self) -> &'static str {
        "network (crates.io API)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let cfg = Config {
            days: args.parse_or("days", 90usize)?.clamp(14, 90),
            threshold: args.parse_or("threshold", 6.0f64)?,
            min_daily: args.parse_or("min-daily", 100.0f64)?,
        };
        let (subject, names) = select(ctx, args)?;
        let mut rep = Report::new("anomaly", subject);
        let mut table = Table::new("Downloads", &["Crate", "Created", "Downloads (period)", "Median/day", "Max/day (date)", "Anomalies"]);
        let mut data = Vec::new();
        let mut failed = Vec::new();
        let mut last_err = None;
        for name in &names {
            let r = fetch(ctx, name).and_then(|(k, d)| build_series(name, &k, &d, cfg.days));
            let s = match r {
                Ok(s) => s,
                Err(e) => {
                    failed.push(format!("{name}: {e}"));
                    last_err = Some(e);
                    continue;
                }
            };
            let found = detect(&s, &cfg);
            let (maxi, maxv) = s.total.iter().enumerate().fold((0, 0.0), |a, (i, &v)| if v > a.1 { (i, v) } else { a });
            let sum: f64 = s.total.iter().sum();
            table.row([
                name.clone(),
                s.created.map(util::format_date).unwrap_or_else(|| "?".into()),
                util::human_count(sum as u64),
                format!("{:.0}", median(&s.total)),
                if s.total.is_empty() { "-".into() } else { format!("{} ({})", util::human_count(maxv as u64), day_str(s.start + maxi as i64)) },
                if found.is_empty() { "-".into() } else { found.iter().map(|a| a.code.trim_start_matches("anomaly/")).collect::<Vec<_>>().join(", ") },
            ]);
            for a in &found {
                let mut f = Finding::new(a.severity, a.code, a.message.clone()).krate(name, a.version.clone()).detail(a.detail.clone());
                f = f.fix(a.fix.clone());
                rep.finding(f);
            }
            data.push(json!({
                "crate": name,
                "created_at": s.created.map(util::format_unix),
                "start": day_str(s.start),
                "days": s.total.len(),
                "downloads": sum as u64,
                "median_per_day": median(&s.total),
                "max_per_day": maxv as u64,
                "max_date": if s.total.is_empty() { Value::Null } else { json!(day_str(s.start + maxi as i64)) },
                "daily": s.total.iter().enumerate().map(|(i, v)| json!([day_str(s.start + i as i64), *v as u64])).collect::<Vec<_>>(),
                "anomalies": found.iter().map(|a| json!({"code": a.code, "severity": a.severity, "version": a.version, "date": a.date, "message": a.message, "detail": a.detail})).collect::<Vec<_>>(),
            }));
        }
        if data.is_empty() {
            return Err(last_err.unwrap_or_else(|| Error::Network("no download data could be fetched".into())));
        }
        for f in &failed {
            rep.note(format!("skipped {f}"));
        }
        let n_anom = rep.findings.iter().filter(|f| f.severity >= Severity::Medium).count();
        rep.summary(format!("{} crate(s) analyzed over {} days: {} anomaly finding(s)", data.len(), cfg.days, n_anom));
        rep.table(table);
        rep.note(format!(
            "Method: robust z-score (median/MAD of the trailing 28 same-type days) > {}, ratio > 3x and excess > {} downloads/day; release days skipped; weekdays and weekends compared separately.",
            cfg.threshold, cfg.min_daily
        ));
        rep.note("Per-version history covers only the most recent versions crates.io reports; downloads include CI and mirrors, so treat anomalies as leads.");
        rep.data = json!({"crates": data, "config": {"days": cfg.days, "threshold": cfg.threshold, "min_daily": cfg.min_daily}});
        Ok(rep)
    }
}

pub struct Config {
    pub days: usize,
    pub threshold: f64,
    pub min_daily: f64,
}

/// Crates on the command line, or the project's dependencies.
fn select(ctx: &Ctx, args: &Args) -> Result<(String, Vec<String>)> {
    if !args.positional.is_empty() {
        let mut v = Vec::new();
        for p in &args.positional {
            let s = CrateSpec::parse(p)?;
            if !v.contains(&s.name) {
                v.push(s.name);
            }
        }
        return Ok((v.join(", "), v));
    }
    let meta = Metadata::load(ctx, &MetaOpts::default())?;
    let mut names: BTreeSet<String> = BTreeSet::new();
    if args.flag("all") {
        for p in meta.registry_packages(true) {
            names.insert(p.name.clone());
        }
    } else {
        let by_id = meta.by_id();
        for m in meta.members() {
            if let Some(n) = meta.node(&m.id) {
                for d in &n.deps {
                    if let Some(p) = by_id.get(d.pkg.as_str()) {
                        if p.is_crates_io() {
                            names.insert(p.name.clone());
                        }
                    }
                }
            }
        }
    }
    let only: Vec<String> = args.list("only").iter().map(|s| util::normalize_crate_name(s)).collect();
    let mut v: Vec<String> = names.into_iter().filter(|n| only.is_empty() || only.contains(&util::normalize_crate_name(n))).collect();
    if let Some(limit) = args.value("limit") {
        let limit: usize = limit.parse().map_err(|_| Error::Usage(format!("invalid --limit {limit}")))?;
        // fewest published versions first: young/small crates are where inflation stands out
        let idx = index::versions_many(ctx, &v);
        v.sort_by_key(|n| (idx.get(n).and_then(|x| x.as_ref()).map(|x| x.len()).unwrap_or(usize::MAX), n.clone()));
        v.truncate(limit);
    }
    if v.is_empty() {
        return Err(Error::Usage("no crates.io dependencies to analyze (name crates: CRATE...)".into()));
    }
    let label = meta.members().iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
    Ok((format!("project {label} ({} dependencies)", v.len()), v))
}

fn fetch(ctx: &Ctx, name: &str) -> Result<(Value, Value)> {
    let mut k = api::krate(ctx, name)?;
    if k["versions"].as_array().is_none_or(|v| v.is_empty()) {
        // newer crates.io responses may omit embedded versions
        if let Ok(vs) = api::versions(ctx, name) {
            k["versions"] = Value::Array(vs);
        }
    }
    let d = api::downloads(ctx, name)?;
    Ok((k, d))
}

/// Day number (days since 1970-01-01).
fn day_of(s: &str) -> Option<i64> {
    util::parse_time(s).map(|t| t.div_euclid(86_400))
}

fn day_str(d: i64) -> String {
    util::format_date(d * 86_400)
}

/// 0 = Sunday.
fn weekday(d: i64) -> i64 {
    (d + 4).rem_euclid(7)
}

fn is_weekend(d: i64) -> bool {
    matches!(weekday(d), 0 | 6)
}

#[derive(Debug, Clone)]
pub struct VInfo {
    pub num: String,
    pub created: Option<i64>,
    pub yanked: bool,
}

/// Daily download series of one crate.
#[derive(Debug, Clone)]
pub struct Series {
    pub start: i64,
    pub total: Vec<f64>,
    pub per_version: BTreeMap<u64, Vec<f64>>,
    pub versions: BTreeMap<u64, VInfo>,
    /// Crate creation time (unix seconds).
    pub created: Option<i64>,
}

pub fn build_series(name: &str, krate: &Value, dl: &Value, days: usize) -> Result<Series> {
    let mut versions = BTreeMap::new();
    for v in krate["versions"].as_array().into_iter().flatten() {
        let Some(id) = v["id"].as_u64() else { continue };
        versions.insert(
            id,
            VInfo {
                num: v["num"].as_str().unwrap_or("?").to_string(),
                created: v["created_at"].as_str().and_then(day_of),
                yanked: v["yanked"].as_bool().unwrap_or(false),
            },
        );
    }
    let created = krate["crate"]["created_at"].as_str().and_then(util::parse_time);
    let mut points: Vec<(i64, Option<u64>, f64)> = Vec::new();
    for e in dl["version_downloads"].as_array().into_iter().flatten() {
        let (Some(d), Some(n)) = (e["date"].as_str().and_then(day_of), e["downloads"].as_f64()) else { continue };
        points.push((d, e["version"].as_u64(), n));
    }
    for e in dl["meta"]["extra_downloads"].as_array().into_iter().flatten() {
        let (Some(d), Some(n)) = (e["date"].as_str().and_then(day_of), e["downloads"].as_f64()) else { continue };
        points.push((d, None, n));
    }
    if points.is_empty() {
        return Err(Error::NotFound(format!("crates.io has no download history for {name}")));
    }
    let max = points.iter().map(|p| p.0).max().unwrap_or(0);
    let min = points.iter().map(|p| p.0).min().unwrap_or(0).max(max - days as i64 + 1);
    let n = (max - min + 1) as usize;
    let mut total = vec![0.0; n];
    let mut per_version: BTreeMap<u64, Vec<f64>> = BTreeMap::new();
    for (d, v, c) in points {
        if d < min {
            continue;
        }
        let i = (d - min) as usize;
        total[i] += c;
        if let Some(v) = v {
            per_version.entry(v).or_insert_with(|| vec![0.0; n])[i] += c;
        }
    }
    Ok(Series { start: min, total, per_version, versions, created })
}

/// One detected anomaly.
#[derive(Debug, Clone)]
pub struct Anom {
    pub code: &'static str,
    pub severity: Severity,
    pub version: Option<String>,
    pub date: String,
    pub message: String,
    pub detail: String,
    pub fix: String,
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 }
}

pub fn detect(s: &Series, cfg: &Config) -> Vec<Anom> {
    let mut out = Vec::new();
    let n = s.total.len();
    let day = |i: usize| s.start + i as i64;
    let release_days: BTreeSet<i64> = s.versions.values().filter_map(|v| v.created).flat_map(|d| [d, d + 1]).collect();
    let mut covered: BTreeSet<usize> = BTreeSet::new();
    let now_day = util::unix_now().div_euclid(86_400);
    let young = s.created.is_some_and(|c| now_day - c.div_euclid(86_400) <= 180 || day(n.saturating_sub(1)) - c.div_euclid(86_400) <= 180);

    // (4) young crate: dormant then spike
    if young && n >= 15 {
        let (p, peak) = s.total.iter().enumerate().fold((0, 0.0), |a, (i, &v)| if v > a.1 { (i, v) } else { a });
        if p >= 14 {
            let before = &s.total[..p];
            let med = median(before);
            // a jump that holds for the following week is adoption (a popular crate started
            // depending on it), which the daily check reports as a level shift
            let after = &s.total[(p + 1).min(n)..(p + 8).min(n)];
            let sustained = after.len() >= 3 && median(after) >= 0.5 * peak;
            if med <= 5.0 && peak >= cfg.min_daily.max(50.0 * med.max(1.0)) && !sustained {
                covered.extend(p.saturating_sub(1)..(p + 7).min(n));
                out.push(Anom {
                    code: "anomaly/dormant-then-spike",
                    severity: Severity::High,
                    version: None,
                    date: day_str(day(p)),
                    message: format!("young crate jumped from ~{med:.0} downloads/day to {peak:.0} on {}", day_str(day(p))),
                    detail: format!(
                        "crate created {}; median {med:.1}/day over the {p} days before the spike. Sudden mass downloads of a new, previously unused crate are typical of typosquat/malware campaigns and bot inflation",
                        s.created.map(util::format_date).unwrap_or_else(|| "?".into())
                    ),
                    fix: "Verify the crate is the one you meant (name, owners, repository) and review its source before use".into(),
                });
            }
        }
    }

    // (2) new version burst
    for (id, info) in &s.versions {
        let Some(c) = info.created else { continue };
        let Some(series) = s.per_version.get(id) else { continue };
        if c < s.start + 14 || c > day(n.saturating_sub(1)) {
            continue;
        }
        let ci = (c - s.start) as usize;
        let base = median(&s.total[ci.saturating_sub(28)..ci]);
        let end = (ci + 3).min(n);
        if end <= ci {
            continue;
        }
        let new_avg = mean(&series[ci..end]);
        let others: Vec<f64> = (ci..end).map(|i| s.total[i] - series[i]).collect();
        let others_avg = mean(&others);
        if new_avg >= 2.0 * base.max(1.0) && new_avg >= cfg.min_daily && others_avg >= 0.7 * base {
            covered.extend(ci.saturating_sub(1)..(ci + 7).min(n));
            out.push(Anom {
                code: "anomaly/new-version-burst",
                severity: Severity::Medium,
                version: Some(info.num.clone()),
                date: day_str(c),
                message: format!(
                    "{} got {new_avg:.0} downloads/day in its first {} day(s) after release on {}, {:.1}x the crate's usual daily total, while older versions did not drop",
                    info.num,
                    end - ci,
                    day_str(c),
                    new_avg / base.max(1.0)
                ),
                detail: format!("median daily total in the 28 days before release: {base:.0}; older versions during the burst: {others_avg:.0}/day. An organic release replaces older versions instead of adding on top of them"),
                fix: format!("Compare the release with the repository (sm-crates srcverify) and check who published {} (sm-crates trustpub)", info.num),
            });
        }
    }

    // (3) old or yanked version growth
    let latest_id = s
        .versions
        .iter()
        .filter(|(_, v)| !v.yanked)
        .max_by(|a, b| util::parse_version(&a.1.num).cmp(&util::parse_version(&b.1.num)))
        .map(|(id, _)| *id);
    if n >= 21 {
        for (id, series) in &s.per_version {
            let Some(info) = s.versions.get(id) else { continue };
            let ver = util::parse_version(&info.num);
            let superseded = s.versions.values().any(|o| {
                !o.yanked
                    && o.created.is_some_and(|c| c <= day(n - 1) - 30)
                    && match (&ver, util::parse_version(&o.num)) {
                        (Some(a), Some(b)) => b > *a && util::semver_bucket(&b) == util::semver_bucket(a),
                        _ => false,
                    }
            });
            if !info.yanked && !superseded {
                continue;
            }
            // the baseline window must lie entirely after the release, or a young version's
            // first downloads would look like growth from zero
            if info.created.is_none_or(|c| c > day(n - 1) - 35) {
                continue;
            }
            let recent = mean(&series[n - 7..]);
            let base = median(&series[n.saturating_sub(35)..n - 7]);
            if recent < 5.0 * base.max(1.0) || recent - base < cfg.min_daily / 2.0 {
                continue;
            }
            let latest_recent = latest_id.and_then(|l| s.per_version.get(&l)).map(|v| mean(&v[n - 7..])).unwrap_or(0.0);
            let (code, sev, what) = if info.yanked {
                ("anomaly/yanked-version-growth", Severity::High, "yanked version")
            } else if recent > latest_recent {
                ("anomaly/old-version-growth", Severity::High, "superseded version")
            } else {
                ("anomaly/old-version-growth", Severity::Medium, "superseded version")
            };
            out.push(Anom {
                code,
                severity: sev,
                version: Some(info.num.clone()),
                date: day_str(day(n - 7)),
                message: format!("{what} {} jumped to {recent:.0} downloads/day over the last 7 days (from ~{base:.0}/day)", info.num),
                detail: format!(
                    "{:.1}x growth since {}; the latest version had {latest_recent:.0}/day over the same days. Someone is pinning or mirroring this release",
                    recent / base.max(1.0),
                    day_str(day(n - 7))
                ),
                fix: format!("Check why {} is being pulled (Cargo.lock pins, `=` requirements, mirrors) and whether it has known vulnerabilities (cargo audit)", info.num),
            });
        }
    }

    // (1) daily spikes of the total
    let mut i = 14;
    while i < n {
        if covered.contains(&i) || release_days.contains(&day(i)) {
            i += 1;
            continue;
        }
        let Some(z) = spike_score(s, i, cfg) else {
            i += 1;
            continue;
        };
        // merge consecutive spike days
        let mut j = i;
        while j + 1 < n && !release_days.contains(&day(j + 1)) && spike_score(s, j + 1, cfg).is_some() {
            j += 1;
        }
        let (pk, peak) = (i..=j).map(|k| (k, s.total[k])).fold((i, 0.0), |a, b| if b.1 > a.1 { b } else { a });
        let base = baseline(s, pk).0;
        let after: Vec<f64> = s.total[(j + 1).min(n)..(j + 8).min(n)].to_vec();
        let sustained = j - i >= 4 || (after.len() >= 3 && median(&after) >= 0.5 * peak);
        // which version carried it
        let carrier = s
            .per_version
            .iter()
            .map(|(id, v)| (id, v[pk] - median(&v[pk.saturating_sub(28)..pk])))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .filter(|(_, inc)| *inc > 0.5 * (peak - base))
            .and_then(|(id, _)| s.versions.get(id))
            .map(|v| v.num.clone());
        let span = if j > i { format!("{} to {}", day_str(day(i)), day_str(day(j))) } else { day_str(day(i)) };
        let via = carrier.as_ref().map(|v| format!(", mostly version {v}")).unwrap_or_default();
        if sustained {
            out.push(Anom {
                code: "anomaly/level-shift",
                severity: Severity::Info,
                version: carrier.clone(),
                date: day_str(day(i)),
                message: format!("downloads stepped up on {span} from ~{base:.0}/day to {peak:.0}/day and stayed there{via}"),
                detail: format!("median over the following week {:.0}/day; a lasting step usually means new dependents (organic adoption)", median(&after)),
                fix: "No action needed unless the crate's dependents do not explain it".into(),
            });
        } else {
            out.push(Anom {
                code: "anomaly/download-spike",
                severity: Severity::Medium,
                version: carrier.clone(),
                date: day_str(day(pk)),
                message: format!("download spike on {span}: {peak:.0}/day vs a usual ~{base:.0}/day ({:.1}x, robust z {z:.1}){via}", peak / base.max(1.0)),
                detail: format!(
                    "baseline: median of the trailing 28 {} days; no release of the crate on those days; the spike did not persist (following week median {:.0}/day)",
                    if is_weekend(day(pk)) { "weekend" } else { "weekday" },
                    median(&after)
                ),
                fix: "Check for bot inflation or a compromised dependent (sm-crates trustpub; recent reverse dependencies on crates.io)".into(),
            });
        }
        i = j + 1;
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.date.cmp(&b.date)));
    out
}

/// (median, sigma) of the trailing 28 days of the same day type before index `i`.
fn baseline(s: &Series, i: usize) -> (f64, f64) {
    let lo = i.saturating_sub(28);
    let we = is_weekend(s.start + i as i64);
    let same: Vec<f64> = (lo..i).filter(|&k| is_weekend(s.start + k as i64) == we).map(|k| s.total[k]).collect();
    let w: Vec<f64> = if same.len() >= 4 { same } else { s.total[lo..i].to_vec() };
    let m = median(&w);
    let sigma = (1.4826 * mad(&w)).max(0.1 * m).max(1.0);
    (m, sigma)
}

fn spike_score(s: &Series, i: usize, cfg: &Config) -> Option<f64> {
    let x = s.total[i];
    let (m, sigma) = baseline(s, i);
    let z = (x - m) / sigma;
    (z > cfg.threshold && x > 3.0 * m && x - m >= cfg.min_daily).then_some(z)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(total: Vec<f64>) -> Series {
        Series { start: util::days_from_civil(2025, 1, 6), total, per_version: BTreeMap::new(), versions: BTreeMap::new(), created: Some(0) }
    }

    fn cfg() -> Config {
        Config { days: 90, threshold: 6.0, min_daily: 100.0 }
    }

    #[test]
    fn weekly_pattern_is_quiet_and_spike_fires() {
        // 2025-01-06 is a Monday
        let base: Vec<f64> = (0..90).map(|i| if matches!(i % 7, 5 | 6) { 300.0 + (i % 3) as f64 * 10.0 } else { 1000.0 + (i % 5) as f64 * 20.0 }).collect();
        assert!(detect(&series(base.clone()), &cfg()).is_empty());
        let mut sp = base.clone();
        sp[60] = 9000.0;
        let a = detect(&series(sp), &cfg());
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!(a[0].code, "anomaly/download-spike");
        // a lasting step is a level shift
        let mut step = base;
        for v in step.iter_mut().skip(70) {
            *v *= 6.0;
        }
        let a = detect(&series(step), &cfg());
        assert!(a.iter().all(|x| x.code == "anomaly/level-shift" && x.severity == Severity::Info), "{a:?}");
        assert!(weekday(util::days_from_civil(2025, 1, 6)) == 1 && is_weekend(util::days_from_civil(2025, 1, 5)));
    }

    #[test]
    fn young_crate_adoption_is_not_a_dormant_spike() {
        let today = util::unix_now().div_euclid(86_400);
        let young = |total: Vec<f64>| Series {
            start: today - total.len() as i64 + 1,
            total,
            per_version: BTreeMap::new(),
            versions: BTreeMap::new(),
            created: Some((today - 60) * 86_400),
        };
        // near zero for 30 days, then a lasting jump: a new dependent, not an attack
        let mut t: Vec<f64> = (0..60).map(|i| (i % 3) as f64).collect();
        for v in t.iter_mut().skip(30) {
            *v = 800.0 + 0.0;
        }
        let a = detect(&young(t), &cfg());
        assert!(a.iter().all(|x| x.code != "anomaly/dormant-then-spike"), "{a:?}");
        assert!(a.iter().any(|x| x.code == "anomaly/level-shift"), "{a:?}");
        // a one-day burst that collapses again is still flagged
        let mut t: Vec<f64> = (0..60).map(|i| (i % 3) as f64).collect();
        t[40] = 5000.0;
        let a = detect(&young(t), &cfg());
        assert!(a.iter().any(|x| x.code == "anomaly/dormant-then-spike" && x.severity == Severity::High), "{a:?}");
    }
}
