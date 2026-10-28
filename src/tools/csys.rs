//! Bundled C Library Scanner: Find C libraries vendored in -sys/-src crates, match their versions to CVEs, and flag links conflicts.
//!
//! `cargo audit` only knows Rust advisories. A `-sys` crate that compiles a
//! bundled copy of OpenSSL, SQLite or zlib inherits that library's CVEs, which
//! are tracked in NVD under the C library's name. This tool finds the bundled
//! copies, works out their upstream versions and looks them up in NVD.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::http::Ttl;
use crate::registry::{download, index};
use crate::report::{Finding, Report, Severity, Table};
use crate::tools::common::{self, CrateRef, Select};
use crate::tools::unsafe_hotspots::par_map;
use crate::tools::{Group, Tool};
use crate::util;

pub struct Csys;

const OPTS: &[Opt] = &[
    Opt::value("only", "A,B", "Only check these dependencies (comma-separated names)"),
    Opt::flag("no-scan", "Only consider -sys/-src crates and crates with a `links` key (skip scanning other crates' tarballs for C sources)"),
    Opt::flag("no-cve", "Skip the NVD lookup (versions and links checks only)"),
];

impl Tool for Csys {
    fn name(&self) -> &'static str {
        "csys"
    }
    fn title(&self) -> &'static str {
        "Bundled C Library Scanner"
    }
    fn group(&self) -> Group {
        Group::SupplyChain
    }
    fn summary(&self) -> &'static str {
        "Find C libraries vendored in -sys/-src crates, match their versions to CVEs, and flag links conflicts"
    }
    fn usage(&self) -> &'static str {
        "[CRATE[@VERSION]...] [OPTIONS]"
    }
    fn about(&self) -> &'static str {
        "Finds C libraries bundled inside Rust crates and checks the bundled versions against NVD. Candidates are
crates named *-sys / *-src, crates whose index entry has a `links` key, and (unless --no-scan) any
crate whose .crate contains C/C++ sources. The upstream version is read from semver build metadata
first (openssl-src 300.3.1+3.3.1 -> OpenSSL 3.3.1, libgit2-sys 0.17.0+1.8.1, curl-sys
0.4.73+curl-8.8.0, zstd-sys 2.0.13+zstd.1.5.6, bzip2-sys, libnghttp2-sys ...), otherwise from the
bundled headers (opensslv.h / VERSION.dat, git2/version.h, sqlite3.h, zlib.h, zlib-ng.h, curlver.h,
libssh2.h, zstd.h, lz4.h, lzma/version.h, png.h, expat.h, xmlversion.h, mbedtls version headers,
pcre2.h, uv/version.h, nghttp2ver.h, brotli version.h, libwebp, freetype.h, hb-version.h,
bzlib_private.h, libjpeg-turbo CMakeLists.txt).

Whether the vendored copy is actually compiled depends on features: in a project the enabled
features are read from cargo metadata (`vendored`, `bundled`, `static`, ...); copies that are not
built (the system library is used instead) are reported at low severity, and copies built only when
no system library is found are marked \"if no system lib\".

CVEs come from the NVD CVE API 2.0 (cpeName=cpe:2.3:a:<vendor>:<product>:<version>, e.g.
openssl:openssl, sqlite:sqlite, haxx:libcurl, facebook:zstandard), cached for a day. NVD allows 5
requests per 30 s without a key: set NVD_API_KEY to go faster. Severity follows the highest CVSS v4.0
/ v3.x base severity. The fix names the newest release of the same crate whose build metadata bundles
a newer upstream version. Also reported: two packages with the same `links` value (cargo refuses to
build them together) and the same C library compiled from two different crates (duplicate-symbol
risk), both medium. NVD's CPE matching is only as good as its data: a version absent from NVD
yields no CVEs, so read a clean result as \"nothing known\", not \"safe\"."
    }
    fn options(&self) -> &'static [Opt] {
        OPTS
    }
    fn examples(&self) -> &'static [&'static str] {
        &[
            "sm-crates csys",
            "sm-crates csys openssl-src@300.0.1+3.0.1 libsqlite3-sys@0.28.0",
            "sm-crates csys libz-sys zstd-sys curl-sys --no-cve",
            "sm-crates csys --no-scan --json",
        ]
    }
    fn requires(&self) -> &'static str {
        "network (crate downloads, NVD CVE API; NVD_API_KEY optional)"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report> {
        let (subject, crates, meta) = common::select(ctx, args, Select::default())?;
        let crates: Vec<CrateRef> = common::only(args, crates).into_iter().filter(|c| c.is_registry()).collect();
        common::non_empty(&crates)?;
        let mut rep = Report::new("csys", subject);
        let project = meta.is_some();

        // Index entries (links) for every crate.
        let names: Vec<String> = crates.iter().map(|c| c.name.clone()).collect::<BTreeSet<_>>().into_iter().collect();
        let idx = index::versions_many(ctx, &names);
        let entry = |c: &CrateRef| idx.get(&c.name).and_then(|v| v.as_ref()).and_then(|vs| index::find(vs, &c.version).cloned());

        // Candidates.
        let scan = !args.flag("no-scan");
        let probes = par_map(&crates, 8, |c| -> Result<Option<Candidate>> {
            let e = entry(c);
            let links = e.as_ref().and_then(|e| e.links.clone());
            let named = c.name.ends_with("-sys") || c.name.ends_with("_sys") || c.name.ends_with("-src") || c.name.ends_with("_src");
            if !named && links.is_none() {
                if !scan {
                    return Ok(None);
                }
                let data = download::crate_bytes(ctx, &c.name, &c.version)?;
                let entries = download::list_entries(&data)?;
                if !entries.iter().any(|(p, _)| is_c_source(p)) {
                    return Ok(None);
                }
            }
            let dir = c.source_dir(ctx)?;
            Ok(Some(analyze_crate(c, &dir, links)))
        });
        let mut cands: Vec<Candidate> = Vec::new();
        for (c, p) in crates.iter().zip(probes) {
            match p {
                Ok(Some(mut cand)) => {
                    if let (Some(m), Some(id)) = (&meta, &c.id) {
                        cand.features = Some(m.features_of(id));
                    }
                    cands.push(cand);
                }
                Ok(None) => {}
                Err(e) => rep.note(format!("{}: skipped ({e})", c.spec())),
            }
        }

        // Newest bundled upstream per crate (from build metadata of later releases).
        for cand in &mut cands {
            for lib in &mut cand.libs {
                if let Some(vs) = idx.get(&cand.name).and_then(|v| v.as_ref()) {
                    lib.fixed_in = newest_bundle(vs, &cand.name, lib.key, &lib.version);
                }
            }
        }

        // NVD.
        let use_nvd = !args.flag("no-cve");
        let mut nvd_state = NvdState { last: Mutex::new(None), error: Mutex::new(None), unreachable: false };
        let mut cve_cache: BTreeMap<(String, String), Option<Vec<Cve>>> = BTreeMap::new();
        if use_nvd {
            let wanted: BTreeSet<(String, String)> = cands
                .iter()
                .flat_map(|c| c.libs.iter())
                .filter(|l| !l.version.is_empty())
                .map(|l| (l.key.to_string(), l.version.clone()))
                .collect();
            for (k, v) in wanted {
                let Some(lib) = lib_info(&k) else { continue };
                // after a transport failure (NVD unreachable) do not wait out the rate limit for every library
                if nvd_state.unreachable {
                    cve_cache.insert((k, v), None);
                    continue;
                }
                let r = nvd_lookup(ctx, args, lib, &v, &mut nvd_state);
                cve_cache.insert((k, v), r);
            }
            if let Some(e) = nvd_state.error.get_mut().ok().and_then(|e| e.take()) {
                rep.note(format!("NVD lookups failed for some libraries ({e}); their CVE counts are unknown, not zero"));
            }
        }

        // Tables and findings.
        let mut t = Table::new(
            "Bundled C libraries",
            &["Crate", "Version", "C library", "Upstream version", "Version from", "Vendored copy built?", "CVEs", "Newer bundle"],
        );
        let mut other = Table::new("Other bundled C/C++ sources", &["Crate", "Version", "C/C++ files", "Links"]);
        let mut data = Vec::new();
        let mut by_lib: BTreeMap<&'static str, Vec<(String, String)>> = BTreeMap::new();
        let mut total_cves = 0;
        for cand in &cands {
            if cand.libs.is_empty() {
                if cand.c_files > 0 {
                    other.row([cand.name.clone(), cand.version.clone(), cand.c_files.to_string(), cand.links.clone().unwrap_or_else(|| "-".into())]);
                }
                data.push(cand.to_json(&[], project));
                continue;
            }
            let mut libs_json = Vec::new();
            for lib in &cand.libs {
                let info = lib_info(lib.key);
                let in_use = cand.in_use(lib.key, project);
                if in_use != InUse::No {
                    by_lib.entry(lib.key).or_default().push((cand.name.clone(), cand.version.clone()));
                }
                let cves = if use_nvd { cve_cache.get(&(lib.key.to_string(), lib.version.clone())).cloned().flatten() } else { None };
                let display = info.map(|i| i.display).unwrap_or(lib.key);
                t.row([
                    cand.name.clone(),
                    cand.version.clone(),
                    display.to_string(),
                    if lib.version.is_empty() { "?".into() } else { lib.version.clone() },
                    lib.source.clone(),
                    in_use.label().to_string(),
                    match (&cves, use_nvd) {
                        (_, false) => "not checked".into(),
                        (Some(v), _) => v.len().to_string(),
                        (None, _) => "unknown".into(),
                    },
                    lib.fixed_in.as_ref().map(|(c, u)| format!("{c} ({u})")).unwrap_or_else(|| "-".into()),
                ]);
                let k = |f: Finding| f.krate(&cand.name, Some(&cand.version));
                let fix = match &lib.fixed_in {
                    Some((c, u)) => format!("update {} to {c} (bundles {display} {u})", cand.name),
                    None => format!("update {} and check which {display} it bundles, or build against a patched system {display}", cand.name),
                };
                if let Some(cves) = &cves {
                    total_cves += cves.len();
                    if !cves.is_empty() {
                        let worst = cves.iter().map(|c| c.severity).max().unwrap_or(Severity::Medium);
                        let sev = match in_use {
                            InUse::No => Severity::Low,
                            _ => worst,
                        };
                        let mut sorted = cves.clone();
                        sorted.sort_by(|a, b| b.score.total_cmp(&a.score).then(b.id.cmp(&a.id)));
                        let mut detail: Vec<String> = sorted
                            .iter()
                            .take(10)
                            .map(|c| format!("{} {} {:.1}: {}", c.id, c.severity.as_str().to_uppercase(), c.score, c.summary))
                            .collect();
                        if sorted.len() > 10 {
                            detail.push(format!("… and {} more", sorted.len() - 10));
                        }
                        if in_use == InUse::No {
                            detail.push("the vendored copy is not built with the enabled features; the system library is used (check your OS package)".into());
                        } else if in_use == InUse::Maybe {
                            detail.push("the vendored copy is built only when no system library is found".into());
                        }
                        let counts = count_by_severity(cves);
                        let mut f = k(Finding::new(
                            sev,
                            "csys/cve",
                            format!("bundled {display} {} has {} known CVE(s){counts}", lib.version, cves.len()),
                        ))
                        .detail(detail.join("\n"))
                        .fix(fix.clone());
                        if let Some(p) = &lib.path {
                            f = f.at(p.clone(), None);
                        }
                        rep.finding(f);
                    }
                }
                if cves.as_ref().is_none_or(|c| c.is_empty()) {
                    if let Some((c, u)) = &lib.fixed_in {
                        rep.finding(k(Finding::new(
                            Severity::Low,
                            "csys/outdated",
                            format!("bundled {display} {} is older than the {u} bundled by {} {c}", lib.version, cand.name),
                        ))
                        .fix(fix.clone()));
                    }
                }
                libs_json.push(json!({
                    "library": lib.key, "display": display, "upstream_version": lib.version, "version_source": lib.source,
                    "header": lib.path, "vendored_in_use": in_use.code(),
                    "cpe": info.filter(|_| !lib.version.is_empty()).map(|i| cpe(i, &lib.version)),
                    "cves": cves.as_ref().map(|v| v.iter().map(|c| json!({"id": c.id, "severity": c.severity.as_str(), "score": c.score, "summary": c.summary})).collect::<Vec<_>>()),
                    "newer_bundle": lib.fixed_in.as_ref().map(|(c, u)| json!({"crate_version": c, "upstream_version": u})),
                }));
            }
            data.push(cand.to_json(&libs_json, project));
        }
        rep.table(t);
        rep.table(other);

        // Same C library compiled from different crates.
        for (lib, users) in &by_lib {
            let distinct: BTreeSet<&String> = users.iter().map(|(n, _)| n).collect();
            if distinct.len() > 1 {
                let display = lib_info(lib).map(|i| i.display).unwrap_or(lib);
                rep.finding(
                    Finding::new(
                        Severity::Medium,
                        "csys/duplicate-library",
                        format!("{display} is bundled by {} different crates: {}", distinct.len(), users.iter().map(|(n, v)| format!("{n}@{v}")).collect::<Vec<_>>().join(", ")),
                    )
                    .detail("two statically linked copies of the same C library can clash at link time (duplicate symbols) or silently use different versions")
                    .fix("enable the features that make one crate link the other's copy (e.g. a `system`/`pkg-config` feature), or drop one of them"),
                );
            }
        }
        // links conflicts.
        let mut links: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        match &meta {
            Some(m) => {
                let reach = m.reachable(true, true);
                for p in m.packages.iter().filter(|p| reach.contains(&p.id)) {
                    if let Some(l) = &p.links {
                        links.entry(l.clone()).or_default().insert(p.spec());
                    }
                }
            }
            None => {
                for c in &crates {
                    if let Some(l) = entry(c).and_then(|e| e.links) {
                        links.entry(l).or_default().insert(c.spec());
                    }
                }
            }
        }
        for (l, pkgs) in &links {
            if pkgs.len() > 1 {
                rep.finding(
                    Finding::new(
                        Severity::Medium,
                        "csys/links-conflict",
                        format!("{} packages declare links = \"{l}\": {}", pkgs.len(), pkgs.iter().cloned().collect::<Vec<_>>().join(", ")),
                    )
                    .detail("cargo allows only one package per native library name in a build; these cannot be compiled together")
                    .fix("align the dependents on one version of the -sys crate"),
                );
            }
        }

        let with_lib = cands.iter().filter(|c| !c.libs.is_empty()).count();
        // libraries whose CVEs could not be looked up (NVD unreachable, or version unknown)
        let unknown = cands
            .iter()
            .flat_map(|c| c.libs.iter())
            .filter(|l| l.version.is_empty() || cve_cache.get(&(l.key.to_string(), l.version.clone())).is_none_or(|r| r.is_none()))
            .count();
        rep.summary(format!(
            "{} of {} crate(s) bundle a known C library{}; {} with other C/C++ sources",
            with_lib,
            crates.len(),
            match (use_nvd, unknown) {
                (false, _) => String::new(),
                (true, 0) => format!(" ({total_cves} known CVE(s) in bundled versions)"),
                (true, u) => format!(" ({total_cves} known CVE(s) in bundled versions; CVEs NOT checked for {u} bundled librar{})", if u == 1 { "y" } else { "ies" }),
            },
            cands.iter().filter(|c| c.libs.is_empty() && c.c_files > 0).count()
        ));
        let bindings = cands.iter().filter(|c| c.libs.is_empty() && c.c_files == 0).count();
        if bindings > 0 {
            rep.note(format!("{bindings} -sys/links crate(s) bundle no C sources (they bind to a system library or another crate's copy)"));
        }
        if !scan {
            rep.note("--no-scan: crates not named -sys/-src and without `links` were not inspected for C sources");
        }
        rep.data = json!({ "crates": data, "links": links });
        Ok(rep)
    }
}

// ---------------------------------------------------------------- libraries

struct LibInfo {
    key: &'static str,
    display: &'static str,
    vendor: &'static str,
    product: &'static str,
}

const LIBS: &[LibInfo] = &[
    LibInfo { key: "openssl", display: "OpenSSL", vendor: "openssl", product: "openssl" },
    LibInfo { key: "libgit2", display: "libgit2", vendor: "libgit2_project", product: "libgit2" },
    LibInfo { key: "sqlite", display: "SQLite", vendor: "sqlite", product: "sqlite" },
    LibInfo { key: "zlib", display: "zlib", vendor: "zlib", product: "zlib" },
    LibInfo { key: "zlib-ng", display: "zlib-ng", vendor: "zlib-ng", product: "zlib-ng" },
    LibInfo { key: "curl", display: "libcurl", vendor: "haxx", product: "libcurl" },
    LibInfo { key: "libssh2", display: "libssh2", vendor: "libssh2", product: "libssh2" },
    LibInfo { key: "zstd", display: "zstd", vendor: "facebook", product: "zstandard" },
    LibInfo { key: "lz4", display: "LZ4", vendor: "lz4_project", product: "lz4" },
    LibInfo { key: "xz", display: "XZ Utils (liblzma)", vendor: "tukaani", product: "xz" },
    LibInfo { key: "libpng", display: "libpng", vendor: "libpng", product: "libpng" },
    LibInfo { key: "expat", display: "Expat", vendor: "libexpat_project", product: "libexpat" },
    LibInfo { key: "libxml2", display: "libxml2", vendor: "xmlsoft", product: "libxml2" },
    LibInfo { key: "mbedtls", display: "Mbed TLS", vendor: "arm", product: "mbed_tls" },
    LibInfo { key: "pcre2", display: "PCRE2", vendor: "pcre", product: "pcre2" },
    LibInfo { key: "libuv", display: "libuv", vendor: "libuv", product: "libuv" },
    LibInfo { key: "nghttp2", display: "nghttp2", vendor: "nghttp2", product: "nghttp2" },
    LibInfo { key: "brotli", display: "Brotli", vendor: "google", product: "brotli" },
    LibInfo { key: "libwebp", display: "libwebp", vendor: "webmproject", product: "libwebp" },
    LibInfo { key: "freetype", display: "FreeType", vendor: "freetype", product: "freetype" },
    LibInfo { key: "harfbuzz", display: "HarfBuzz", vendor: "harfbuzz_project", product: "harfbuzz" },
    LibInfo { key: "bzip2", display: "bzip2", vendor: "bzip", product: "bzip2" },
    LibInfo { key: "libjpeg-turbo", display: "libjpeg-turbo", vendor: "libjpeg-turbo", product: "libjpeg-turbo" },
];

fn lib_info(key: &str) -> Option<&'static LibInfo> {
    LIBS.iter().find(|l| l.key == key)
}

fn cpe(l: &LibInfo, version: &str) -> String {
    format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", l.vendor, l.product, version)
}

/// When a crate's bundled copy is compiled.
#[derive(Debug, Clone, Copy)]
enum Policy {
    Always,
    /// Only with one of these features.
    Feature(&'static [&'static str]),
    /// With one of these features, or when no system library is found.
    Fallback(&'static [&'static str]),
    /// Unless one of these features is enabled.
    Unless(&'static [&'static str]),
}

/// Known crates: (crate, library, whether build metadata carries the upstream version, policy).
const CRATES: &[(&str, &str, bool, Policy)] = &[
    ("openssl-src", "openssl", true, Policy::Always),
    ("libgit2-sys", "libgit2", true, Policy::Fallback(&["vendored"])),
    ("libsqlite3-sys", "sqlite", false, Policy::Feature(&["bundled", "bundled-windows", "bundled-sqlcipher", "bundled-sqlcipher-vendored-openssl"])),
    ("libz-sys", "zlib", false, Policy::Fallback(&["static"])),
    ("libz-sys", "zlib-ng", false, Policy::Feature(&["zlib-ng", "zlib-ng-no-cmake-experimental-community-maintained"])),
    ("libz-ng-sys", "zlib-ng", true, Policy::Always),
    ("curl-sys", "curl", true, Policy::Fallback(&["static-curl"])),
    ("libssh2-sys", "libssh2", false, Policy::Fallback(&["vendored-openssl"])),
    ("zstd-sys", "zstd", true, Policy::Unless(&["pkg-config"])),
    ("libnghttp2-sys", "nghttp2", true, Policy::Always),
    ("bzip2-sys", "bzip2", true, Policy::Fallback(&["static"])),
    ("lzma-sys", "xz", false, Policy::Fallback(&["static"])),
    ("liblzma-sys", "xz", true, Policy::Fallback(&["static"])),
    ("lz4-sys", "lz4", false, Policy::Always),
    ("expat-sys", "expat", false, Policy::Always),
    ("mbedtls-sys-auto", "mbedtls", false, Policy::Always),
    ("pcre2-sys", "pcre2", false, Policy::Fallback(&["static"])),
    ("libuv-sys2", "libuv", false, Policy::Always),
    ("brotli-sys", "brotli", false, Policy::Always),
    ("libwebp-sys", "libwebp", false, Policy::Always),
    ("freetype-sys", "freetype", false, Policy::Fallback(&["bundled"])),
    ("harfbuzz-sys", "harfbuzz", false, Policy::Feature(&["bundled"])),
    ("mozjpeg-sys", "libjpeg-turbo", false, Policy::Always),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InUse {
    Yes,
    No,
    Maybe,
    Unknown,
}

impl InUse {
    fn label(&self) -> &'static str {
        match self {
            InUse::Yes => "yes",
            InUse::No => "no (system lib)",
            InUse::Maybe => "if no system lib",
            InUse::Unknown => "depends on features",
        }
    }
    fn code(&self) -> &'static str {
        match self {
            InUse::Yes => "yes",
            InUse::No => "no",
            InUse::Maybe => "if-no-system-lib",
            InUse::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct Lib {
    key: &'static str,
    version: String,
    /// `build metadata` or the header path.
    source: String,
    path: Option<String>,
    fixed_in: Option<(String, String)>,
}

#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    version: String,
    links: Option<String>,
    c_files: usize,
    libs: Vec<Lib>,
    features: Option<Vec<String>>,
}

impl Candidate {
    fn in_use(&self, lib: &str, project: bool) -> InUse {
        let policy = CRATES.iter().find(|(c, l, _, _)| *c == self.name && *l == lib).map(|x| x.3);
        let Some(policy) = policy else {
            // Unknown crate that ships C sources: it most likely compiles them.
            return if self.name.ends_with("-sys") || self.name.ends_with("_sys") { InUse::Unknown } else { InUse::Yes };
        };
        let on = |list: &[&str]| self.features.as_ref().is_some_and(|f| f.iter().any(|x| list.contains(&x.as_str())));
        match (policy, project && self.features.is_some()) {
            (Policy::Always, _) => InUse::Yes,
            (Policy::Feature(_), false) | (Policy::Fallback(_), false) | (Policy::Unless(_), false) => InUse::Unknown,
            (Policy::Feature(l), true) => {
                if on(l) {
                    InUse::Yes
                } else {
                    InUse::No
                }
            }
            (Policy::Fallback(l), true) => {
                if on(l) {
                    InUse::Yes
                } else {
                    InUse::Maybe
                }
            }
            (Policy::Unless(l), true) => {
                if on(l) {
                    InUse::No
                } else {
                    InUse::Yes
                }
            }
        }
    }

    fn to_json(&self, libs: &[Value], project: bool) -> Value {
        json!({"crate": self.name, "version": self.version, "links": self.links, "c_source_files": self.c_files,
               "enabled_features": if project { json!(self.features) } else { Value::Null }, "libraries": libs})
    }
}

fn is_c_source(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".s", ".asm"].iter().any(|e| l.ends_with(e))
}

/// Upstream version from semver build metadata: `300.3.1+3.3.1` -> `3.3.1`,
/// `0.4.73+curl-8.8.0` -> `8.8.0`, `111.28.0+1.1.1w` -> `1.1.1w`.
pub fn version_from_metadata(v: &str) -> Option<String> {
    let meta = v.split_once('+')?.1;
    let b = meta.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.' || b[i - 1] == b'-') {
            let start = i;
            let mut j = i;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                j += 1;
            }
            let mut s = meta[start..j].trim_end_matches('.').to_string();
            if s.contains('.') {
                // OpenSSL 1.x letter releases: 1.1.1w
                if j < b.len() && b[j].is_ascii_lowercase() && (j + 1 == b.len() || !b[j + 1].is_ascii_alphanumeric()) {
                    s.push(b[j] as char);
                }
                return Some(s);
            }
            i = j;
        } else {
            i += 1;
        }
    }
    None
}

/// Compare upstream versions like `1.1.1w`, `3.0.1`, `1.5.6`.
fn cmp_upstream(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> (Vec<u64>, String) {
        let mut nums = Vec::new();
        let mut suffix = String::new();
        for part in s.split('.') {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            nums.push(digits.parse().unwrap_or(0));
            let rest: String = part.chars().skip_while(|c| c.is_ascii_digit()).collect();
            if !rest.is_empty() {
                suffix = rest;
            }
        }
        (nums, suffix)
    };
    let (an, asx) = parse(a);
    let (bn, bsx) = parse(b);
    let n = an.len().max(bn.len());
    for i in 0..n {
        let (x, y) = (an.get(i).copied().unwrap_or(0), bn.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    asx.cmp(&bsx)
}

/// The newest non-yanked release of `krate` whose build metadata bundles an upstream version newer than `current`.
fn newest_bundle(vs: &[index::IndexVersion], krate: &str, lib: &str, current: &str) -> Option<(String, String)> {
    if current.is_empty() || !CRATES.iter().any(|(c, l, meta, _)| *c == krate && *l == lib && *meta) {
        return None;
    }
    vs.iter()
        .filter(|v| !v.yanked && !v.is_prerelease())
        .filter_map(|v| version_from_metadata(&v.vers).map(|u| (v, u)))
        .filter(|(_, u)| cmp_upstream(u, current) == std::cmp::Ordering::Greater)
        .max_by(|a, b| cmp_upstream(&a.1, &b.1).then_with(|| a.0.version().cmp(&b.0.version())))
        .map(|(v, u)| (v.vers.clone(), u))
}

fn analyze_crate(c: &CrateRef, dir: &Path, links: Option<String>) -> Candidate {
    let files = util::walk_files(dir);
    let c_files = files.iter().filter(|p| is_c_source(&util::rel(dir, p))).count();
    let mut libs: Vec<Lib> = Vec::new();
    // 1. build metadata of known crates
    for (krate, lib, meta, _) in CRATES {
        if *krate == c.name && *meta {
            if let Some(v) = version_from_metadata(&c.version) {
                libs.push(Lib { key: lib, version: v, source: "build metadata".into(), path: None, fixed_in: None });
            }
        }
    }
    // 2. headers; the first copy found wins, so look at alternative bundles (libsqlite3-sys ships
    // SQLCipher's amalgamation next to SQLite's) and test fixtures last
    let mut ordered: Vec<&std::path::PathBuf> = files.iter().collect();
    ordered.sort_by_key(|p| {
        let rel = util::rel(dir, p).to_ascii_lowercase();
        let secondary = rel.split('/').any(|c| matches!(c, "sqlcipher" | "test" | "tests" | "testdata" | "examples" | "fuzz" | "benches"));
        (secondary, rel)
    });
    for p in ordered {
        let rel = util::rel(dir, p);
        let base = p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        let Some(key) = header_lib(&base, &rel) else { continue };
        if libs.iter().any(|l| l.key == key) {
            // keep the first detection, but remember a header path for metadata-only entries
            if let Some(l) = libs.iter_mut().find(|l| l.key == key && l.path.is_none()) {
                l.path = Some(rel);
            }
            continue;
        }
        if std::fs::metadata(p).map(|m| m.len() > 16 * 1024 * 1024).unwrap_or(true) {
            continue;
        }
        let Ok(text) = util::read_to_string_lossy(p) else { continue };
        if let Some(v) = header_version(key, &base, &text, p) {
            libs.push(Lib { key, version: v, source: rel.clone(), path: Some(rel), fixed_in: None });
        }
    }
    // known crate whose bundled library we could not identify: still list it (but not the
    // optional second library of a crate that bundles one we did find, e.g. libz-sys without zlib-ng)
    let found_any = !libs.is_empty();
    for (krate, lib, _, _) in CRATES {
        if *krate == c.name && !found_any && !libs.iter().any(|l| l.key == *lib) && c_files > 0 {
            libs.push(Lib { key: lib, version: String::new(), source: "not found".into(), path: None, fixed_in: None });
        }
    }
    Candidate { name: c.name.clone(), version: c.version.clone(), links, c_files, libs, features: None }
}

/// Which library a header file identifies.
fn header_lib(base: &str, rel: &str) -> Option<&'static str> {
    let r = rel.to_ascii_lowercase();
    Some(match base {
        "opensslv.h" | "VERSION.dat" if r.contains("openssl") || base == "opensslv.h" => "openssl",
        "version.h" if r.ends_with("git2/version.h") => "libgit2",
        "sqlite3.h" => "sqlite",
        "zlib.h" if !r.contains("zlib-ng") => "zlib",
        "zlib-ng.h" | "zlib-ng.h.in" => "zlib-ng",
        "curlver.h" => "curl",
        "libssh2.h" => "libssh2",
        "zstd.h" => "zstd",
        "lz4.h" => "lz4",
        "version.h" if r.ends_with("lzma/version.h") => "xz",
        "png.h" => "libpng",
        "expat.h" => "expat",
        "xmlversion.h" => "libxml2",
        "build_info.h" | "version.h" if r.contains("mbedtls/") => "mbedtls",
        "pcre2.h" | "pcre2.h.generic" | "pcre2.h.in" => "pcre2",
        "version.h" if r.ends_with("uv/version.h") => "libuv",
        "nghttp2ver.h" => "nghttp2",
        "version.h" if r.contains("brotli") && r.ends_with("common/version.h") => "brotli",
        "vp8i_dec.h" => "libwebp",
        "freetype.h" => "freetype",
        "hb-version.h" => "harfbuzz",
        "bzlib_private.h" => "bzip2",
        "CMakeLists.txt" if r.contains("jpeg") => "libjpeg-turbo",
        _ => return None,
    })
}

/// `#define NAME "value"` (also `# define`).
fn define_str(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix('#') else { continue };
        let Some(rest) = rest.trim_start().strip_prefix("define") else { continue };
        let rest = rest.trim_start();
        let Some(after) = rest.strip_prefix(name) else { continue };
        if !after.starts_with([' ', '\t']) {
            continue;
        }
        let v = after.trim();
        if let Some(q) = v.strip_prefix('"') {
            return q.split('"').next().map(String::from);
        }
    }
    None
}

/// `#define NAME 12` (decimal or hex).
fn define_num(text: &str, name: &str) -> Option<u64> {
    for line in text.lines() {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix('#') else { continue };
        let Some(rest) = rest.trim_start().strip_prefix("define") else { continue };
        let Some(after) = rest.trim_start().strip_prefix(name) else { continue };
        if !after.starts_with([' ', '\t']) {
            continue;
        }
        let tok: String = after.trim().trim_start_matches('(').chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        let tok = tok.trim_end_matches(['U', 'L', 'u', 'l']);
        return if let Some(h) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) { u64::from_str_radix(h, 16).ok() } else { tok.parse().ok() };
    }
    None
}

fn triple(text: &str, a: &str, b: &str, c: &str) -> Option<String> {
    Some(format!("{}.{}.{}", define_num(text, a)?, define_num(text, b)?, define_num(text, c)?))
}

/// Keep only a plain dotted version (drops `-DEV`, `.zlib-ng`, dates, `@VERSION@` templates).
fn clean(v: &str) -> Option<String> {
    let v = v.trim();
    let mut out = String::new();
    for ch in v.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            out.push(ch);
        } else {
            if out.contains('.') && ch.is_ascii_lowercase() && !out.ends_with('.') {
                out.push(ch);
            }
            break;
        }
    }
    let out = out.trim_end_matches('.').to_string();
    out.contains('.').then_some(out)
}

fn header_version(key: &str, base: &str, text: &str, path: &Path) -> Option<String> {
    match key {
        "openssl" => {
            if base == "VERSION.dat" {
                let get = |k: &str| text.lines().find_map(|l| l.trim().strip_prefix(&format!("{k}=")).map(|v| v.trim().trim_matches('"').to_string()));
                return Some(format!("{}.{}.{}", get("MAJOR")?, get("MINOR")?, get("PATCH")?));
            }
            // "OpenSSL 1.1.1w  11 Sep 2023"
            let t = define_str(text, "OPENSSL_VERSION_TEXT").or_else(|| define_str(text, "OPENSSL_VERSION_STR"))?;
            let v = t.split_whitespace().find(|w| w.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
            clean(v)
        }
        "libgit2" => define_str(text, "LIBGIT2_VERSION").and_then(|v| clean(&v)).or_else(|| triple(text, "LIBGIT2_VER_MAJOR", "LIBGIT2_VER_MINOR", "LIBGIT2_VER_REVISION")),
        "sqlite" => define_str(text, "SQLITE_VERSION").and_then(|v| clean(&v)),
        "zlib" => define_str(text, "ZLIB_VERSION").and_then(|v| clean(&v)),
        "zlib-ng" => define_str(text, "ZLIBNG_VERSION").and_then(|v| clean(&v)),
        "curl" => define_str(text, "LIBCURL_VERSION").and_then(|v| clean(&v)),
        "libssh2" => define_str(text, "LIBSSH2_VERSION").and_then(|v| clean(&v)),
        "zstd" => triple(text, "ZSTD_VERSION_MAJOR", "ZSTD_VERSION_MINOR", "ZSTD_VERSION_RELEASE"),
        "lz4" => triple(text, "LZ4_VERSION_MAJOR", "LZ4_VERSION_MINOR", "LZ4_VERSION_RELEASE"),
        "xz" => triple(text, "LZMA_VERSION_MAJOR", "LZMA_VERSION_MINOR", "LZMA_VERSION_PATCH"),
        "libpng" => define_str(text, "PNG_LIBPNG_VER_STRING").and_then(|v| clean(&v)),
        "expat" => triple(text, "XML_MAJOR_VERSION", "XML_MINOR_VERSION", "XML_MICRO_VERSION"),
        "libxml2" => define_str(text, "LIBXML_DOTTED_VERSION").and_then(|v| clean(&v)),
        "mbedtls" => define_str(text, "MBEDTLS_VERSION_STRING").and_then(|v| clean(&v)),
        "pcre2" => Some(format!("{}.{}", define_num(text, "PCRE2_MAJOR")?, define_num(text, "PCRE2_MINOR")?)),
        "libuv" => triple(text, "UV_VERSION_MAJOR", "UV_VERSION_MINOR", "UV_VERSION_PATCH"),
        "nghttp2" => define_str(text, "NGHTTP2_VERSION").and_then(|v| clean(&v)),
        "brotli" => {
            let h = define_num(text, "BROTLI_VERSION")?;
            Some(format!("{}.{}.{}", h >> 24, (h >> 12) & 0xfff, h & 0xfff))
        }
        "libwebp" => triple(text, "DEC_MAJ_VERSION", "DEC_MIN_VERSION", "DEC_REV_VERSION"),
        "freetype" => triple(text, "FREETYPE_MAJOR", "FREETYPE_MINOR", "FREETYPE_PATCH"),
        "harfbuzz" => define_str(text, "HB_VERSION_STRING").and_then(|v| clean(&v)),
        "bzip2" => define_str(text, "BZ_VERSION").and_then(|v| clean(&v)),
        "libjpeg-turbo" => {
            // only the libjpeg-turbo top-level CMakeLists (it sits next to jpeglib.h)
            let dir = path.parent()?;
            if !dir.join("jpeglib.h").is_file() {
                return None;
            }
            text.lines().find_map(|l| {
                let l = l.trim();
                let inner = l.strip_prefix("set(VERSION ").or_else(|| l.strip_prefix("set(VERSION\t"))?;
                clean(inner.trim_end_matches(')'))
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------- NVD

#[derive(Debug, Clone)]
struct Cve {
    id: String,
    severity: Severity,
    score: f64,
    summary: String,
}

struct NvdState {
    last: Mutex<Option<Instant>>,
    error: Mutex<Option<String>>,
    /// A request failed at the transport level (no HTTP response).
    unreachable: bool,
}

fn count_by_severity(cves: &[Cve]) -> String {
    let mut parts = Vec::new();
    for s in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
        let n = cves.iter().filter(|c| c.severity == s).count();
        if n > 0 {
            parts.push(format!("{n} {}", s.as_str()));
        }
    }
    if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) }
}

/// Whether the HTTP cache already holds a fresh 200 response for `url` (mirrors `Http`'s cache layout),
/// so the NVD rate limit only applies to real requests.
fn nvd_cached(ctx: &Ctx, url: &str, refresh: bool) -> bool {
    if refresh {
        return false;
    }
    let h = util::sha256_hex(url.as_bytes());
    let p = ctx.cache_dir.join("http").join(&h[..2]).join(&h[2..]);
    let Ok(data) = std::fs::read(p) else { return false };
    let head: String = data.iter().take_while(|&&b| b != b'\n').map(|&b| b as char).collect();
    let mut it = head.split(' ');
    let (Some(t), Some(s)) = (it.next().and_then(|t| t.parse::<i64>().ok()), it.next()) else { return false };
    (s == "200" || s == "404") && util::unix_now() - t < 86_400 || ctx.offline
}

fn nvd_lookup(ctx: &Ctx, args: &Args, lib: &LibInfo, version: &str, st: &mut NvdState) -> Option<Vec<Cve>> {
    match nvd_query(ctx, args, "cpeName", lib, version, st)? {
        Some(v) => Some(v),
        // NVD rejects a cpeName that is not in its CPE dictionary (common for library releases
        // NVD never catalogued) with 404, although CVEs with version ranges may still cover it:
        // ask again with virtualMatchString, which matches the same criteria without the dictionary
        None => Some(nvd_query(ctx, args, "virtualMatchString", lib, version, st)?.unwrap_or_default()),
    }
}

/// One NVD query; `Some(None)` when NVD answers 404.
fn nvd_query(ctx: &Ctx, args: &Args, param: &str, lib: &LibInfo, version: &str, st: &mut NvdState) -> Option<Option<Vec<Cve>>> {
    let key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.trim().is_empty());
    let interval_ms: u64 = std::env::var("SM_NVD_INTERVAL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(if key.is_some() { 700 } else { 6500 });
    let mut out = Vec::new();
    let mut start = 0u64;
    for _page in 0..5 {
        let url = format!("{}?{param}={}&resultsPerPage=2000&startIndex={start}", ctx.endpoints.nvd, cpe(lib, version));
        if !nvd_cached(ctx, &url, args.flag("refresh")) {
            let mut last = st.last.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(t) = *last {
                let wait = Duration::from_millis(interval_ms).saturating_sub(t.elapsed());
                std::thread::sleep(wait);
            }
            *last = Some(Instant::now());
        }
        let headers: Vec<(&str, &str)> = key.as_deref().map(|k| vec![("apiKey", k)]).unwrap_or_default();
        let r = match ctx.http.get_with(&url, Ttl::DAY, &headers) {
            Ok(r) => r,
            Err(e) => {
                st.unreachable = !matches!(e, crate::error::Error::Offline(_));
                *st.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
                return None;
            }
        };
        if r.status == 404 {
            return Some(None);
        }
        if !r.ok() {
            *st.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!("HTTP {} from {}", r.status, ctx.endpoints.nvd));
            return None;
        }
        let v: Value = match r.json() {
            Ok(v) => v,
            Err(e) => {
                *st.error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
                return None;
            }
        };
        let vulns = v["vulnerabilities"].as_array().cloned().unwrap_or_default();
        let n = vulns.len() as u64;
        for item in vulns {
            if !affects(&item["cve"], lib, version) {
                continue;
            }
            if let Some(c) = parse_cve(&item["cve"]) {
                out.push(c);
            }
        }
        let total = v["totalResults"].as_u64().unwrap_or(0);
        start += n;
        if n == 0 || start >= total {
            break;
        }
    }
    Some(Some(out))
}

/// Whether the CVE marks this library itself as vulnerable at this version.
/// NVD also lists products a vulnerable one merely runs on or with (`vulnerable: false`,
/// e.g. SQLite under a PHP PDO bug); those must not count. A CVE NVD has not analyzed yet
/// (no configurations) is kept, since the cpe query already matched it.
fn affects(c: &Value, lib: &LibInfo, version: &str) -> bool {
    let Some(configs) = c["configurations"].as_array() else { return true };
    if configs.is_empty() {
        return true;
    }
    let prefix = format!("cpe:2.3:a:{}:{}:", lib.vendor, lib.product);
    let mut matches = Vec::new();
    collect_cpe_matches(&Value::Array(configs.clone()), &mut matches);
    matches.iter().any(|m| {
        if m["vulnerable"].as_bool() != Some(true) {
            return false;
        }
        let Some(crit) = m["criteria"].as_str() else { return false };
        let Some(rest) = crit.strip_prefix(&prefix) else { return false };
        let cpe_ver = rest.split(':').next().unwrap_or("*");
        if cpe_ver != "*" && cpe_ver != "-" {
            return cmp_upstream(version, cpe_ver) == std::cmp::Ordering::Equal;
        }
        use std::cmp::Ordering::*;
        let bound = |k: &str| m[k].as_str().map(|b| cmp_upstream(version, b));
        bound("versionStartIncluding").is_none_or(|o| o != Less)
            && bound("versionStartExcluding").is_none_or(|o| o == Greater)
            && bound("versionEndIncluding").is_none_or(|o| o != Greater)
            && bound("versionEndExcluding").is_none_or(|o| o == Less)
    })
}

fn collect_cpe_matches(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Array(a) => a.iter().for_each(|x| collect_cpe_matches(x, out)),
        Value::Object(o) => {
            if let Some(Value::Array(ms)) = o.get("cpeMatch") {
                out.extend(ms.iter().cloned());
            }
            for (k, x) in o {
                if k != "cpeMatch" {
                    collect_cpe_matches(x, out);
                }
            }
        }
        _ => {}
    }
}

fn parse_cve(c: &Value) -> Option<Cve> {
    let id = c["id"].as_str()?.to_string();
    if c["vulnStatus"].as_str().is_some_and(|s| s.eq_ignore_ascii_case("rejected")) {
        return None;
    }
    let summary = c["descriptions"]
        .as_array()
        .and_then(|d| d.iter().find(|x| x["lang"] == "en"))
        .and_then(|x| x["value"].as_str())
        .map(|s| {
            let t: String = s.chars().take(140).collect();
            if s.chars().count() > 140 { format!("{t}…") } else { t }
        })
        .unwrap_or_default();
    let m = &c["metrics"];
    let pick = |key: &str| -> Option<(String, f64)> {
        let arr = m[key].as_array()?;
        let e = arr.iter().find(|e| e["type"] == "Primary").or_else(|| arr.first())?;
        let sev = e["cvssData"]["baseSeverity"].as_str().or_else(|| e["baseSeverity"].as_str())?.to_string();
        Some((sev, e["cvssData"]["baseScore"].as_f64().unwrap_or(0.0)))
    };
    let (sev, score) = pick("cvssMetricV40").or_else(|| pick("cvssMetricV31")).or_else(|| pick("cvssMetricV30")).or_else(|| pick("cvssMetricV2")).unwrap_or(("MEDIUM".into(), 0.0));
    let severity = match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "LOW" => Severity::Low,
        "NONE" => Severity::Info,
        _ => Severity::Medium,
    };
    Some(Cve { id, severity, score, summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpe_configurations_decide_what_is_affected() {
        let sqlite = lib_info("sqlite").unwrap();
        // CVE-2022-31631: PHP is vulnerable, SQLite is only the platform it runs with.
        let php = serde_json::json!({"configurations":[{"operator":"AND","nodes":[
            {"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","versionEndExcluding":"8.0.27"}]},
            {"operator":"OR","cpeMatch":[{"vulnerable":false,"criteria":"cpe:2.3:a:sqlite:sqlite:-:*:*:*:*:*:*:*"}]}]}]});
        assert!(!affects(&php, sqlite, "3.54.1"));
        let ranged = serde_json::json!({"configurations":[{"nodes":[{"cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*","versionStartIncluding":"3.0.0","versionEndExcluding":"3.43.0"}]}]}]});
        assert!(affects(&ranged, sqlite, "3.42.0"));
        assert!(!affects(&ranged, sqlite, "3.43.0"));
        assert!(!affects(&ranged, sqlite, "3.54.1"));
        let exact = serde_json::json!({"configurations":[{"nodes":[{"cpeMatch":[
            {"vulnerable":true,"criteria":"cpe:2.3:a:sqlite:sqlite:3.39.2:*:*:*:*:*:*:*"}]}]}]});
        assert!(affects(&exact, sqlite, "3.39.2") && !affects(&exact, sqlite, "3.40.0"));
        assert!(affects(&serde_json::json!({"id":"CVE-X"}), sqlite, "3.54.1"), "unanalyzed CVEs stay");
    }

    #[test]
    fn metadata_versions() {
        assert_eq!(version_from_metadata("300.3.1+3.3.1").as_deref(), Some("3.3.1"));
        assert_eq!(version_from_metadata("111.28.0+1.1.1w").as_deref(), Some("1.1.1w"));
        assert_eq!(version_from_metadata("0.17.0+1.8.1").as_deref(), Some("1.8.1"));
        assert_eq!(version_from_metadata("0.4.73+curl-8.8.0").as_deref(), Some("8.8.0"));
        assert_eq!(version_from_metadata("2.0.13+zstd.1.5.6").as_deref(), Some("1.5.6"));
        assert_eq!(version_from_metadata("1.0.0"), None);
        assert_eq!(cmp_upstream("1.1.1w", "1.1.1v"), std::cmp::Ordering::Greater);
        assert_eq!(cmp_upstream("3.0.10", "3.0.9"), std::cmp::Ordering::Greater);
        assert_eq!(cmp_upstream("1.5.6", "1.5.6"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn headers() {
        let p = Path::new("x");
        assert_eq!(header_version("openssl", "opensslv.h", "# define OPENSSL_VERSION_TEXT  \"OpenSSL 1.1.1w  11 Sep 2023\"\n", p).as_deref(), Some("1.1.1w"));
        assert_eq!(header_version("openssl", "VERSION.dat", "MAJOR=3\nMINOR=0\nPATCH=1\nPRE_RELEASE_TAG=\n", p).as_deref(), Some("3.0.1"));
        assert_eq!(header_version("sqlite", "sqlite3.h", "#define SQLITE_VERSION        \"3.46.0\"\n", p).as_deref(), Some("3.46.0"));
        assert_eq!(header_version("zstd", "zstd.h", "#define ZSTD_VERSION_MAJOR    1\n#define ZSTD_VERSION_MINOR    5\n#define ZSTD_VERSION_RELEASE  6\n", p).as_deref(), Some("1.5.6"));
        assert_eq!(header_version("curl", "curlver.h", "#define LIBCURL_VERSION \"8.8.0-DEV\"\n", p).as_deref(), Some("8.8.0"));
        assert_eq!(header_version("brotli", "version.h", "#define BROTLI_VERSION 0x1001000\n", p).as_deref(), Some("1.1.0"));
        assert_eq!(header_version("zlib", "zlib.h", "#define ZLIB_VERSION \"1.3.0.1-motley\"\n", p).as_deref(), Some("1.3.0.1"));
        assert_eq!(header_version("libgit2", "version.h", "#define LIBGIT2_VERSION \"@VERSION@\"\n", p), None);
        assert_eq!(header_lib("zlib.h", "src/zlib/zlib.h"), Some("zlib"));
        assert_eq!(header_lib("zlib.h", "src/zlib-ng/zlib.h"), None);
        assert_eq!(header_lib("version.h", "libgit2/include/git2/version.h"), Some("libgit2"));
    }

    #[test]
    fn sqlcipher_copy_does_not_hide_the_sqlite_amalgamation() {
        let dir = std::env::temp_dir().join(format!("smc-csys-{}", std::process::id()));
        for (p, v) in [("sqlcipher/sqlite3.h", "3.45.3"), ("sqlite3/sqlite3.h", "3.46.0")] {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, format!("#define SQLITE_VERSION        \"{v}\"\n")).unwrap();
        }
        let c = CrateRef { name: "libsqlite3-sys".into(), version: "0.30.1".into(), origin: crate::tools::common::Origin::Registry, via: vec![], id: None };
        let cand = analyze_crate(&c, &dir, Some("sqlite3".into()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(cand.libs.len(), 1);
        assert_eq!(cand.libs[0].version, "3.46.0");
        assert_eq!(cand.libs[0].source, "sqlite3/sqlite3.h");
    }

    #[test]
    fn cve_parsing() {
        let v: Value = serde_json::from_str(r#"{"id":"CVE-2022-0778","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"BN_mod_sqrt loops forever"}],
            "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}],
                       "cvssMetricV2":[{"type":"Primary","baseSeverity":"MEDIUM","cvssData":{"baseScore":5.0}}]}}"#).unwrap();
        let c = parse_cve(&v).unwrap();
        assert_eq!(c.severity, Severity::High);
        assert_eq!(c.score, 7.5);
    }
}
