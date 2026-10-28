//! The crates.io sparse index (index.crates.io).
//!
//! One file per crate, one JSON line per published version. This is the
//! cheapest live source: no rate limit, cached by CDN, and it carries every
//! version's dependencies, features, checksum, yank state, `links` and MSRV.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexDep {
    pub name: String,
    pub req: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "yes")]
    pub default_features: bool,
    #[serde(default)]
    pub target: Option<String>,
    /// `normal`, `dev` or `build` (absent means normal).
    #[serde(default)]
    pub kind: Option<String>,
    /// Real package name when the dependency is renamed.
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default)]
    pub registry: Option<String>,
}

fn yes() -> bool {
    true
}

impl IndexDep {
    /// The package name on crates.io (handles renames).
    pub fn package_name(&self) -> &str {
        self.package.as_deref().unwrap_or(&self.name)
    }
    pub fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or("normal")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexVersion {
    pub name: String,
    pub vers: String,
    #[serde(default)]
    pub deps: Vec<IndexDep>,
    pub cksum: String,
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub features2: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    pub yanked: bool,
    #[serde(default)]
    pub links: Option<String>,
    #[serde(default)]
    pub rust_version: Option<String>,
    #[serde(default)]
    pub v: Option<u32>,
}

impl IndexVersion {
    pub fn version(&self) -> Option<semver::Version> {
        semver::Version::parse(&self.vers).ok()
    }
    /// `features` merged with `features2` (the index splits newer syntax out).
    pub fn all_features(&self) -> BTreeMap<String, Vec<String>> {
        let mut f = self.features.clone();
        if let Some(f2) = &self.features2 {
            for (k, v) in f2 {
                f.entry(k.clone()).or_default().extend(v.iter().cloned());
            }
        }
        f
    }
    pub fn is_prerelease(&self) -> bool {
        self.version().is_some_and(|v| !v.pre.is_empty())
    }
}

/// Index path for a crate name, e.g. `se/rd/serde`, `3/s/syn`, `1/a`.
pub fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

/// Parse an index file body.
pub fn parse_index(body: &str) -> Vec<IndexVersion> {
    body.lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// All published versions of a crate, oldest first (index order).
pub fn versions(ctx: &Ctx, name: &str) -> Result<Vec<IndexVersion>> {
    let url = format!("{}/{}", ctx.endpoints.index, index_path(name));
    let r = ctx.http.get(&url, Ttl::MINUTES_10)?;
    match r.status {
        200 => {
            let v = parse_index(&r.text());
            if v.is_empty() {
                Err(Error::NotFound(format!("crate `{name}` has no versions in the index")))
            } else {
                Ok(v)
            }
        }
        404 | 410 => Err(Error::NotFound(format!("crate `{name}` is not on crates.io"))),
        s => Err(Error::Network(format!("{url} returned HTTP {s}"))),
    }
}

/// Fetch many crates' index files in parallel. Missing crates map to `None`.
pub fn versions_many(ctx: &Ctx, names: &[String]) -> BTreeMap<String, Option<Vec<IndexVersion>>> {
    let urls: Vec<String> = names.iter().map(|n| format!("{}/{}", ctx.endpoints.index, index_path(n))).collect();
    let res = ctx.http.get_many(&urls, Ttl::MINUTES_10, 8);
    names
        .iter()
        .zip(res)
        .map(|(n, r)| {
            let v = r.ok().filter(|r| r.status == 200).map(|r| parse_index(&r.text())).filter(|v| !v.is_empty());
            (n.clone(), v)
        })
        .collect()
}

/// The version cargo would pick for a bare name: newest non-yanked stable,
/// else newest non-yanked prerelease, else newest.
pub fn latest(versions: &[IndexVersion]) -> Option<&IndexVersion> {
    let by_ver = |a: &&IndexVersion, b: &&IndexVersion| a.version().cmp(&b.version());
    versions
        .iter()
        .filter(|v| !v.yanked && !v.is_prerelease())
        .max_by(by_ver)
        .or_else(|| versions.iter().filter(|v| !v.yanked).max_by(by_ver))
        .or_else(|| versions.iter().max_by(by_ver))
}

/// Find an exact version.
pub fn find<'a>(versions: &'a [IndexVersion], vers: &str) -> Option<&'a IndexVersion> {
    let want = semver::Version::parse(vers).ok();
    versions.iter().find(|v| v.vers == vers || (want.is_some() && v.version() == want))
}

/// Newest non-yanked version matching a requirement.
pub fn best_match<'a>(versions: &'a [IndexVersion], req: &semver::VersionReq) -> Option<&'a IndexVersion> {
    versions
        .iter()
        .filter(|v| !v.yanked)
        .filter(|v| v.version().is_some_and(|x| req.matches(&x)))
        .max_by(|a, b| a.version().cmp(&b.version()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("syn"), "3/s/syn");
        assert_eq!(index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn parse_and_pick() {
        let body = r#"{"name":"x","vers":"1.0.0","deps":[{"name":"y","req":"^1","features":[],"optional":false,"default_features":true,"target":null,"kind":"dev"}],"cksum":"aa","features":{"a":[]},"yanked":false}
{"name":"x","vers":"1.1.0","deps":[],"cksum":"bb","features":{},"features2":{"b":["dep:y"]},"yanked":false,"rust_version":"1.70","v":2}
{"name":"x","vers":"1.2.0","deps":[],"cksum":"cc","features":{},"yanked":true}
{"name":"x","vers":"2.0.0-rc.1","deps":[],"cksum":"dd","features":{},"yanked":false}
"#;
        let v = parse_index(body);
        assert_eq!(v.len(), 4);
        assert_eq!(latest(&v).unwrap().vers, "1.1.0");
        assert_eq!(v[0].deps[0].kind(), "dev");
        assert!(v[1].all_features().contains_key("b"));
        assert_eq!(v[1].rust_version.as_deref(), Some("1.70"));
        let req = semver::VersionReq::parse("^1").unwrap();
        assert_eq!(best_match(&v, &req).unwrap().vers, "1.1.0");
        assert_eq!(find(&v, "1.2.0").unwrap().cksum, "cc");
    }
}
