//! crates.io data access: sparse index, web API, `.crate` downloads.

pub mod api;
pub mod download;
pub mod index;

use crate::ctx::Ctx;
use crate::error::{Error, Result};

/// A crate named on the command line: `name`, `name@1.2.3` or `name@^1.2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateSpec {
    pub name: String,
    pub version: Option<String>,
}

impl CrateSpec {
    pub fn parse(s: &str) -> Result<CrateSpec> {
        let (name, ver) = match s.split_once('@') {
            Some((n, v)) => (n, Some(v.trim().to_string())),
            None => (s, None),
        };
        let name = name.trim();
        let valid = !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if !valid {
            return Err(Error::Usage(format!("`{s}` is not a valid crate name (expected NAME or NAME@VERSION)")));
        }
        Ok(CrateSpec { name: name.to_string(), version: ver.filter(|v| !v.is_empty()) })
    }

    /// Resolve against the live index to an exact published version.
    /// A bare name or `@latest` picks the newest non-yanked stable release;
    /// a requirement like `^1.2` picks the newest match.
    pub fn resolve(&self, ctx: &Ctx) -> Result<index::IndexVersion> {
        let vs = index::versions(ctx, &self.name)?;
        let found = match self.version.as_deref() {
            None | Some("latest") => index::latest(&vs),
            Some(v) => match index::find(&vs, v) {
                Some(x) => Some(x),
                None => {
                    let req = semver::VersionReq::parse(v)
                        .map_err(|_| Error::Usage(format!("`{v}` is not a version or version requirement")))?;
                    index::best_match(&vs, &req)
                }
            },
        };
        found.cloned().ok_or_else(|| {
            Error::NotFound(format!("{}@{} is not published on crates.io", self.name, self.version.as_deref().unwrap_or("*")))
        })
    }
}

impl std::fmt::Display for CrateSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}@{v}", self.name),
            None => write!(f, "{}", self.name),
        }
    }
}

/// The canonical crates.io source id strings cargo uses.
pub fn is_crates_io_source(source: Option<&str>) -> bool {
    match source {
        Some(s) => {
            s == "registry+https://github.com/rust-lang/crates.io-index" || s == "sparse+https://index.crates.io/"
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        assert_eq!(CrateSpec::parse("serde").unwrap(), CrateSpec { name: "serde".into(), version: None });
        assert_eq!(CrateSpec::parse("serde@1.0.1").unwrap().version.as_deref(), Some("1.0.1"));
        assert_eq!(CrateSpec::parse("serde_json@^1").unwrap().to_string(), "serde_json@^1");
        assert!(CrateSpec::parse("1bad").is_err());
        assert!(CrateSpec::parse("a/b").is_err());
        assert!(is_crates_io_source(Some("registry+https://github.com/rust-lang/crates.io-index")));
        assert!(!is_crates_io_source(Some("git+https://github.com/x/y")));
    }
}
