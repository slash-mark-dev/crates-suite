//! Helpers shared by tools: choosing which crates to analyze.

use std::path::PathBuf;

use crate::cli::Args;
use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::project::{MetaOpts, Metadata};
use crate::registry::{CrateSpec, download};

/// Where a crate's source comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Published on crates.io; source is downloaded and verified.
    Registry,
    /// A local package (workspace member or path dependency).
    Local(PathBuf),
}

/// A crate selected for analysis.
#[derive(Debug, Clone)]
pub struct CrateRef {
    pub name: String,
    pub version: String,
    pub origin: Origin,
    /// Dependency chain from a workspace member (empty for crates named on the command line).
    pub via: Vec<String>,
    /// `cargo metadata` package id when selected from a project.
    pub id: Option<String>,
}

impl CrateRef {
    pub fn spec(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Directory containing the crate's `Cargo.toml` (downloads and unpacks registry crates).
    pub fn source_dir(&self, ctx: &Ctx) -> Result<PathBuf> {
        match &self.origin {
            Origin::Registry => download::unpacked(ctx, &self.name, &self.version),
            Origin::Local(p) => Ok(p.clone()),
        }
    }

    pub fn is_registry(&self) -> bool {
        self.origin == Origin::Registry
    }
}

/// Selection rules for [`select`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Select {
    /// Include workspace members (local code) as well as dependencies.
    pub members: bool,
    /// Include dev-dependencies of workspace members.
    pub dev: bool,
    /// Include non-crates.io dependencies (git and path) as local sources.
    pub non_registry: bool,
}

/// Crates named on the command line (`NAME[@VERSION]`), resolved against the live index;
/// otherwise the project's dependencies. Returns a subject label and the crates.
pub fn select(ctx: &Ctx, args: &Args, rules: Select) -> Result<(String, Vec<CrateRef>, Option<Metadata>)> {
    if !args.positional.is_empty() {
        let mut out = Vec::new();
        for p in &args.positional {
            let spec = CrateSpec::parse(p)?;
            let v = spec.resolve(ctx)?;
            out.push(CrateRef { name: v.name.clone(), version: v.vers.clone(), origin: Origin::Registry, via: vec![], id: None });
        }
        let label = out.iter().map(|c| c.spec()).collect::<Vec<_>>().join(", ");
        return Ok((label, out, None));
    }
    let meta = Metadata::load(ctx, &MetaOpts::default())?;
    let reach = meta.reachable(rules.dev, true);
    let mut out = Vec::new();
    for p in &meta.packages {
        if !reach.contains(&p.id) {
            continue;
        }
        let member = meta.is_member(&p.id);
        if member && !rules.members {
            continue;
        }
        let origin = if p.is_crates_io() {
            Origin::Registry
        } else if member || rules.non_registry {
            Origin::Local(p.dir())
        } else {
            continue;
        };
        out.push(CrateRef {
            name: p.name.clone(),
            version: p.version.clone(),
            origin,
            via: if member { vec![] } else { meta.path_to(&p.id) },
            id: Some(p.id.clone()),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    let label = meta
        .members()
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Ok((format!("project {label}"), out, Some(meta)))
}

/// Require at least one crate.
pub fn non_empty(v: &[CrateRef]) -> Result<()> {
    if v.is_empty() {
        Err(Error::Usage("nothing to analyze: name a crate (NAME[@VERSION]) or run inside a Cargo project".into()))
    } else {
        Ok(())
    }
}

/// `--only a,b` filter on crate names.
pub fn only(args: &Args, v: Vec<CrateRef>) -> Vec<CrateRef> {
    let only = args.list("only");
    if only.is_empty() {
        return v;
    }
    v.into_iter().filter(|c| only.iter().any(|o| crate::util::normalize_crate_name(o) == crate::util::normalize_crate_name(&c.name))).collect()
}
