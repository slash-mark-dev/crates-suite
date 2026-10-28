//! The local Cargo project: `cargo metadata`, `Cargo.lock`, dependency paths.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::registry::is_crates_io_source;
use crate::util;

#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub packages: Vec<Package>,
    pub workspace_members: Vec<String>,
    #[serde(default)]
    pub workspace_default_members: Vec<String>,
    pub resolve: Option<Resolve>,
    pub workspace_root: PathBuf,
    pub target_directory: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub id: String,
    pub source: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
    pub manifest_path: PathBuf,
    #[serde(default)]
    pub edition: String,
    pub rust_version: Option<String>,
    pub links: Option<String>,
    pub license: Option<String>,
    pub repository: Option<String>,
    #[serde(default)]
    pub publish: Option<Vec<String>>,
}

impl Package {
    pub fn is_crates_io(&self) -> bool {
        is_crates_io_source(self.source.as_deref())
    }
    pub fn dir(&self) -> PathBuf {
        self.manifest_path.parent().map(Path::to_path_buf).unwrap_or_default()
    }
    pub fn has_build_script(&self) -> bool {
        self.targets.iter().any(|t| t.kind.iter().any(|k| k == "custom-build"))
    }
    pub fn is_proc_macro(&self) -> bool {
        self.targets.iter().any(|t| t.kind.iter().any(|k| k == "proc-macro"))
    }
    pub fn lib_target(&self) -> Option<&Target> {
        self.targets
            .iter()
            .find(|t| t.kind.iter().any(|k| matches!(k.as_str(), "lib" | "rlib" | "proc-macro" | "dylib" | "cdylib" | "staticlib")))
    }
    pub fn spec(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub req: String,
    pub kind: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "yes")]
    pub uses_default_features: bool,
    #[serde(default)]
    pub features: Vec<String>,
    pub target: Option<String>,
    pub rename: Option<String>,
    pub source: Option<String>,
    pub path: Option<PathBuf>,
}

fn yes() -> bool {
    true
}

impl Dependency {
    pub fn kind(&self) -> &str {
        self.kind.as_deref().unwrap_or("normal")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    pub name: String,
    #[serde(default)]
    pub kind: Vec<String>,
    #[serde(default)]
    pub crate_types: Vec<String>,
    pub src_path: PathBuf,
    #[serde(default)]
    pub edition: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Resolve {
    pub nodes: Vec<Node>,
    pub root: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Node {
    pub id: String,
    #[serde(default)]
    pub deps: Vec<NodeDep>,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeDep {
    pub name: String,
    pub pkg: String,
    #[serde(default)]
    pub dep_kinds: Vec<DepKind>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DepKind {
    pub kind: Option<String>,
    pub target: Option<String>,
}

impl NodeDep {
    /// Whether this edge is used for a normal (non-dev, non-build) build.
    pub fn is_normal(&self) -> bool {
        self.dep_kinds.is_empty() || self.dep_kinds.iter().any(|k| k.kind.is_none())
    }
    pub fn is_build(&self) -> bool {
        self.dep_kinds.iter().any(|k| k.kind.as_deref() == Some("build"))
    }
    pub fn is_dev(&self) -> bool {
        !self.dep_kinds.is_empty() && self.dep_kinds.iter().all(|k| k.kind.as_deref() == Some("dev"))
    }
}

/// Options for running `cargo metadata`.
#[derive(Debug, Clone, Default)]
pub struct MetaOpts {
    pub features: Vec<String>,
    pub all_features: bool,
    pub no_default_features: bool,
    /// `--filter-platform`; `None` keeps every platform.
    pub filter_platform: Option<String>,
    pub no_deps: bool,
}

impl Metadata {
    /// Run `cargo metadata` for the project in `ctx`.
    pub fn load(ctx: &Ctx, opts: &MetaOpts) -> Result<Metadata> {
        let manifest = ctx.manifest_path();
        if !manifest.is_file() {
            return Err(Error::Env(format!(
                "no Cargo.toml at {} (run inside a Cargo project or pass --project DIR)",
                manifest.display()
            )));
        }
        let mut cmd = Command::new(&ctx.cargo);
        // run in the project so its `.cargo/config.toml` (source replacement, target-dir...) applies
        cmd.current_dir(ctx.project_root());
        cmd.args(["metadata", "--format-version", "1", "--manifest-path"]).arg(&manifest);
        if ctx.offline {
            cmd.arg("--offline");
        }
        if opts.all_features {
            cmd.arg("--all-features");
        }
        if opts.no_default_features {
            cmd.arg("--no-default-features");
        }
        if !opts.features.is_empty() {
            cmd.arg("--features").arg(opts.features.join(","));
        }
        if let Some(p) = &opts.filter_platform {
            cmd.arg("--filter-platform").arg(p);
        }
        if opts.no_deps {
            cmd.arg("--no-deps");
        }
        let out = util::run(&mut cmd, Duration::from_secs(600))?;
        if !out.success() {
            return Err(Error::Env(format!("cargo metadata failed:\n{}", out.stderr.trim())));
        }
        serde_json::from_str(&out.stdout).map_err(|e| Error::Parse(format!("cargo metadata output: {e}")))
    }

    pub fn package(&self, id: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.id == id)
    }

    pub fn by_id(&self) -> HashMap<&str, &Package> {
        self.packages.iter().map(|p| (p.id.as_str(), p)).collect()
    }

    pub fn node(&self, id: &str) -> Option<&Node> {
        self.resolve.as_ref()?.nodes.iter().find(|n| n.id == id)
    }

    pub fn members(&self) -> Vec<&Package> {
        self.workspace_members.iter().filter_map(|id| self.package(id)).collect()
    }

    pub fn is_member(&self, id: &str) -> bool {
        self.workspace_members.iter().any(|m| m == id)
    }

    /// Package ids in the resolved graph reachable from workspace members.
    /// `include_dev` controls whether dev-dependency edges of members are followed
    /// (dev-dependencies of dependencies are never built and never followed).
    pub fn reachable(&self, include_dev: bool, include_build: bool) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let Some(res) = &self.resolve else { return seen };
        let nodes: HashMap<&str, &Node> = res.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let mut q: VecDeque<(String, bool)> = self.workspace_members.iter().map(|m| (m.clone(), true)).collect();
        while let Some((id, is_member)) = q.pop_front() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(n) = nodes.get(id.as_str()) {
                for d in &n.deps {
                    let ok = d.is_normal() || (include_build && d.is_build()) || (include_dev && is_member && d.is_dev());
                    if ok {
                        q.push_back((d.pkg.clone(), self.is_member(&d.pkg)));
                    }
                }
            }
        }
        seen
    }

    /// crates.io packages reachable from the workspace (normal + build edges,
    /// plus dev edges of members when `include_dev`).
    pub fn registry_packages(&self, include_dev: bool) -> Vec<&Package> {
        let r = self.reachable(include_dev, true);
        let mut v: Vec<&Package> = self.packages.iter().filter(|p| p.is_crates_io() && r.contains(&p.id)).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
        v
    }

    /// Shortest dependency chain from a workspace member to `target_id`,
    /// as package specs (`member@1.0.0 -> a@2.0.0 -> target@1.2.3`).
    pub fn path_to(&self, target_id: &str) -> Vec<String> {
        let Some(res) = &self.resolve else { return vec![] };
        let nodes: HashMap<&str, &Node> = res.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let by_id = self.by_id();
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut q: VecDeque<String> = self.workspace_members.iter().cloned().collect();
        let mut seen: BTreeSet<String> = q.iter().cloned().collect();
        while let Some(id) = q.pop_front() {
            if id == target_id {
                let mut chain = vec![id.clone()];
                let mut cur = id;
                while let Some(p) = prev.get(&cur) {
                    chain.push(p.clone());
                    cur = p.clone();
                }
                chain.reverse();
                return chain.iter().map(|i| by_id.get(i.as_str()).map(|p| p.spec()).unwrap_or_else(|| i.clone())).collect();
            }
            if let Some(n) = nodes.get(id.as_str()) {
                for d in &n.deps {
                    if seen.insert(d.pkg.clone()) {
                        prev.insert(d.pkg.clone(), id.clone());
                        q.push_back(d.pkg.clone());
                    }
                }
            }
        }
        vec![]
    }

    /// Packages that depend directly on `id` (reverse edges).
    pub fn dependents_of(&self, id: &str) -> Vec<(&Package, &NodeDep)> {
        let mut out = Vec::new();
        if let Some(res) = &self.resolve {
            for n in &res.nodes {
                for d in &n.deps {
                    if d.pkg == id {
                        if let Some(p) = self.package(&n.id) {
                            out.push((p, d));
                        }
                    }
                }
            }
        }
        out
    }

    /// Features enabled on a package in this resolve.
    pub fn features_of(&self, id: &str) -> Vec<String> {
        self.node(id).map(|n| n.features.clone()).unwrap_or_default()
    }
}

/// A package entry from `Cargo.lock`.
#[derive(Debug, Clone, Deserialize)]
pub struct LockPackage {
    pub name: String,
    pub version: String,
    pub source: Option<String>,
    pub checksum: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LockFile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

/// Parse a `Cargo.lock` (v1 to v4).
pub fn parse_lockfile(text: &str) -> Result<Vec<LockPackage>> {
    let lf: LockFile = toml::from_str(text)?;
    Ok(lf.package)
}

/// Find `Cargo.lock` for the project (walks up to the workspace root).
pub fn find_lockfile(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(d) = cur {
        let p = d.join("Cargo.lock");
        if p.is_file() {
            return Some(p);
        }
        cur = d.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfile_parse() {
        let t = r#"
version = 4

[[package]]
name = "a"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
"#;
        let l = parse_lockfile(t).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[1].checksum.as_deref(), Some("abc"));
        assert!(is_crates_io_source(l[1].source.as_deref()));
    }

    #[test]
    fn node_dep_kinds() {
        let d: NodeDep = serde_json::from_str(r#"{"name":"x","pkg":"x","dep_kinds":[{"kind":"dev","target":null}]}"#).unwrap();
        assert!(d.is_dev() && !d.is_normal());
        let d: NodeDep = serde_json::from_str(r#"{"name":"x","pkg":"x","dep_kinds":[{"kind":null,"target":null},{"kind":"dev","target":null}]}"#).unwrap();
        assert!(d.is_normal() && !d.is_dev());
    }
}
