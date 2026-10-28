//! Shared run context: endpoints, HTTP client, cache, project location.

use std::path::{Path, PathBuf};

use crate::cli::Args;
use crate::error::{Error, Result};
use crate::http::Http;

/// Base URLs of every live data source. Each can be overridden with an
/// environment variable (used by the test suite's mock server, and useful for
/// mirrors).
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// crates.io API, `SM_CRATES_API_URL`.
    pub api: String,
    /// Sparse index, `SM_CRATES_INDEX_URL`.
    pub index: String,
    /// `.crate` downloads, `SM_CRATES_DL_URL`.
    pub dl: String,
    /// docs.rs, `SM_DOCSRS_URL`.
    pub docsrs: String,
    /// GitHub REST API, `SM_GITHUB_API_URL`.
    pub github_api: String,
    /// raw.githubusercontent.com, `SM_GITHUB_RAW_URL`.
    pub github_raw: String,
    /// OSV API, `SM_OSV_URL`.
    pub osv: String,
    /// NVD CVE API 2.0, `SM_NVD_URL`.
    pub nvd: String,
    /// Rust release channels, `SM_RUST_DIST_URL`.
    pub rust_dist: String,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).map(|v| v.trim_end_matches('/').to_string()).unwrap_or_else(|| default.to_string())
}

impl Endpoints {
    pub fn from_env() -> Endpoints {
        Endpoints {
            api: env_or("SM_CRATES_API_URL", "https://crates.io/api/v1"),
            index: env_or("SM_CRATES_INDEX_URL", "https://index.crates.io"),
            dl: env_or("SM_CRATES_DL_URL", "https://static.crates.io/crates"),
            docsrs: env_or("SM_DOCSRS_URL", "https://docs.rs"),
            github_api: env_or("SM_GITHUB_API_URL", "https://api.github.com"),
            github_raw: env_or("SM_GITHUB_RAW_URL", "https://raw.githubusercontent.com"),
            osv: env_or("SM_OSV_URL", "https://api.osv.dev"),
            nvd: env_or("SM_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"),
            rust_dist: env_or("SM_RUST_DIST_URL", "https://static.rust-lang.org/dist"),
        }
    }

    /// Hosts that get the one-request-per-second limit (crates.io API).
    pub fn limited_hosts(&self) -> Vec<String> {
        let host = self.api.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("").to_string();
        vec![host]
    }
}

/// Everything a tool needs besides its arguments.
pub struct Ctx {
    pub http: Http,
    pub endpoints: Endpoints,
    pub cache_dir: PathBuf,
    /// Project directory (`--project`, default current directory).
    pub project_dir: PathBuf,
    /// `cargo` executable (`SM_CRATES_CARGO`, default `cargo`).
    pub cargo: String,
    pub offline: bool,
    pub color: bool,
}

impl Ctx {
    pub fn from_args(args: &Args) -> Result<Ctx> {
        let endpoints = Endpoints::from_env();
        let cache_dir = cache_dir();
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| Error::Env(format!("cannot create cache directory {}: {e}", cache_dir.display())))?;
        let offline = args.flag("offline");
        let http = Http::new(cache_dir.clone(), offline, args.flag("refresh"), endpoints.limited_hosts())?;
        let project_dir = match args.value("project") {
            // absolute, because cargo runs with the project as its working directory: a relative
            // `--manifest-path` (or `--project Cargo.toml`, whose parent is "") would not resolve
            Some(p) => std::path::absolute(p)?,
            None => std::env::current_dir()?,
        };
        let color = !args.flag("no-color")
            && std::env::var_os("NO_COLOR").is_none()
            && !args.flag("json")
            && std::io::IsTerminal::is_terminal(&std::io::stdout());
        Ok(Ctx {
            http,
            endpoints,
            cache_dir,
            project_dir,
            cargo: std::env::var("SM_CRATES_CARGO").unwrap_or_else(|_| "cargo".to_string()),
            offline,
            color,
        })
    }

    /// A subdirectory of the cache, created on demand.
    pub fn cache_subdir(&self, name: &str) -> Result<PathBuf> {
        let p = self.cache_dir.join(name);
        std::fs::create_dir_all(&p)?;
        Ok(p)
    }

    pub fn manifest_path(&self) -> PathBuf {
        if self.project_dir.ends_with("Cargo.toml") { self.project_dir.clone() } else { self.project_dir.join("Cargo.toml") }
    }

    pub fn project_root(&self) -> &Path {
        if self.project_dir.ends_with("Cargo.toml") {
            self.project_dir.parent().unwrap_or(Path::new("."))
        } else {
            &self.project_dir
        }
    }
}

/// `SM_CRATES_CACHE`, else the platform cache directory.
pub fn cache_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("SM_CRATES_CACHE") {
        return PathBuf::from(p);
    }
    if let Some(p) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(p).join("sm-crates");
    }
    if cfg!(windows) {
        if let Some(p) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(p).join("sm-crates").join("cache");
        }
    }
    if let Some(h) = std::env::var_os("HOME") {
        let h = PathBuf::from(h);
        if cfg!(target_os = "macos") {
            return h.join("Library").join("Caches").join("sm-crates");
        }
        return h.join(".cache").join("sm-crates");
    }
    std::env::temp_dir().join("sm-crates-cache")
}
