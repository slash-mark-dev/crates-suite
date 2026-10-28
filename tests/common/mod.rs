//! Test harness: a local mock of every live data source, fixture crates and
//! fixture projects, and a helper to run the `sm-crates` binary against them.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

type Routes = Arc<Mutex<HashMap<String, (u16, Vec<u8>)>>>;

/// A tiny HTTP/1.1 server. Paths are matched with the query string first,
/// then without it. Unknown paths return 404.
pub struct Mock {
    pub url: String,
    routes: Routes,
    log: Arc<Mutex<Vec<String>>>,
    index: Arc<Mutex<HashMap<String, Vec<String>>>>,
    pub cache: PathBuf,
}

pub fn temp_dir(prefix: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "smc-test-{prefix}-{}-{n}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

impl Mock {
    pub fn start() -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let (r2, l2) = (routes.clone(), log.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let (r3, l3) = (r2.clone(), l2.clone());
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(s.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let target = parts.next().unwrap_or("/").to_string();
                    let mut len = 0usize;
                    loop {
                        let mut h = String::new();
                        if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                            break;
                        }
                        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; len];
                    let _ = reader.read_exact(&mut body);
                    l3.lock().unwrap().push(format!("{method} {target}"));
                    let routes = r3.lock().unwrap();
                    let key_post = format!("POST {target}");
                    let path_only = target.split('?').next().unwrap_or("").to_string();
                    let found = if method == "POST" {
                        routes.get(&key_post).or_else(|| routes.get(&format!("POST {path_only}")))
                    } else {
                        routes.get(&target).or_else(|| routes.get(&path_only))
                    };
                    let (status, data) = found.cloned().unwrap_or((404, b"{\"errors\":[{\"detail\":\"Not Found\"}]}".to_vec()));
                    drop(routes);
                    let head = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n",
                        data.len()
                    );
                    let _ = s.write_all(head.as_bytes());
                    let _ = s.write_all(&data);
                    let _ = s.flush();
                });
            }
        });
        Mock { url, routes, log, index: Arc::new(Mutex::new(HashMap::new())), cache: temp_dir("cache") }
    }

    /// Serve `body` at `path` (path may include a query string).
    pub fn route(&self, path: &str, status: u16, body: impl Into<Vec<u8>>) {
        self.routes.lock().unwrap().insert(path.to_string(), (status, body.into()));
    }

    pub fn json(&self, path: &str, v: &Value) {
        self.route(path, 200, v.to_string());
    }

    /// Serve a POST route (e.g. OSV `/osv/v1/query`).
    pub fn post_json(&self, path: &str, v: &Value) {
        self.route(&format!("POST {path}"), 200, v.to_string());
    }

    pub fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// Publish a crate version to the mock index and download server.
    /// `files` are paths inside the crate (e.g. `src/lib.rs`); a minimal
    /// `Cargo.toml` is generated unless one is given. Returns the checksum.
    pub fn publish(&self, name: &str, version: &str, files: &[(&str, &str)], extra: Value) -> String {
        let mut all: Vec<(String, Vec<u8>)> = files.iter().map(|(p, c)| (p.to_string(), c.as_bytes().to_vec())).collect();
        if !files.iter().any(|(p, _)| *p == "Cargo.toml") {
            all.push(("Cargo.toml".into(), format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n").into_bytes()));
        }
        let data = make_crate(&format!("{name}-{version}"), &all);
        let cksum = sha256(&data);
        self.route(&format!("/dl/{name}/{name}-{version}.crate"), 200, data);
        let mut line = json!({"name": name, "vers": version, "deps": [], "cksum": cksum, "features": {}, "yanked": false});
        if let Value::Object(m) = extra {
            for (k, v) in m {
                line[k] = v;
            }
        }
        let path = index_path(name);
        let mut idx = self.index.lock().unwrap();
        let lines = idx.entry(path.clone()).or_default();
        lines.push(line.to_string());
        self.route(&format!("/index/{path}"), 200, lines.join("\n") + "\n");
        cksum
    }

    /// Command for the `sm-crates` binary wired to this mock.
    pub fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sm-crates"));
        c.env_remove("CARGO_TARGET_DIR");
        let u = &self.url;
        c.env("SM_CRATES_API_URL", format!("{u}/api/v1"))
            .env("SM_CRATES_INDEX_URL", format!("{u}/index"))
            .env("SM_CRATES_DL_URL", format!("{u}/dl"))
            .env("SM_DOCSRS_URL", format!("{u}/docsrs"))
            .env("SM_GITHUB_API_URL", format!("{u}/gh"))
            .env("SM_GITHUB_RAW_URL", format!("{u}/raw"))
            .env("SM_OSV_URL", format!("{u}/osv"))
            .env("SM_NVD_URL", format!("{u}/nvd"))
            .env("SM_RUST_DIST_URL", format!("{u}/dist"))
            .env("SM_CRATES_CACHE", &self.cache)
            .env("SM_CRATES_NO_CARGO_CACHE", "1")
            .env("SM_CRATES_API_INTERVAL_MS", "0")
            .env("NO_COLOR", "1")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("GITHUB_TOKEN")
            .env_remove("GH_TOKEN");
        c
    }
}

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("bad JSON ({e}):\n{}\nstderr:\n{}", self.stdout, self.stderr))
    }
    /// Findings with a given code.
    pub fn codes(&self) -> Vec<String> {
        self.json()["findings"].as_array().unwrap().iter().map(|f| f["code"].as_str().unwrap().to_string()).collect()
    }
}

pub fn run(mut c: Command) -> Out {
    let o = c.output().expect("run sm-crates");
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// Run `sm-crates ARGS...` against the mock.
pub fn sm(mock: &Mock, args: &[&str]) -> Out {
    let mut c = mock.cmd();
    c.args(args);
    run(c)
}

pub fn index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

pub fn sha256(d: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(d);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub fn make_crate(prefix: &str, files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (p, d) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        b.append_data(&mut h, format!("{prefix}/{p}"), d.as_slice()).unwrap();
    }
    let tar = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar).unwrap();
    gz.finish().unwrap()
}

/// Write files under `dir`, creating directories.
pub fn write_files(dir: &Path, files: &[(&str, &str)]) {
    for (p, c) in files {
        let f = dir.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, c).unwrap();
    }
}

/// A crate to vendor into a fixture project as if it came from crates.io.
pub struct Vendored<'a> {
    pub name: &'a str,
    pub version: &'a str,
    /// Full Cargo.toml (must be what `cargo package` would produce: no path deps).
    pub manifest: String,
    pub files: Vec<(&'a str, &'a str)>,
}

/// Create a project whose crates.io dependencies are served from a vendored
/// directory source (cargo resolves offline, while `cargo metadata` still
/// reports them as crates.io packages). Each vendored crate is also published
/// to the mock, so `sm-crates` can download and verify it.
pub fn project(mock: &Mock, root_files: &[(&str, &str)], vendored: &[Vendored]) -> PathBuf {
    let dir = temp_dir("proj");
    write_files(&dir, root_files);
    if !vendored.is_empty() {
        let vdir = dir.join("vendor");
        for v in vendored {
            let mut files: Vec<(&str, &str)> = v.files.clone();
            files.push(("Cargo.toml", v.manifest.as_str()));
            let deps_json = deps_from_manifest(&v.manifest);
            let cksum = mock.publish(v.name, v.version, &files, json!({"deps": deps_json, "features": features_from_manifest(&v.manifest)}));
            let cdir = vdir.join(format!("{}-{}", v.name, v.version));
            write_files(&cdir, &files);
            std::fs::write(cdir.join(".cargo-checksum.json"), json!({"files": {}, "package": cksum}).to_string()).unwrap();
        }
        write_files(
            &dir,
            &[(
                ".cargo/config.toml",
                "[source.crates-io]\nreplace-with = \"vendored\"\n\n[source.vendored]\ndirectory = \"vendor\"\n\n[net]\noffline = true\n",
            )],
        );
    }
    dir
}

fn deps_from_manifest(m: &str) -> Value {
    let t: toml::Value = toml::from_str(m).unwrap();
    let mut out = Vec::new();
    for (section, kind) in [("dependencies", "normal"), ("dev-dependencies", "dev"), ("build-dependencies", "build")] {
        if let Some(tbl) = t.get(section).and_then(|d| d.as_table()) {
            for (name, spec) in tbl {
                let (req, features, optional, default_features) = match spec {
                    toml::Value::String(s) => (s.clone(), vec![], false, true),
                    toml::Value::Table(t) => (
                        t.get("version").and_then(|v| v.as_str()).unwrap_or("*").to_string(),
                        t.get("features").and_then(|f| f.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                        t.get("optional").and_then(|o| o.as_bool()).unwrap_or(false),
                        t.get("default-features").and_then(|o| o.as_bool()).unwrap_or(true),
                    ),
                    _ => continue,
                };
                out.push(json!({"name": name, "req": req, "features": features, "optional": optional, "default_features": default_features, "target": null, "kind": kind}));
            }
        }
    }
    Value::Array(out)
}

fn features_from_manifest(m: &str) -> Value {
    let t: toml::Value = toml::from_str(m).unwrap();
    match t.get("features") {
        Some(f) => serde_json::to_value(f).unwrap(),
        None => json!({}),
    }
}

/// A minimal crates.io-style Cargo.toml for a vendored crate.
pub fn manifest(name: &str, version: &str, extra: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n\n{extra}")
}
