//! HTTP client with an on-disk cache, crates.io rate limiting and retries.
//!
//! crates.io's crawler policy asks for an identifying User-Agent and at most
//! one API request per second. Every request to the crates.io API host goes
//! through a shared limiter; the sparse index and static.crates.io have no
//! such limit and are fetched in parallel.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::error::{Error, Result};
use crate::util;

pub const USER_AGENT: &str = concat!(
    "sm-crates/",
    env!("CARGO_PKG_VERSION"),
    " (Slash Mark Crates.io Suite; +https://github.com/slash-mark-dev/crates-suite)"
);

/// How long a cached response stays fresh.
#[derive(Debug, Clone, Copy)]
pub enum Ttl {
    /// Never refetch (immutable content such as `.crate` files).
    Forever,
    Seconds(u64),
}

impl Ttl {
    pub const MINUTES_10: Ttl = Ttl::Seconds(600);
    pub const HOUR: Ttl = Ttl::Seconds(3600);
    pub const HOURS_6: Ttl = Ttl::Seconds(6 * 3600);
    pub const DAY: Ttl = Ttl::Seconds(86_400);
}

/// A finished response.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub url: String,
}

impl Response {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body).map_err(|e| Error::Parse(format!("{}: {e}", self.url)))
    }
}

pub struct Http {
    agent: ureq::Agent,
    cache_dir: PathBuf,
    offline: bool,
    refresh: bool,
    /// Hosts limited to one request per `interval`.
    limited: Mutex<HashMap<String, Instant>>,
    limited_hosts: Vec<String>,
    interval: Duration,
}

impl Http {
    pub fn new(cache_dir: PathBuf, offline: bool, refresh: bool, limited_hosts: Vec<String>) -> Result<Http> {
        let mut cfg = ureq::Agent::config_builder()
            .user_agent(USER_AGENT)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .max_redirects(10);
        if let Some(certs) = extra_root_certs()? {
            let tls = ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(certs)))
                .build();
            cfg = cfg.tls_config(tls);
        }
        let interval_ms: u64 =
            std::env::var("SM_CRATES_API_INTERVAL_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
        Ok(Http {
            agent: ureq::Agent::new_with_config(cfg.build()),
            cache_dir,
            offline,
            refresh,
            limited: Mutex::new(HashMap::new()),
            limited_hosts,
            interval: Duration::from_millis(interval_ms),
        })
    }

    pub fn offline(&self) -> bool {
        self.offline
    }

    fn cache_path(&self, url: &str) -> PathBuf {
        let h = util::sha256_hex(url.as_bytes());
        self.cache_dir.join("http").join(&h[..2]).join(&h[2..])
    }

    /// GET with caching. Non-2xx responses are returned, not turned into errors
    /// (404 is cached too, so a missing crate is not refetched every run).
    pub fn get(&self, url: &str, ttl: Ttl) -> Result<Response> {
        self.get_with(url, ttl, &[])
    }

    pub fn get_with(&self, url: &str, ttl: Ttl, headers: &[(&str, &str)]) -> Result<Response> {
        let path = self.cache_path(url);
        if !self.refresh || self.offline {
            if let Some(r) = read_cache(&path, url, ttl, self.offline) {
                return Ok(r);
            }
        }
        if self.offline {
            return Err(Error::Offline(url.to_string()));
        }
        let resp = self.fetch(url, headers)?;
        if resp.ok() || resp.status == 404 || resp.status == 410 {
            write_cache(&path, &resp);
        }
        Ok(resp)
    }

    /// GET and require a 2xx status.
    pub fn get_ok(&self, url: &str, ttl: Ttl) -> Result<Response> {
        let r = self.get(url, ttl)?;
        match r.status {
            200..=299 => Ok(r),
            404 | 410 => Err(Error::NotFound(url.to_string())),
            s => Err(Error::Network(format!("{url} returned HTTP {s}"))),
        }
    }

    pub fn get_json(&self, url: &str, ttl: Ttl) -> Result<Value> {
        self.get_ok(url, ttl)?.json()
    }

    /// POST a JSON body (never cached unless `cache` is set, then keyed by URL + body).
    pub fn post_json(&self, url: &str, body: &Value, ttl: Option<Ttl>) -> Result<Response> {
        let key = format!("POST {url} {body}");
        let path = self.cache_path(&key);
        if let Some(ttl) = ttl {
            if !self.refresh || self.offline {
                if let Some(r) = read_cache(&path, url, ttl, self.offline) {
                    return Ok(r);
                }
            }
        }
        if self.offline {
            return Err(Error::Offline(url.to_string()));
        }
        self.wait_turn(url);
        let mut last = String::new();
        for attempt in 0..3 {
            let r = self
                .agent
                .post(url)
                .header("Content-Type", "application/json")
                .send(body.to_string().as_bytes());
            match r {
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    let mut buf = Vec::new();
                    resp.body_mut().as_reader().read_to_end(&mut buf)?;
                    if (status == 429 || status >= 500) && attempt < 2 {
                        std::thread::sleep(Duration::from_millis(800 * (attempt + 1)));
                        continue;
                    }
                    let out = Response { status, body: buf, url: url.to_string() };
                    if ttl.is_some() && out.ok() {
                        write_cache(&path, &out);
                    }
                    return Ok(out);
                }
                Err(e) => {
                    last = e.to_string();
                    std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
                }
            }
        }
        Err(Error::Network(format!("{url}: {last}")))
    }

    fn host_of(url: &str) -> String {
        url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("").to_string()
    }

    fn wait_turn(&self, url: &str) {
        let host = Self::host_of(url);
        if !self.limited_hosts.iter().any(|h| *h == host) {
            return;
        }
        loop {
            let mut m = self.limited.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            match m.get(&host) {
                Some(last) if now.duration_since(*last) < self.interval => {
                    let wait = self.interval - now.duration_since(*last);
                    drop(m);
                    std::thread::sleep(wait);
                }
                _ => {
                    m.insert(host, now);
                    return;
                }
            }
        }
    }

    fn fetch(&self, url: &str, headers: &[(&str, &str)]) -> Result<Response> {
        let mut last = String::new();
        for attempt in 0..3u64 {
            self.wait_turn(url);
            let mut req = self.agent.get(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            if url.contains("api.github.com") || std::env::var("SM_GITHUB_API_URL").is_ok_and(|b| url.starts_with(&b)) {
                if let Some(tok) = github_token() {
                    req = req.header("Authorization", &format!("Bearer {tok}"));
                }
                req = req.header("Accept", "application/vnd.github+json");
            }
            match req.call() {
                Ok(mut resp) => {
                    let status = resp.status().as_u16();
                    let mut buf = Vec::new();
                    resp.body_mut()
                        .with_config()
                        .limit(512 * 1024 * 1024)
                        .reader()
                        .read_to_end(&mut buf)
                        .map_err(|e| Error::Network(format!("{url}: {e}")))?;
                    if (status == 429 || status >= 500) && attempt < 2 {
                        last = format!("HTTP {status}");
                        std::thread::sleep(Duration::from_millis(1000 * (attempt + 1)));
                        continue;
                    }
                    return Ok(Response { status, body: buf, url: url.to_string() });
                }
                Err(e) => {
                    last = e.to_string();
                    if attempt < 2 {
                        std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
                    }
                }
            }
        }
        Err(Error::Network(format!("{url}: {last}")))
    }

    /// Fetch many URLs in parallel (rate limits still apply per host).
    pub fn get_many(&self, urls: &[String], ttl: Ttl, threads: usize) -> Vec<Result<Response>> {
        let threads = threads.clamp(1, 16).min(urls.len().max(1));
        let next = std::sync::atomic::AtomicUsize::new(0);
        let results: Mutex<Vec<Option<Result<Response>>>> = Mutex::new((0..urls.len()).map(|_| None).collect());
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if i >= urls.len() {
                            break;
                        }
                        let r = self.get(&urls[i], ttl);
                        results.lock().unwrap_or_else(|e| e.into_inner())[i] = Some(r);
                    }
                });
            }
        });
        results
            .into_inner()
            .unwrap_or_else(|e| e.into_inner())
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(Error::Network("request not run".into()))))
            .collect()
    }
}

pub fn github_token() -> Option<String> {
    ["GITHUB_TOKEN", "GH_TOKEN"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

/// Extra trusted roots from `SSL_CERT_FILE` (corporate proxies, sandboxes).
fn extra_root_certs() -> Result<Option<Vec<ureq::tls::Certificate<'static>>>> {
    let Some(path) = std::env::var_os("SSL_CERT_FILE") else { return Ok(None) };
    let Ok(pem) = std::fs::read(&path) else { return Ok(None) };
    let text = String::from_utf8_lossy(&pem);
    let mut certs = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            inside = true;
            cur.clear();
        }
        if inside {
            cur.push_str(line);
            cur.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            inside = false;
            if let Ok(c) = ureq::tls::Certificate::from_pem(cur.as_bytes()) {
                certs.push(c);
            }
        }
    }
    Ok(if certs.is_empty() { None } else { Some(certs) })
}

// Cache format: one file per URL. First line: "<unix-time> <status>\n", then the body.

fn read_cache(path: &Path, url: &str, ttl: Ttl, any_age: bool) -> Option<Response> {
    let data = std::fs::read(path).ok()?;
    let nl = data.iter().position(|&b| b == b'\n')?;
    let head = std::str::from_utf8(&data[..nl]).ok()?;
    let mut parts = head.split(' ');
    let t: i64 = parts.next()?.parse().ok()?;
    let status: u16 = parts.next()?.parse().ok()?;
    if !any_age {
        if let Ttl::Seconds(s) = ttl {
            if util::unix_now() - t > s as i64 {
                return None;
            }
        }
    }
    Some(Response { status, body: data[nl + 1..].to_vec(), url: url.to_string() })
}

fn write_cache(path: &Path, r: &Response) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut data = format!("{} {}\n", util::unix_now(), r.status).into_bytes();
    data.extend_from_slice(&r.body);
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&tmp, &data).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_round_trip_and_expiry() {
        let dir = util::temp_dir("httptest").unwrap();
        let p = dir.join("x");
        write_cache(&p, &Response { status: 200, body: b"hello\nworld".to_vec(), url: "u".into() });
        let r = read_cache(&p, "u", Ttl::HOUR, false).unwrap();
        assert_eq!(r.body, b"hello\nworld");
        assert_eq!(r.status, 200);
        std::fs::write(&p, b"0 200\nold").unwrap();
        assert!(read_cache(&p, "u", Ttl::HOUR, false).is_none());
        assert!(read_cache(&p, "u", Ttl::HOUR, true).is_some());
        assert!(read_cache(&p, "u", Ttl::Forever, false).is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn host_parsing() {
        assert_eq!(Http::host_of("https://crates.io/api/v1/x"), "crates.io");
        assert_eq!(Http::host_of("http://127.0.0.1:8080/a"), "127.0.0.1:8080");
    }
}

#[cfg(test)]
mod live {
    /// SM_LIVE=1 SSL_CERT_FILE=... cargo test live_fetch -- --ignored
    #[test]
    #[ignore]
    fn live_fetch() {
        let dir = crate::util::temp_dir("live").unwrap();
        let h = super::Http::new(dir, false, true, vec!["crates.io".into()]).unwrap();
        let r = h.get("https://index.crates.io/se/rd/serde", super::Ttl::HOUR).unwrap();
        assert_eq!(r.status, 200);
        let r = h.get("https://crates.io/api/v1/crates/serde", super::Ttl::HOUR).unwrap();
        assert_eq!(r.status, 200, "{}", r.text());
        let r = h.get("https://static.crates.io/crates/itoa/itoa-1.0.11.crate", super::Ttl::HOUR).unwrap();
        assert_eq!(r.status, 200);
        println!("ok {} bytes", r.body.len());
    }
}
