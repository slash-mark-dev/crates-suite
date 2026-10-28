//! Small shared helpers: time, processes, hashing, files, versions.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

// ---------------------------------------------------------------- strings

/// Levenshtein distance.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// crates.io treats `-` and `_` as the same character in names.
pub fn normalize_crate_name(n: &str) -> String {
    n.to_ascii_lowercase().replace('-', "_")
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

pub fn human_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 10_000 {
        format!("{:.1}k", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

pub fn human_duration(secs: f64) -> String {
    if secs >= 3600.0 {
        format!("{:.1}h", secs / 3600.0)
    } else if secs >= 60.0 {
        format!("{}m{:02}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    } else {
        format!("{secs:.1}s")
    }
}

// ---------------------------------------------------------------- time

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Days since 1970-01-01 to (y, m, d). Howard Hinnant's algorithm.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (y, m, d) to days since 1970-01-01.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub fn now_rfc3339() -> String {
    format_unix(unix_now())
}

pub fn format_unix(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let rem = t.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

pub fn format_date(t: i64) -> String {
    format_unix(t)[..10].to_string()
}

/// Parse `YYYY-MM-DD[THH:MM:SS[.fff][Z|±HH:MM]]` to unix seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 10 {
        return None;
    }
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: u32 = s.get(5..7)?.parse().ok()?;
    let d: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut t = days_from_civil(y, m, d) * 86_400;
    if s.len() >= 19 {
        let hh: i64 = s.get(11..13)?.parse().ok()?;
        let mm: i64 = s.get(14..16)?.parse().ok()?;
        let ss: i64 = s.get(17..19)?.parse().ok()?;
        t += hh * 3600 + mm * 60 + ss;
        let rest = &s[19..];
        let rest = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
        if let Some(off) = rest.strip_prefix('+').or_else(|| rest.strip_prefix('-')) {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let oh: i64 = off.get(0..2)?.parse().ok()?;
            let om: i64 = off.get(3..5).and_then(|x| x.parse().ok()).unwrap_or(0);
            t -= sign * (oh * 3600 + om * 60);
        }
    }
    Some(t)
}

/// Whole days between a timestamp string and now.
pub fn age_days(s: &str) -> Option<i64> {
    parse_time(s).map(|t| (unix_now() - t) / 86_400)
}

// ---------------------------------------------------------------- hashing

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------- files

/// Recursively list files under `root` (sorted), skipping `target/` and `.git/`.
pub fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                let name = e.file_name();
                if name == "target" || name == ".git" {
                    continue;
                }
                stack.push(p);
            } else if ft.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Path relative to `base`, with forward slashes.
pub fn rel(base: &Path, p: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

pub fn read_to_string_lossy(p: &Path) -> Result<String> {
    let b = std::fs::read(p)?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// A fresh, empty, unique scratch directory under the cache.
pub fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir().join("sm-crates");
    std::fs::create_dir_all(&base)?;
    for i in 0..1000u32 {
        let p = base.join(format!("{prefix}-{}-{}-{i}", std::process::id(), unix_now()));
        if std::fs::create_dir(&p).is_ok() {
            return Ok(p);
        }
    }
    Err(Error::Env("could not create a temporary directory".into()))
}

// ---------------------------------------------------------------- processes

/// Output of a finished (or timed-out) child process.
#[derive(Debug, Clone)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub elapsed: Duration,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

/// Find a program on PATH.
pub fn which(prog: &str) -> Option<PathBuf> {
    if prog.contains('/') || prog.contains('\\') {
        let p = PathBuf::from(prog);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT").unwrap_or(".EXE;.CMD;.BAT".into()).split(';').map(|s| s.to_lowercase()).collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        for e in &exts {
            let c = dir.join(format!("{prog}{e}"));
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// Run a command to completion with a timeout, capturing output.
pub fn run(cmd: &mut Command, timeout: Duration) -> Result<Output> {
    let start = Instant::now();
    let prog = format!("{:?}", cmd.get_program());
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Env(format!("could not run {prog}: {e}")))?;
    let mut so = child.stdout.take();
    let mut se = child.stderr.take();
    let t1 = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(o) = so.as_mut() {
            let _ = std::io::Read::read_to_end(o, &mut s);
        }
        s
    });
    let t2 = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(o) = se.as_mut() {
            let _ = std::io::Read::read_to_end(o, &mut s);
        }
        s
    });
    let mut timed_out = false;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            timed_out = true;
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = String::from_utf8_lossy(&t1.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t2.join().unwrap_or_default()).into_owned();
    Ok(Output { code: status.and_then(|s| s.code()), stdout, stderr, timed_out, elapsed: start.elapsed() })
}

// ---------------------------------------------------------------- versions

/// Parse a version leniently (accepts `1.2` and `1`).
pub fn parse_version(v: &str) -> Option<semver::Version> {
    let v = v.trim().trim_start_matches('v');
    semver::Version::parse(v).ok().or_else(|| {
        let parts: Vec<&str> = v.split('.').collect();
        match parts.len() {
            1 => semver::Version::parse(&format!("{v}.0.0")).ok(),
            2 => semver::Version::parse(&format!("{v}.0")).ok(),
            _ => None,
        }
    })
}

/// Cargo's compatibility bucket: `1.x` -> "1", `0.3.x` -> "0.3", `0.0.4` -> "0.0.4".
pub fn semver_bucket(v: &semver::Version) -> String {
    if v.major > 0 {
        v.major.to_string()
    } else if v.minor > 0 {
        format!("0.{}", v.minor)
    } else {
        format!("0.0.{}", v.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        for t in [0i64, 951_782_400, 1_700_000_000, 4_102_444_800] {
            assert_eq!(parse_time(&format_unix(t)), Some(t));
        }
        assert_eq!(parse_time("2024-02-29T12:00:00.123456+05:30"), parse_time("2024-02-29T06:30:00Z"));
        assert_eq!(parse_time("2024-02-29"), Some(days_from_civil(2024, 2, 29) * 86400));
        assert_eq!(parse_time("garbage"), None);
    }

    #[test]
    fn distances_and_names() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(normalize_crate_name("Serde-JSON"), "serde_json");
    }

    #[test]
    fn buckets() {
        assert_eq!(semver_bucket(&parse_version("1.2.3").unwrap()), "1");
        assert_eq!(semver_bucket(&parse_version("0.3.1").unwrap()), "0.3");
        assert_eq!(semver_bucket(&parse_version("0.0.4").unwrap()), "0.0.4");
        assert_eq!(parse_version("2").unwrap().to_string(), "2.0.0");
    }

    #[test]
    fn runs_with_timeout() {
        let o = run(Command::new("sh").args(["-c", "echo hi; echo err >&2"]), Duration::from_secs(10)).unwrap();
        assert!(o.success());
        assert_eq!(o.stdout.trim(), "hi");
        assert_eq!(o.stderr.trim(), "err");
        let o = run(Command::new("sh").args(["-c", "sleep 5"]), Duration::from_millis(200)).unwrap();
        assert!(o.timed_out);
    }

    #[test]
    fn misc() {
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(hex(&[0xab, 1]), "ab01");
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
