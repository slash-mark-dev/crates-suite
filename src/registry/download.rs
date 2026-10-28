//! Downloading, verifying and unpacking `.crate` files.
//!
//! Every download is checked against the SHA-256 checksum recorded in the
//! sparse index, so a tampered mirror or proxy cannot feed us different code.
//! Files already in cargo's own cache (`~/.cargo/registry/cache`) are reused.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;
use crate::registry::index;
use crate::util;

/// Maximum unpacked size we accept for one crate (protects against tar bombs).
const MAX_UNPACKED: u64 = 1024 * 1024 * 1024;

fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join(".cargo")))
}

/// A `.crate` already downloaded by cargo, if any.
fn cargo_cached(name: &str, version: &str) -> Option<PathBuf> {
    if std::env::var_os("SM_CRATES_NO_CARGO_CACHE").is_some() {
        return None;
    }
    let dir = cargo_home()?.join("registry").join("cache");
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        if !e.file_name().to_string_lossy().starts_with("index.crates.io-") {
            continue;
        }
        let p = e.path().join(format!("{name}-{version}.crate"));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Look up the checksum of `name@version` in the sparse index.
pub fn index_checksum(ctx: &Ctx, name: &str, version: &str) -> Result<String> {
    let vs = index::versions(ctx, name)?;
    index::find(&vs, version)
        .map(|v| v.cksum.clone())
        .ok_or_else(|| Error::NotFound(format!("{name}@{version} is not in the crates.io index")))
}

/// Path to a verified `.crate` file.
pub fn crate_file(ctx: &Ctx, name: &str, version: &str) -> Result<PathBuf> {
    let cksum = index_checksum(ctx, name, version)?;
    let dir = ctx.cache_subdir("crates")?;
    let ours = dir.join(format!("{name}-{version}.crate"));
    for candidate in [Some(ours.clone()), cargo_cached(name, version)].into_iter().flatten() {
        if let Ok(data) = std::fs::read(&candidate) {
            if util::sha256_hex(&data) == cksum {
                return Ok(candidate);
            }
        }
    }
    let url = format!("{}/{name}/{name}-{version}.crate", ctx.endpoints.dl);
    let r = ctx.http.get_ok(&url, Ttl::Forever)?;
    let got = util::sha256_hex(&r.body);
    if got != cksum {
        return Err(Error::Parse(format!(
            "checksum mismatch for {name}@{version}: index says {cksum}, download is {got}. \
             The download was altered in transit or by a mirror"
        )));
    }
    let tmp = ours.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, &r.body)?;
    std::fs::rename(&tmp, &ours)?;
    Ok(ours)
}

/// Raw bytes of a verified `.crate` file.
pub fn crate_bytes(ctx: &Ctx, name: &str, version: &str) -> Result<Vec<u8>> {
    Ok(std::fs::read(crate_file(ctx, name, version)?)?)
}

/// Unpack a verified crate into the cache and return its root directory
/// (the directory that contains `Cargo.toml`).
pub fn unpacked(ctx: &Ctx, name: &str, version: &str) -> Result<PathBuf> {
    let root = ctx.cache_subdir("src")?;
    let dest = root.join(format!("{name}-{version}"));
    if dest.join(".sm-complete").is_file() {
        return Ok(dest);
    }
    let file = crate_file(ctx, name, version)?;
    let tmp = root.join(format!(".{name}-{version}.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    unpack_to(&std::fs::read(&file)?, &format!("{name}-{version}"), &tmp)?;
    std::fs::write(tmp.join(".sm-complete"), b"")?;
    let _ = std::fs::remove_dir_all(&dest);
    if std::fs::rename(&tmp, &dest).is_err() {
        // Another process won the race; use its copy.
        let _ = std::fs::remove_dir_all(&tmp);
    }
    Ok(dest)
}

/// List the files of a `.crate` without unpacking: `(path, size)`.
pub fn list_entries(data: &[u8]) -> Result<Vec<(String, u64)>> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut ar = tar::Archive::new(gz);
    let mut out = Vec::new();
    for e in ar.entries().map_err(|e| Error::Parse(format!("bad crate archive: {e}")))? {
        let e = e.map_err(|e| Error::Parse(format!("bad crate archive: {e}")))?;
        let p = e.path().map_err(|e| Error::Parse(e.to_string()))?.to_string_lossy().replace('\\', "/");
        out.push((p, e.header().size().unwrap_or(0)));
    }
    Ok(out)
}

/// Unpack a gzip'd tarball, stripping `prefix/` and refusing anything that
/// could escape `dest` (absolute paths, `..`, links, devices).
pub fn unpack_to(data: &[u8], prefix: &str, dest: &Path) -> Result<()> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut ar = tar::Archive::new(gz);
    let mut total = 0u64;
    for e in ar.entries().map_err(|e| Error::Parse(format!("bad crate archive: {e}")))? {
        let mut e = e.map_err(|e| Error::Parse(format!("bad crate archive: {e}")))?;
        let et = e.header().entry_type();
        if !(et.is_file() || et.is_dir()) {
            continue;
        }
        let path = e.path().map_err(|e| Error::Parse(e.to_string()))?.into_owned();
        let mut comps = path.components();
        match comps.next() {
            Some(Component::Normal(first)) if first.to_string_lossy() == prefix => {}
            Some(Component::Normal(_)) => {}
            _ => continue,
        }
        let rest: PathBuf = comps.collect();
        if rest.as_os_str().is_empty() || rest.components().any(|c| !matches!(c, Component::Normal(_))) {
            continue;
        }
        let out = dest.join(&rest);
        if et.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        total += e.header().size().unwrap_or(0);
        if total > MAX_UNPACKED {
            return Err(Error::Parse(format!("{prefix} unpacks to more than 1 GiB; refusing")));
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::new();
        e.read_to_end(&mut buf)?;
        std::fs::write(&out, &buf)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn make_crate(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (p, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, format!("{prefix}/{p}"), *d).unwrap();
        }
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn unpacks_and_lists() {
        let data = make_crate("x-1.0.0", &[("Cargo.toml", b"[package]"), ("src/lib.rs", b"fn a(){}")]);
        let d = util::temp_dir("unpack").unwrap();
        unpack_to(&data, "x-1.0.0", &d).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("src/lib.rs")).unwrap(), "fn a(){}");
        let l = list_entries(&data).unwrap();
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0, "x-1.0.0/Cargo.toml");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn refuses_traversal() {
        // tar::Builder refuses to write `..`, so craft the header name manually.
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        let data = b"evil";
        h.set_size(4);
        h.set_mode(0o644);
        {
            let name = b"x-1.0.0/../../escape.txt";
            let gnu = h.as_gnu_mut().unwrap();
            gnu.name[..name.len()].copy_from_slice(name);
        }
        h.set_cksum();
        b.append(&h, &data[..]).unwrap();
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        let d = util::temp_dir("trav").unwrap();
        unpack_to(&gz.finish().unwrap(), "x-1.0.0", &d.join("inner")).unwrap();
        assert!(!d.join("escape.txt").exists());
        let _ = std::fs::remove_dir_all(d);
    }
}
