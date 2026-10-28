//! The crates.io web API (rate-limited to one request per second).

use serde_json::Value;

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::http::Ttl;

fn get(ctx: &Ctx, path: &str, ttl: Ttl) -> Result<Value> {
    let url = format!("{}{}", ctx.endpoints.api, path);
    let r = ctx.http.get(&url, ttl)?;
    match r.status {
        200..=299 => r.json(),
        404 => Err(Error::NotFound(format!("crates.io: {path}"))),
        403 => Err(Error::Network(format!(
            "crates.io refused {path} (HTTP 403); check that outbound requests are not blocked by a proxy"
        ))),
        s => Err(Error::Network(format!("crates.io {path} returned HTTP {s}"))),
    }
}

/// Follow crates.io seek pagination (`meta.next_page`) up to `max_pages`.
fn paged(ctx: &Ctx, path: &str, key: &str, ttl: Ttl, max_pages: usize) -> Result<(Vec<Value>, Value)> {
    let mut out = Vec::new();
    let base = path.split('?').next().unwrap_or(path).to_string();
    let mut next = Some(path.to_string());
    let mut last_meta = Value::Null;
    let mut extra = Value::Null;
    for _ in 0..max_pages {
        let Some(p) = next.take() else { break };
        let v = get(ctx, &p, ttl)?;
        if let Some(arr) = v.get(key).and_then(|a| a.as_array()) {
            out.extend(arr.iter().cloned());
        }
        if extra.is_null() {
            extra = v.clone();
        }
        last_meta = v.get("meta").cloned().unwrap_or(Value::Null);
        next = last_meta
            .get("next_page")
            .and_then(|n| n.as_str())
            .filter(|n| !n.is_empty())
            .map(|n| format!("{base}{n}"));
    }
    if let Some(o) = extra.as_object_mut() {
        o.insert("meta".into(), last_meta);
    }
    Ok((out, extra))
}

/// `GET /crates/{name}`: the crate record (`crate` key) plus `versions`.
pub fn krate(ctx: &Ctx, name: &str) -> Result<Value> {
    get(ctx, &format!("/crates/{name}"), Ttl::HOUR)
}

/// Every version record (newest first) with `published_by`, `trustpub_data`,
/// `audit_actions`, `linecounts`, `downloads`, `created_at`, ...
pub fn versions(ctx: &Ctx, name: &str) -> Result<Vec<Value>> {
    Ok(paged(ctx, &format!("/crates/{name}/versions?per_page=100"), "versions", Ttl::HOUR, 50)?.0)
}

/// `GET /crates/{name}/{version}`: one version record (one request, unlike paging `/versions`).
pub fn version(ctx: &Ctx, name: &str, num: &str) -> Result<Value> {
    let v = get(ctx, &format!("/crates/{name}/{num}"), Ttl::DAY)?;
    Ok(v.get("version").cloned().unwrap_or(Value::Null))
}

/// Current owners (users and teams).
pub fn owners(ctx: &Ctx, name: &str) -> Result<Vec<Value>> {
    let v = get(ctx, &format!("/crates/{name}/owners"), Ttl::HOUR)?;
    Ok(v.get("users").and_then(|u| u.as_array()).cloned().unwrap_or_default())
}

/// Per-version daily downloads for the last 90 days (`version_downloads`,
/// `meta.extra_downloads` for versions outside the top ones).
pub fn downloads(ctx: &Ctx, name: &str) -> Result<Value> {
    get(ctx, &format!("/crates/{name}/downloads"), Ttl::HOURS_6)
}

/// Reverse dependencies: `(dependencies, versions, total)`.
pub fn reverse_dependencies(ctx: &Ctx, name: &str, max_pages: usize) -> Result<(Vec<Value>, Vec<Value>, u64)> {
    let mut deps = Vec::new();
    let mut vers = Vec::new();
    let mut total = 0;
    for page in 1..=max_pages.max(1) {
        let v = get(ctx, &format!("/crates/{name}/reverse_dependencies?per_page=100&page={page}"), Ttl::HOURS_6)?;
        total = v["meta"]["total"].as_u64().unwrap_or(0);
        let d = v["dependencies"].as_array().cloned().unwrap_or_default();
        let n = d.len();
        deps.extend(d);
        vers.extend(v["versions"].as_array().cloned().unwrap_or_default());
        if n < 100 || deps.len() as u64 >= total {
            break;
        }
    }
    Ok((deps, vers, total))
}

/// Most-downloaded crates (`sort=downloads` or `sort=recent-downloads`).
pub fn top_crates(ctx: &Ctx, sort: &str, count: usize) -> Result<Vec<Value>> {
    let pages = count.div_ceil(100).max(1);
    let (mut v, _) = paged(ctx, &format!("/crates?sort={sort}&per_page=100"), "crates", Ttl::DAY, pages)?;
    v.truncate(count);
    Ok(v)
}

/// The `crate` object of `GET /crates/{name}`.
pub fn crate_record(v: &Value) -> &Value {
    &v["crate"]
}

#[cfg(test)]
mod tests {
    #[test]
    fn next_page_join() {
        let base = "/crates/x/versions?per_page=100".split('?').next().unwrap();
        assert_eq!(format!("{base}{}", "?per_page=100&seek=abc"), "/crates/x/versions?per_page=100&seek=abc");
    }
}
