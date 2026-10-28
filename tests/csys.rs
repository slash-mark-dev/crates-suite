//! csys against mock crates and a mock NVD CVE API 2.0
//! (`GET /rest/json/cves/2.0?cpeName=...` / `?virtualMatchString=...`, answering
//! `{"totalResults", "vulnerabilities": [{"cve": {"id", "descriptions", "metrics"}}]}`).
mod common;
use common::*;
use serde_json::json;

fn cves(id: &str, sev: &str, score: f64) -> serde_json::Value {
    json!({"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "vulnerabilities": [{"cve": {
        "id": id, "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "heap overflow in inflate"}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev}}]}
    }}]})
}

fn setup() -> Mock {
    let m = Mock::start();
    m.publish(
        "libz-sys",
        "1.1.8",
        &[("src/lib.rs", ""), ("src/zlib/zlib.h", "#define ZLIB_VERSION \"1.2.11.1-motley\"\n"), ("src/zlib/inflate.c", "int x;\n")],
        json!({"links": "z"}),
    );
    m
}

fn csys(m: &Mock, args: &[&str]) -> Out {
    let mut c = m.cmd();
    c.env("SM_NVD_INTERVAL_MS", "0").env_remove("NVD_API_KEY").arg("csys").args(args);
    run(c)
}

#[test]
fn version_missing_from_the_cpe_dictionary_is_still_matched() {
    let m = setup();
    // cpeName answers 404 (not in NVD's CPE dictionary); the range match still applies
    m.json("/nvd?virtualMatchString=cpe:2.3:a:zlib:zlib:1.2.11.1:*:*:*:*:*:*:*&resultsPerPage=2000&startIndex=0", &cves("CVE-2022-37434", "CRITICAL", 9.8));
    let o = csys(&m, &["libz-sys@1.1.8", "--json"]);
    assert_eq!(o.code, 1, "{}\n{}\n{:?}", o.stdout, o.stderr, m.requests());
    let v = o.json();
    let f = v["findings"].as_array().unwrap().iter().find(|f| f["code"] == "csys/cve").expect("cve finding").clone();
    assert!(f["message"].as_str().unwrap().contains("zlib 1.2.11.1"), "{f}");
    assert!(f["detail"].as_str().unwrap().contains("CVE-2022-37434"), "{f}");
    assert_eq!(v["data"]["crates"][0]["libraries"][0]["cves"].as_array().unwrap().len(), 1);
}

#[test]
fn unreachable_nvd_is_not_reported_as_clean() {
    let m = setup();
    m.route("/nvd", 503, "unavailable");
    let o = csys(&m, &["libz-sys@1.1.8"]);
    assert_eq!(o.code, 0, "{}\n{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("NOT checked for 1 bundled library"), "{}", o.stdout);
    assert!(!o.stdout.contains("(0 known CVE(s) in bundled versions)"), "{}", o.stdout);
    assert!(o.stdout.contains("unknown"), "{}", o.stdout);
}
