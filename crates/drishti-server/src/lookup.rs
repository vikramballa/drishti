//! Opt-in online reputation checks. Off by default (`online.enabled`);
//! each check runs only when the person clicks it, and sends the minimum:
//!
//! | Service       | Sends                                   |
//! |---------------|-----------------------------------------|
//! | VirusTotal    | the file's SHA-256 fingerprint only     |
//! | MalwareBazaar | the file's SHA-256 fingerprint only     |
//! | URLhaus       | web domain names found inside the file  |
//! | AbuseIPDB     | public IP addresses found inside the file |
//!
//! The file itself is never uploaded. Results are cached on disk.

use crate::api::{ApiError, R, bad, valid_sha};
use crate::net::{HttpReq, fetch};
use crate::secrets;
use crate::state::Shared;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;

pub struct Service {
    pub id: &'static str,
    pub name: &'static str,
    pub key: &'static str,
    pub sends: &'static str,
    pub what: &'static str,
}

pub const SERVICES: &[Service] = &[
    Service {
        id: "virustotal",
        name: "VirusTotal",
        key: "virustotal",
        sends: "the file's fingerprint (SHA-256), not the file",
        what: "Asks whether about 70 antivirus programs have seen this exact file before.",
    },
    Service {
        id: "malwarebazaar",
        name: "MalwareBazaar",
        key: "abusech",
        sends: "the file's fingerprint (SHA-256), not the file",
        what: "Checks a public collection of known malware.",
    },
    Service {
        id: "urlhaus",
        name: "URLhaus",
        key: "abusech",
        sends: "web domain names found inside the file",
        what: "Checks whether web addresses inside the file are known to spread malware.",
    },
    Service {
        id: "abuseipdb",
        name: "AbuseIPDB",
        key: "abuseipdb",
        sends: "public IP addresses found inside the file",
        what: "Checks whether IP addresses inside the file have been reported for attacks.",
    },
];

pub fn enabled(st: &Shared) -> bool {
    crate::ai::setting_str(st, "online.enabled").as_deref() == Some("true")
}

fn cache_path(st: &Shared, id: &str, sha: &str) -> std::path::PathBuf {
    st.data_dir.join("lookups").join(format!("{id}-{sha}.json"))
}

/// `GET /binaries/{sha}/lookups` — services, whether usable, cached results.
pub async fn list(State(st): State<Shared>, Path(sha): Path<String>) -> R<Json<Value>> {
    valid_sha(&sha)?;
    let on = enabled(&st);
    let v: Vec<Value> = SERVICES
        .iter()
        .map(|s| {
            let cached = std::fs::read(cache_path(&st, s.id, &sha))
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            json!({"id": s.id, "name": s.name, "sends": s.sends, "what": s.what,
                   "key_set": secrets::get(&st, s.key).is_some(), "key_id": s.key, "result": cached})
        })
        .collect();
    Ok(Json(
        json!({"enabled": on, "online": crate::net::available(), "services": v}),
    ))
}

fn unavailable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, msg.into())
}

/// `POST /binaries/{sha}/lookups/{service}` — run one check now.
pub async fn run(
    State(st): State<Shared>,
    Path((sha, id)): Path<(String, String)>,
) -> R<Json<Value>> {
    valid_sha(&sha)?;
    if !enabled(&st) {
        return Err(unavailable(
            "Online checks are turned off. Turn them on in Settings → Online checks.",
        ));
    }
    let svc = SERVICES
        .iter()
        .find(|s| s.id == id)
        .ok_or_else(|| bad("unknown service"))?;
    let key = secrets::get(&st, svc.key).ok_or_else(|| {
        unavailable(format!(
            "Add your free {} key in Settings → Online checks first.",
            svc.name
        ))
    })?;
    let v = match svc.id {
        "virustotal" => virustotal(&sha, &key).await,
        "malwarebazaar" => malwarebazaar(&sha, &key).await,
        "urlhaus" | "abuseipdb" => {
            let s = crate::api::session(&st, &sha).await?;
            let iocs = drishti_loader::insights::iocs(&s.strings);
            if svc.id == "urlhaus" {
                urlhaus(&domains(&iocs), &key).await
            } else {
                abuseipdb(&public_ips(&iocs), &key).await
            }
        }
        _ => Err("unknown service".into()),
    }
    .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e))?;
    let mut v = v;
    v["checked_at"] = json!(crate::util::now());
    v["service"] = json!(svc.id);
    let p = cache_path(&st, svc.id, &sha);
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(&p, serde_json::to_vec(&v).unwrap_or_default());
    Ok(Json(v))
}

fn http_error(service: &str, code: u16) -> String {
    match code {
        401 | 403 => {
            format!("{service} rejected the API key. Check it in Settings → Online checks.")
        }
        429 => format!(
            "{service} says too many requests. Free keys allow a few checks per minute; wait a moment."
        ),
        c => format!("{service} answered with an error ({c})."),
    }
}

async fn virustotal(sha: &str, key: &str) -> Result<Value, String> {
    let req = HttpReq::get(format!("https://www.virustotal.com/api/v3/files/{sha}"))
        .header(format!("x-apikey: {key}"))
        .header("Accept: application/json");
    let (code, body) = fetch(req, 8 << 20).await?;
    if code == 404 {
        return Ok(
            json!({"verdict": "unknown", "headline": "VirusTotal has never seen this exact file. That's common for new, rare or personal files, and doesn't mean it's safe or unsafe."}),
        );
    }
    if code != 200 {
        return Err(http_error("VirusTotal", code));
    }
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| "unexpected answer from VirusTotal".to_string())?;
    let a = &v["data"]["attributes"];
    let s = &a["last_analysis_stats"];
    let n = |k: &str| s[k].as_u64().unwrap_or(0);
    let (mal, sus) = (n("malicious"), n("suspicious"));
    let total = mal + sus + n("undetected") + n("harmless");
    let mut detections: Vec<Value> = a["last_analysis_results"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, r)| matches!(r["category"].as_str(), Some("malicious" | "suspicious")))
        .map(|(eng, r)| json!({"engine": eng, "result": r["result"], "category": r["category"]}))
        .collect();
    detections.truncate(80);
    let label = a["popular_threat_classification"]["suggested_threat_label"].as_str();
    let (verdict, headline) = match mal {
        0 if sus == 0 => (
            "clean",
            format!("None of {total} antivirus programs flag this file."),
        ),
        0 => (
            "warning",
            format!(
                "{sus} of {total} antivirus programs find this file suspicious; none call it malicious."
            ),
        ),
        1..=2 => (
            "warning",
            format!(
                "{mal} of {total} antivirus programs flag this file. A few detections are often false alarms."
            ),
        ),
        _ => (
            "danger",
            format!(
                "{mal} of {total} antivirus programs say this file is malicious{}.",
                label.map(|l| format!(" ({l})")).unwrap_or_default()
            ),
        ),
    };
    let ts = |k: &str| a[k].as_u64().map(crate::util::rfc3339);
    Ok(
        json!({"verdict": verdict, "headline": headline, "malicious": mal, "suspicious": sus, "total": total,
              "label": label, "names": a["names"].as_array().map(|n| n.iter().take(8).cloned().collect::<Vec<_>>()),
              "type": a["type_description"], "first_seen": ts("first_submission_date"), "last_seen": ts("last_analysis_date"),
              "reputation": a["reputation"], "detections": detections,
              "link": format!("https://www.virustotal.com/gui/file/{sha}")}),
    )
}

async fn malwarebazaar(sha: &str, key: &str) -> Result<Value, String> {
    let req = HttpReq::post(
        "https://mb-api.abuse.ch/api/v1/",
        "application/x-www-form-urlencoded",
        format!("query=get_info&hash={sha}"),
    )
    .header(format!("Auth-Key: {key}"));
    let (code, body) = fetch(req, 4 << 20).await?;
    if code != 200 {
        return Err(http_error("MalwareBazaar", code));
    }
    let v: Value = serde_json::from_slice(&body)
        .map_err(|_| "unexpected answer from MalwareBazaar".to_string())?;
    match v["query_status"].as_str() {
        Some("ok") => {
            let d = &v["data"][0];
            let sig = d["signature"].as_str();
            Ok(json!({"verdict": "danger",
                      "headline": format!("This exact file is in MalwareBazaar's collection of known malware{}.", sig.map(|s| format!(" ({s})")).unwrap_or_default()),
                      "signature": sig, "first_seen": d["first_seen"], "file_name": d["file_name"], "tags": d["tags"],
                      "link": format!("https://bazaar.abuse.ch/sample/{sha}/")}))
        }
        Some("hash_not_found") | Some("no_results") => Ok(
            json!({"verdict": "clean", "headline": "Not in MalwareBazaar's collection of known malware."}),
        ),
        Some("unknown_auth_key") | Some("illegal_auth_key") => {
            Err(http_error("MalwareBazaar", 401))
        }
        other => Err(format!("MalwareBazaar: {}", other.unwrap_or("no answer"))),
    }
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host
        .rsplit('@')
        .next()?
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_lowercase();
    (host.contains('.')
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    .then_some(host)
}

fn is_private_v4(ip: &std::net::Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.octets()[0] >= 224
}

fn domains(iocs: &[drishti_loader::insights::Ioc]) -> Vec<String> {
    let mut v: Vec<String> = iocs
        .iter()
        .filter(|i| i.kind == "url")
        .filter_map(|i| host_of(&i.value))
        .filter(|h| h.parse::<std::net::Ipv4Addr>().is_err())
        .filter(|h| {
            !h.ends_with(".local")
                && !h.ends_with("localhost")
                && !h.ends_with(".example")
                && !h.ends_with("example.com")
        })
        .collect();
    v.sort();
    v.dedup();
    v.truncate(20);
    v
}

fn public_ips(iocs: &[drishti_loader::insights::Ioc]) -> Vec<String> {
    let mut v: Vec<String> = iocs
        .iter()
        .filter(|i| i.kind == "ip")
        .filter_map(|i| {
            i.value
                .split(':')
                .next()?
                .parse::<std::net::Ipv4Addr>()
                .ok()
        })
        .filter(|ip| !is_private_v4(ip))
        .map(|ip| ip.to_string())
        .collect();
    v.sort();
    v.dedup();
    v.truncate(10);
    v
}

async fn urlhaus(hosts: &[String], key: &str) -> Result<Value, String> {
    if hosts.is_empty() {
        return Ok(
            json!({"verdict": "clean", "headline": "No web addresses inside this file to check.", "hosts": []}),
        );
    }
    let mut out = Vec::new();
    let mut bad_hosts = 0;
    for h in hosts {
        let req = HttpReq::post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            "application/x-www-form-urlencoded",
            format!("host={h}"),
        )
        .header(format!("Auth-Key: {key}"));
        let req = HttpReq {
            timeout: Duration::from_secs(20),
            ..req
        };
        let (code, body) = fetch(req, 2 << 20).await?;
        if code != 200 {
            return Err(http_error("URLhaus", code));
        }
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let known = v["query_status"].as_str() == Some("ok");
        if known {
            bad_hosts += 1;
        }
        out.push(json!({"host": h, "known_bad": known, "url_count": v["url_count"],
                        "threats": v["urls"].as_array().map(|u| u.iter().take(5).filter_map(|x| x["threat"].as_str().map(str::to_string)).collect::<Vec<_>>()),
                        "link": known.then(|| format!("https://urlhaus.abuse.ch/host/{h}/"))}));
    }
    Ok(
        json!({"verdict": if bad_hosts > 0 { "danger" } else { "clean" },
              "headline": if bad_hosts > 0 { format!("{bad_hosts} of {} web addresses inside are known for spreading malware.", out.len()) }
                          else { format!("None of the {} web addresses inside are on URLhaus's list of malware sites.", out.len()) },
              "hosts": out}),
    )
}

async fn abuseipdb(ips: &[String], key: &str) -> Result<Value, String> {
    if ips.is_empty() {
        return Ok(
            json!({"verdict": "clean", "headline": "No public IP addresses inside this file to check.", "ips": []}),
        );
    }
    let mut out = Vec::new();
    let mut worst = 0u64;
    for ip in ips {
        let req = HttpReq::get(format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        ))
        .header(format!("Key: {key}"))
        .header("Accept: application/json");
        let (code, body) = fetch(req, 1 << 20).await?;
        if code != 200 {
            return Err(http_error("AbuseIPDB", code));
        }
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let d = &v["data"];
        let score = d["abuseConfidenceScore"].as_u64().unwrap_or(0);
        worst = worst.max(score);
        out.push(json!({"ip": ip, "score": score, "country": d["countryCode"], "isp": d["isp"], "domain": d["domain"],
                        "reports": d["totalReports"], "link": format!("https://www.abuseipdb.com/check/{ip}")}));
    }
    let (verdict, headline) = match worst {
        0..=10 => (
            "clean",
            format!(
                "None of the {} IP addresses inside have notable abuse reports.",
                out.len()
            ),
        ),
        11..=50 => (
            "warning",
            "Some IP addresses inside have been reported for abuse.".to_string(),
        ),
        _ => (
            "danger",
            "IP addresses inside are widely reported for attacks or spam.".to_string(),
        ),
    };
    Ok(json!({"verdict": verdict, "headline": headline, "ips": out}))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hosts() {
        assert_eq!(
            super::host_of("https://user@Evil.EXAMPLE.org:8080/a?b").as_deref(),
            Some("evil.example.org")
        );
        assert_eq!(
            super::host_of("cdn.example.net/x").as_deref(),
            Some("cdn.example.net")
        );
        assert_eq!(super::host_of("http://localhost/"), None);
        assert!(super::is_private_v4(&"192.168.1.4".parse().unwrap()));
        assert!(!super::is_private_v4(&"8.8.8.8".parse().unwrap()));
    }
}
