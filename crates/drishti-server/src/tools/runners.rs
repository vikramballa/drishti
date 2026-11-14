//! Per-tool commands and output parsers. Every runner returns a normalized
//! result for the UI:
//!
//! ```json
//! { "verdict": "clean|warning|danger|info|error",
//!   "headline": "one plain sentence",
//!   "items": [{"title", "detail", "severity": "high|medium|low|info"}],
//!   "data": { …tool-specific… }, "duration_ms": n }
//! ```

use super::{RunSpec, ToolDef, input_link, rules_dir, run};
use crate::state::{Session, Shared};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn item(title: impl Into<String>, detail: impl Into<String>, severity: &str) -> Value {
    json!({"title": title.into(), "detail": detail.into(), "severity": severity})
}

fn os<S: Into<OsString>>(s: S) -> OsString {
    s.into()
}

fn spec<'a>(t: &'a ToolDef, bin: &Path, work: PathBuf, args: Vec<OsString>) -> RunSpec<'a> {
    RunSpec {
        tool: t,
        bin: bin.to_path_buf(),
        args,
        work,
        extra_writable: Vec::new(),
        env: Vec::new(),
        timeout: Duration::from_secs(t.timeout_s),
        stdout_cap: 32 << 20,
    }
}

/// Short-lived work folder for tools whose output is parsed and dropped.
fn temp_work(st: &Shared, tool: &str, sha: &str) -> PathBuf {
    super::tools_dir(st).join("tmp").join(format!(
        "{tool}-{}-{}",
        &sha[..12.min(sha.len())],
        crate::util::new_id()
    ))
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn timeout_err(t: &ToolDef) -> String {
    format!(
        "{} took longer than {} minutes and was stopped",
        t.name,
        t.timeout_s / 60
    )
}

/// Run one tool on a file and turn its output into a plain-language result.
pub async fn run_tool(
    st: &Shared,
    t: &'static ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    match t.id {
        "yara" => yara(st, t, bin, input, s).await,
        "clamav" => clamav(st, t, bin, input, s).await,
        "capa" => capa(st, t, bin, input, s).await,
        "floss" => floss(st, t, bin, input, s).await,
        "exiftool" => exiftool(st, t, bin, input, s).await,
        "oletools" => olevba(st, t, bin, input, s).await,
        "binwalk" => binwalk(st, t, bin, input, s).await,
        "jadx" => super::source::jadx(st, t, bin, input, s).await,
        "ilspy" => super::source::ilspy(st, t, bin, input, s).await,
        "wabt" => super::source::wabt(st, t, bin, input, s).await,
        "ipsw" => super::source::ipsw(st, t, bin, input, s).await,
        _ => Err("this tool has no runner".into()),
    }
}

// ---------------------------------------------------------------- YARA

pub fn yara_rules(st: &Shared) -> Option<PathBuf> {
    let p = rules_dir(st).join("yara").join("rules.yarc");
    p.is_file().then_some(p)
}

/// `Rule [tag,tag] [k="v",k=1] path` (tags only with `-g`).
/// (rule name, tags, metadata key/value pairs)
type YaraHit = (String, Vec<String>, Vec<(String, String)>);

fn parse_yara_line(line: &str) -> Option<YaraHit> {
    let line = line.trim();
    let (rule, mut rest) = line.split_once(' ')?;
    let mut tags = Vec::new();
    let mut meta = Vec::new();
    let mut blocks = Vec::new();
    while rest.starts_with('[') {
        // Find the matching ']' outside quotes.
        let mut in_q = false;
        let mut esc = false;
        let mut end = None;
        for (i, c) in rest.char_indices().skip(1) {
            if esc {
                esc = false;
                continue;
            }
            match c {
                '\\' if in_q => esc = true,
                '"' => in_q = !in_q,
                ']' if !in_q => {
                    end = Some(i);
                    break;
                }
                _ => {}
            }
        }
        let e = end?;
        blocks.push(rest[1..e].to_string());
        rest = rest[e + 1..].trim_start();
    }
    for b in blocks {
        if b.contains('=') {
            // k="v",k=1 — split on commas outside quotes.
            let mut cur = String::new();
            let mut in_q = false;
            let mut esc = false;
            let mut parts = Vec::new();
            for c in b.chars() {
                if esc {
                    cur.push(c);
                    esc = false;
                    continue;
                }
                match c {
                    '\\' if in_q => {
                        esc = true;
                        continue;
                    }
                    '"' => in_q = !in_q,
                    ',' if !in_q => {
                        parts.push(std::mem::take(&mut cur));
                        continue;
                    }
                    _ => {}
                }
                if c != '"' {
                    cur.push(c);
                }
            }
            parts.push(cur);
            for p in parts {
                if let Some((k, v)) = p.split_once('=') {
                    meta.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        } else {
            tags = b
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
        }
    }
    Some((rule.to_string(), tags, meta))
}

async fn yara(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let rules = yara_rules(st).ok_or("YARA rules aren't downloaded yet (Settings → Tools)")?;
    let work = TempDir(temp_work(st, "yara", &s.sha));
    let args = vec![
        os("-w"),
        os("-m"),
        os("-g"),
        os("-p"),
        os("2"),
        os("-C"),
        rules.into_os_string(),
        input.as_os_str().to_owned(),
    ];
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    if o.code != Some(0) && o.stdout.is_empty() {
        return Err(format!(
            "YARA failed: {}",
            o.stderr.trim().chars().take(300).collect::<String>()
        ));
    }
    let n_rules = std::fs::read_to_string(rules_dir(st).join("yara").join("count"))
        .ok()
        .and_then(|c| c.trim().parse::<u64>().ok());
    let mut items = Vec::new();
    let mut worst = 0u64;
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let Some((rule, tags, meta)) = parse_yara_line(line) else {
            continue;
        };
        let get = |k: &str| meta.iter().find(|(m, _)| m == k).map(|(_, v)| v.clone());
        let score = get("score")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        worst = worst.max(score);
        let sev = if score >= 75 {
            "high"
        } else if score >= 50 {
            "medium"
        } else {
            "low"
        };
        let detail = get("description")
            .unwrap_or_else(|| "Matched a pattern written by security researchers.".into());
        let mut d = detail;
        if let Some(a) = get("author") {
            d += &format!(" (rule by {a})");
        }
        items.push(json!({"title": rule.replace('_', " "), "detail": d, "severity": sev, "rule": rule, "tags": tags,
                          "reference": get("reference")}));
        if items.len() >= 200 {
            break;
        }
    }
    let count = n_rules.map(|n| format!("{n} ")).unwrap_or_default();
    let (verdict, headline) = if items.is_empty() {
        (
            "clean",
            format!("No known malware patterns matched ({count}patterns checked)."),
        )
    } else if worst >= 75 {
        (
            "danger",
            format!(
                "Matched {} known malicious pattern{}. Treat this file as dangerous.",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            ),
        )
    } else {
        (
            "warning",
            format!(
                "Matched {} pattern{} worth a look. Matches can be false alarms: read what each one means.",
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            ),
        )
    };
    Ok(
        json!({"verdict": verdict, "headline": headline, "items": items, "duration_ms": o.duration_ms}),
    )
}

// ---------------------------------------------------------------- ClamAV

/// Folder with the ClamAV signature database (Homebrew's, or our own).
pub fn clamav_db_dir() -> Option<PathBuf> {
    let has_db = |d: &Path| {
        ["main.cvd", "main.cld"].iter().any(|f| d.join(f).is_file())
            && ["daily.cvd", "daily.cld"]
                .iter()
                .any(|f| d.join(f).is_file())
    };
    for d in [
        "/opt/homebrew/var/lib/clamav",
        "/usr/local/var/lib/clamav",
        "/var/lib/clamav",
    ] {
        let p = PathBuf::from(d);
        if has_db(&p) {
            return Some(p);
        }
    }
    None
}

pub fn clamav_db_age_days(d: &Path) -> Option<u64> {
    let m = ["daily.cld", "daily.cvd"]
        .iter()
        .filter_map(|f| std::fs::metadata(d.join(f)).and_then(|m| m.modified()).ok())
        .max()?;
    Some(m.elapsed().ok()?.as_secs() / 86_400)
}

async fn clamav(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let db = clamav_db_dir()
        .ok_or("the ClamAV virus database isn't downloaded yet (Settings → Tools)")?;
    let work = TempDir(temp_work(st, "clamav", &s.sha));
    let args = vec![
        os("--no-summary"),
        os("--stdout"),
        os("--max-filesize=2000M"),
        os("--max-scansize=2000M"),
        os("--alert-exceeds-max=no"),
        os(format!("--database={}", db.display())),
        input.as_os_str().to_owned(),
    ];
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    let out = String::from_utf8_lossy(&o.stdout);
    let age = clamav_db_age_days(&db);
    let stale = age.is_some_and(|a| a > 7);
    let age_note = match age {
        Some(a) if a > 7 => format!(
            " The virus database is {a} days old, so very new threats may be missed: update it in Settings → Tools."
        ),
        _ => String::new(),
    };
    match o.code {
        Some(0) => Ok(
            json!({"verdict": "clean", "headline": format!("No viruses found.{age_note}"),
                              "items": [], "stale_db": stale, "duration_ms": o.duration_ms}),
        ),
        Some(1) => {
            let items: Vec<Value> = out
                .lines()
                .filter_map(|l| l.strip_suffix(" FOUND"))
                .filter_map(|l| l.rsplit_once(": ").map(|(_, sig)| sig.to_string()))
                .map(|sig| {
                    let test = sig.contains("Eicar") || sig.contains("Test");
                    item(
                        sig.clone(),
                        if test {
                            "A harmless antivirus test file."
                        } else {
                            "ClamAV recognised this as a known threat."
                        },
                        if test { "low" } else { "high" },
                    )
                })
                .collect();
            Ok(
                json!({"verdict": "danger", "headline": format!("Found a known threat.{age_note}"), "items": items,
                      "stale_db": stale, "duration_ms": o.duration_ms}),
            )
        }
        _ => Err(format!(
            "ClamAV couldn't scan this file: {}",
            o.stderr
                .lines()
                .filter(|l| !l.contains("Warning"))
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(300)
                .collect::<String>()
        )),
    }
}

// ---------------------------------------------------------------- capa

pub fn capa_rules(st: &Shared) -> Option<(PathBuf, PathBuf)> {
    let r = rules_dir(st).join("capa");
    let (rules, sigs) = (r.join("rules"), r.join("sigs"));
    (rules.is_dir() && sigs.is_dir()).then_some((rules, sigs))
}

/// Plain names for capa's top-level namespaces.
fn capa_area(ns: &str) -> &'static str {
    match ns.split('/').next().unwrap_or("") {
        "anti-analysis" => "Hides from analysis tools",
        "collection" => "Collects information",
        "communication" => "Network and communication",
        "data-manipulation" => "Encodes, encrypts or compresses data",
        "executable" => "Program structure",
        "host-interaction" => "Uses the computer (files, processes, settings)",
        "impact" => "Can cause damage",
        "linking" => "Loads code at runtime",
        "load-code" => "Loads extra code",
        "persistence" => "Starts itself again (persistence)",
        "runtime" => "Runtime / language",
        "targeting" => "Targets specific systems",
        "nursery" => "Other",
        "malware-family" => "Known malware family",
        "exploitation" => "Exploits weaknesses",
        _ => "Other",
    }
}

fn capa_severity(ns: &str, attack: bool) -> &'static str {
    let top = ns.split('/').next().unwrap_or("");
    match top {
        "malware-family" | "impact" | "exploitation" => "high",
        "anti-analysis" | "persistence" => "medium",
        _ if ns.contains("inject") || ns.contains("keylog") || ns.contains("screenshot") => {
            "medium"
        }
        _ if attack => "low",
        _ => "info",
    }
}

async fn capa(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let (rules, sigs) =
        capa_rules(st).ok_or("capa rules aren't downloaded yet (Settings → Tools)")?;
    let work = TempDir(temp_work(st, "capa", &s.sha));
    let inp = input_link(&work.0, input, s.info.format);
    let args = vec![
        os("-j"),
        os("-q"),
        os("-r"),
        rules.into_os_string(),
        os("-s"),
        sigs.into_os_string(),
        inp.into_os_string(),
    ];
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    let v: Value = serde_json::from_slice(&o.stdout).map_err(|_| {
        let e: String = o
            .stderr
            .lines()
            .filter(|l| l.contains("ERROR") || l.contains("rror"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "capa couldn't analyse this file{}",
            if e.is_empty() {
                String::new()
            } else {
                format!(": {}", e.chars().take(300).collect::<String>())
            }
        )
    })?;
    let mut items = Vec::new();
    for (name, r) in v["rules"].as_object().into_iter().flatten() {
        let m = &r["meta"];
        if m["lib"].as_bool() == Some(true) {
            continue;
        }
        let ns = m["namespace"].as_str().unwrap_or("");
        let attack: Vec<String> = m["attack"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                a["technique"]
                    .as_str()
                    .map(|t| format!("{t} ({})", a["id"].as_str().unwrap_or("")))
            })
            .collect();
        let n = r["matches"]
            .as_array()
            .map(|a| a.len())
            .or_else(|| r["matches"].as_object().map(|o| o.len()))
            .unwrap_or(0);
        items.push(json!({
            "title": name, "detail": capa_area(ns), "severity": capa_severity(ns, !attack.is_empty()),
            "namespace": ns, "attack": attack, "places": n,
        }));
    }
    items.sort_by_key(|i| match i["severity"].as_str() {
        Some("high") => 0,
        Some("medium") => 1,
        Some("low") => 2,
        _ => 3,
    });
    let high = items.iter().filter(|i| i["severity"] == "high").count();
    let medium = items.iter().filter(|i| i["severity"] == "medium").count();
    let (verdict, headline) = match (items.len(), high, medium) {
        (0, _, _) => (
            "clean",
            "capa recognised no notable capabilities.".to_string(),
        ),
        (n, h, _) if h > 0 => (
            "danger",
            format!("capa found {n} capabilities, {h} of them typical of harmful software."),
        ),
        (n, _, m) if m > 0 => (
            "warning",
            format!("capa found {n} capabilities, {m} worth a closer look."),
        ),
        (n, _, _) => (
            "info",
            format!("capa found {n} capabilities; none of them are unusual on their own."),
        ),
    };
    Ok(
        json!({"verdict": verdict, "headline": headline, "items": items, "duration_ms": o.duration_ms}),
    )
}

// ---------------------------------------------------------------- FLOSS

async fn floss(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = TempDir(temp_work(st, "floss", &s.sha));
    let inp = input_link(&work.0, input, s.info.format);
    let args = vec![
        os("-j"),
        os("-q"),
        os("--only"),
        os("stack"),
        os("tight"),
        os("decoded"),
        os("--"),
        inp.into_os_string(),
    ];
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    let v: Value = serde_json::from_slice(&o.stdout).map_err(|_| {
        format!(
            "FLOSS couldn't analyse this file: {}",
            o.stderr.trim().chars().take(300).collect::<String>()
        )
    })?;
    let mut items = Vec::new();
    for (k, label) in [
        ("decoded_strings", "decoded at runtime"),
        ("stack_strings", "built piece by piece"),
        ("tight_strings", "built in a tight loop"),
    ] {
        for x in v["strings"][k].as_array().into_iter().flatten().take(300) {
            if let Some(sv) = x["string"].as_str() {
                items.push(json!({"title": sv, "detail": format!("Hidden text {label}"), "severity": "info", "kind": k}));
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    items.retain(|i| seen.insert(i["title"].as_str().unwrap_or("").to_string()));
    let n = items.len();
    let headline = if n == 0 {
        "No hidden or scrambled text found.".to_string()
    } else {
        format!(
            "Found {n} piece{} of text the program hides until it runs. Normal programs rarely do this; read them for addresses or commands.",
            if n == 1 { "" } else { "s" }
        )
    };
    Ok(
        json!({"verdict": if n == 0 { "clean" } else { "warning" }, "headline": headline, "items": items, "duration_ms": o.duration_ms}),
    )
}

// ---------------------------------------------------------------- ExifTool

/// Tag (without group) → plain label, in display order.
const EXIF_HIGHLIGHTS: &[(&str, &str)] = &[
    ("GPSPosition", "Location (GPS)"),
    ("GPSAltitude", "Altitude"),
    ("Make", "Camera / phone maker"),
    ("Model", "Camera / phone model"),
    ("LensModel", "Lens"),
    ("DateTimeOriginal", "Photo taken"),
    ("CreateDate", "Created"),
    ("ModifyDate", "Last changed"),
    ("Software", "Software"),
    ("HostComputer", "Computer"),
    ("Artist", "Artist"),
    ("Author", "Author"),
    ("Creator", "Creator"),
    ("LastModifiedBy", "Last edited by"),
    ("Company", "Company"),
    ("Manager", "Manager"),
    ("Title", "Title"),
    ("Subject", "Subject"),
    ("CreatorTool", "Made with"),
    ("Producer", "Produced by"),
    ("Application", "Application"),
    ("AppVersion", "Application version"),
    ("Template", "Template"),
    ("TotalEditTime", "Total editing time"),
    ("RevisionNumber", "Revision"),
    ("Pages", "Pages"),
    ("PageCount", "Pages"),
    ("Words", "Words"),
    ("CompanyName", "Company"),
    ("ProductName", "Product"),
    ("FileDescription", "Description"),
    ("OriginalFileName", "Original file name"),
    ("InternalName", "Internal name"),
    ("LegalCopyright", "Copyright"),
    ("FileVersion", "File version"),
    ("ProductVersion", "Product version"),
    ("TimeStamp", "Built (time stamp)"),
    ("SerialNumber", "Device serial number"),
    ("OwnerName", "Owner"),
    ("ImageSize", "Size (pixels)"),
    ("Duration", "Duration"),
    ("Encoder", "Encoder"),
    ("HandlerVendorID", "Recorded with"),
    ("ContentCreateDate", "Recorded"),
    ("Comment", "Comment"),
    ("UserComment", "Comment"),
    ("XPComment", "Comment"),
];

fn exif_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(a) => a.iter().map(exif_value).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

async fn exiftool(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = TempDir(temp_work(st, "exiftool", &s.sha));
    // -c prints GPS as signed decimal degrees; -b-less JSON keeps binary out.
    let args = vec![
        os("-json"),
        os("-G1"),
        os("-a"),
        os("-c"),
        os("%+.6f"),
        os("-api"),
        os("LargeFileSupport=1"),
        input.as_os_str().to_owned(),
    ];
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    let v: Value = serde_json::from_slice(&o.stdout)
        .map_err(|_| "ExifTool couldn't read this file".to_string())?;
    let obj = v
        .get(0)
        .and_then(|o| o.as_object())
        .ok_or("ExifTool returned nothing")?;
    let mut fields = Vec::new();
    for (k, val) in obj {
        let (group, tag) = k.split_once(':').unwrap_or(("", k));
        // Drop facts about our own copy of the file (path, our timestamps).
        if matches!(group, "System" | "ExifTool") || k == "SourceFile" || tag.ends_with("Directory")
        {
            continue;
        }
        let sv = exif_value(val);
        if sv.is_empty() || sv.len() > 2000 || sv.starts_with("(Binary data") {
            continue;
        }
        fields.push(json!({"group": group, "tag": tag, "value": sv}));
        if fields.len() >= 600 {
            break;
        }
    }
    let mut highlights = Vec::new();
    let mut gps: Option<(f64, f64)> = None;
    for (tag, label) in EXIF_HIGHLIGHTS {
        if highlights.iter().any(|h: &Value| h["label"] == *label) {
            continue;
        }
        if let Some(f) = fields.iter().find(|f| f["tag"] == *tag) {
            let val = f["value"].as_str().unwrap_or("").to_string();
            if *tag == "GPSPosition" {
                let mut it = val.split(',').map(|x| x.trim().parse::<f64>());
                if let (Some(Ok(la)), Some(Ok(lo))) = (it.next(), it.next())
                    && (-90.0..=90.0).contains(&la)
                    && (-180.0..=180.0).contains(&lo)
                    && !(la == 0.0 && lo == 0.0)
                {
                    gps = Some((la, lo));
                }
            }
            highlights.push(json!({"label": label, "value": val, "tag": tag}));
        }
    }
    let mut items = Vec::new();
    if let Some((la, lo)) = gps {
        items.push(item("Contains the exact location where it was made", format!("GPS {la:.5}, {lo:.5}. Anyone you send this file to can see this place. Remove location data before sharing if that matters to you."), "medium"));
    }
    if highlights.iter().any(|h| h["tag"] == "SerialNumber") {
        items.push(item(
            "Contains a device serial number",
            "This can identify the exact camera or phone that made it.",
            "low",
        ));
    }
    if highlights.iter().any(|h| {
        matches!(
            h["tag"].as_str(),
            Some("Author" | "Creator" | "Artist" | "LastModifiedBy" | "OwnerName")
        )
    }) {
        items.push(item(
            "Contains people's names",
            "The file records who made or edited it.",
            "info",
        ));
    }
    let headline = match (gps.is_some(), highlights.len()) {
        (true, _) => "This file records where it was made (GPS location) and other hidden details."
            .to_string(),
        (false, 0) => "No notable hidden details found.".to_string(),
        (false, n) => format!(
            "Found {n} hidden detail{} (who, what, when).",
            if n == 1 { "" } else { "s" }
        ),
    };
    Ok(
        json!({"verdict": if gps.is_some() { "warning" } else { "info" }, "headline": headline, "items": items,
              "data": {"highlights": highlights, "fields": fields, "gps": gps.map(|(a, b)| json!({"lat": a, "lon": b}))},
              "duration_ms": o.duration_ms}),
    )
}

// ---------------------------------------------------------------- oletools

async fn olevba(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = TempDir(temp_work(st, "olevba", &s.sha));
    let inp = input_link(&work.0, input, s.info.format);
    let args = vec![os("--json"), os("--decode"), inp.into_os_string()];
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    let v: Value = serde_json::from_slice(&o.stdout).map_err(|_| {
        format!(
            "oletools couldn't read this file: {}",
            o.stderr.trim().chars().take(200).collect::<String>()
        )
    })?;
    let mut macros = Vec::new();
    let mut items = Vec::new();
    let mut auto = false;
    let mut suspicious = 0;
    for f in v
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["type"] != "MetaInformation")
    {
        for m in f["macros"].as_array().into_iter().flatten().take(50) {
            let code = m["code"].as_str().unwrap_or("");
            macros.push(json!({"name": m["vba_filename"], "stream": m["ole_stream"],
                               "code": code.chars().take(200_000).collect::<String>()}));
        }
        for a in f["analysis"].as_array().into_iter().flatten().take(200) {
            let typ = a["type"].as_str().unwrap_or("");
            let sev = match typ {
                "AutoExec" => {
                    auto = true;
                    "high"
                }
                "Suspicious" => {
                    suspicious += 1;
                    "medium"
                }
                "IOC" => "medium",
                _ => "info",
            };
            let plain = match typ {
                "AutoExec" => "Runs by itself when the document is opened or closed.",
                "Suspicious" => "Uses a command often seen in harmful macros.",
                "IOC" => "Contains an address, file name or command (indicator).",
                "Hex String" | "Base64 String" | "Dridex String" | "VBA string" => {
                    "Hidden or encoded text."
                }
                _ => "",
            };
            items.push(json!({"title": format!("{}: {}", typ, a["keyword"].as_str().unwrap_or("")),
                              "detail": format!("{} {}", plain, a["description"].as_str().unwrap_or("")).trim().to_string(), "severity": sev}));
        }
    }
    let (verdict, headline) = if macros.is_empty() {
        ("clean", "No macros (hidden programs) found.".to_string())
    } else if auto && suspicious > 0 {
        (
            "danger",
            format!(
                "Contains {} macro{} that run automatically and use suspicious commands. Do not enable macros when opening it.",
                macros.len(),
                if macros.len() == 1 { "" } else { "s" }
            ),
        )
    } else if auto {
        ("warning", "Contains macros that run automatically when opened. Only enable them if you trust the sender.".to_string())
    } else {
        (
            "warning",
            format!(
                "Contains {} macro{} (small programs). They only run if you enable them.",
                macros.len(),
                if macros.len() == 1 { "" } else { "s" }
            ),
        )
    };
    Ok(
        json!({"verdict": verdict, "headline": headline, "items": items, "data": {"macros": macros}, "duration_ms": o.duration_ms}),
    )
}

// ---------------------------------------------------------------- binwalk

async fn binwalk(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = TempDir(temp_work(st, "binwalk", &s.sha));
    let log = work.0.join("log.json");
    // Signature scan only: extraction would run many external unpackers.
    let args = vec![
        os(format!("--log={}", log.display())),
        os("--quiet"),
        input.as_os_str().to_owned(),
    ];
    std::fs::create_dir_all(&work.0).map_err(|e| e.to_string())?;
    let o = run(st, spec(t, bin, work.0.clone(), args)).await?;
    if o.timed_out {
        return Err(timeout_err(t));
    }
    let v: Value = serde_json::from_slice(&super::read_capped(&log, 16 << 20)).map_err(|_| {
        format!(
            "binwalk couldn't scan this file: {}",
            o.stderr.trim().chars().take(200).collect::<String>()
        )
    })?;
    let mut items = Vec::new();
    for e in v.as_array().into_iter().flatten() {
        for m in e["Analysis"]["file_map"]
            .as_array()
            .into_iter()
            .flatten()
            .take(500)
        {
            items.push(
                json!({"title": m["name"], "detail": m["description"], "severity": "info",
                              "offset": m["offset"], "size": m["size"]}),
            );
        }
    }
    let n = items.len();
    let headline = match n {
        0 => "No embedded files found.".to_string(),
        1 => "Found 1 recognisable file or data block inside.".to_string(),
        n => format!(
            "Found {n} recognisable files or data blocks inside. This is normal for firmware and archives."
        ),
    };
    Ok(
        json!({"verdict": "info", "headline": headline, "items": items, "duration_ms": o.duration_ms}),
    )
}

// ---------------------------------------------------------------- radare2

pub async fn r2ghidra_available() -> bool {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let dirs = [
        home.join(".local/share/radare2/plugins"),
        PathBuf::from("/opt/homebrew/lib/radare2"),
        PathBuf::from("/usr/local/lib/radare2"),
    ];
    dirs.iter().any(|d| {
        walk_find(d, 3, &|n| {
            n.starts_with("core_ghidra")
                || n.starts_with("libcore_ghidra")
                || n.contains("r2ghidra")
        })
    })
}

fn walk_find(d: &Path, depth: u32, f: &dyn Fn(&str) -> bool) -> bool {
    let Ok(rd) = std::fs::read_dir(d) else {
        return false;
    };
    for e in rd.flatten() {
        let n = e.file_name();
        let n = n.to_string_lossy();
        if f(&n) {
            return true;
        }
        if depth > 0
            && e.file_type().is_ok_and(|t| t.is_dir())
            && walk_find(&e.path(), depth - 1, f)
        {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------- setup

/// Download rules / databases for a tool (network, user-initiated, not on
/// the input file, so it runs outside the sandbox).
pub async fn setup(st: &Shared, what: &str) -> Result<(), String> {
    match what {
        "yara-rules" => setup_yara(st).await,
        "capa-rules" => setup_capa(st).await,
        "clamav-db" => setup_clamav().await,
        _ => Err("unknown setup".into()),
    }
}

async fn download(url: &str, dest: &Path, max: u64) -> Result<(), String> {
    let curl = ["/usr/bin/curl", "/opt/homebrew/bin/curl"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .or_else(|| super::which("curl"))
        .ok_or("curl is not installed")?;
    if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let o = tokio::process::Command::new(curl)
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "5",
            "--connect-timeout",
            "15",
            "--max-time",
            "600",
            "--max-filesize",
        ])
        .arg(max.to_string())
        .arg("--output")
        .arg(dest)
        .arg(url)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!(
            "download failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .trim()
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(())
}

/// Extract a zip safely: only regular files, no absolute paths or `..`,
/// bounded total size and count.
fn unzip_safe(
    zip: &Path,
    dest: &Path,
    keep: &dyn Fn(&str) -> Option<String>,
) -> Result<usize, String> {
    use std::io::Read;
    let f = std::fs::File::open(zip).map_err(|e| e.to_string())?;
    let mut z = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
    let mut total: u64 = 0;
    let mut n = 0;
    for i in 0..z.len().min(20_000) {
        let mut e = z.by_index(i).map_err(|e| e.to_string())?;
        if !e.is_file() {
            continue;
        }
        let Some(rel) = e.enclosed_name() else {
            continue;
        };
        let Some(out_rel) = keep(&rel.to_string_lossy()) else {
            continue;
        };
        if out_rel.split('/').any(|c| c == ".." || c.is_empty()) {
            continue;
        }
        let out = dest.join(&out_rel);
        if let Some(d) = out.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let mut buf = Vec::new();
        e.by_ref()
            .take(64 << 20)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        total += buf.len() as u64;
        if total > 512 << 20 {
            return Err("archive too large".into());
        }
        std::fs::write(&out, buf).map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

async fn setup_yara(st: &Shared) -> Result<(), String> {
    let dir = rules_dir(st).join("yara");
    let tmp = rules_dir(st).join(format!("yara-dl-{}", crate::util::new_id()));
    let _g = TempDir(tmp.clone());
    let zip = tmp.join("rules.zip");
    download(
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        &zip,
        100 << 20,
    )
    .await?;
    let ex = tmp.join("x");
    let zip2 = zip.clone();
    let ex2 = ex.clone();
    tokio::task::spawn_blocking(move || {
        unzip_safe(&zip2, &ex2, &|p| {
            p.ends_with(".yar").then(|| "rules.yar".to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    let src = ex.join("rules.yar");
    let text =
        std::fs::read_to_string(&src).map_err(|_| "the rules download was empty".to_string())?;
    let count = text
        .lines()
        .filter(|l| l.starts_with("rule ") || l.starts_with("private rule "))
        .count();
    let version = text
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("* Version:")
                .or_else(|| l.trim().strip_prefix("Version:"))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_else(|| crate::util::now()[..10].to_string());
    let yarac = super::which("yarac").ok_or("yarac (part of YARA) is not installed")?;
    let compiled = tmp.join("rules.yarc");
    let o = tokio::process::Command::new(yarac)
        .arg("-w")
        .arg(&src)
        .arg(&compiled)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        return Err(format!(
            "compiling the rules failed: {}",
            String::from_utf8_lossy(&o.stderr)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::rename(&compiled, dir.join("rules.yarc")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("count"), count.to_string()).map_err(|e| e.to_string())?;
    std::fs::write(
        rules_dir(st).join("yara-rules.version"),
        format!("yara-forge-core {version}"),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn setup_capa(st: &Shared) -> Result<(), String> {
    let t = super::def("capa").ok_or("capa unknown")?;
    let bin = super::locate(t).ok_or("capa is not installed")?;
    let ver = super::version(t, &bin)
        .await
        .ok_or("couldn't read the capa version")?;
    let ver = ver.trim_start_matches('v').to_string();
    if !ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("unexpected capa version {ver}"));
    }
    let base = rules_dir(st).join("capa");
    let tmp = rules_dir(st).join(format!("capa-dl-{}", crate::util::new_id()));
    let _g = TempDir(tmp.clone());
    let zip = tmp.join("rules.zip");
    download(
        &format!("https://codeload.github.com/mandiant/capa-rules/zip/refs/tags/v{ver}"),
        &zip,
        50 << 20,
    )
    .await?;
    let new_rules = tmp.join("rules");
    let (z2, r2) = (zip.clone(), new_rules.clone());
    let n = tokio::task::spawn_blocking(move || {
        unzip_safe(&z2, &r2, &|p| {
            // capa-rules-<ver>/<ns>/…/x.yml → <ns>/…/x.yml
            let rest = p.split_once('/')?.1;
            (rest.ends_with(".yml") && !rest.starts_with('.')).then(|| rest.to_string())
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    if n < 100 {
        return Err("the capa rules download looks incomplete".into());
    }
    let sigs = tmp.join("sigs");
    for f in [
        "1_flare_msvc_rtf_32_64.sig",
        "2_flare_msvc_atlmfc_32_64.sig",
        "3_flare_common_libs.sig",
    ] {
        download(
            &format!("https://raw.githubusercontent.com/mandiant/capa/v{ver}/sigs/{f}"),
            &sigs.join(f),
            64 << 20,
        )
        .await?;
    }
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    std::fs::rename(&new_rules, base.join("rules")).map_err(|e| e.to_string())?;
    std::fs::rename(&sigs, base.join("sigs")).map_err(|e| e.to_string())?;
    std::fs::write(
        rules_dir(st).join("capa-rules.version"),
        format!("capa-rules {ver}"),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

async fn setup_clamav() -> Result<(), String> {
    let fc = super::which("freshclam").ok_or("freshclam (part of ClamAV) is not installed")?;
    let o = tokio::time::timeout(
        Duration::from_secs(900),
        tokio::process::Command::new(fc)
            .arg("--stdout")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "updating the virus database took too long".to_string())?
    .map_err(|e| e.to_string())?;
    if !o.status.success() {
        let out = String::from_utf8_lossy(&o.stdout);
        let msg = out
            .lines()
            .rev()
            .find(|l| l.contains("ERROR") || l.contains("WARNING"))
            .unwrap_or("freshclam failed");
        return Err(msg.chars().take(300).collect());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_line() {
        let (r, tags, meta) =
            parse_yara_line(r#"Test_Eicar [test,av] [description="EICAR \"test\" file, a=b",author="me",score =60] /tmp/x y.com"#).unwrap();
        assert_eq!(r, "Test_Eicar");
        assert_eq!(tags, vec!["test", "av"]);
        assert_eq!(
            meta[0],
            ("description".into(), "EICAR \"test\" file, a=b".into())
        );
        assert_eq!(meta[2], ("score".into(), "60".into()));
        let (r, tags, meta) = parse_yara_line("Rule_2 [] [] /x").unwrap();
        assert_eq!((r.as_str(), tags.len(), meta.len()), ("Rule_2", 0, 0));
    }
}
