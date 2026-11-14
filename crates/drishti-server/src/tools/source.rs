//! Readable source trees for other kinds of apps: Android/Java (JADX),
//! .NET (ILSpy), WebAssembly (WABT), Apple class lists (ipsw), and the
//! JavaScript inside Electron apps (`app.asar`, read in-process).
//!
//! Tool output stays in `tools/work/<tool>/<sha>/`; the browse endpoint
//! only serves regular files below that folder.

use super::{RunSpec, ToolDef, input_link, run, work_dir};
use crate::api::{R, bad, not_found, valid_sha};
use crate::state::{Session, Shared};
use axum::Json;
use axum::extract::{Query, State};
use drishti_model::Format;
use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const MAX_FILES: usize = 60_000;
const MAX_READ: usize = 2 << 20;

fn fresh(dir: &Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())
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
        stdout_cap: 1 << 20,
    }
}

/// Files below `root` (relative paths, sizes), skipping symlinks.
fn list_tree(root: &Path, filter: &dyn Fn(&str) -> bool) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file()
                && let Ok(rel) = e.path().strip_prefix(root)
            {
                let r = rel.to_string_lossy().replace('\\', "/");
                if !r.starts_with('.') && filter(&r) {
                    out.push((r, e.metadata().map(|m| m.len()).unwrap_or(0)));
                }
                if out.len() >= MAX_FILES {
                    return out;
                }
            }
        }
    }
    out.sort();
    out
}

/// Plain meanings of Android permissions people care about.
fn android_permission(p: &str) -> Option<(&'static str, &'static str)> {
    let short = p.rsplit('.').next().unwrap_or(p);
    Some(match short {
        "CAMERA" => ("Camera", "high"),
        "RECORD_AUDIO" => ("Microphone", "high"),
        "ACCESS_FINE_LOCATION" => ("Exact location", "high"),
        "ACCESS_COARSE_LOCATION" => ("Approximate location", "medium"),
        "ACCESS_BACKGROUND_LOCATION" => ("Location while in the background", "high"),
        "READ_CONTACTS" | "WRITE_CONTACTS" => ("Contacts", "high"),
        "READ_SMS" | "RECEIVE_SMS" | "SEND_SMS" => ("Text messages (SMS)", "high"),
        "READ_CALL_LOG" | "WRITE_CALL_LOG" => ("Call history", "high"),
        "CALL_PHONE" => ("Make phone calls", "medium"),
        "READ_PHONE_STATE" | "READ_PHONE_NUMBERS" => ("Phone number and status", "medium"),
        "READ_EXTERNAL_STORAGE" | "WRITE_EXTERNAL_STORAGE" | "MANAGE_EXTERNAL_STORAGE" => {
            ("Files and photos", "medium")
        }
        "READ_MEDIA_IMAGES" | "READ_MEDIA_VIDEO" => ("Photos and videos", "medium"),
        "READ_CALENDAR" | "WRITE_CALENDAR" => ("Calendar", "medium"),
        "BODY_SENSORS" => ("Body sensors (heart rate)", "medium"),
        "BLUETOOTH_SCAN" | "BLUETOOTH_CONNECT" => ("Nearby Bluetooth devices", "low"),
        "SYSTEM_ALERT_WINDOW" => ("Draw over other apps", "high"),
        "BIND_ACCESSIBILITY_SERVICE" => ("Control the screen (accessibility)", "high"),
        "BIND_DEVICE_ADMIN" => ("Device administrator", "high"),
        "REQUEST_INSTALL_PACKAGES" => ("Install other apps", "high"),
        "RECEIVE_BOOT_COMPLETED" => ("Start when the phone turns on", "low"),
        "INTERNET" => ("Internet", "info"),
        "POST_NOTIFICATIONS" => ("Show notifications", "info"),
        "QUERY_ALL_PACKAGES" => ("See all installed apps", "medium"),
        "GET_ACCOUNTS" => ("Accounts on the device", "medium"),
        "USE_BIOMETRIC" | "USE_FINGERPRINT" => ("Fingerprint / face unlock", "info"),
        "FOREGROUND_SERVICE" => ("Keep running in the background", "low"),
        "WAKE_LOCK" => ("Keep the phone awake", "info"),
        _ => return None,
    })
}

fn manifest_permissions(xml: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for seg in xml.split("<uses-permission").skip(1) {
        let Some(i) = seg.find("android:name=\"") else {
            continue;
        };
        let rest = &seg[i + 14..];
        let Some(j) = rest.find('"') else { continue };
        let name = &rest[..j];
        let (label, sev) = android_permission(name).unwrap_or(("Other permission", "info"));
        out.push(json!({"name": name, "label": label, "severity": sev}));
    }
    out.sort_by_key(|p| match p["severity"].as_str() {
        Some("high") => 0,
        Some("medium") => 1,
        Some("low") => 2,
        _ => 3,
    });
    out.dedup_by(|a, b| a["name"] == b["name"]);
    out
}

pub async fn jadx(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = work_dir(st, "jadx", &s.sha);
    fresh(&work)?;
    let inp = input_link(&work, input, s.info.format);
    let out = work.join("out");
    let args = vec![
        "-d".into(),
        out.clone().into_os_string(),
        "--log-level".into(),
        "error".into(),
        "-j".into(),
        "2".into(),
        inp.into_os_string(),
    ];
    let o = run(st, spec(t, bin, work.clone(), args)).await?;
    if o.timed_out {
        return Err("JADX took too long on this app".into());
    }
    let files = list_tree(&out, &|p| {
        p.ends_with(".java") || p.ends_with(".kt") || p.ends_with("AndroidManifest.xml")
    });
    if files.is_empty() {
        return Err(format!(
            "JADX produced no source code: {}",
            o.stderr.trim().chars().take(300).collect::<String>()
        ));
    }
    let manifest =
        std::fs::read_to_string(out.join("resources/AndroidManifest.xml")).unwrap_or_default();
    let perms = manifest_permissions(&manifest);
    let package = manifest
        .split("package=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .map(str::to_string);
    let classes = files.iter().filter(|f| f.0.ends_with(".java")).count();
    let risky: Vec<&Value> = perms.iter().filter(|p| p["severity"] == "high").collect();
    let items: Vec<Value> = perms
        .iter()
        .map(|p| json!({"title": p["label"], "detail": p["name"], "severity": p["severity"]}))
        .collect();
    let headline = if s.info.format == Format::Apk {
        format!(
            "Turned the app back into {classes} Java file{}. It asks for {} permission{}{}.",
            if classes == 1 { "" } else { "s" },
            perms.len(),
            if perms.len() == 1 { "" } else { "s" },
            if risky.is_empty() {
                String::new()
            } else {
                format!(", {} of them sensitive", risky.len())
            }
        )
    } else {
        format!(
            "Turned the code back into {classes} Java file{}.",
            if classes == 1 { "" } else { "s" }
        )
    };
    Ok(
        json!({"verdict": if risky.is_empty() { "info" } else { "warning" }, "headline": headline, "items": items,
              "data": {"tree": "jadx", "files": files.len(), "classes": classes, "permissions": perms, "package": package},
              "duration_ms": o.duration_ms}),
    )
}

pub async fn ilspy(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = work_dir(st, "ilspy", &s.sha);
    fresh(&work)?;
    let inp = input_link(&work, input, s.info.format);
    let out = work.join("out");
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let args = vec![
        "-p".into(),
        "-o".into(),
        out.clone().into_os_string(),
        inp.into_os_string(),
    ];
    let o = run(st, spec(t, bin, work.clone(), args)).await?;
    if o.timed_out {
        return Err("ILSpy took too long on this program".into());
    }
    let files = list_tree(&out, &|p| p.ends_with(".cs") || p.ends_with(".csproj"));
    if files.is_empty() {
        return Err(format!(
            "ILSpy produced no source code: {}",
            o.stderr.trim().chars().take(300).collect::<String>()
        ));
    }
    Ok(
        json!({"verdict": "info", "headline": format!("Turned the program back into {} C# files.", files.len()), "items": [],
              "data": {"tree": "ilspy", "files": files.len()}, "duration_ms": o.duration_ms}),
    )
}

pub async fn wabt(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = work_dir(st, "wabt", &s.sha);
    fresh(&work)?;
    let out = work.join("out");
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let args = vec![
        "--fold-exprs".into(),
        "--generate-names".into(),
        "-o".into(),
        out.join("module.wat").into_os_string(),
        input.as_os_str().to_owned(),
    ];
    let o = run(st, spec(t, bin, work.clone(), args)).await?;
    if o.timed_out {
        return Err("WABT took too long".into());
    }
    let wat = out.join("module.wat");
    if !wat.is_file() {
        return Err(format!(
            "WABT couldn't read this module: {}",
            o.stderr.trim().chars().take(300).collect::<String>()
        ));
    }
    // Imports/exports summary (what the module needs from the page, and offers).
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    if let Some(objdump) = super::which("wasm-objdump") {
        let o2 = run(
            st,
            spec(
                t,
                &objdump,
                work.clone(),
                vec![
                    "-x".into(),
                    "-j".into(),
                    "Import".into(),
                    "-j".into(),
                    "Export".into(),
                    input.as_os_str().to_owned(),
                ],
            ),
        )
        .await;
        if let Ok(o2) = o2 {
            let txt = String::from_utf8_lossy(&o2.stdout).into_owned();
            let mut sec = "";
            for l in txt.lines() {
                if l.starts_with("Import[") {
                    sec = "i";
                    continue;
                }
                if l.starts_with("Export[") {
                    sec = "e";
                    continue;
                }
                if let Some(x) = l.trim().strip_prefix("- ") {
                    let name = x
                        .rsplit("<- ")
                        .next()
                        .or_else(|| x.rsplit("-> ").next())
                        .unwrap_or(x)
                        .trim_matches('"')
                        .to_string();
                    if sec == "i" {
                        imports.push(name)
                    } else if sec == "e" {
                        exports.push(name)
                    }
                }
            }
            let _ = std::fs::write(out.join("imports-exports.txt"), txt);
        }
    }
    let items: Vec<Value> = imports.iter().take(200).map(|i| json!({"title": i, "detail": "Needs this from the web page / host", "severity": "info"})).collect();
    Ok(
        json!({"verdict": "info", "headline": format!("WebAssembly module with {} imports and {} exports, shown as readable text.", imports.len(), exports.len()),
              "items": items, "data": {"tree": "wabt", "files": 2, "exports": exports}, "duration_ms": o.duration_ms}),
    )
}

pub async fn ipsw(
    st: &Shared,
    t: &ToolDef,
    bin: &Path,
    input: &Path,
    s: &Session,
) -> Result<Value, String> {
    let work = work_dir(st, "ipsw", &s.sha);
    fresh(&work)?;
    let out = work.join("out");
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
    let arch: Option<&str> = match s.image.as_deref().map(|i| i.arch) {
        _ if s.info.format != Format::MachoFat => None,
        Some(drishti_model::Arch::Aarch64) => Some("arm64"),
        Some(drishti_model::Arch::X86_64) => Some("x86_64"),
        _ => None,
    };
    let mut total_ms = 0;
    let mut classes: Vec<Value> = Vec::new();
    let mut protocols = 0usize;
    let mut swift_types = 0usize;
    for (sub, file) in [
        ("class-dump", "objc-classes.h"),
        ("swift-dump", "swift-types.txt"),
    ] {
        let mut args: Vec<OsString> = vec![sub.into(), input.as_os_str().to_owned()];
        if let Some(a) = arch {
            args.extend(["--arch".into(), a.into()]);
        }
        let mut sp = spec(t, bin, work.clone(), args);
        sp.stdout_cap = 24 << 20;
        let o = run(st, sp).await?;
        total_ms += o.duration_ms;
        if o.timed_out {
            return Err("ipsw took too long".into());
        }
        let txt = String::from_utf8_lossy(&o.stdout).into_owned();
        if txt.trim().is_empty() {
            continue;
        }
        if sub == "class-dump" {
            for l in txt.lines() {
                if let Some(r) = l.strip_prefix("@interface ") {
                    let name = r
                        .split([' ', '(', ':', '{', '<'])
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let sup = r.split_once(':').map(|(_, b)| {
                        b.trim()
                            .split([' ', '{', '<'])
                            .next()
                            .unwrap_or("")
                            .to_string()
                    });
                    if !name.is_empty() && classes.len() < 30_000 {
                        classes.push(json!({"name": name, "super": sup, "lang": "objc"}));
                    }
                } else if l.starts_with("@protocol ") {
                    protocols += 1;
                }
            }
        } else {
            for l in txt.lines() {
                for kw in ["class ", "struct ", "enum ", "protocol "] {
                    if let Some(r) = l.strip_prefix(kw) {
                        swift_types += 1;
                        let name = r
                            .split([' ', ':', '{', '<'])
                            .next()
                            .unwrap_or("")
                            .to_string();
                        if kw == "class " && !name.is_empty() && classes.len() < 30_000 {
                            let sup = r.split_once(": ").map(|(_, b)| {
                                b.split([' ', '{', ',']).next().unwrap_or("").to_string()
                            });
                            classes.push(json!({"name": name, "super": sup, "lang": "swift"}));
                        }
                    }
                }
            }
        }
        std::fs::write(out.join(file), txt).map_err(|e| e.to_string())?;
    }
    if classes.is_empty() && swift_types == 0 {
        return Err("No Objective-C or Swift classes found in this program.".into());
    }
    let n = classes.len();
    Ok(json!({"verdict": "info",
              "headline": format!("Lists {n} classes ({protocols} Objective-C protocols, {swift_types} Swift types). Class names often describe features directly."),
              "items": [], "data": {"tree": "ipsw", "classes": classes, "files": 2}, "duration_ms": total_ms}))
}

// ---------------------------------------------------------------- browsing

#[derive(Deserialize)]
pub struct SourceQ {
    tool: String,
    #[serde(default)]
    path: Option<String>,
}

/// Reject `..`, absolute paths and anything odd before touching the disk.
fn safe_rel(p: &str) -> Option<PathBuf> {
    if p.is_empty() || p.len() > 1024 || p.contains('\0') {
        return None;
    }
    let pb = PathBuf::from(p);
    pb.components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then_some(pb)
}

/// `GET /binaries/{sha}/source?tool=jadx|ilspy|wabt|ipsw|asar[&path=]`
/// Without `path`: the file list. With `path`: that file's text.
pub async fn browse(
    State(st): State<Shared>,
    axum::extract::Path(sha): axum::extract::Path<String>,
    Query(q): Query<SourceQ>,
) -> R<Json<Value>> {
    valid_sha(&sha)?;
    if q.tool == "asar" {
        return asar(&st, &sha, q.path.as_deref()).await;
    }
    if !matches!(q.tool.as_str(), "jadx" | "ilspy" | "wabt" | "ipsw") {
        return Err(bad("unknown source tool"));
    }
    let root = work_dir(&st, &q.tool, &sha).join("out");
    if !root.is_dir() {
        return Err(not_found("run the tool first"));
    }
    match q.path.as_deref() {
        None => {
            let r2 = root.clone();
            let files = tokio::task::spawn_blocking(move || list_tree(&r2, &|_| true)).await?;
            Ok(Json(
                json!({"files": files.iter().map(|(p, n)| json!([p, n])).collect::<Vec<_>>(), "truncated": files.len() >= MAX_FILES}),
            ))
        }
        Some(p) => {
            let rel = safe_rel(p).ok_or_else(|| bad("invalid path"))?;
            let full = root.join(&rel);
            let meta = std::fs::symlink_metadata(&full).map_err(|_| not_found("no such file"))?;
            if !meta.is_file() {
                return Err(bad("not a file"));
            }
            let canon = std::fs::canonicalize(&full)?;
            if !canon.starts_with(std::fs::canonicalize(&root)?) {
                return Err(bad("invalid path"));
            }
            let data = super::read_capped(&canon, MAX_READ);
            Ok(Json(
                json!({"path": p, "size": meta.len(), "truncated": meta.len() as usize > MAX_READ,
                            "text": String::from_utf8_lossy(&data)}),
            ))
        }
    }
}

/// Electron `app.asar`: the file itself, or the one inside an opened app.
async fn asar(st: &Shared, sha: &str, path: Option<&str>) -> R<Json<Value>> {
    let s = crate::api::session(st, sha).await?;
    let bytes_owner: std::sync::Arc<drishti_loader::Blob> = if s.info.format == Format::Asar {
        s.blob.clone()
    } else {
        let p = crate::extra::bundle_asar(st, sha)
            .ok_or_else(|| not_found("this app has no Electron code archive"))?;
        std::sync::Arc::new(drishti_loader::Blob::open(&p)?)
    };
    let path = path.map(str::to_string);
    let v = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let b = bytes_owner.as_ref().as_ref();
        match path {
            None => {
                let files = drishti_loader::asar_children(b, MAX_FILES);
                Ok(json!({"files": files.iter().map(|c| json!([c.path, c.size])).collect::<Vec<_>>(), "truncated": files.len() >= MAX_FILES}))
            }
            Some(p) => {
                let data = drishti_loader::asar_read(b, &p).ok_or("no such file in the archive (or it is stored outside it)")?;
                let n = data.len();
                Ok(json!({"path": p, "size": n, "truncated": n > MAX_READ,
                          "text": String::from_utf8_lossy(&data[..n.min(MAX_READ)])}))
            }
        }
    })
    .await?
    .map_err(bad)?;
    Ok(Json(v))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rel_paths() {
        assert!(super::safe_rel("sources/com/a/B.java").is_some());
        assert!(super::safe_rel("../etc/passwd").is_none());
        assert!(super::safe_rel("/etc/passwd").is_none());
        assert!(super::safe_rel("a/../../b").is_none());
        assert!(super::safe_rel("").is_none());
    }

    #[test]
    fn permissions() {
        let p = super::manifest_permissions(
            r#"<manifest package="x"><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.CAMERA"/></manifest>"#,
        );
        assert_eq!(p[0]["label"], "Camera");
        assert_eq!(p.len(), 2);
    }
}
