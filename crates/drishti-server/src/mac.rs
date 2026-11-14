//! Whole-Mac checks (local mode only): what starts automatically, and a
//! quick health check of every installed app. Both only read files and
//! signatures; nothing is run or changed.

use crate::api::{ApiError, R};
use crate::bundle::{bundle_info, codesign_info, read_plist};
use crate::state::Shared;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

fn local_only(st: &Shared) -> R<()> {
    if st.local_mode && cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::FORBIDDEN,
            "available only when Drishti runs on your own Mac".into(),
        ))
    }
}

fn signer(path: &Path) -> Value {
    match codesign_info(path) {
        Some(c) => {
            json!({"kind": c.kind, "developer": c.developer, "team": c.team_id, "notarized": c.notarized})
        }
        None => json!({"kind": "unknown"}),
    }
}

fn verdict_for(kind: &str, notarized: bool, exists: bool) -> (&'static str, &'static str) {
    if !exists {
        return (
            "caution",
            "Leftover: the program it starts no longer exists.",
        );
    }
    match kind {
        "apple" => ("good", "Part of macOS or an Apple app."),
        "app_store" => ("good", "From the Mac App Store."),
        "developer_id" if notarized => ("good", "From an identified developer, checked by Apple."),
        "developer_id" => ("good", "From an identified developer."),
        "development" => ("caution", "A developer test build."),
        "adhoc" => (
            "caution",
            "Signed without an identity: nobody vouches for who made it.",
        ),
        "unsigned" => ("caution", "Not signed: nobody vouches for who made it."),
        _ => ("unknown", "Couldn't read its signature."),
    }
}

/// `GET /local/startup` — launch agents/daemons: programs that start with
/// your Mac or when you log in.
pub async fn startup(State(st): State<Shared>) -> R<Json<Value>> {
    local_only(&st)?;
    let items = tokio::task::spawn_blocking(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let dirs = [
            (home.join("Library/LaunchAgents"), "When you log in (just for you)"),
            (PathBuf::from("/Library/LaunchAgents"), "When anyone logs in"),
            (PathBuf::from("/Library/LaunchDaemons"), "When the Mac starts (runs as administrator)"),
        ];
        let mut out = Vec::new();
        for (d, when) in dirs {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten().take(400) {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("plist") {
                    continue;
                }
                let v = read_plist(&p).unwrap_or(Value::Null);
                let program = v["Program"].as_str().map(str::to_string).or_else(|| {
                    v["ProgramArguments"].as_array().and_then(|a| a.first()).and_then(|x| x.as_str()).map(str::to_string)
                });
                let args: Vec<String> = v["ProgramArguments"].as_array().into_iter().flatten().skip(1).take(8)
                    .filter_map(|x| x.as_str().map(str::to_string)).collect();
                let prog_path = program.as_deref().map(PathBuf::from);
                let exists = prog_path.as_ref().is_some_and(|p| p.exists());
                let sig = prog_path.as_deref().filter(|_| exists).map(signer).unwrap_or(json!({"kind": "unknown"}));
                let (level, note) = verdict_for(sig["kind"].as_str().unwrap_or(""), sig["notarized"].as_bool().unwrap_or(false), exists || program.is_none());
                let app = prog_path.as_deref().and_then(bundle_info).and_then(|b| b.name);
                let homebrew = program.as_deref().is_some_and(|p| p.starts_with("/opt/homebrew/") || p.starts_with("/usr/local/Cellar/") || p.starts_with("/usr/local/opt/"));
                let (level, note) = if program.is_none() {
                    ("info", "Empty: it doesn't start anything (probably left over from an app you removed).")
                } else if homebrew && exists {
                    ("good", "Installed with Homebrew (a package manager for developers). Homebrew programs normally have no developer signature.")
                } else {
                    (level, note)
                };
                let interp = program.as_deref().is_some_and(|p| {
                    ["/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python3", "/usr/bin/osascript", "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/curl"].contains(&p)
                });
                out.push(json!({
                    "file": p, "label": v["Label"], "when": when, "program": program, "args": args, "app": app,
                    "run_at_load": v["RunAtLoad"].as_bool().unwrap_or(false),
                    "keep_alive": !v["KeepAlive"].is_null() && v["KeepAlive"] != json!(false),
                    "disabled": v["Disabled"].as_bool().unwrap_or(false),
                    "signer": sig,
                    "level": if interp { "caution" } else { level },
                    "note": if interp { "Runs a script through a system tool. Check that you recognise it." } else { note },
                }));
            }
        }
        out.sort_by_key(|i| match i["level"].as_str() { Some("caution") => 0, Some("unknown") => 1, _ => 2 });
        out
    })
    .await?;
    Ok(Json(json!({"items": items})))
}

static SCAN: OnceLock<Mutex<Option<(Instant, Value)>>> = OnceLock::new();

/// `GET /local/scan-apps` — one line per installed app: who made it,
/// whether Apple checked it, what it may access, built-in trackers.
pub async fn scan_apps(State(st): State<Shared>) -> R<Json<Value>> {
    local_only(&st)?;
    let cache = SCAN.get_or_init(Default::default);
    if let Ok(c) = cache.lock()
        && let Some((t, v)) = c.as_ref()
        && t.elapsed() < Duration::from_secs(600)
    {
        return Ok(Json(v.clone()));
    }
    let v = tokio::task::spawn_blocking(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let mut apps: Vec<PathBuf> = Vec::new();
        for d in [PathBuf::from("/Applications"), home.join("Applications"), PathBuf::from("/Applications/Utilities")] {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("app") {
                    apps.push(p);
                }
            }
        }
        apps.sort();
        apps.dedup();
        apps.truncate(400);
        let mut out = Vec::new();
        for app in apps {
            let Some(b) = bundle_info(&app.join("Contents/Info.plist")) else { continue };
            let sig = signer(&app);
            let kind = sig["kind"].as_str().unwrap_or("unknown").to_string();
            let (level, note) = verdict_for(&kind, sig["notarized"].as_bool().unwrap_or(false), true);
            let access: Vec<&str> = b.usage.iter().filter_map(|(k, _)| crate::bundle::usage_label(k).map(|l| l.1)).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
            let fw = b.frameworks.iter().map(|f| f.to_lowercase()).collect::<Vec<_>>();
            let kits: Vec<&str> = [
                ("sentry", "Sentry"), ("firebase", "Firebase"), ("googleanalytics", "Google Analytics"), ("fbsdk", "Facebook SDK"),
                ("amplitude", "Amplitude"), ("mixpanel", "Mixpanel"), ("segment", "Segment"), ("appcenter", "App Center"),
                ("sparkle", "Sparkle updates"), ("electron framework", "Electron"), ("crashlytics", "Crashlytics"), ("bugsnag", "Bugsnag"),
                ("datadog", "Datadog"), ("posthog", "PostHog"), ("appsflyer", "AppsFlyer"), ("adjust", "Adjust"),
            ]
            .iter()
            .filter(|(n, _)| fw.iter().any(|f| f.contains(n)))
            .map(|(_, l)| *l)
            .collect();
            let exe = std::fs::read_dir(app.join("Contents/MacOS")).ok().and_then(|mut r| r.next()).and_then(|e| e.ok()).map(|e| e.path());
            out.push(json!({
                "name": b.name.clone().unwrap_or_else(|| app.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()),
                "path": app, "exe": exe, "id": b.bundle_id, "version": b.version,
                "signer": sig, "level": level, "note": note,
                "access": access, "kits": kits, "electron": b.asar.is_some(), "login_items": b.helpers.iter().filter(|h| h.ends_with(".app")).count(),
            }));
        }
        out.sort_by(|a, b| {
            let r = |x: &Value| match x["level"].as_str() { Some("caution") => 0, Some("unknown") => 1, _ => 2 };
            r(a).cmp(&r(b)).then(a["name"].as_str().unwrap_or("").to_lowercase().cmp(&b["name"].as_str().unwrap_or("").to_lowercase()))
        });
        json!({"apps": out, "scanned_at": crate::util::now()})
    })
    .await?;
    if let Ok(mut c) = cache.lock() {
        *c = Some((Instant::now(), v.clone()));
    }
    Ok(Json(v))
}
