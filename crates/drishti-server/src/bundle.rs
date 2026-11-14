//! Facts about the app a file belongs to (macOS `.app` bundles opened in
//! place): name, version, the permission explanations the developer wrote
//! (`NS…UsageDescription`), bundled frameworks, an Electron `app.asar`, and
//! the code signature ("who made this").
//!
//! Uses the system's read-only tools `plutil` (plist → JSON) and `codesign`
//! (signature details / verification). The app itself is never run.

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Default)]
pub struct Bundle {
    pub root: PathBuf,
    pub name: Option<String>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
    pub min_os: Option<String>,
    pub copyright: Option<String>,
    pub category: Option<String>,
    /// (Info.plist key, the developer's explanation shown to users)
    pub usage: Vec<(String, String)>,
    pub frameworks: Vec<String>,
    pub helpers: Vec<String>,
    pub asar: Option<PathBuf>,
    pub url_schemes: Vec<String>,
    pub background_only: bool,
}

/// The enclosing `X.app` of a path, if any.
pub fn bundle_root(p: &Path) -> Option<PathBuf> {
    p.ancestors()
        .find(|a| {
            a.extension().and_then(|e| e.to_str()) == Some("app") && a.join("Contents").is_dir()
        })
        .map(Path::to_path_buf)
}

fn plist_json(p: &Path) -> Option<Value> {
    if !cfg!(target_os = "macos") || !p.is_file() {
        return None;
    }
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-", "--"])
        .arg(p)
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.len() > 8 << 20 {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

/// Read a property list (XML or binary) as JSON. plutil can't put dates
/// or data in JSON, so those plists are converted to XML and read by a
/// small parser instead (dates become strings, data is dropped).
pub fn read_plist(p: &Path) -> Option<Value> {
    plist_json(p).or_else(|| plist_via_xml(p))
}

fn plist_via_xml(p: &Path) -> Option<Value> {
    if !cfg!(target_os = "macos") || !p.is_file() {
        return None;
    }
    let out = Command::new("/usr/bin/plutil")
        .args(["-convert", "xml1", "-o", "-", "--"])
        .arg(p)
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.len() > 8 << 20 {
        return None;
    }
    parse_xml_plist(&String::from_utf8_lossy(&out.stdout))
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Minimal XML plist reader (the subset plutil emits).
pub fn parse_xml_plist(x: &str) -> Option<Value> {
    let body = x.split_once("<plist")?.1.split_once('>')?.1;
    let mut pos = 0usize;
    fn skip_ws(x: &str, pos: &mut usize) {
        while x[*pos..].starts_with(char::is_whitespace) {
            *pos += x[*pos..].chars().next().map_or(1, char::len_utf8);
        }
    }
    fn tag<'a>(x: &'a str, pos: &mut usize) -> Option<&'a str> {
        skip_ws(x, pos);
        let rest = &x[*pos..];
        if !rest.starts_with('<') {
            return None;
        }
        let end = rest.find('>')?;
        *pos += end + 1;
        Some(&rest[1..end])
    }
    fn text<'a>(x: &'a str, pos: &mut usize, close: &str) -> Option<&'a str> {
        let rest = &x[*pos..];
        let end = rest.find(close)?;
        *pos += end + close.len();
        Some(&rest[..end])
    }
    fn value(x: &str, pos: &mut usize, depth: u32) -> Option<Value> {
        if depth > 32 {
            return None;
        }
        let t = tag(x, pos)?;
        Some(match t {
            "dict" => {
                let mut m = serde_json::Map::new();
                loop {
                    let save = *pos;
                    let t = tag(x, pos)?;
                    if t == "/dict" {
                        break;
                    }
                    if t != "key" {
                        *pos = save;
                        return None;
                    }
                    let k = unescape(text(x, pos, "</key>")?);
                    let v = value(x, pos, depth + 1)?;
                    m.insert(k, v);
                }
                Value::Object(m)
            }
            "dict/" => Value::Object(Default::default()),
            "array" => {
                let mut a = Vec::new();
                loop {
                    let save = *pos;
                    if tag(x, pos)? == "/array" {
                        break;
                    }
                    *pos = save;
                    a.push(value(x, pos, depth + 1)?);
                }
                Value::Array(a)
            }
            "array/" => Value::Array(Vec::new()),
            "string" => Value::String(unescape(text(x, pos, "</string>")?)),
            "string/" => Value::String(String::new()),
            "date" => Value::String(text(x, pos, "</date>")?.to_string()),
            "integer" => text(x, pos, "</integer>")?
                .trim()
                .parse::<i64>()
                .map(Value::from)
                .unwrap_or(Value::Null),
            "real" => text(x, pos, "</real>")?
                .trim()
                .parse::<f64>()
                .ok()
                .and_then(|f| serde_json::Number::from_f64(f).map(Value::Number))
                .unwrap_or(Value::Null),
            "true/" => Value::Bool(true),
            "false/" => Value::Bool(false),
            "data" => {
                text(x, pos, "</data>")?;
                Value::Null
            }
            "data/" => Value::Null,
            _ => return None,
        })
    }
    value(body, &mut pos, 0)
}

type Cache<T> = OnceLock<Mutex<HashMap<PathBuf, (SystemTime, T)>>>;
static BUNDLES: Cache<Option<Bundle>> = OnceLock::new();
static SIGNS: Cache<Option<Codesign>> = OnceLock::new();

fn cached<T: Clone>(c: &'static Cache<T>, key: &Path, f: impl FnOnce() -> T) -> T {
    let mtime = std::fs::metadata(key)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let m = c.get_or_init(Default::default);
    if let Ok(g) = m.lock()
        && let Some((t, v)) = g.get(key)
        && *t == mtime
    {
        return v.clone();
    }
    let v = f();
    if let Ok(mut g) = m.lock() {
        if g.len() > 256 {
            g.clear();
        }
        g.insert(key.to_path_buf(), (mtime, v.clone()));
    }
    v
}

pub fn bundle_info(file: &Path) -> Option<Bundle> {
    let root = bundle_root(file)?;
    cached(&BUNDLES, &root, || read_bundle(&root))
}

fn read_bundle(root: &Path) -> Option<Bundle> {
    let info = read_plist(&root.join("Contents/Info.plist"))?;
    let s = |k: &str| {
        info[k]
            .as_str()
            .map(str::to_string)
            .filter(|v| !v.trim().is_empty())
    };
    let mut usage: Vec<(String, String)> = info
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(k, _)| k.starts_with("NS") && k.ends_with("UsageDescription"))
        .filter_map(|(k, v)| {
            v.as_str()
                .map(|t| (k.clone(), t.chars().take(400).collect()))
        })
        .collect();
    usage.sort();
    let names = |dir: &Path, ext: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                ext.iter().any(|x| n.ends_with(x)).then_some(n)
            })
            .collect();
        v.sort();
        v.truncate(300);
        v
    };
    let frameworks = names(
        &root.join("Contents/Frameworks"),
        &[".framework", ".dylib", ".app"],
    );
    let mut helpers = names(&root.join("Contents/Library/LoginItems"), &[".app"]);
    helpers.extend(names(&root.join("Contents/Library/LaunchServices"), &[""]));
    helpers.extend(names(&root.join("Contents/XPCServices"), &[".xpc"]));
    let asar = [
        "Contents/Resources/app.asar",
        "Contents/Resources/default_app.asar",
    ]
    .iter()
    .map(|p| root.join(p))
    .find(|p| p.is_file());
    let url_schemes = info["CFBundleURLTypes"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|t| {
            t["CFBundleURLSchemes"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|x| x.as_str().map(str::to_string))
        .take(20)
        .collect();
    Some(Bundle {
        root: root.to_path_buf(),
        name: s("CFBundleDisplayName").or_else(|| s("CFBundleName")),
        bundle_id: s("CFBundleIdentifier"),
        version: s("CFBundleShortVersionString").or_else(|| s("CFBundleVersion")),
        min_os: s("LSMinimumSystemVersion"),
        copyright: s("NSHumanReadableCopyright"),
        category: s("LSApplicationCategoryType"),
        usage,
        frameworks,
        helpers,
        asar,
        url_schemes,
        background_only: info["LSUIElement"].as_bool() == Some(true)
            || info["LSBackgroundOnly"].as_bool() == Some(true),
    })
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Codesign {
    /// Certificate chain, leaf first ("Developer ID Application: X (TEAM)").
    pub authority: Vec<String>,
    pub team_id: Option<String>,
    pub identifier: Option<String>,
    pub notarized: bool,
    pub adhoc: bool,
    pub signed: bool,
    pub runtime: bool,
    /// The developer or company name from the leaf certificate.
    pub developer: Option<String>,
    /// "apple" | "app_store" | "developer_id" | "development" | "adhoc" | "unsigned" | "other"
    pub kind: String,
    /// Full verification (seal intact); `None` until checked.
    pub valid: Option<bool>,
    pub verify_error: Option<String>,
}

fn run_codesign(args: &[&str], p: &Path, timeout: Duration) -> Option<(bool, String)> {
    let mut child = Command::new("/usr/bin/codesign")
        .args(args)
        .arg(p)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let t0 = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    use std::io::Read;
                    let _ = e.by_ref().take(64 << 10).read_to_string(&mut err);
                }
                return Some((st.success(), err));
            }
            Ok(None) if t0.elapsed() < timeout => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// Signature details of a bundle or file (fast: reads, doesn't verify).
pub fn codesign_info(p: &Path) -> Option<Codesign> {
    if !cfg!(target_os = "macos") || !Path::new("/usr/bin/codesign").is_file() {
        return None;
    }
    let target = bundle_root(p).unwrap_or_else(|| p.to_path_buf());
    cached(&SIGNS, &target, || {
        let (ok, txt) = run_codesign(&["-dvv"], &target, Duration::from_secs(10))?;
        let mut c = Codesign::default();
        if !ok {
            c.kind = "unsigned".into();
            return Some(c);
        }
        c.signed = true;
        for l in txt.lines() {
            if let Some(a) = l.strip_prefix("Authority=") {
                c.authority.push(a.trim().to_string());
            } else if let Some(t) = l.strip_prefix("TeamIdentifier=") {
                c.team_id = Some(t.trim().to_string()).filter(|t| t != "not set");
            } else if let Some(i) = l.strip_prefix("Identifier=") {
                c.identifier = Some(i.trim().to_string());
            } else if l.starts_with("Notarization Ticket=") {
                c.notarized = true;
            } else if l.starts_with("Signature=adhoc") {
                c.adhoc = true;
            } else if l.contains("flags=") && l.contains("runtime") {
                c.runtime = true;
            }
        }
        let leaf = c.authority.first().cloned().unwrap_or_default();
        c.kind = if c.adhoc {
            "adhoc"
        } else if leaf == "Software Signing"
            || leaf == "macOS Software Signing"
            || leaf.starts_with("Apple Code Signing")
        {
            "apple"
        } else if leaf.starts_with("Apple Mac OS Application Signing")
            || leaf.starts_with("Apple iPhone OS Application Signing")
        {
            "app_store"
        } else if leaf.starts_with("Developer ID Application:") {
            "developer_id"
        } else if leaf.starts_with("Apple Development:") || leaf.starts_with("Mac Developer:") {
            "development"
        } else {
            "other"
        }
        .into();
        c.developer = match c.kind.as_str() {
            "apple" => Some("Apple".into()),
            "app_store" => None,
            _ => leaf.split_once(": ").map(|(_, n)| {
                n.rsplit_once(" (")
                    .map(|(a, _)| a)
                    .unwrap_or(n)
                    .trim()
                    .to_string()
            }),
        };
        Some(c)
    })
}

/// Full check that the signature is intact (hashes every sealed file:
/// a few seconds for large apps). Not cached across file changes.
pub fn codesign_verify(p: &Path) -> (Option<bool>, Option<String>) {
    let target = bundle_root(p).unwrap_or_else(|| p.to_path_buf());
    match run_codesign(&["--verify", "--strict"], &target, Duration::from_secs(60)) {
        Some((true, _)) => (Some(true), None),
        Some((false, e)) => (
            Some(false),
            e.lines().find(|l| !l.trim().is_empty()).map(|l| {
                l.trim_start_matches(&*target.to_string_lossy())
                    .trim_start_matches(':')
                    .trim()
                    .chars()
                    .take(200)
                    .collect()
            }),
        ),
        None => (None, Some("verification took too long".into())),
    }
}

/// Plain meaning of an Info.plist usage key.
pub fn usage_label(key: &str) -> Option<(&'static str, &'static str)> {
    Some(match key {
        "NSCameraUsageDescription" => ("camera", "Camera"),
        "NSMicrophoneUsageDescription" => ("microphone", "Microphone"),
        "NSLocationUsageDescription"
        | "NSLocationWhenInUseUsageDescription"
        | "NSLocationAlwaysUsageDescription"
        | "NSLocationAlwaysAndWhenInUseUsageDescription" => ("location", "Location"),
        "NSContactsUsageDescription" => ("contacts", "Contacts"),
        "NSCalendarsUsageDescription" | "NSCalendarsFullAccessUsageDescription" => {
            ("calendar", "Calendar")
        }
        "NSRemindersUsageDescription" | "NSRemindersFullAccessUsageDescription" => {
            ("reminders", "Reminders")
        }
        "NSPhotoLibraryUsageDescription" | "NSPhotoLibraryAddUsageDescription" => {
            ("photos", "Photos")
        }
        "NSAppleEventsUsageDescription" => ("automation", "Control other apps"),
        "NSBluetoothAlwaysUsageDescription" | "NSBluetoothPeripheralUsageDescription" => {
            ("bluetooth", "Bluetooth")
        }
        "NSSpeechRecognitionUsageDescription" => ("speech", "Speech recognition"),
        "NSDesktopFolderUsageDescription" => ("files", "Desktop folder"),
        "NSDocumentsFolderUsageDescription" => ("files", "Documents folder"),
        "NSDownloadsFolderUsageDescription" => ("files", "Downloads folder"),
        "NSRemovableVolumesUsageDescription" | "NSNetworkVolumesUsageDescription" => {
            ("files", "External and network drives")
        }
        "NSLocalNetworkUsageDescription" => ("local_network", "Devices on your local network"),
        "NSFaceIDUsageDescription" => ("biometrics", "Face ID / Touch ID"),
        "NSSystemAdministrationUsageDescription" => ("admin", "Administrator actions"),
        "NSHomeKitUsageDescription" => ("home", "Smart-home devices"),
        "NSHealthShareUsageDescription" | "NSHealthUpdateUsageDescription" => {
            ("health", "Health data")
        }
        "NSMotionUsageDescription" => ("motion", "Motion and fitness"),
        "NSUserTrackingUsageDescription" => {
            ("tracking", "Track you across other apps and websites")
        }
        "NSAudioCaptureUsageDescription" => ("screen", "Record system audio"),
        "NSFocusStatusUsageDescription" => ("focus", "Focus status"),
        "NSScreenCaptureUsageDescription" => ("screen", "Screen recording"),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn roots() {
        let p = std::path::Path::new("/Applications/Foo.app/Contents/MacOS/Foo");
        // Only returns a root when it exists on disk.
        let r = super::bundle_root(p);
        assert!(r.is_none() || r.unwrap().ends_with("Foo.app"));
        assert_eq!(
            super::usage_label("NSCameraUsageDescription").unwrap().0,
            "camera"
        );
        let v = super::parse_xml_plist(r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>a &amp; b</string><key>When</key><date>2020-01-01T00:00:00Z</date><key>Args</key><array><string>/bin/x</string><string>-y</string></array><key>On</key><true/><key>Blob</key><data>AAEC</data><key>N</key><integer>5</integer><key>E</key><dict/></dict></plist>"#).unwrap();
        assert_eq!(v["Label"], "a & b");
        assert_eq!(v["Args"][1], "-y");
        assert_eq!(v["On"], true);
        assert_eq!(v["N"], 5);
    }
}
