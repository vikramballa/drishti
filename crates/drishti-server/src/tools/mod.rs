//! External tools (spec §3.5 / §7.7, roadmap C): optional programs such as
//! Ghidra, capa, YARA or ExifTool that Drishti finds on this computer and
//! runs on demand, each in a sandbox.
//!
//! Rules for every tool run (spec §8):
//! - The input file is only ever *read* by the tool; Drishti never executes
//!   the input. Tools are static analysers.
//! - macOS: the tool runs under `sandbox-exec` with **no network** and
//!   **write access only to its own work folder** (plus the system temp
//!   folder). `HOME` points into the work area so tools can't touch the
//!   user's files. Elsewhere, tools only run when the user turned on
//!   `tools.allow_unsandboxed` (a visible setting).
//! - Every run has a time limit and the whole process group is killed when
//!   it's exceeded; output is capped.
//! - Heavy tools (JVM / Python analysers, antivirus) run one at a time.
//! - Results are cached on disk by (file sha-256, tool, tool version).

pub mod decompile;
pub mod runners;
pub mod source;

use crate::api::{ApiError, R, bad, not_found, valid_sha};
use crate::state::Shared;
use drishti_model::Format;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Turns machine code into readable C-like code.
    Decompiler,
    /// Safety checks (malware patterns, antivirus, capabilities).
    Safety,
    /// Hidden details (metadata) and things embedded in files.
    Details,
    /// Opens other kinds of apps (Android, Java, .NET, WebAssembly, Apple).
    Apps,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Decompiler => "decompiler",
            Kind::Safety => "safety",
            Kind::Details => "details",
            Kind::Apps => "apps",
        }
    }
}

pub struct ToolDef {
    pub id: &'static str,
    pub name: &'static str,
    /// One plain-language sentence for non-experts.
    pub what: &'static str,
    pub kind: Kind,
    /// Executable names, first found wins.
    pub bins: &'static [&'static str],
    pub install: &'static str,
    pub homepage: &'static str,
    pub license: &'static str,
    pub heavy: bool,
    pub timeout_s: u64,
    /// Which files the tool understands.
    pub supports: fn(Format) -> bool,
    /// Runs automatically for matching files (light, fast tools only).
    pub auto: bool,
    /// Rules / databases the tool needs before it can work.
    pub setup: Option<&'static str>,
}

fn native(f: Format) -> bool {
    f.is_native()
}
fn pe_elf(f: Format) -> bool {
    matches!(f, Format::Pe | Format::PeDotnet | Format::Elf)
}
fn pe_only(f: Format) -> bool {
    matches!(f, Format::Pe)
}
fn any(_: Format) -> bool {
    true
}
fn office(f: Format) -> bool {
    matches!(f, Format::Ole | Format::Ooxml)
}
fn embedded(f: Format) -> bool {
    !f.is_native() && !matches!(f, Format::Pdf | Format::Asar)
}
fn java(f: Format) -> bool {
    matches!(
        f,
        Format::Apk | Format::Dex | Format::Jar | Format::JavaClass
    )
}
fn dotnet(f: Format) -> bool {
    matches!(f, Format::PeDotnet)
}
fn wasm(f: Format) -> bool {
    matches!(f, Format::Wasm)
}
fn macho(f: Format) -> bool {
    matches!(f, Format::Macho | Format::MachoFat)
}

pub static TOOLS: &[ToolDef] = &[
    ToolDef {
        id: "ghidra",
        name: "Ghidra",
        what: "Turns machine code into readable C-like code, one function at a time (free, made by the NSA).",
        kind: Kind::Decompiler,
        bins: &["analyzeHeadless"],
        install: "brew install ghidra",
        homepage: "https://ghidra-sre.org",
        license: "Apache-2.0",
        heavy: true,
        timeout_s: 900,
        supports: native,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "radare2",
        name: "radare2",
        what: "A small, fast decompiler. Add the r2ghidra plugin for Ghidra-quality output.",
        kind: Kind::Decompiler,
        bins: &["r2", "radare2"],
        install: "brew install radare2 && r2pm -ci r2ghidra",
        homepage: "https://rada.re",
        license: "LGPL-3.0",
        heavy: false,
        timeout_s: 180,
        supports: native,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "capa",
        name: "capa",
        what: "Lists what a Windows or Linux program can do, in plain words (from Mandiant).",
        kind: Kind::Safety,
        bins: &["capa"],
        install: "uv tool install flare-capa",
        homepage: "https://github.com/mandiant/capa",
        license: "Apache-2.0",
        heavy: true,
        timeout_s: 900,
        supports: pe_elf,
        auto: false,
        setup: Some("capa-rules"),
    },
    ToolDef {
        id: "floss",
        name: "FLOSS",
        what: "Finds text that a Windows program hides or scrambles (often used by malware).",
        kind: Kind::Safety,
        bins: &["floss"],
        install: "uv tool install flare-floss",
        homepage: "https://github.com/mandiant/flare-floss",
        license: "Apache-2.0",
        heavy: true,
        timeout_s: 900,
        supports: pe_only,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "yara",
        name: "YARA",
        what: "Checks the file against thousands of patterns of known malware.",
        kind: Kind::Safety,
        bins: &["yara"],
        install: "brew install yara",
        homepage: "https://virustotal.github.io/yara/",
        license: "BSD-3-Clause",
        heavy: false,
        timeout_s: 300,
        supports: any,
        auto: true,
        setup: Some("yara-rules"),
    },
    ToolDef {
        id: "clamav",
        name: "ClamAV",
        what: "Free antivirus scan that works offline (uses about 1 GB of memory while scanning).",
        kind: Kind::Safety,
        bins: &["clamscan"],
        install: "brew install clamav",
        homepage: "https://www.clamav.net",
        license: "GPL-2.0",
        heavy: true,
        timeout_s: 600,
        supports: any,
        auto: false,
        setup: Some("clamav-db"),
    },
    ToolDef {
        id: "exiftool",
        name: "ExifTool",
        what: "Reads hidden details: which camera or phone took a photo, where (GPS), who wrote a document, which company made a program.",
        kind: Kind::Details,
        bins: &["exiftool"],
        install: "brew install exiftool",
        homepage: "https://exiftool.org",
        license: "Artistic/GPL",
        heavy: false,
        timeout_s: 60,
        supports: any,
        auto: true,
        setup: None,
    },
    ToolDef {
        id: "oletools",
        name: "oletools",
        what: "Finds macros (small hidden programs) in Word, Excel and PowerPoint files.",
        kind: Kind::Safety,
        bins: &["olevba"],
        install: "uv tool install oletools",
        homepage: "https://github.com/decalage2/oletools",
        license: "BSD-2-Clause",
        heavy: false,
        timeout_s: 120,
        supports: office,
        auto: true,
        setup: None,
    },
    ToolDef {
        id: "binwalk",
        name: "binwalk",
        what: "Finds files hidden inside other files, such as firmware for routers and cameras.",
        kind: Kind::Details,
        bins: &["binwalk"],
        install: "brew install binwalk",
        homepage: "https://github.com/ReFirmLabs/binwalk",
        license: "MIT",
        heavy: false,
        timeout_s: 300,
        supports: embedded,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "jadx",
        name: "JADX",
        what: "Turns Android apps and Java programs back into readable Java code.",
        kind: Kind::Apps,
        bins: &["jadx"],
        install: "brew install jadx",
        homepage: "https://github.com/skylot/jadx",
        license: "Apache-2.0",
        heavy: true,
        timeout_s: 1200,
        supports: java,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "ilspy",
        name: "ILSpy",
        what: "Turns Windows .NET programs back into readable C# code.",
        kind: Kind::Apps,
        bins: &["ilspycmd"],
        install: "brew install dotnet && dotnet tool install -g ilspycmd",
        homepage: "https://github.com/icsharpcode/ILSpy",
        license: "MIT",
        heavy: true,
        timeout_s: 900,
        supports: dotnet,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "wabt",
        name: "WABT",
        what: "Shows WebAssembly (code that runs in web browsers) as readable text.",
        kind: Kind::Apps,
        bins: &["wasm2wat"],
        install: "brew install wabt",
        homepage: "https://github.com/WebAssembly/wabt",
        license: "Apache-2.0",
        heavy: false,
        timeout_s: 120,
        supports: wasm,
        auto: false,
        setup: None,
    },
    ToolDef {
        id: "ipsw",
        name: "ipsw class-dump",
        what: "Lists the building blocks (classes) of Mac and iPhone apps: often names features directly.",
        kind: Kind::Apps,
        bins: &["ipsw"],
        install: "brew install blacktop/tap/ipsw",
        homepage: "https://github.com/blacktop/ipsw",
        license: "MIT",
        heavy: false,
        timeout_s: 300,
        supports: macho,
        auto: false,
        setup: None,
    },
];

pub fn def(id: &str) -> Option<&'static ToolDef> {
    TOOLS.iter().find(|t| t.id == id)
}

// ---------------------------------------------------------------- locating

/// Folders searched in addition to `PATH` (apps started from the Dock or
/// launchd get a minimal PATH).
fn extra_dirs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if let Some(h) = std::env::var_os("HOME").map(PathBuf::from) {
        v.push(h.join(".local/bin"));
        v.push(h.join(".cargo/bin"));
        v.push(h.join(".dotnet/tools"));
        v.push(h.join(".local/share/radare2/prefix/bin"));
    }
    if let Some(g) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        v.push(PathBuf::from(g).join("support"));
    }
    for g in [
        "/opt/homebrew/opt/ghidra/libexec/support",
        "/usr/local/opt/ghidra/libexec/support",
    ] {
        v.push(PathBuf::from(g));
    }
    v
}

/// Find an executable on PATH or in the usual install folders.
pub fn which(bin: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend(extra_dirs());
    dirs.into_iter().map(|d| d.join(bin)).find(|p| p.is_file())
}

pub fn locate(t: &ToolDef) -> Option<PathBuf> {
    t.bins.iter().find_map(|b| which(b))
}

/// JDK for Ghidra/JADX: JAVA_HOME, then Homebrew's openjdk (Ghidra 12 needs 25+).
pub fn java_home() -> Option<PathBuf> {
    let ok = |p: PathBuf| p.join("bin/java").is_file().then_some(p);
    for k in ["DRISHTI_JAVA_HOME"] {
        if let Some(p) = std::env::var_os(k).map(PathBuf::from).and_then(ok) {
            return Some(p);
        }
    }
    for p in [
        "/opt/homebrew/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home",
        "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
        "/usr/local/opt/openjdk@25/libexec/openjdk.jdk/Contents/Home",
        "/usr/local/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
    ] {
        if let Some(p) = ok(PathBuf::from(p)) {
            return Some(p);
        }
    }
    std::env::var_os("JAVA_HOME")
        .map(PathBuf::from)
        .and_then(ok)
}

/// .NET runtime for ILSpy: `ilspycmd` is an app host that only looks in
/// `/usr/local/share/dotnet` unless `DOTNET_ROOT` says otherwise, and
/// Homebrew installs it elsewhere.
pub fn dotnet_root() -> Option<PathBuf> {
    let ok = |p: PathBuf| p.join("dotnet").is_file().then_some(p);
    if let Some(p) = std::env::var_os("DOTNET_ROOT")
        .map(PathBuf::from)
        .and_then(ok)
    {
        return Some(p);
    }
    [
        "/opt/homebrew/opt/dotnet/libexec",
        "/usr/local/opt/dotnet/libexec",
        "/usr/local/share/dotnet",
    ]
    .iter()
    .find_map(|p| ok(PathBuf::from(p)))
}

/// Runtime locations a tool needs in its environment (Java, .NET).
fn runtime_env(c: &mut tokio::process::Command) {
    if let Some(j) = java_home() {
        c.env("JAVA_HOME", j);
    }
    if let Some(d) = dotnet_root() {
        c.env("DOTNET_ROOT", d)
            .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            .env("DOTNET_NOLOGO", "1");
    }
}

type VersionCache = Mutex<HashMap<PathBuf, (std::time::SystemTime, Option<String>)>>;
static VERSIONS: OnceLock<VersionCache> = OnceLock::new();

fn first_version(text: &str) -> Option<String> {
    for tok in text.split(|c: char| c.is_whitespace() || matches!(c, ',' | '(' | ')' | '/')) {
        let t = tok.trim_start_matches('v');
        if t.contains('.')
            && t.chars().next().is_some_and(|c| c.is_ascii_digit())
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
        {
            return Some(t.chars().take(24).collect());
        }
    }
    None
}

/// Tool version (cached per executable modification time).
pub async fn version(t: &ToolDef, bin: &Path) -> Option<String> {
    let mtime = std::fs::metadata(bin).and_then(|m| m.modified()).ok()?;
    let cache = VERSIONS.get_or_init(Default::default);
    if let Ok(c) = cache.lock()
        && let Some((m, v)) = c.get(bin)
        && *m == mtime
    {
        return v.clone();
    }
    let v = match t.id {
        "ghidra" => bin
            .parent()
            .and_then(|s| s.parent())
            .and_then(|root| {
                std::fs::read_to_string(root.join("Ghidra/application.properties")).ok()
            })
            .and_then(|p| {
                p.lines().find_map(|l| {
                    l.strip_prefix("application.version=")
                        .map(|v| v.trim().to_string())
                })
            }),
        _ => {
            let arg = match t.id {
                "exiftool" => "-ver",
                "ipsw" => "version",
                "radare2" => "-v",
                // olevba prints its banner (with the version) when run bare.
                "oletools" => "",
                _ => "--version",
            };
            let mut c = tokio::process::Command::new(bin);
            if !arg.is_empty() {
                c.arg(arg);
            }
            c.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            runtime_env(&mut c);
            match tokio::time::timeout(Duration::from_secs(8), c.output()).await {
                Ok(Ok(o)) => {
                    let txt = format!(
                        "{}\n{}",
                        String::from_utf8_lossy(&o.stdout),
                        String::from_utf8_lossy(&o.stderr)
                    );
                    let txt = match t.id {
                        // "olevba 0.60.2 on Python …"
                        "oletools" => txt
                            .lines()
                            .find(|l| l.contains("olevba "))
                            .unwrap_or("")
                            .to_string(),
                        _ => txt,
                    };
                    first_version(&txt)
                }
                _ => None,
            }
        }
    };
    if let Ok(mut c) = cache.lock() {
        c.insert(bin.to_path_buf(), (mtime, v.clone()));
    }
    v
}

// ---------------------------------------------------------------- folders

pub fn tools_dir(st: &Shared) -> PathBuf {
    st.data_dir.join("tools")
}
pub fn rules_dir(st: &Shared) -> PathBuf {
    tools_dir(st).join("rules")
}
fn results_dir(st: &Shared) -> PathBuf {
    tools_dir(st).join("results")
}
/// Per-file work folder for a tool (kept for tools with browsable output).
pub fn work_dir(st: &Shared, tool: &str, sha: &str) -> PathBuf {
    tools_dir(st).join("work").join(tool).join(sha)
}
fn sandbox_home(st: &Shared) -> PathBuf {
    tools_dir(st).join("home")
}

// ---------------------------------------------------------------- sandbox

pub fn sandbox_available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file()
}

fn unsandboxed_allowed(st: &Shared) -> bool {
    crate::ai::setting_str(st, "tools.allow_unsandboxed").as_deref() == Some("true")
}

fn sb_quote(p: &Path) -> String {
    let s = p.to_string_lossy();
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Seatbelt profile: everything a normal process may do, except the
/// network, and writing outside `writable` + temp.
fn profile(writable: &[&Path]) -> String {
    let mut p = String::from(
        "(version 1)\n(allow default)\n(deny network*)\n(deny file-write*)\n(allow file-write*",
    );
    for w in writable {
        // Resolve /var → /private/var etc. so the rule matches real paths.
        let real = std::fs::canonicalize(w).unwrap_or_else(|_| w.to_path_buf());
        p += &format!(" (subpath {})", sb_quote(&real));
    }
    p += " (subpath \"/private/var/folders\") (subpath \"/private/tmp\") (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/stdout\") (literal \"/dev/stderr\") (regex #\"^/dev/tty\") (regex #\"^/dev/fd/\"))\n";
    p
}

pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub timed_out: bool,
    pub duration_ms: u64,
}

pub struct RunSpec<'a> {
    pub tool: &'a ToolDef,
    pub bin: PathBuf,
    pub args: Vec<OsString>,
    /// Working directory; the only place (besides temp) the tool may write.
    pub work: PathBuf,
    pub extra_writable: Vec<PathBuf>,
    pub env: Vec<(String, OsString)>,
    pub timeout: Duration,
    pub stdout_cap: usize,
}

/// Run a tool in the sandbox. stdout/stderr go to files in `work`, so a
/// chatty tool can't exhaust memory; the caller gets at most `stdout_cap`.
pub async fn run(st: &Shared, spec: RunSpec<'_>) -> Result<Output, String> {
    std::fs::create_dir_all(&spec.work).map_err(|e| e.to_string())?;
    let home = sandbox_home(st);
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let out_p = spec.work.join(".stdout");
    let err_p = spec.work.join(".stderr");
    let out_f = std::fs::File::create(&out_p).map_err(|e| e.to_string())?;
    let err_f = std::fs::File::create(&err_p).map_err(|e| e.to_string())?;
    let mut cmd = if sandbox_available() {
        let mut w: Vec<&Path> = vec![&spec.work, &home];
        w.extend(spec.extra_writable.iter().map(|p| p.as_path()));
        let mut c = tokio::process::Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(profile(&w)).arg(&spec.bin);
        c
    } else if unsandboxed_allowed(st) {
        tokio::process::Command::new(&spec.bin)
    } else {
        return Err("tools only run inside a sandbox, which isn't available on this system. You can allow running without one in Settings → Tools.".into());
    };
    cmd.args(&spec.args)
        .current_dir(&spec.work)
        .env("HOME", &home)
        .env("TMPDIR", &spec.work)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("_JAVA_OPTIONS", format!("-Duser.home={}", home.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::from(out_f))
        .stderr(Stdio::from(err_f))
        .kill_on_drop(true);
    runtime_env(&mut cmd);
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    #[cfg(unix)]
    cmd.process_group(0);
    let t0 = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", spec.tool.name))?;
    let pid = child.id();
    let (code, timed_out) = match tokio::time::timeout(spec.timeout, child.wait()).await {
        Ok(Ok(s)) => (s.code(), false),
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => {
            kill_group(pid).await;
            let _ = child.kill().await;
            (None, true)
        }
    };
    // Helpers a tool started (e.g. the JVM under a shell script) die too.
    kill_group(pid).await;
    let stdout = read_capped(&out_p, spec.stdout_cap);
    let stderr = String::from_utf8_lossy(&read_capped(&err_p, 16 << 10)).into_owned();
    let _ = std::fs::remove_file(&out_p);
    let _ = std::fs::remove_file(&err_p);
    Ok(Output {
        code,
        stdout,
        stderr,
        timed_out,
        duration_ms: t0.elapsed().as_millis() as u64,
    })
}

async fn kill_group(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(p) = pid {
        let _ = tokio::process::Command::new("/bin/kill")
            .arg("-9")
            .arg(format!("-{p}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }
    #[cfg(not(unix))]
    let _ = pid;
}

pub fn read_capped(p: &Path, cap: usize) -> Vec<u8> {
    use std::io::Read;
    let mut v = Vec::new();
    if let Ok(f) = std::fs::File::open(p) {
        let _ = f.take(cap as u64).read_to_end(&mut v);
    }
    v
}

/// A path for the tool to read: tools often decide by file extension, so
/// link the input under a name with the right one inside the work folder.
pub fn input_link(work: &Path, src: &Path, format: Format) -> PathBuf {
    let ext = match format {
        Format::Apk => "apk",
        Format::Dex => "dex",
        Format::Jar => "jar",
        Format::JavaClass => "class",
        Format::Wasm => "wasm",
        Format::Pe | Format::PeDotnet => "exe",
        Format::Pdf => "pdf",
        Format::Ole => "doc",
        Format::Ooxml => match src.extension().and_then(|e| e.to_str()) {
            Some(e) => return link(work, src, e),
            None => "docx",
        },
        _ => match src.extension().and_then(|e| e.to_str()) {
            Some(e) if e.len() <= 8 => return link(work, src, e),
            _ => "bin",
        },
    };
    link(work, src, ext)
}

fn link(work: &Path, src: &Path, ext: &str) -> PathBuf {
    let ext: String = ext.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let dst = work.join(format!("input.{}", ext.to_lowercase()));
    let _ = std::fs::remove_file(&dst);
    #[cfg(unix)]
    if std::os::unix::fs::symlink(src, &dst).is_ok() {
        return dst;
    }
    src.to_path_buf()
}

// ---------------------------------------------------------------- tasks + cache

#[derive(Clone)]
pub struct Task {
    pub status: &'static str,
    pub started: Instant,
    pub error: Option<String>,
}

static TASKS: OnceLock<Mutex<HashMap<String, Task>>> = OnceLock::new();
static HEAVY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
static LIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

pub(crate) fn tasks() -> &'static Mutex<HashMap<String, Task>> {
    TASKS.get_or_init(Default::default)
}

pub fn task(key: &str) -> Option<Task> {
    tasks().lock().ok()?.get(key).cloned()
}

/// Start `fut` once per `key` in the background (heavy tools queue one at
/// a time). Returns false when it was already running.
pub fn spawn_task<F>(st: &Shared, key: String, heavy: bool, fut: F) -> bool
where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    {
        let Ok(mut m) = tasks().lock() else {
            return false;
        };
        if m.get(&key)
            .is_some_and(|t| t.status == "running" || t.status == "queued")
        {
            return false;
        }
        m.insert(
            key.clone(),
            Task {
                status: "queued",
                started: Instant::now(),
                error: None,
            },
        );
    }
    let st = st.clone();
    tokio::spawn(async move {
        let sem = if heavy { &HEAVY } else { &LIGHT };
        let _permit = sem.acquire().await;
        if let Ok(mut m) = tasks().lock()
            && let Some(t) = m.get_mut(&key)
        {
            t.status = "running";
            t.started = Instant::now();
        }
        emit(&st, &key, "running", None);
        let r = fut.await;
        let (status, err) = match r {
            Ok(()) => ("done", None),
            Err(e) => ("failed", Some(e)),
        };
        if let Ok(mut m) = tasks().lock() {
            m.insert(
                key.clone(),
                Task {
                    status,
                    started: Instant::now(),
                    error: err.clone(),
                },
            );
        }
        emit(&st, &key, status, err);
    });
    true
}

fn emit(st: &Shared, key: &str, status: &str, err: Option<String>) {
    st.emit(crate::state::Event {
        kind: "tool",
        job_id: Some(key.to_string()),
        sha256: key.split(':').nth(1).map(str::to_string),
        status: Some(status.to_string()),
        phase: key.split(':').next().map(str::to_string),
        functions: None,
        instructions: None,
        message: err,
    });
}

pub fn result_path(st: &Shared, tool: &str, sha: &str, ver: &str) -> PathBuf {
    let h = crate::util::short_hash(format!("{ver}|{}", setup_version(st, tool)).as_bytes());
    results_dir(st).join(format!("{tool}-{sha}-{h}.json"))
}

pub fn load_result(p: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

pub fn store_result(p: &Path, v: &Value) {
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = p.with_extension(format!("tmp{}", std::process::id()));
    if std::fs::write(&tmp, serde_json::to_vec(v).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, p);
    }
    prune(tools_root_of(p), 4 << 30);
}

/// Keep `tools/` (results + work folders) under a size budget, oldest first.
fn prune(root: Option<&Path>, max: u64) {
    let Some(root) = root else { return };
    let mut items: Vec<(std::time::SystemTime, u64, PathBuf)> = Vec::new();
    for sub in ["results", "work"] {
        let d = root.join(sub);
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if sub == "work" {
                // work/<tool>/<sha>
                if let Ok(rd2) = std::fs::read_dir(e.path()) {
                    for e2 in rd2.flatten() {
                        let p = e2.path();
                        let t = e2
                            .metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or(std::time::UNIX_EPOCH);
                        items.push((t, dir_size(&p), p));
                    }
                }
            } else if let Ok(m) = e.metadata() {
                items.push((
                    m.modified().unwrap_or(std::time::UNIX_EPOCH),
                    m.len(),
                    e.path(),
                ));
            }
        }
    }
    let mut total: u64 = items.iter().map(|i| i.1).sum();
    if total <= max {
        return;
    }
    items.sort_by_key(|i| i.0);
    for (_, sz, p) in items {
        if total <= max {
            break;
        }
        let _ = if p.is_dir() {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        total = total.saturating_sub(sz);
    }
}

/// `results/<file>` → the tools root.
fn tools_root_of(p: &Path) -> Option<&Path> {
    p.parent()?.parent()
}

pub fn dir_size(p: &Path) -> u64 {
    let mut n = 0;
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(e.path()),
                Ok(t) if t.is_file() => n += e.metadata().map(|m| m.len()).unwrap_or(0),
                _ => {}
            }
        }
    }
    n
}

// ---------------------------------------------------------------- setup (rules, databases)

/// Version marker of downloaded rules/databases (part of the cache key).
pub fn setup_version(st: &Shared, tool: &str) -> String {
    match def(tool).and_then(|t| t.setup) {
        Some(s) => std::fs::read_to_string(rules_dir(st).join(format!("{s}.version")))
            .unwrap_or_default()
            .trim()
            .to_string(),
        None => String::new(),
    }
}

/// Is the tool's rules/database present? (None = nothing needed.)
pub fn setup_state(st: &Shared, t: &ToolDef) -> Option<Value> {
    let s = t.setup?;
    Some(match s {
        "clamav-db" => {
            let db = runners::clamav_db_dir();
            let age = db.as_ref().and_then(|d| runners::clamav_db_age_days(d));
            json!({"id": s, "ready": db.is_some(), "age_days": age,
                   "label": "Virus database", "action": "Update virus database",
                   "note": "Downloads the free ClamAV signature database (about 300 MB) with freshclam."})
        }
        "yara-rules" => json!({"id": s, "ready": runners::yara_rules(st).is_some(),
                   "version": setup_version(st, "yara"),
                   "label": "Malware patterns", "action": "Download YARA-Forge rules",
                   "note": "Downloads the free YARA-Forge core rule set (thousands of patterns from security researchers)."}),
        "capa-rules" => json!({"id": s, "ready": runners::capa_rules(st).is_some(),
                   "version": setup_version(st, "capa"),
                   "label": "Capability rules", "action": "Download capa rules",
                   "note": "Downloads Mandiant's free capa rules that match the installed capa version."}),
        _ => json!({"id": s, "ready": true}),
    })
}

// ---------------------------------------------------------------- endpoints

async fn describe(st: &Shared, t: &'static ToolDef) -> Value {
    let path = locate(t);
    let ver = match &path {
        Some(p) => version(t, p).await,
        None => None,
    };
    let java_ok = t.id != "ghidra" || java_home().is_some();
    json!({
        "id": t.id, "name": t.name, "what": t.what, "kind": t.kind.as_str(),
        "installed": path.is_some(), "path": path, "version": ver,
        "install": t.install, "homepage": t.homepage, "license": t.license,
        "heavy": t.heavy, "auto": t.auto, "setup": setup_state(st, t),
        "java_ok": java_ok,
        "extra": match t.id {
            "radare2" if path.is_some() => json!({"r2ghidra": runners::r2ghidra_available().await}),
            _ => Value::Null,
        },
    })
}

/// `GET /tools` — every known tool and whether it's installed.
pub async fn list(axum::extract::State(st): axum::extract::State<Shared>) -> axum::Json<Value> {
    let mut v = Vec::new();
    for t in TOOLS {
        v.push(describe(&st, t).await);
    }
    axum::Json(json!({
        "tools": v,
        "sandbox": sandbox_available(),
        "allow_unsandboxed": unsandboxed_allowed(&st),
        "online": crate::net::available(),
        "tasks": setup_tasks(),
    }))
}

fn setup_tasks() -> Value {
    let Ok(m) = tasks().lock() else {
        return json!({});
    };
    let mut o = serde_json::Map::new();
    for (k, t) in m.iter().filter(|(k, _)| k.starts_with("setup:")) {
        o.insert(k.clone(), json!({"status": t.status, "error": t.error}));
    }
    Value::Object(o)
}

/// `POST /tools/{id}/setup` — download rules / update the virus database.
pub async fn setup(
    axum::extract::State(st): axum::extract::State<Shared>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> R<axum::Json<Value>> {
    let t = def(&id).ok_or_else(|| not_found("unknown tool"))?;
    let s = t.setup.ok_or_else(|| bad("this tool needs no setup"))?;
    if !st.local_mode {
        return Err(ApiError(
            axum::http::StatusCode::FORBIDDEN,
            "setup is only available in local mode".into(),
        ));
    }
    let key = format!("setup:{s}");
    let st2 = st.clone();
    let started = spawn_task(&st, key.clone(), true, async move {
        runners::setup(&st2, s).await
    });
    Ok(axum::Json(json!({"key": key, "started": started})))
}

/// Applicable tools for a file + their cached results / running state.
pub async fn for_binary(
    axum::extract::State(st): axum::extract::State<Shared>,
    axum::extract::Path(sha): axum::extract::Path<String>,
) -> R<axum::Json<Value>> {
    let s = crate::api::session(&st, &sha).await?;
    let fmt = s.info.format;
    let mut out = Vec::new();
    for t in TOOLS
        .iter()
        .filter(|t| (t.supports)(fmt) && t.kind != Kind::Decompiler)
    {
        let path = locate(t);
        let ver = match &path {
            Some(p) => version(t, p).await.unwrap_or_default(),
            None => String::new(),
        };
        let key = format!("{}:{sha}", t.id);
        let res = path
            .as_ref()
            .and_then(|_| load_result(&result_path(&st, t.id, &sha, &ver)));
        let tk = task(&key);
        let setup = setup_state(&st, t);
        let ready = setup
            .as_ref()
            .is_none_or(|s| s["ready"].as_bool() == Some(true));
        // Light tools that need nothing run on their own.
        if res.is_none() && tk.is_none() && t.auto && path.is_some() && ready {
            start(&st, t, &sha).await?;
        }
        let tk = task(&key);
        out.push(json!({
            "id": t.id, "name": t.name, "what": t.what, "kind": t.kind.as_str(),
            "installed": path.is_some(), "install": t.install, "heavy": t.heavy,
            "setup": setup,
            "status": match (&res, &tk) {
                (_, Some(k)) if k.status == "running" || k.status == "queued" => k.status,
                (Some(_), _) => "done",
                (None, Some(k)) => k.status,
                (None, None) => "idle",
            },
            "error": tk.and_then(|k| k.error),
            "result": res,
        }));
    }
    Ok(axum::Json(json!({ "tools": out })))
}

async fn start(st: &Shared, t: &'static ToolDef, sha: &str) -> R<bool> {
    valid_sha(sha)?;
    let bin = locate(t).ok_or_else(|| {
        bad(format!(
            "{} is not installed. Install it with: {}",
            t.name, t.install
        ))
    })?;
    let ver = version(t, &bin).await.unwrap_or_default();
    let key = format!("{}:{sha}", t.id);
    let (st2, sha2) = (st.clone(), sha.to_string());
    Ok(spawn_task(st, key, t.heavy, async move {
        let s = crate::api::session(&st2, &sha2).await.map_err(|e| e.1)?;
        let input = st2.binary_location(&sha2).ok_or("file not found")?;
        let res = runners::run_tool(&st2, t, &bin, &input, &s).await?;
        let mut res = res;
        res["tool"] = json!(t.id);
        res["version"] = json!(ver);
        res["finished_at"] = json!(crate::util::now());
        store_result(&result_path(&st2, t.id, &sha2, &ver), &res);
        Ok(())
    }))
}

/// `POST /binaries/{sha}/tools/{id}` — run a tool now.
pub async fn run_on(
    axum::extract::State(st): axum::extract::State<Shared>,
    axum::extract::Path((sha, id)): axum::extract::Path<(String, String)>,
) -> R<axum::Json<Value>> {
    let t = def(&id).ok_or_else(|| not_found("unknown tool"))?;
    let s = crate::api::session(&st, &sha).await?;
    if !(t.supports)(s.info.format) {
        return Err(bad(format!("{} doesn't work on this kind of file", t.name)));
    }
    if let Some(su) = setup_state(&st, t)
        && su["ready"].as_bool() != Some(true)
    {
        return Err(bad(format!(
            "{} needs its {} first (Settings → Tools)",
            t.name,
            su["label"].as_str().unwrap_or("rules")
        )));
    }
    // A re-run replaces the cached result.
    if let Some(bin) = locate(t) {
        let ver = version(t, &bin).await.unwrap_or_default();
        let _ = std::fs::remove_file(result_path(&st, t.id, &sha, &ver));
    }
    let started = start(&st, t, &sha).await?;
    Ok(axum::Json(json!({"started": started})))
}

// ---------------------------------------------------------------- results for other modules

/// Newest cached result of every tool for `sha` (any tool version).
pub fn results_for(st: &Shared, sha: &str) -> Vec<Value> {
    let mut best: HashMap<String, (std::time::SystemTime, PathBuf)> = HashMap::new();
    let Ok(rd) = std::fs::read_dir(results_dir(st)) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        let Some(stem) = n.strip_suffix(".json") else {
            continue;
        };
        // <tool>-<sha>-<hash>; decompiler results are per function, skip them.
        let mut parts = stem.splitn(3, '-');
        let (Some(tool), Some(s), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if s != sha || tool.starts_with("decomp") || def(tool).is_none() {
            continue;
        }
        let t = e
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if best.get(tool).is_none_or(|(bt, _)| t > *bt) {
            best.insert(tool.to_string(), (t, e.path()));
        }
    }
    let mut v: Vec<Value> = best
        .into_values()
        .filter_map(|(_, p)| load_result(&p))
        .collect();
    v.sort_by(|a, b| a["tool"].as_str().cmp(&b["tool"].as_str()));
    v
}

/// Cached online-lookup results for `sha`.
pub fn lookups_for(st: &Shared, sha: &str) -> Vec<Value> {
    crate::lookup::SERVICES
        .iter()
        .filter_map(|s| {
            let p = st
                .data_dir
                .join("lookups")
                .join(format!("{}-{sha}.json", s.id));
            load_result(&p)
        })
        .collect()
}

/// Tool and lookup results as compact text for the AI's FACTS block.
pub fn facts_from_results(st: &Shared, sha: &str) -> String {
    let mut f = String::new();
    for r in results_for(st, sha)
        .iter()
        .chain(lookups_for(st, sha).iter())
    {
        let name = r["tool"].as_str().or(r["service"].as_str()).unwrap_or("?");
        let pretty = def(name).map(|t| t.name).unwrap_or(name);
        f += &format!(
            "\nCHECK by {pretty} (result: {}): {}\n",
            r["verdict"].as_str().unwrap_or("info"),
            r["headline"].as_str().unwrap_or("")
        );
        for it in r["items"].as_array().into_iter().flatten().take(12) {
            f += &format!(
                "- [{}] {}: {}\n",
                it["severity"].as_str().unwrap_or("info"),
                it["title"]
                    .as_str()
                    .map(|t| t.chars().take(120).collect::<String>())
                    .unwrap_or_default(),
                it["detail"]
                    .as_str()
                    .map(|t| t.chars().take(200).collect::<String>())
                    .unwrap_or_default()
            );
        }
        for h in r["data"]["highlights"]
            .as_array()
            .into_iter()
            .flatten()
            .take(25)
        {
            f += &format!(
                "- {}: {}\n",
                h["label"].as_str().unwrap_or(""),
                h["value"]
                    .as_str()
                    .map(|t| t.chars().take(160).collect::<String>())
                    .unwrap_or_default()
            );
        }
        for p in r["data"]["permissions"]
            .as_array()
            .into_iter()
            .flatten()
            .take(30)
        {
            f += &format!(
                "- Android permission: {} ({})\n",
                p["label"].as_str().unwrap_or(""),
                p["name"].as_str().unwrap_or("")
            );
        }
        if let Some(d) = r["detections"].as_array().filter(|d| !d.is_empty()) {
            let names: Vec<String> = d
                .iter()
                .take(10)
                .map(|x| {
                    format!(
                        "{}: {}",
                        x["engine"].as_str().unwrap_or(""),
                        x["result"].as_str().unwrap_or("")
                    )
                })
                .collect();
            f += &format!("- detections: {}\n", names.join("; "));
        }
    }
    f
}
