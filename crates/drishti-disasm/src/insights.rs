//! Behaviour detection (capa-style, rule based) and a plain-language summary.
//!
//! A rule names an ability ("spawns processes") and the APIs that imply it.
//! Evidence is the set of functions that reference those imports, so users
//! can jump straight to the code responsible.

use crate::analyze::Analysis;
use drishti_loader::Image;
use drishti_loader::insights::Signing;
use drishti_model::{Addr, Arch, FileInfo};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct FnRef {
    pub entry: Addr,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Behavior {
    pub name: &'static str,
    pub category: &'static str,
    /// "info" | "low" | "medium" | "high"
    pub severity: &'static str,
    pub description: &'static str,
    pub apis: Vec<String>,
    pub functions: Vec<FnRef>,
    pub function_count: usize,
}

struct Rule {
    name: &'static str,
    category: &'static str,
    severity: &'static str,
    description: &'static str,
    /// Exact API names (case-insensitive); a trailing `*` matches a prefix.
    apis: &'static [&'static str],
    /// Minimum number of distinct APIs that must be imported.
    min: usize,
}

const RULES: &[Rule] = &[
    Rule {
        name: "Network sockets",
        category: "network",
        severity: "info",
        description: "Opens raw network connections.",
        apis: &[
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "sendto",
            "recvfrom",
            "WSAStartup",
            "nw_connection_create",
        ],
        min: 2,
    },
    Rule {
        name: "HTTP client",
        category: "network",
        severity: "info",
        description: "Talks to web servers.",
        apis: &[
            "curl_easy_perform",
            "curl_easy_init",
            "InternetOpen*",
            "HttpSendRequest*",
            "WinHttpOpen",
            "WinHttpSendRequest",
            "URLDownloadToFile*",
            "OBJC_CLASS_$_NSURLSession",
            "OBJC_CLASS_$_NSURLConnection",
            "CFHTTPMessageCreateRequest",
        ],
        min: 1,
    },
    Rule {
        name: "DNS lookups",
        category: "network",
        severity: "info",
        description: "Resolves host names.",
        apis: &[
            "getaddrinfo",
            "gethostbyname",
            "DnsQuery*",
            "res_query",
            "CFHostStartInfoResolution",
        ],
        min: 1,
    },
    Rule {
        name: "TLS / certificates",
        category: "network",
        severity: "info",
        description: "Uses TLS or evaluates certificates.",
        apis: &[
            "SSL_connect",
            "SSL_read",
            "SSL_write",
            "SecTrustEvaluate*",
            "SSLHandshake",
            "tls_connect",
        ],
        min: 1,
    },
    Rule {
        name: "Spawns processes",
        category: "process",
        severity: "low",
        description: "Starts other programs.",
        apis: &[
            "fork",
            "vfork",
            "execve",
            "execv",
            "execvp",
            "execl",
            "posix_spawn",
            "posix_spawnp",
            "CreateProcess*",
            "ShellExecute*",
            "WinExec",
            "OBJC_CLASS_$_NSTask",
        ],
        min: 1,
    },
    Rule {
        name: "Runs shell commands",
        category: "process",
        severity: "medium",
        description: "Executes commands through a shell.",
        apis: &["system", "popen"],
        min: 1,
    },
    Rule {
        name: "Loads code at runtime",
        category: "process",
        severity: "low",
        description: "Loads libraries or resolves symbols dynamically.",
        apis: &[
            "dlopen",
            "dlsym",
            "LoadLibrary*",
            "GetProcAddress",
            "NSCreateObjectFileImageFromMemory",
            "NSLinkModule",
        ],
        min: 1,
    },
    Rule {
        name: "Process injection",
        category: "process",
        severity: "high",
        description: "Writes into or starts threads in another process.",
        apis: &[
            "WriteProcessMemory",
            "CreateRemoteThread*",
            "VirtualAllocEx",
            "NtCreateThreadEx",
            "QueueUserAPC",
            "task_for_pid",
            "mach_vm_write",
            "thread_create_running",
        ],
        min: 2,
    },
    Rule {
        name: "Changes memory protection",
        category: "memory",
        severity: "low",
        description: "Makes memory executable or writable (JIT, unpacking, hooks).",
        apis: &[
            "mprotect",
            "VirtualProtect*",
            "vm_protect",
            "mach_vm_protect",
            "pthread_jit_write_protect_np",
        ],
        min: 1,
    },
    Rule {
        name: "Debugger detection",
        category: "anti-analysis",
        severity: "medium",
        description: "Checks whether it is being debugged.",
        apis: &[
            "ptrace",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString*",
        ],
        min: 1,
    },
    Rule {
        name: "System fingerprinting",
        category: "discovery",
        severity: "info",
        description: "Reads machine and OS details.",
        apis: &[
            "sysctl",
            "sysctlbyname",
            "uname",
            "gethostname",
            "GetComputerName*",
            "GetVersionEx*",
            "IOServiceGetMatchingService",
            "getifaddrs",
        ],
        min: 2,
    },
    Rule {
        name: "File enumeration",
        category: "file",
        severity: "info",
        description: "Walks directories.",
        apis: &[
            "opendir",
            "readdir",
            "fts_open",
            "fts_read",
            "nftw",
            "FindFirstFile*",
            "FindNextFile*",
            "scandir",
        ],
        min: 1,
    },
    Rule {
        name: "Deletes files",
        category: "file",
        severity: "info",
        description: "Removes files.",
        apis: &["unlink", "unlinkat", "remove", "DeleteFile*", "rmdir"],
        min: 1,
    },
    Rule {
        name: "Cryptography",
        category: "crypto",
        severity: "info",
        description: "Encrypts, decrypts or hashes data.",
        apis: &[
            "CCCrypt",
            "CCCryptorCreate",
            "CC_SHA256",
            "CC_MD5",
            "CC_SHA1",
            "CCHmac",
            "EVP_EncryptInit*",
            "EVP_DecryptInit*",
            "EVP_DigestInit*",
            "AES_encrypt",
            "CryptEncrypt",
            "CryptDecrypt",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "SecKeyCreateEncryptedData",
        ],
        min: 1,
    },
    Rule {
        name: "Random numbers",
        category: "crypto",
        severity: "info",
        description: "Generates cryptographic random data.",
        apis: &[
            "SecRandomCopyBytes",
            "arc4random_buf",
            "getentropy",
            "RAND_bytes",
            "BCryptGenRandom",
            "CryptGenRandom",
            "getrandom",
        ],
        min: 1,
    },
    Rule {
        name: "Keychain / credential store",
        category: "credentials",
        severity: "low",
        description: "Reads or writes stored secrets.",
        apis: &[
            "SecItemCopyMatching",
            "SecItemAdd",
            "SecItemUpdate",
            "SecKeychainFindGenericPassword",
            "CredRead*",
            "CredEnumerate*",
            "CryptUnprotectData",
        ],
        min: 1,
    },
    Rule {
        name: "Privilege changes",
        category: "privilege",
        severity: "medium",
        description: "Requests or switches privileges.",
        apis: &[
            "setuid",
            "seteuid",
            "setgid",
            "AuthorizationExecuteWithPrivileges",
            "AuthorizationCreate",
            "AdjustTokenPrivileges",
            "SMJobBless",
        ],
        min: 1,
    },
    Rule {
        name: "Persistence",
        category: "persistence",
        severity: "medium",
        description: "Can register itself to start automatically.",
        apis: &[
            "SMLoginItemSetEnabled",
            "SMJobSubmit",
            "LSSharedFileListInsertItemURL",
            "OBJC_CLASS_$_SMAppService",
            "RegSetValue*",
            "CreateService*",
            "RegCreateKey*",
        ],
        min: 1,
    },
    Rule {
        name: "Screen capture",
        category: "collection",
        severity: "medium",
        description: "Captures screen contents.",
        apis: &[
            "CGWindowListCreateImage",
            "CGDisplayCreateImage",
            "CGDisplayStreamCreate*",
            "OBJC_CLASS_$_SCStream",
            "BitBlt",
            "OBJC_CLASS_$_SCShareableContent",
        ],
        min: 1,
    },
    Rule {
        name: "Keyboard / input monitoring",
        category: "collection",
        severity: "medium",
        description: "Observes or injects keyboard and mouse events.",
        apis: &[
            "CGEventTapCreate",
            "CGEventPost",
            "SetWindowsHookEx*",
            "GetAsyncKeyState",
            "IOHIDManagerCreate",
            "OBJC_CLASS_$_NSEvent",
        ],
        min: 1,
    },
    Rule {
        name: "Camera / microphone",
        category: "collection",
        severity: "medium",
        description: "Records audio or video.",
        apis: &[
            "OBJC_CLASS_$_AVCaptureDevice",
            "OBJC_CLASS_$_AVCaptureSession",
            "OBJC_CLASS_$_AVAudioRecorder",
            "AudioQueueNewInput",
            "waveInOpen",
        ],
        min: 1,
    },
    Rule {
        name: "Location",
        category: "collection",
        severity: "low",
        description: "Reads the device location.",
        apis: &["OBJC_CLASS_$_CLLocationManager"],
        min: 1,
    },
    Rule {
        name: "Clipboard",
        category: "collection",
        severity: "low",
        description: "Reads or writes the clipboard.",
        apis: &[
            "OBJC_CLASS_$_NSPasteboard",
            "OBJC_CLASS_$_UIPasteboard",
            "GetClipboardData",
            "SetClipboardData",
        ],
        min: 1,
    },
    Rule {
        name: "Windows registry",
        category: "config",
        severity: "info",
        description: "Reads or modifies the registry.",
        apis: &[
            "RegOpenKey*",
            "RegQueryValue*",
            "RegEnumKey*",
            "RegDeleteKey*",
        ],
        min: 1,
    },
    Rule {
        name: "SQLite database",
        category: "data",
        severity: "info",
        description: "Stores data in SQLite.",
        apis: &[
            "sqlite3_open",
            "sqlite3_open_v2",
            "sqlite3_exec",
            "sqlite3_prepare_v2",
        ],
        min: 1,
    },
    Rule {
        name: "Compression",
        category: "data",
        severity: "info",
        description: "Compresses or decompresses data.",
        apis: &[
            "inflate",
            "deflate",
            "compress2",
            "uncompress",
            "BZ2_bzDecompress",
            "lzma_code",
            "ZSTD_decompress",
            "compression_decode_buffer",
        ],
        min: 1,
    },
    Rule {
        name: "Script / AppleScript execution",
        category: "process",
        severity: "medium",
        description: "Runs scripts.",
        apis: &[
            "OBJC_CLASS_$_NSAppleScript",
            "OSACompile",
            "OSAExecute",
            "OBJC_CLASS_$_JSContext",
        ],
        min: 1,
    },
    Rule {
        name: "Kernel / driver interaction",
        category: "system",
        severity: "low",
        description: "Talks to kernel drivers.",
        apis: &[
            "IOConnectCallMethod",
            "IOServiceOpen",
            "DeviceIoControl",
            "ioctl",
        ],
        min: 1,
    },
];

fn matches(import: &str, pat: &str) -> bool {
    let n = import.trim_start_matches('_');
    match pat.strip_suffix('*') {
        Some(p) => n.len() >= p.len() && n[..p.len()].eq_ignore_ascii_case(p),
        None => n.eq_ignore_ascii_case(pat),
    }
}

/// Evaluate behaviour rules. With an analysis, each hit lists the
/// functions that reference the matching imports.
pub fn behaviors(img: &Image, analysis: Option<&Analysis>) -> Vec<Behavior> {
    let mut out = Vec::new();
    for r in RULES {
        let hits: Vec<&drishti_model::Symbol> = img
            .imports
            .iter()
            .filter(|i| r.apis.iter().any(|p| matches(&i.name, p)))
            .collect();
        if hits.len() < r.min {
            continue;
        }
        let mut entries: Vec<u64> = Vec::new();
        if let Some(a) = analysis {
            for i in &hits {
                if i.addr.0 == 0 {
                    continue;
                }
                for x in a.xrefs_to(i.addr.0).iter().take(2000) {
                    if let Some(f) = a.function_containing(x.from) {
                        entries.push(f.entry);
                    }
                }
                if let Some(stub) = a.function_at(i.addr.0) {
                    entries.extend(stub.called_by.iter().copied());
                }
            }
            entries.sort_unstable();
            entries.dedup();
        }
        let functions = entries
            .iter()
            .take(25)
            .filter_map(|&e| {
                analysis.and_then(|a| a.function_at(e)).map(|f| FnRef {
                    entry: Addr(e),
                    name: f.name.to_string(),
                })
            })
            .collect();
        let mut apis: Vec<String> = hits
            .iter()
            .map(|i| {
                i.display_name()
                    .trim_start_matches('_')
                    .replace("OBJC_CLASS_$_", "")
            })
            .collect();
        apis.sort();
        apis.dedup();
        apis.truncate(12);
        out.push(Behavior {
            name: r.name,
            category: r.category,
            severity: r.severity,
            description: r.description,
            apis,
            functions,
            function_count: entries.len(),
        });
    }
    let rank = |s: &str| match s {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    };
    out.sort_by_key(|b| rank(b.severity));
    out
}

/// A short plain-language description of the binary for non-experts.
pub fn summary(
    info: &FileInfo,
    img: Option<&Image>,
    signing: Option<&Signing>,
    behaviors: &[Behavior],
    functions: Option<usize>,
) -> String {
    let fmt = serde_json::to_value(info.format)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let Some(img) = img else {
        return format!(
            "{} is a {} file ({} bytes). It contains no native machine code that the core engine analyses; see the contents list below.",
            info.file_name, fmt, info.size
        );
    };
    let platform = match serde_json::to_value(info.platform)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .as_deref()
    {
        Some("macos") => "macOS",
        Some("ios") => "iOS",
        Some("windows") => "Windows",
        Some("linux") => "Linux",
        Some("android") => "Android",
        Some("dotnet") => ".NET",
        _ => "an unknown platform",
    };
    let arch = match info.arch {
        Arch::Aarch64 => "ARM64 (Apple Silicon / AArch64)",
        Arch::X86_64 => "Intel/AMD 64-bit",
        Arch::X86 => "Intel 32-bit",
        Arch::Arm => "ARM 32-bit",
        _ => "another CPU",
    };
    let kind = if img.entry.is_some() {
        "program"
    } else {
        "library"
    };
    let mut s = format!("This is a {kind} for {platform}, built for {arch}");
    let langs: Vec<&str> = info
        .compiler_hints
        .iter()
        .filter_map(|h| match h.as_str() {
            "swift" => Some("Swift"),
            "objc" => Some("Objective-C"),
            "go" => Some("Go"),
            "rust" => Some("Rust"),
            "electron" => Some("Electron (Chromium + Node.js)"),
            "flutter" => Some("Flutter"),
            "dotnet" => Some(".NET"),
            "msvc" => Some("Microsoft Visual C++"),
            "gcc" => Some("GCC"),
            "clang" => Some("Clang"),
            _ => None,
        })
        .collect();
    if !langs.is_empty() {
        s.push_str(&format!(", made with {}", langs.join(", ")));
    }
    s.push('.');
    if info.container.is_some() && !info.children.is_empty() {
        s.push_str(&format!(
            " The file is a universal binary with {} CPU slices; this view shows one of them.",
            info.children.len()
        ));
    }
    if let Some(n) = functions {
        s.push_str(&format!(
            " It contains about {n} functions and uses {} functions from {} system libraries.",
            img.imports.len(),
            img.libraries.len()
        ));
    }
    if let Some(sg) = signing {
        s.push_str(match (sg.signed, sg.adhoc) {
            (false, _) => " It is not code-signed.",
            (true, true) => " It is ad-hoc signed (no verified developer).",
            (true, false) => " It is signed by a developer certificate.",
        });
        if sg
            .entitlements
            .iter()
            .any(|(k, v)| k == "com.apple.security.app-sandbox" && v == "true")
        {
            s.push_str(" It runs inside the App Sandbox.");
        }
    }
    if info.is_packed_suspected == Some(true) {
        s.push_str(" Its code looks packed or encrypted, so static results may be incomplete.");
    }
    if info.is_stripped == Some(true) {
        s.push_str(" Debug symbols were removed, so most functions have generated names.");
    }
    let notable: Vec<&str> = behaviors
        .iter()
        .filter(|b| b.severity != "info")
        .map(|b| b.name)
        .take(6)
        .collect();
    if !notable.is_empty() {
        s.push_str(&format!(
            " Notable abilities: {}.",
            notable.join(", ").to_lowercase()
        ));
    }
    s
}
