//! Triage heuristics: packing, suspicious API combinations, findings.

use crate::image::{Image, PERM_X, import_capability};
use drishti_model::{Finding, FindingKind, Format, Severity};

const PACKER_SECTIONS: &[&str] = &[
    "UPX0",
    "UPX1",
    "UPX2",
    ".UPX0",
    ".UPX1",
    ".aspack",
    ".adata",
    ".MPRESS1",
    ".MPRESS2",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".enigma1",
    ".petite",
    ".nsp0",
    ".nsp1",
    "PEC2",
    "PEC2TO",
    ".packed",
    ".kkrunchy",
];

fn packer_section(img: &Image) -> Option<&str> {
    img.sections
        .iter()
        .map(|s| s.name.as_str())
        .find(|n| PACKER_SECTIONS.iter().any(|p| n.eq_ignore_ascii_case(p)))
}

fn high_entropy_exec(img: &Image) -> Option<(&str, f32)> {
    img.sections
        .iter()
        .filter(|s| {
            s.file_size > 4096
                && s.entropy > 7.2
                && (s.perms.contains('x') || img.perms(s.vaddr.0) & PERM_X != 0)
        })
        .map(|s| (s.name.as_str(), s.entropy))
        .next()
}

/// Packing is suspected on high-entropy code, packer section names, or (PE)
/// almost no imports.
pub fn packed_suspected(img: &Image) -> bool {
    packer_section(img).is_some()
        || high_entropy_exec(img).is_some()
        || (img.format == Format::Pe && img.imports.len() < 4 && !img.code.is_empty())
}

/// Rule-based findings for the triage dashboard.
pub fn findings(img: &Image) -> Vec<Finding> {
    let mut out = Vec::new();
    let f = |kind, severity, title: String, detail: String| Finding {
        kind,
        severity,
        title,
        detail,
        addrs: Vec::new(),
        source: "rule".into(),
    };
    if let Some(p) = packer_section(img) {
        out.push(f(
            FindingKind::Packer,
            Severity::Medium,
            format!("Packer section {p}"),
            "Section name matches a known packer.".into(),
        ));
    }
    if let Some((n, e)) = high_entropy_exec(img) {
        out.push(f(
            FindingKind::HighEntropy,
            Severity::Medium,
            format!("High-entropy code section {n}"),
            format!("Entropy {e:.2} > 7.2 suggests compressed or encrypted code."),
        ));
    }
    for w in &img.warnings {
        if w.contains("encrypted") {
            out.push(f(
                FindingKind::Other,
                Severity::Info,
                "Encrypted App Store binary".into(),
                w.clone(),
            ));
        }
    }
    let has = |n: &str| {
        img.imports.iter().any(|i| {
            i.name.trim_start_matches('_').eq_ignore_ascii_case(n)
                || i.name
                    .trim_start_matches('_')
                    .to_ascii_lowercase()
                    .starts_with(&n.to_ascii_lowercase())
        })
    };
    let combos: &[(&[&str], &str, Severity)] = &[
        (
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "Remote thread injection API set",
            Severity::High,
        ),
        (
            &["OpenProcess", "WriteProcessMemory"],
            "Writes another process's memory",
            Severity::Medium,
        ),
        (
            &["SetWindowsHookEx", "GetAsyncKeyState"],
            "Keyboard hooking APIs",
            Severity::Medium,
        ),
        (&["IsDebuggerPresent"], "Debugger detection", Severity::Low),
        (
            &["URLDownloadToFile"],
            "Downloads files from URLs",
            Severity::Medium,
        ),
        (
            &["ptrace"],
            "Uses ptrace (anti-debug or process control)",
            Severity::Low,
        ),
        (
            &["task_for_pid"],
            "Acquires other processes' Mach task ports",
            Severity::Medium,
        ),
        (
            &["CryptEncrypt", "FindFirstFile"],
            "File enumeration + encryption",
            Severity::Medium,
        ),
    ];
    for (apis, title, sev) in combos {
        if apis.iter().all(|a| has(a)) {
            out.push(f(
                FindingKind::SuspiciousApi,
                *sev,
                (*title).into(),
                format!("Imports: {}", apis.join(", ")),
            ));
        }
    }
    let mut caps: Vec<&str> = img
        .imports
        .iter()
        .filter_map(|i| import_capability(&i.name))
        .collect();
    caps.sort_unstable();
    caps.dedup();
    if !caps.is_empty() {
        out.push(f(
            FindingKind::Other,
            Severity::Info,
            "Capabilities".into(),
            caps.join(", "),
        ));
    }
    out
}
