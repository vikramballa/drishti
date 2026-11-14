//! PE samples (x86-64, ARM64, x86; hardened + weak) cross-compiled by
//! `corpus/build-pe.sh` with clang + lld-link: imports/IAT, hardening,
//! .pdata seeds, jump tables, no-return propagation, behaviours, IOCs.
//! Skipped when the toolchain is missing, unless DRISHTI_REQUIRE_PE=1.

mod common;

use common::*;
use drishti_disasm::insights::behaviors;
use drishti_loader::insights::{hardening, iocs};
use drishti_model::{Arch, Format, XrefKind};
use std::path::{Path, PathBuf};
use std::process::Command;

fn build_pe(dir: &TempDir) -> Option<PathBuf> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/build-pe.sh");
    let st = Command::new("sh").arg(&script).arg(&dir.0).status();
    match st {
        Ok(s) if s.success() => Some(dir.0.clone()),
        other => {
            assert!(
                std::env::var_os("DRISHTI_REQUIRE_PE").is_none(),
                "PE samples could not be built ({other:?})"
            );
            eprintln!("PE toolchain not available; skipping");
            None
        }
    }
}

const SAMPLES: &[(&str, Arch, bool)] = &[
    ("pe-x86_64-hard.exe", Arch::X86_64, true),
    ("pe-x86_64-weak.exe", Arch::X86_64, false),
    ("pe-arm64-hard.exe", Arch::Aarch64, true),
    ("pe-x86-hard.exe", Arch::X86, true),
    ("pe-x86-weak.exe", Arch::X86, false),
];

#[test]
fn pe_samples() {
    let dir = TempDir::new("pe");
    let Some(out) = build_pe(&dir) else { return };
    for &(file, arch, hard) in SAMPLES {
        let path = out.join(file);
        let img = load(&path);
        assert_eq!(img.format, Format::Pe, "{file}");
        assert_eq!(img.arch, arch, "{file}");

        // Imports: names, libraries and IAT slots.
        let libs: Vec<String> = img
            .libraries
            .iter()
            .map(|l| l.to_ascii_lowercase())
            .collect();
        for l in ["kernel32.dll", "user32.dll", "advapi32.dll"] {
            assert!(libs.contains(&l.to_string()), "{file}: {libs:?}");
        }
        let imp = |n: &str| {
            img.imports
                .iter()
                .find(|i| i.name == n)
                .unwrap_or_else(|| panic!("{file}: import {n} missing: {:?}", img.imports))
        };
        let exit = imp("ExitProcess");
        assert!(
            img.import_slots.contains_key(&exit.addr.0),
            "{file}: IAT slot"
        );
        assert_eq!(
            exit.library
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("kernel32.dll")
        );
        imp("MessageBoxA");
        imp("RegSetValueExA");

        // Hardening.
        let (checks, _) = hardening(&img);
        let st = |n: &str| {
            checks
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.status)
                .unwrap_or_else(|| panic!("{file}: no {n} check in {checks:?}"))
        };
        let want = if hard { "good" } else { "bad" };
        assert_eq!(st("ASLR"), want, "{file}");
        assert_eq!(st("DEP / NX"), want, "{file}");
        assert_eq!(st("Control Flow Guard"), want, "{file}");
        assert_eq!(st("Stack cookie"), "good", "{file}: load-config cookie");
        assert_eq!(st("Authenticode"), "bad", "{file}");
        if arch != Arch::X86 {
            assert_eq!(st("High-entropy ASLR"), want, "{file}");
        }

        // Analysis: .pdata seeds (64-bit), jump table, IAT calls, no-return.
        if arch != Arch::X86 {
            assert!(img.function_ranges.len() >= 4, "{file}: .pdata ranges");
            for &(s, e) in &img.function_ranges {
                assert!(
                    e > s && img.is_code(s),
                    "{file}: bad .pdata range {s:#x}..{e:#x}"
                );
            }
        }
        let a = run(&img);
        assert!(
            a.stats.jump_tables >= 1,
            "{file}: switch jump table not recovered"
        );
        assert!(
            a.xrefs_to(exit.addr.0)
                .iter()
                .any(|x| x.kind == XrefKind::Call),
            "{file}: no call through the ExitProcess IAT slot"
        );
        let entry = img.entry.expect("entry");
        assert!(
            a.function_at(entry).is_some_and(|f| f.noreturn),
            "{file}: entry ends in ExitProcess"
        );
        // `die` (MessageBoxA + ExitProcess) becomes no-return by propagation.
        let msg = imp("MessageBoxA").addr.0;
        let die = a
            .functions
            .iter()
            .find(|f| f.entry != entry && f.calls.contains(&msg) && f.calls.contains(&exit.addr.0))
            .unwrap_or_else(|| panic!("{file}: die() not found"));
        assert!(die.noreturn, "{file}: die() should be noreturn");

        // Behaviours with evidence.
        let b = behaviors(&img, Some(&a));
        for name in [
            "Debugger detection",
            "Changes memory protection",
            "Windows registry",
        ] {
            let hit = b
                .iter()
                .find(|x| x.name == name)
                .unwrap_or_else(|| panic!("{file}: behaviour {name} missing"));
            assert!(!hit.functions.is_empty(), "{file}: {name} has no functions");
        }

        // Indicators.
        let blob = drishti_loader::open(&path).expect("open");
        let strings = drishti_loader::strings(&blob, Some(&img), 4, 10_000);
        let v = iocs(&strings);
        assert!(
            v.iter()
                .any(|i| i.kind == "url" && i.value == "https://www.example.net/pe-sample"),
            "{file}: {v:?}"
        );
        assert!(v.iter().any(|i| i.kind == "registry"), "{file}: {v:?}");
    }
}
