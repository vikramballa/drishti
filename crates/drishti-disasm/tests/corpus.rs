//! Function-detection accuracy on the benign C corpus (spec §9.3).
//! Compiles `corpus/src/*.c` with clang (skipped if clang is missing) and
//! compares discovered starts in the stripped binary with symbols.

use drishti_disasm::{Options, analyze};
use drishti_model::SymbolKind;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

fn clang() -> Option<PathBuf> {
    let ok = Command::new("clang")
        .arg("--version")
        .output()
        .ok()?
        .status
        .success();
    ok.then(|| PathBuf::from("clang"))
}

fn build(src: &Path, out: &Path, opt: &str, arch: &str) -> bool {
    let target = if cfg!(target_os = "macos") {
        vec!["-arch", arch]
    } else {
        vec![]
    };
    let ok = Command::new("clang")
        .args(["-g", opt])
        .args(&target)
        .arg("-o")
        .arg(out)
        .arg(src)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return false;
    }
    let stripped = out.with_extension("stripped");
    std::fs::copy(out, &stripped).is_ok()
        && Command::new("strip")
            .arg(&stripped)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

/// (precision, recall, what was missed / wrongly found, for the message).
fn score(bin: &Path, hints: bool) -> (f64, f64, String) {
    let truth_img = drishti_loader::load_image(drishti_loader::open(bin).unwrap(), None).unwrap();
    let truth: BTreeSet<u64> = truth_img
        .symbols
        .iter()
        .filter(|s| {
            s.kind == SymbolKind::Function
                && truth_img.code_range(s.addr.0).is_some_and(|c| !c.is_stub)
        })
        .map(|s| s.addr.0)
        .collect();
    let img = drishti_loader::load_image(
        drishti_loader::open(&bin.with_extension("stripped")).unwrap(),
        None,
    )
    .unwrap();
    let a = analyze(
        &img,
        &Options {
            use_hints: hints,
            ..Default::default()
        },
        &|_| {},
        &AtomicBool::new(false),
    )
    .unwrap();
    let found: BTreeSet<u64> = a
        .functions
        .iter()
        .filter(|f| img.code_range(f.entry).is_some_and(|c| !c.is_stub))
        .map(|f| f.entry)
        .collect();
    let tp = found.intersection(&truth).count() as f64;
    let name = |a: &u64| {
        let n = truth_img
            .symbols
            .iter()
            .find(|s| s.addr.0 == *a)
            .map_or("?", |s| s.name.as_str());
        format!("{a:#x} {n}")
    };
    let missed: Vec<String> = truth.difference(&found).map(name).collect();
    let extra: Vec<String> = found.difference(&truth).map(name).collect();
    (
        tp / found.len().max(1) as f64,
        tp / truth.len().max(1) as f64,
        format!("missed {missed:?}, extra {extra:?}"),
    )
}

#[test]
fn corpus_function_detection() {
    if clang().is_none() {
        eprintln!("clang not found; skipping corpus test");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/src");
    let dir = std::env::temp_dir().join(format!("drishti-corpus-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let archs: &[&str] = if cfg!(target_os = "macos") {
        &["arm64", "x86_64"]
    } else {
        &["native"]
    };
    let mut ran = 0;
    let mut failures = Vec::new();
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let src = entry.path();
        if src.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }
        for &arch in archs {
            for opt in ["-O0", "-O2"] {
                let out = dir.join(format!(
                    "{}-{arch}{opt}",
                    src.file_stem().unwrap().to_string_lossy()
                ));
                if !build(&src, &out, opt, arch) {
                    continue;
                }
                for hints in [true, false] {
                    let (p, r, detail) = score(&out, hints);
                    let (min_p, min_r) = if opt == "-O0" {
                        (0.95, 0.95)
                    } else {
                        (0.85, 0.85)
                    };
                    if p < min_p || r < min_r {
                        failures.push(format!(
                            "{} hints={hints}: precision {p:.2} recall {r:.2}; {detail}",
                            out.display()
                        ));
                    }
                    ran += 1;
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ran > 0, "no corpus binaries were built");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
