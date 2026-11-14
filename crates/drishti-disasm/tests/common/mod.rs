//! Shared helpers for corpus-based tests: compile `corpus/src/*.c` with
//! clang into a per-test temporary directory (tests skip without clang).
#![allow(dead_code)]

use drishti_disasm::{Analysis, Options, analyze};
use drishti_loader::Image;
use drishti_model::SymbolKind;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;

pub fn have_clang() -> bool {
    Command::new("clang")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn src(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/src")
        .join(name)
}

/// Architectures the host toolchain can target (`native` off macOS).
pub fn archs() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        &["arm64", "x86_64"]
    } else {
        &["native"]
    }
}

pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let d = std::env::temp_dir().join(format!("drishti-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).expect("create temp dir");
        TempDir(d)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Compile `src` → `out` (with debug info) and `out.stripped`.
pub fn build(src: &Path, out: &Path, opt: &str, arch: &str) -> bool {
    let target: Vec<&str> = if arch == "native" {
        vec![]
    } else {
        vec!["-arch", arch]
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

/// Build one corpus program; returns the unstripped path.
pub fn build_one(dir: &TempDir, file: &str, opt: &str, arch: &str) -> Option<PathBuf> {
    let stem = Path::new(file).file_stem()?.to_string_lossy().into_owned();
    let out = dir.0.join(format!("{stem}-{arch}{opt}"));
    build(&src(file), &out, opt, arch).then_some(out)
}

pub fn load(p: &Path) -> Image {
    drishti_loader::load_image(drishti_loader::open(p).expect("open"), None).expect("load")
}

pub fn run(img: &Image) -> Analysis {
    analyze(img, &Options::default(), &|_| {}, &AtomicBool::new(false)).expect("analyze")
}

/// Function symbols of an unstripped build: address → name without the
/// leading underscore.
pub fn truth(img: &Image) -> BTreeMap<u64, String> {
    img.symbols
        .iter()
        .filter(|s| {
            s.kind == SymbolKind::Function && img.code_range(s.addr.0).is_some_and(|c| !c.is_stub)
        })
        .map(|s| (s.addr.0, s.name.trim_start_matches('_').to_string()))
        .collect()
}

/// Address of a function symbol by name (unstripped build).
pub fn sym(img: &Image, name: &str) -> u64 {
    truth(img)
        .into_iter()
        .find(|(_, n)| n == name)
        .map(|(a, _)| a)
        .unwrap_or_else(|| panic!("symbol {name} not found"))
}
