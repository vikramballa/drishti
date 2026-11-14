//! Corrupted binaries through the full analysis + rendering path must not panic.
use drishti_disasm::{Options, analyze, disasm};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

fn rng(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

#[test]
fn corrupted_binaries_analyse_without_panic() {
    let Ok(orig) = std::fs::read("/bin/ls").or_else(|_| std::fs::read("/bin/sh")) else {
        return;
    };
    let mut seed = 7u64;
    for round in 0..120 {
        let mut b = orig.clone();
        let n = 1 + rng(&mut seed) % 64;
        for _ in 0..n {
            // Half the time hit headers, otherwise anywhere (code, tables).
            let span = if round % 2 == 0 {
                b.len().min(8192)
            } else {
                b.len()
            };
            let i = (rng(&mut seed) as usize) % span;
            b[i] = rng(&mut seed) as u8;
        }
        let blob = Arc::new(drishti_loader::Blob::from_vec(b));
        let Ok(img) = drishti_loader::load_image(blob, None) else {
            continue;
        };
        let Ok(a) = analyze(&img, &Options::default(), &|_| {}, &AtomicBool::new(false)) else {
            continue;
        };
        for f in a.functions.iter().take(20) {
            let _ = a.cfg(&img, f.entry);
            let _ = disasm(&img, f.entry, 64, &|_| None);
        }
    }
}

/// The fuzz regression inputs (kept with the loader tests) through the same
/// path as the `disasm` fuzz target: analysis, behaviours, CFG, fingerprint.
#[test]
fn fuzz_regressions_analyse_without_panic() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../drishti-loader/tests/fixtures/fuzz"
    );
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(bytes) = std::fs::read(e.path()) else {
            continue;
        };
        let t = std::time::Instant::now();
        let blob = Arc::new(drishti_loader::Blob::from_vec(bytes));
        let Ok(img) = drishti_loader::load_image(blob, None) else {
            continue;
        };
        let opts = Options {
            max_functions: 2000,
            max_insns_per_function: 20_000,
            ..Default::default()
        };
        if let Ok(a) = analyze(&img, &opts, &|_| {}, &AtomicBool::new(false)) {
            let _ = drishti_disasm::insights::behaviors(&img, Some(&a));
            for f in a.functions.iter().take(20) {
                let _ = a.cfg(&img, f.entry);
                let _ = drishti_disasm::diff::fingerprint(&img, f);
            }
        }
        assert!(
            t.elapsed().as_secs() < 5,
            "{:?} took {:?}",
            e.path(),
            t.elapsed()
        );
    }
}
