//! Hostile-input robustness (spec §7.2, §8.3): truncated and corrupted
//! binaries must never panic anywhere in the pipeline. A lightweight
//! complement to the cargo-fuzz targets that runs in every `cargo test`.

use drishti_loader::{Blob, detect, file_info, load_image, strings};
use std::sync::Arc;

fn samples() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for p in ["/bin/ls", "/bin/sh", "/usr/bin/true", "/bin/cat"] {
        if let Ok(b) = std::fs::read(p) {
            v.push(b);
        }
    }
    v
}

/// xorshift64 — deterministic, dependency-free randomness.
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn exercise(bytes: Vec<u8>) {
    let _ = detect(&bytes);
    let blob = Arc::new(Blob::from_vec(bytes));
    let img = load_image(blob.clone(), None).ok();
    let _ = file_info(&blob, "x", img.as_ref());
    let _ = strings(&blob, img.as_ref(), 4, 10_000);
    if let Some(i) = &img {
        let _ = drishti_loader::triage::findings(i);
        for a in i.function_hints.iter().take(50) {
            let _ = i.read(*a, 64);
        }
    }
}

#[test]
fn truncated_inputs_do_not_panic() {
    for s in samples() {
        let mut len = s.len();
        while len > 0 {
            exercise(s[..len].to_vec());
            len = len * 2 / 3;
        }
    }
}

#[test]
fn corrupted_headers_do_not_panic() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for s in samples() {
        for _ in 0..300 {
            let mut b = s.clone();
            // Corrupt the first 8 KiB, where headers and load commands live.
            for _ in 0..(1 + rng(&mut seed) % 16) {
                let i = (rng(&mut seed) as usize) % b.len().min(8192);
                b[i] = rng(&mut seed) as u8;
            }
            exercise(b);
        }
    }
}

#[test]
fn tiny_random_inputs() {
    let mut seed = 42u64;
    for n in 0..2000usize {
        let len = n % 300;
        let mut b: Vec<u8> = (0..len).map(|_| rng(&mut seed) as u8).collect();
        // Give some of them real magic numbers.
        let magics: [&[u8]; 7] = [
            b"\x7fELF",
            b"MZ",
            &[0xcf, 0xfa, 0xed, 0xfe],
            &[0xca, 0xfe, 0xba, 0xbe],
            b"PK\x03\x04",
            b"dex\n035\0",
            b"\0asm",
        ];
        let m = magics[n % magics.len()];
        if b.len() >= m.len() {
            b[..m.len()].copy_from_slice(m);
        }
        exercise(b);
    }
}

/// Inputs that crashed or stalled the fuzzers (goblin export-trie panic on a
/// bad re-export ordinal; stack overflow walking a hostile trie; a symbol
/// count of ~4 billion that took 9.6 s to iterate; an ELF `.init_array`
/// whose `sh_size` was ~2^64, scanned pointer by pointer). Kept as regression
/// tests; the files are tiny mutated corpus binaries.
#[test]
fn fuzz_regressions_do_not_panic_or_stall() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fuzz");
    let mut n = 0;
    for e in std::fs::read_dir(dir).expect("fixtures dir") {
        let p = e.expect("entry").path();
        let bytes = std::fs::read(&p).expect("read fixture");
        let t = std::time::Instant::now();
        exercise(bytes);
        // Generous bound (debug builds, loaded CI); the bugs took 10–160 s.
        assert!(
            t.elapsed().as_secs() < 5,
            "{} took {:?}",
            p.display(),
            t.elapsed()
        );
        n += 1;
    }
    assert!(n >= 3);
}
