//! Behaviours, indicators, hardening, crypto constants, no-return
//! propagation and the diff matcher, checked on the benign corpus
//! (`corpus/src/netclient.c`, `switches.c`). Skipped without clang.

mod common;

use common::*;
use drishti_disasm::analyze::Isadec;
use drishti_disasm::arch::Flow;
use drishti_disasm::diff::diff;
use drishti_disasm::insights::behaviors;
use drishti_loader::insights::{crypto_constants, hardening, iocs};

#[test]
fn hardening_and_signing_macho() {
    if !have_clang() || !cfg!(target_os = "macos") {
        return;
    }
    let dir = TempDir::new("hardening");
    let bin = build_one(&dir, "netclient.c", "-O2", "arm64").expect("build");
    let img = load(&bin);
    let (checks, signing) = hardening(&img);
    let status = |n: &str| {
        checks
            .iter()
            .find(|c| c.name == n)
            .map(|c| c.status)
            .unwrap_or_else(|| panic!("check {n} missing: {checks:?}"))
    };
    assert_eq!(status("PIE / ASLR"), "good");
    assert_eq!(status("Stack execution"), "good");
    // `char req[256]` makes clang emit a stack protector.
    assert_eq!(status("Stack canary"), "good");
    // ld signs arm64 executables ad hoc.
    let sg = signing.expect("signing info");
    assert!(sg.signed && sg.adhoc, "{sg:?}");
    assert!(!sg.hardened_runtime);
}

#[test]
fn indicators_from_strings() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("iocs");
    let arch = archs()[0];
    let bin = build_one(&dir, "netclient.c", "-O0", arch).expect("build");
    let blob = drishti_loader::open(&bin).expect("open");
    let img = load(&bin);
    let strings = drishti_loader::strings(&blob, Some(&img), 4, 100_000);
    let v = iocs(&strings);
    let has = |k: &str, val: &str| v.iter().any(|i| i.kind == k && i.value == val);
    assert!(
        has("url", "https://updates.example.com/api/v1/check"),
        "{v:?}"
    );
    assert!(has("ip", "203.0.113.77"), "{v:?}");
    assert!(has("email", "support@example.com"), "{v:?}");
    assert!(has("path", "/etc/netclient.conf"), "{v:?}");
    assert!(has("path", "/usr/bin/true"), "{v:?}");
    // Indicator addresses point at the string in the image.
    let url = v.iter().find(|i| i.kind == "url").expect("url");
    let bytes = img.read(url.addr.0, 8).expect("mapped");
    assert_eq!(bytes, b"https://");
}

#[test]
fn crypto_constant_table() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("crypto");
    for &arch in archs() {
        let bin = build_one(&dir, "netclient.c", "-O2", arch).expect("build");
        let img = load(&bin);
        let f = crypto_constants(&img);
        let sha = f
            .iter()
            .find(|f| f.title.contains("SHA-256 constants"))
            .unwrap_or_else(|| panic!("{arch}: no SHA-256 table in {f:?}"));
        let k = img
            .symbols
            .iter()
            .find(|s| s.name.trim_start_matches('_') == "K256")
            .expect("K256 symbol");
        assert!(sha.addrs.iter().any(|a| a.0 == k.addr.0), "{arch}: {sha:?}");
        assert!(!f.iter().any(|f| f.title.contains("AES")), "{arch}: {f:?}");
    }
}

#[test]
fn behaviours_with_evidence() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("behaviours");
    for &arch in archs() {
        let bin = build_one(&dir, "netclient.c", "-O2", arch).expect("build");
        let truth_img = load(&bin);
        let open_conn = sym(&truth_img, "open_conn");
        let run_helper = sym(&truth_img, "run_helper");
        let img = load(&bin.with_extension("stripped"));
        let a = run(&img);
        let b = behaviors(&img, Some(&a));
        let get = |n: &str| {
            b.iter()
                .find(|x| x.name == n)
                .unwrap_or_else(|| panic!("{arch}: behaviour {n} missing"))
        };
        let net = get("Network sockets");
        assert!(net.apis.iter().any(|x| x == "socket"), "{:?}", net.apis);
        assert!(
            net.functions.iter().any(|f| f.entry.0 == open_conn),
            "{arch}: open_conn not in {:?}",
            net.functions
        );
        let dns = get("DNS lookups");
        assert!(dns.functions.iter().any(|f| f.entry.0 == open_conn));
        let spawn = get("Spawns processes");
        assert!(
            spawn.functions.iter().any(|f| f.entry.0 == run_helper),
            "{arch}: {:?}",
            spawn.functions
        );
        // Severity ordering: high → info.
        let rank = |s: &str| {
            ["high", "medium", "low", "info"]
                .iter()
                .position(|x| *x == s)
        };
        assert!(
            b.windows(2)
                .all(|w| rank(w[0].severity) <= rank(w[1].severity))
        );
        // Without an analysis the rules still fire, without evidence.
        let bare = behaviors(&img, None);
        assert!(
            bare.iter()
                .any(|x| x.name == "Network sockets" && x.functions.is_empty())
        );
    }
}

/// True if the last instruction of `[start, end)` is a call to `target`.
fn block_ends_with_call_to(
    img: &drishti_loader::Image,
    start: u64,
    end: u64,
    targets: &[u64],
) -> bool {
    let mut dec = Isadec::new(img).expect("isa");
    let mut pc = start;
    let mut last = None;
    while pc < end {
        let Some(d) = dec.decode(pc) else { break };
        last = Some(d.flow);
        pc += u64::from(d.len);
    }
    matches!(last, Some(Flow::Call(t)) if targets.contains(&t))
}

#[test]
fn interprocedural_noreturn() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("noreturn");
    for &arch in archs() {
        for opt in ["-O0", "-O2"] {
            for file in ["netclient.c", "switches.c"] {
                let bin = build_one(&dir, file, opt, arch).expect("build");
                let truth_img = load(&bin);
                let t = truth(&truth_img);
                let img = load(&bin.with_extension("stripped"));
                let a = run(&img);
                let noret: Vec<&str> = if file == "netclient.c" {
                    vec!["fatal", "usage"]
                } else {
                    vec!["die"]
                };
                let mut targets = Vec::new();
                for n in &noret {
                    let at = sym(&truth_img, n);
                    let f = a.function_at(at).unwrap_or_else(|| panic!("{n} not found"));
                    assert!(f.noreturn, "{file} {arch}{opt}: {n} should be noreturn");
                    targets.push(at);
                }
                for f in &a.functions {
                    let name = t.get(&f.entry).map(String::as_str).unwrap_or("");
                    if ["main", "must", "open_conn", "parse_port", "dense", "fib"].contains(&name) {
                        assert!(!f.noreturn, "{file} {arch}{opt}: {name} wrongly noreturn");
                    }
                    // No fall-through out of a block that ends in a no-return call.
                    let cfg = a.cfg(&img, f.entry).expect("cfg");
                    for b in &cfg {
                        if block_ends_with_call_to(&img, b.start, b.end, &targets) {
                            assert!(
                                b.succs.is_empty(),
                                "{file} {arch}{opt}: block {:#x} in {name} falls through after a noreturn call",
                                b.start
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn self_diff_is_unchanged() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("selfdiff");
    let bin = build_one(&dir, "netclient.c", "-O2", archs()[0]).expect("build");
    let img = load(&bin.with_extension("stripped"));
    let a = run(&img);
    let img2 = load(&bin.with_extension("stripped"));
    let b = run(&img2);
    let d = diff(&img, &a, &img2, &b);
    assert!(
        d.changed.is_empty() && d.added.is_empty() && d.removed.is_empty(),
        "{d:?}"
    );
    assert_eq!(d.unchanged, a.functions.len());
}

/// Diff an -O0 build against an -O2 build of the same source (both
/// stripped) and score pairs against the symbols of the unstripped builds.
/// Only functions present in both builds (not inlined away) count.
fn diff_match_rate(file: &str, arch: &str, dir: &TempDir) -> (usize, usize, Vec<String>) {
    let o0 = build_one(dir, file, "-O0", arch).expect("build O0");
    let o2 = build_one(dir, file, "-O2", arch).expect("build O2");
    let t0 = truth(&load(&o0));
    let t2 = truth(&load(&o2));
    let i0 = load(&o0.with_extension("stripped"));
    let i2 = load(&o2.with_extension("stripped"));
    let a0 = run(&i0);
    let a2 = run(&i2);
    let d = diff(&i0, &a0, &i2, &a2);
    let pairs: std::collections::HashMap<u64, u64> = d.pairs.iter().copied().collect();
    let names2: std::collections::HashMap<&str, u64> =
        t2.iter().map(|(a, n)| (n.as_str(), *a)).collect();
    let mut total = 0;
    let mut ok = 0;
    let mut wrong = Vec::new();
    for (a, n) in &t0 {
        let Some(&want) = names2.get(n.as_str()) else {
            continue; // inlined away at -O2
        };
        total += 1;
        match pairs.get(a) {
            Some(&got) if got == want => ok += 1,
            Some(&got) => wrong.push(format!(
                "{n}: paired with {}",
                t2.get(&got).map(String::as_str).unwrap_or("?")
            )),
            None => wrong.push(format!("{n}: unmatched")),
        }
    }
    (ok, total, wrong)
}

#[test]
fn diff_matches_across_optimisation_levels() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("diffopt");
    let mut ok = 0;
    let mut total = 0;
    let mut report = Vec::new();
    for &arch in archs() {
        for file in ["netclient.c", "switches.c"] {
            let (o, t, w) = diff_match_rate(file, arch, &dir);
            ok += o;
            total += t;
            report.push(format!("{file} {arch}: {o}/{t} {w:?}"));
        }
    }
    let rate = ok as f64 / total.max(1) as f64;
    eprintln!(
        "diff O0↔O2: {ok}/{total} = {rate:.2}\n{}",
        report.join("\n")
    );
    assert!(total > 0);
    assert!(rate >= 0.8, "match rate {rate:.2}\n{}", report.join("\n"));
}

#[test]
fn analysis_cache_round_trip_on_real_binaries() {
    if !have_clang() {
        return;
    }
    let dir = TempDir::new("cache");
    for &arch in archs() {
        let bin = build_one(&dir, "netclient.c", "-O2", arch).expect("build");
        let img = load(&bin.with_extension("stripped"));
        let a = run(&img);
        let bytes = drishti_disasm::cache::encode(&a);
        let b = drishti_disasm::cache::decode(&bytes).expect("decode");
        assert_eq!(a.functions.len(), b.functions.len());
        assert_eq!(a.xrefs, b.xrefs);
        for (x, y) in a.functions.iter().zip(&b.functions) {
            assert_eq!(
                (
                    x.entry,
                    &x.name,
                    x.noreturn,
                    &x.calls,
                    &x.called_by,
                    &x.ranges
                ),
                (
                    y.entry,
                    &y.name,
                    y.noreturn,
                    &y.calls,
                    &y.called_by,
                    &y.ranges
                )
            );
            // CFGs rebuilt from the cached analysis are identical.
            let ca = a.cfg(&img, x.entry).expect("cfg");
            let cb = b.cfg(&img, y.entry).expect("cfg");
            assert_eq!(ca.len(), cb.len());
            for (p, q) in ca.iter().zip(&cb) {
                assert_eq!((p.start, p.end, &p.succs), (q.start, q.end, &q.succs));
            }
            let lo = x.ranges.first().map(|r| r.0).unwrap_or(x.entry);
            let hi = x.ranges.last().map(|r| r.1).unwrap_or(x.entry);
            assert_eq!(a.xrefs_from(lo, hi), b.xrefs_from(lo, hi));
        }
    }
}

/// ELF imports are GOT slots, referenced only by the PLT stub's `jmp`: the
/// behaviour must name the stub's caller, not the stub (this only showed on
/// Linux CI before the fixture existed).
#[test]
fn elf_plt_behaviours_name_the_caller() {
    let p =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elf-x86_64-plt.bin");
    let img = load(&p);
    let a = run(&img);
    let open_conn = sym(&img, "open_conn");
    let b = behaviors(&img, Some(&a));
    for n in ["Network sockets", "DNS lookups"] {
        let x = b
            .iter()
            .find(|x| x.name == n)
            .unwrap_or_else(|| panic!("{n} missing"));
        let entries: Vec<u64> = x.functions.iter().map(|f| f.entry.0).collect();
        assert_eq!(entries, vec![open_conn], "{n}");
    }
}
