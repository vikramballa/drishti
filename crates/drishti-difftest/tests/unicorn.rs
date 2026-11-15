//! Lifter + IR interpreter vs Unicorn, one instruction at a time.
//! `make difftest`; `PROPTEST_CASES=N` for a longer run.

use drishti_difftest::*;
use proptest::prelude::*;
use proptest::strategy::ValueTree;

fn zero() -> Machine {
    Machine {
        x: [0; 31],
        sp: DATA + DATA_LEN / 2,
        nzcv: 0,
        v: [0; 32],
        tpidr: 0,
        tpidrro: 0,
    }
}

fn same(word: u32, m: &Machine, w: &Windows) {
    let (ir, uc) = run_both(word, m, w).expect("ir").expect("unicorn");
    if let Some(d) = diff(&ir, &uc) {
        panic!("{word:#010x}: {d}");
    }
}

/// Day 11: one hand-written instruction behaves the same in both.
#[test]
fn one_instruction_matches() {
    let mut m = zero();
    m.x[1] = 0x1234;
    // add x0, x1, #0x10
    same(0x9100_4020, &m, &vec![]);
    let uc = run_unicorn(0x9100_4020, &m, &vec![]).expect("unicorn");
    assert_eq!(uc.m.x[0], 0x1244);
    assert_eq!(uc.next_pc, PC + 4);
}

/// Hand-picked instructions with known traps (flags, sign extension,
/// writeback, SP, NZCV round trip, atomics, vectors, branches).
#[test]
fn hand_picked_instructions_match() {
    let mut m = zero();
    for (n, v) in m.x.iter_mut().enumerate() {
        *v = DATA + 0x8_0000 + 0x100 * n as u64;
    }
    m.x[2] = 0x8000_0000_0000_0001;
    m.x[3] = 7;
    m.nzcv = 0b0110;
    m.v[1] = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210;
    let mut win = Vec::new();
    for k in 0..31u64 {
        let base = DATA + 0x8_0000 + 0x100 * k;
        win.push((
            base,
            (0..0x100)
                .map(|i| (i as u8).wrapping_mul(37) ^ k as u8)
                .collect(),
        ));
    }
    let words = [
        0xab02_0020u32, // adds x0, x1, x2
        0xfa02_0020,    // sbcs x0, x1, x2
        0x3a43_1824,    // ccmn w1, #3, #4, ne
        0x9a82_0020,    // csel x0, x1, x2, eq
        0xda81_a420,    // cneg x0, x1, lt
        0x9b42_7c20,    // smulh x0, x1, x2
        0xdac0_1420,    // cls x0, x1
        0xdac0_0020,    // rbit x0, x1
        0xb378_1c20,    // bfi x0, x1, #8, #8
        0x937f_fc20,    // asr x0, x1, #63
        0xf81f_0c22,    // str x2, [x1, #-16]!
        0xf841_0420,    // ldr x0, [x1], #16
        0x7880_7020,    // ldursh x0, [x1, #7]
        0xa9bf_7bfd,    // stp x29, x30, [sp, #-16]!
        0x6940_0440,    // ldpsw x0, x1, [x2]  (x2 is not a pointer: fault → skip)
        0xf822_0020,    // ldadd x2, x0, [x1]
        0xc8a4_7c26,    // cas x4, x6, [x1]
        0xb822_6020,    // ldumax w2, w0, [x1]
        0x4cdf_a040,    // ld1 {v0.16b, v1.16b}, [x2], #32 (x2 not a pointer)
        0x4e04_0c24,    // dup v4.4s, w1
        0x0e07_3c20,    // umov w0, v1.b[3]
        0x4e0c_1fe4,    // mov v4.s[1], wzr
        0x6e25_1ca5,    // eor v5.16b, v5.16b, v5.16b
        0x1e6e_1001,    // fmov d1, #1.0
        0xd53b_4201,    // mrs x1, nzcv
        0xd51b_4203,    // msr nzcv, x3
        0x5400_004c,    // b.gt #8
        0xb708_0040,    // tbnz x0, #33, #8
        0x97ff_ffff,    // bl #-4
        0xd63f_03c0,    // blr x30
        0xd65f_03c0,    // ret
    ];
    let mut ran = 0;
    for w in words {
        let uc = match run_unicorn(w, &m, &win) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("skipped {w:#010x}: {e}");
                continue;
            }
        };
        let ir = run_ir(w, &m, &win).unwrap_or_else(|e| panic!("{w:#010x}: {e}"));
        if let Some(d) = diff(&ir, &uc) {
            panic!("{w:#010x}: {d}");
        }
        ran += 1;
    }
    assert!(ran >= 28, "only {ran} ran in Unicorn");
}

/// Instruction groups the lifter handles: (fixed-bit mask, value, uses
/// memory). Other bits are random.
const GROUPS: &[(u32, u32, bool)] = &[
    (0x1f00_0000, 0x1000_0000, false), // ADR/ADRP
    (0x1f80_0000, 0x1100_0000, false), // add/sub immediate
    (0x1f80_0000, 0x1200_0000, false), // logical immediate
    (0x1f80_0000, 0x1280_0000, false), // move wide
    (0x1f80_0000, 0x1300_0000, false), // bitfield
    (0x1fa0_0000, 0x1380_0000, false), // extract
    (0x7c00_0000, 0x1400_0000, false), // B/BL
    (0xff00_0010, 0x5400_0000, false), // B.cond
    (0x7e00_0000, 0x3400_0000, false), // CBZ/CBNZ
    (0x7e00_0000, 0x3600_0000, false), // TBZ/TBNZ
    (0xfe1f_fc1f, 0xd61f_0000, false), // BR/BLR/RET (plain)
    (0xffff_f01f, 0xd503_201f, false), // hints
    (0xffff_f01f, 0xd503_301f, false), // barriers
    (0x1f00_0000, 0x0a00_0000, false), // logical shifted register
    (0x1f20_0000, 0x0b00_0000, false), // add/sub shifted register
    (0x1f20_0000, 0x0b20_0000, false), // add/sub extended register
    (0x1fe0_fc00, 0x1a00_0000, false), // ADC/SBC
    (0x3fe0_0010, 0x3a40_0000, false), // CCMP/CCMN
    (0x3fe0_0000, 0x1a80_0000, false), // conditional select
    (0x7fe0_0000, 0x1ac0_0000, false), // data processing, 2 source
    (0x7fe0_0000, 0x5ac0_0000, false), // data processing, 1 source
    (0x1f00_0000, 0x1b00_0000, false), // data processing, 3 source
    (0x3b00_0000, 0x1800_0000, true),  // load literal
    (0x3a00_0000, 0x2800_0000, true),  // load/store pair
    (0x3f00_0000, 0x0800_0000, true),  // exclusive / ordered / CAS
    (0xbfbf_0000, 0x0c00_0000, true),  // LD1/ST1 multiple
    (0xbfa0_0000, 0x0c80_0000, true),  // LD1/ST1 multiple, post-index
    (0x3b00_0000, 0x3900_0000, true),  // load/store unsigned offset
    (0x3b20_0000, 0x3800_0000, true),  // load/store imm9
    (0x3b20_0c00, 0x3820_0800, true),  // load/store register offset
    (0x3f20_0c00, 0x3820_0000, true),  // LSE atomics
    (0x7f36_fc00, 0x1e26_0000, false), // FMOV general
    (0xff3f_fc00, 0x1e20_4000, false), // FMOV register
    (0xff20_1fe0, 0x1e20_1000, false), // FMOV immediate
    (0x9ff8_0400, 0x0f00_0400, false), // SIMD modified immediate
    (0x9fe0_8400, 0x0e00_0400, false), // SIMD copy
    (0x9f20_fc00, 0x0e20_1c00, false), // SIMD logical three-same
];

#[derive(Debug, Clone)]
struct Case {
    word: u32,
    m: Machine,
    win: Windows,
}

fn case() -> impl Strategy<Value = Case> {
    (
        0..GROUPS.len(),
        any::<u32>(),
        prop::array::uniform31(any::<u64>()),
        prop::array::uniform31(0u8..4),
        any::<u8>(),
        prop::array::uniform32(any::<u128>()),
        any::<(u64, u64, u64)>(),
    )
        .prop_map(|(g, bits, raw, kind, nzcv, v, (sp, t0, t1))| {
            let (mask, val, mem) = GROUPS[g];
            let word = val | (bits & !mask);
            // Memory groups: keep the base register a pointer and index
            // registers small, so most cases don't fault.
            let mid = DATA + DATA_LEN / 2;
            let ptr = |r: u64| (mid - 0x4000 + (r % 0x8000)) & !0xf;
            let mut x = [0u64; 31];
            for n in 0..31 {
                x[n] = match (mem, kind[n]) {
                    (true, 0 | 1) => ptr(raw[n]),
                    (true, 2) => raw[n] % 64,
                    (false, 0) => raw[n] % 256,
                    (false, 1) => (raw[n] as i64 % 256) as u64,
                    _ => raw[n],
                };
            }
            if mem {
                let rn = ((word >> 5) & 0x1f) as usize;
                if rn < 31 {
                    x[rn] = ptr(raw[rn]);
                }
            }
            let mut win: Windows = Vec::new();
            let lo = mid - 0x5000;
            let fill: Vec<u8> = (0..0xa000u64)
                .map(|i| (i.wrapping_mul(0x9e37_79b9).wrapping_add(t0) >> 13) as u8)
                .collect();
            win.push((lo, fill));
            Case {
                word,
                m: Machine {
                    x,
                    sp: ptr(sp),
                    nzcv: nzcv & 0xf,
                    v,
                    tpidr: t0,
                    tpidrro: t1,
                },
                win,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 4000,
        max_global_rejects: 1_000_000,
        ..ProptestConfig::default()
    })]

    /// Day 12: random words from every lifted group, random state.
    #[test]
    fn random_instructions_match_unicorn(c in case()) {
        let mut probe = Vec::new();
        let lifted = drishti_ir::a64::lift(c.word, PC, &mut probe) == drishti_ir::a64::Lifted::Ok;
        prop_assume!(lifted && !excluded(c.word));
        // Faults (unmapped/unaligned access) and encodings Unicorn's CPU
        // model rejects are skipped; anything that runs must match.
        match run_both(c.word, &c.m, &c.win) {
            Err(e) => return Err(TestCaseError::fail(format!("{:#010x}: {e}", c.word))),
            Ok(None) => prop_assume!(false),
            Ok(Some((ir, uc))) => {
                if let Some(d) = diff(&ir, &uc) {
                    return Err(TestCaseError::fail(format!("{:#010x}: {d}", c.word)));
                }
            }
        }
    }
}

/// Per-group statistics over a deterministic random run: how many cases
/// actually executed, why the rest were skipped, and every word the lifter
/// accepts but the CPU model calls invalid (a decoder that accepts
/// unallocated encodings). `DIFF_PER_GROUP=N` (default 400).
#[test]
fn every_group_runs_and_matches() {
    let per: usize = std::env::var("DIFF_PER_GROUP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let mut rng = proptest::test_runner::TestRunner::deterministic();
    let strat = case();
    let mut mismatches = Vec::new();
    let mut invalid = Vec::new();
    let (mut total_ran, mut total) = (0usize, 0usize);
    for (g, &(mask, val, _)) in GROUPS.iter().enumerate() {
        let (mut ran, mut lifted, mut skipped) = (
            0usize,
            0usize,
            std::collections::BTreeMap::<String, usize>::new(),
        );
        let mut tries = 0;
        while lifted < per && tries < per * 20 {
            tries += 1;
            let mut c = strat.new_tree(&mut rng).expect("case").current();
            c.word = val | (c.word & !mask);
            // The state was built for another word: re-point this word's
            // base register (memory groups) at the data window.
            if GROUPS[g].2 {
                let rn = ((c.word >> 5) & 31) as usize;
                let p = (DATA + DATA_LEN / 2 - 0x4000
                    + (c.m.x.get(rn).copied().unwrap_or(c.m.sp) % 0x8000))
                    & !0xf;
                if rn < 31 {
                    c.m.x[rn] = p;
                } else {
                    c.m.sp = p;
                }
            }
            let mut probe = Vec::new();
            if drishti_ir::a64::lift(c.word, PC, &mut probe) != drishti_ir::a64::Lifted::Ok
                || excluded(c.word)
            {
                continue;
            }
            lifted += 1;
            if let Err(e) = run_unicorn(c.word, &c.m, &c.win) {
                if e.contains("INSN_INVALID") || e.contains("EXCEPTION") {
                    invalid.push(c.word);
                }
                *skipped.entry(e).or_default() += 1;
                continue;
            }
            ran += 1;
            match run_both(c.word, &c.m, &c.win) {
                Ok(Some((ir, uc))) => {
                    if let Some(d) = diff(&ir, &uc) {
                        mismatches.push(format!("{:#010x}: {d}", c.word));
                    }
                }
                Ok(None) => {
                    mismatches.push(format!("{:#010x}: unicorn failed on the probe run", c.word))
                }
                Err(e) => mismatches.push(format!("{:#010x}: {e}", c.word)),
            }
        }
        total += lifted;
        total_ran += ran;
        eprintln!("group {g:>2} {val:#010x}: {ran:>4}/{lifted:<4} ran  skipped {skipped:?}");
    }
    invalid.sort_unstable();
    invalid.dedup();
    eprintln!(
        "ran {total_ran} of {total} lifted cases; {} mismatches; {} lifted-but-invalid words",
        mismatches.len(),
        invalid.len()
    );
    for m in mismatches.iter().take(30) {
        eprintln!("  MISMATCH {m}");
    }
    for w in invalid.iter().take(30) {
        eprintln!("  INVALID-IN-UNICORN {w:#010x}");
    }
    assert!(mismatches.is_empty(), "{} mismatches", mismatches.len());
    assert!(
        invalid.is_empty(),
        "the lifter accepts {} encodings the CPU model rejects",
        invalid.len()
    );
    assert!(
        total_ran * 10 >= total * 9,
        "only {total_ran} of {total} cases ran"
    );
}
