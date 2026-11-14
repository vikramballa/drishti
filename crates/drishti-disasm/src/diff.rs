//! Binary diffing: match functions between two versions of a program and
//! report what was added, removed or changed (BinDiff-style, lightweight).
//!
//! Matching order: symbol name → identical position-independent
//! fingerprint (unique on both sides) → iterative similarity of features
//! that survive recompilation (imported callees, referenced strings and
//! constant data, distinctive immediates, arithmetic op classes) plus
//! already-matched call-graph neighbours → positional pairing of the
//! unmatched runs between two matched anchors.

use crate::analyze::{Analysis, Func};
use crate::arch::decode_x86;
use drishti_loader::Image;
use drishti_model::{Addr, Arch, NameSource};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

fn mix(h: u64, v: u64) -> u64 {
    (h ^ v).wrapping_mul(0x0000_0100_0000_01b3)
}

/// Hash of a function's instructions with addresses masked out, so the
/// same code at a different location hashes identically.
pub fn fingerprint(img: &Image, f: &Func) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut scratch = iced_x86::Instruction::default();
    for &(s, e) in f.ranges.iter() {
        let Some(bytes) = img.read(s, (e - s) as usize) else {
            continue;
        };
        match img.arch {
            Arch::Aarch64 => {
                for w in bytes.chunks_exact(4) {
                    let i = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                    // Mask PC-relative immediates: B/BL, B.cond/CBZ, TBZ, ADR/ADRP, LDR literal.
                    let m = if i & 0x7c00_0000 == 0x1400_0000 {
                        i & 0xfc00_0000
                    } else if i & 0xff00_0000 == 0x5400_0000
                        || i & 0x7e00_0000 == 0x3400_0000
                        || i & 0x3b00_0000 == 0x1800_0000
                    {
                        i & 0xff00_001f
                    } else if i & 0x7e00_0000 == 0x3600_0000 {
                        i & 0xfff8_001f
                    } else if i & 0x1f00_0000 == 0x1000_0000 {
                        i & 0x9f00_001f
                    } else if i & 0xff80_0000 == 0x9100_0000 || i & 0x3b00_0000 == 0x3900_0000 {
                        // add / load-store immediates following adrp: page offsets move.
                        i & 0xffc0_03ff
                    } else {
                        i
                    };
                    h = mix(h, u64::from(m));
                }
            }
            Arch::X86 | Arch::X86_64 => {
                let bits = if img.arch == Arch::X86 { 32 } else { 64 };
                let mut off = 0usize;
                while off < bytes.len() {
                    let Some(d) = decode_x86(&bytes[off..], s + off as u64, bits, &mut scratch)
                    else {
                        break;
                    };
                    h = mix(h, scratch.code() as u64);
                    h = mix(
                        h,
                        u64::from(scratch.op0_register() as u32) << 8
                            | u64::from(scratch.op1_register() as u32),
                    );
                    off += d.len as usize;
                }
            }
            _ => {}
        }
    }
    mix(h, u64::from(f.insns))
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffFn {
    pub name: String,
    pub old: Option<Addr>,
    pub new: Option<Addr>,
    pub old_size: u64,
    pub new_size: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Diff {
    pub unchanged: usize,
    pub changed: Vec<DiffFn>,
    pub added: Vec<DiffFn>,
    pub removed: Vec<DiffFn>,
    pub truncated: bool,
    /// Every matched pair (old entry, new entry), changed or not.
    #[serde(skip)]
    pub pairs: Vec<(u64, u64)>,
}

const MAX_LIST: usize = 2000;

pub fn diff(old_img: &Image, old: &Analysis, new_img: &Image, new: &Analysis) -> Diff {
    let fo: Vec<u64> = old
        .functions
        .iter()
        .map(|f| fingerprint(old_img, f))
        .collect();
    let fnw: Vec<u64> = new
        .functions
        .iter()
        .map(|f| fingerprint(new_img, f))
        .collect();
    let mut m_old: Vec<Option<usize>> = vec![None; old.functions.len()];
    let mut m_new: Vec<Option<usize>> = vec![None; new.functions.len()];

    // 1. By symbol name (unique names only).
    let mut by_name: HashMap<&str, Option<usize>> = HashMap::new();
    for (i, f) in new.functions.iter().enumerate() {
        if f.name_source == NameSource::Symbol {
            by_name
                .entry(&f.name)
                .and_modify(|v| *v = None)
                .or_insert(Some(i));
        }
    }
    for (i, f) in old.functions.iter().enumerate() {
        if f.name_source == NameSource::Symbol
            && let Some(Some(j)) = by_name.get(&*f.name)
            && m_new[*j].is_none()
        {
            m_old[i] = Some(*j);
            m_new[*j] = Some(i);
        }
    }
    // 2. By fingerprint unique on both sides.
    let mut cnt_o: HashMap<u64, (u32, usize)> = HashMap::new();
    for (i, &h) in fo.iter().enumerate() {
        if m_old[i].is_none() {
            let e = cnt_o.entry(h).or_insert((0, i));
            e.0 += 1;
        }
    }
    let mut cnt_n: HashMap<u64, (u32, usize)> = HashMap::new();
    for (j, &h) in fnw.iter().enumerate() {
        if m_new[j].is_none() {
            let e = cnt_n.entry(h).or_insert((0, j));
            e.0 += 1;
        }
    }
    for (h, &(c, i)) in &cnt_o {
        if c == 1
            && let Some(&(1, j)) = cnt_n.get(h)
        {
            m_old[i] = Some(j);
            m_new[j] = Some(i);
        }
    }
    // 3. Similarity of optimisation-stable features + call-graph neighbours.
    similarity_match(old_img, old, new_img, new, &mut m_old, &mut m_new);
    // 4. Positional pairing between anchors: equal-length unmatched runs.
    positional_match(&mut m_old, &mut m_new);

    let mut d = Diff::default();
    let item = |o: Option<&Func>, n: Option<&Func>| DiffFn {
        name: n.or(o).map(|f| f.name.to_string()).unwrap_or_default(),
        old: o.map(|f| Addr(f.entry)),
        new: n.map(|f| Addr(f.entry)),
        old_size: o.map(|f| f.size).unwrap_or(0),
        new_size: n.map(|f| f.size).unwrap_or(0),
    };
    for (i, f) in old.functions.iter().enumerate() {
        match m_old[i] {
            Some(j) => {
                d.pairs.push((f.entry, new.functions[j].entry));
                if fo[i] == fnw[j] {
                    d.unchanged += 1;
                } else if d.changed.len() < MAX_LIST {
                    d.changed.push(item(Some(f), Some(&new.functions[j])));
                } else {
                    d.truncated = true;
                }
            }
            None if f.is_thunk => {}
            None => {
                if d.removed.len() < MAX_LIST {
                    d.removed.push(item(Some(f), None));
                } else {
                    d.truncated = true;
                }
            }
        }
    }
    for (j, f) in new.functions.iter().enumerate() {
        if m_new[j].is_none() && !f.is_thunk {
            if d.added.len() < MAX_LIST {
                d.added.push(item(None, Some(f)));
            } else {
                d.truncated = true;
            }
        }
    }
    // Named changes first: they are the most meaningful to read.
    d.changed
        .sort_by_key(|c| (!c.name.starts_with("sub_") as u8 ^ 1, c.new));
    d
}

/// Pair equal-length unmatched runs that sit between the same anchors.
fn positional_match(m_old: &mut [Option<usize>], m_new: &mut [Option<usize>]) {
    let mut i = 0;
    let mut j = 0;
    while i < m_old.len() && j < m_new.len() {
        if let Some(t) = m_old[i] {
            if t >= j {
                j = t + 1;
            }
            i += 1;
            continue;
        }
        let ri = (i..m_old.len()).take_while(|&k| m_old[k].is_none()).count();
        while j < m_new.len() && m_new[j].is_some() {
            j += 1;
        }
        let rj = (j..m_new.len()).take_while(|&k| m_new[k].is_none()).count();
        // Only pair when the next anchors agree (same run on both sides).
        let anchor_ok = match (m_old.get(i + ri).copied().flatten(), j + rj) {
            (Some(t), e) => t == e,
            (None, e) => i + ri == m_old.len() && e == m_new.len(),
        };
        if ri == rj && anchor_ok {
            for k in 0..ri {
                m_old[i + k] = Some(j + k);
                m_new[j + k] = Some(i + k);
            }
        }
        i += ri;
        j += rj;
    }
}

// ---------------------------------------------------------------------------
// Similarity matching

/// Feature kinds (folded into the hashed feature) and their weights.
const F_IMPORT: u64 = 1;
const F_STRING: u64 = 2;
const F_DATA: u64 = 3;
const F_IMM: u64 = 4;
const F_OP: u64 = 5;
const F_CALLEE: u64 = 6;
const F_CALLER: u64 = 7;

fn weight(kind: u64) -> f32 {
    match kind {
        F_STRING => 4.0,
        F_IMPORT => 3.0,
        F_DATA | F_IMM | F_CALLEE | F_CALLER => 2.0,
        _ => 1.0,
    }
}

fn feat(kind: u64, v: u64) -> u64 {
    // Low 3 bits carry the kind, so weights can be recovered from the hash.
    (mix(mix(0xcbf2_9ce4_8422_2325, kind), v) & !7) | kind
}

fn hash_bytes(b: &[u8]) -> u64 {
    b.iter()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, &c| mix(h, u64::from(c)))
}

/// Features that do not depend on addresses: sorted, deduplicated.
fn static_features(img: &Image, a: &Analysis, f: &Func) -> Vec<u64> {
    let mut out = Vec::new();
    // Imported callees by name (via thunk or import slot).
    for &c in f.calls.iter() {
        let name = match a.function_at(c) {
            Some(t) if t.is_thunk => Some(t.name.to_string()),
            Some(_) => None,
            None => img.import_at(c).map(|s| s.display_name().to_string()),
        };
        if let Some(n) = name {
            out.push(feat(
                F_IMPORT,
                hash_bytes(n.trim_start_matches('_').as_bytes()),
            ));
        }
    }
    // Referenced strings and constant data, by content.
    for &(s, e) in f.ranges.iter() {
        for x in a.xrefs_from(s, e) {
            if x.kind != drishti_model::XrefKind::DataRead || img.is_code(x.to) {
                continue;
            }
            let Some(b) = img.read(x.to, 64) else {
                continue;
            };
            let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            if n >= 4
                && b[..n]
                    .iter()
                    .all(|c| (0x20..0x7f).contains(c) || *c == b'\n')
            {
                out.push(feat(F_STRING, hash_bytes(&b[..n])));
            } else if b.len() >= 16 && b[..16].iter().any(|&c| c != 0) {
                out.push(feat(F_DATA, hash_bytes(&b[..16])));
            }
        }
    }
    instruction_features(img, f, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

fn keep_imm(img: &Image, v: u64) -> bool {
    (3..=0xffff_ffff).contains(&v) && !img.is_mapped(v)
}

/// Distinctive immediates and arithmetic op classes.
fn instruction_features(img: &Image, f: &Func, out: &mut Vec<u64>) {
    let mut scratch = iced_x86::Instruction::default();
    let mut budget = 4096usize;
    for &(s, e) in f.ranges.iter() {
        let Some(bytes) = img.read(s, (e - s) as usize) else {
            continue;
        };
        match img.arch {
            Arch::Aarch64 => {
                for w in bytes.chunks_exact(4) {
                    let i = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
                    a64_features(img, i, out);
                }
            }
            Arch::X86 | Arch::X86_64 => {
                let bits = if img.arch == Arch::X86 { 32 } else { 64 };
                let mut off = 0usize;
                while off < bytes.len() && budget > 0 {
                    budget -= 1;
                    let Some(d) = decode_x86(&bytes[off..], s + off as u64, bits, &mut scratch)
                    else {
                        break;
                    };
                    x86_features(img, &scratch, out);
                    off += d.len as usize;
                }
            }
            _ => {}
        }
    }
}

fn a64_features(img: &Image, i: u32, out: &mut Vec<u64>) {
    let rd = i & 31;
    let rn = (i >> 5) & 31;
    if i & 0x1f80_0000 == 0x1280_0000 {
        // MOVN / MOVZ / MOVK: imm16 << 16*hw
        let opc = (i >> 29) & 3;
        let v = u64::from((i >> 5) & 0xffff) << (16 * ((i >> 21) & 3));
        if opc != 1 && keep_imm(img, v) {
            out.push(feat(F_IMM, v ^ u64::from(opc == 0) << 40));
        }
    } else if i & 0x1f00_0000 == 0x1100_0000 && (i >> 29) & 1 == 1 && rn != 31 {
        // ADDS / SUBS immediate (cmp / cmn): bounds and constants.
        let v = u64::from((i >> 10) & 0xfff) << if (i >> 22) & 1 == 1 { 12 } else { 0 };
        if keep_imm(img, v) {
            out.push(feat(F_IMM, v));
        }
    } else if i & 0x1f00_0000 == 0x1b00_0000 {
        out.push(feat(F_OP, 1)); // mul / madd / msub / smull / umulh
    } else if i & 0x7fe0_f800 == 0x1ac0_0800 {
        out.push(feat(F_OP, 2)); // udiv / sdiv
    } else if i & 0x7fe0_f000 == 0x1ac0_2000 {
        out.push(feat(F_OP, 3)); // variable shifts
    } else if i & 0x1f00_0000 == 0x0a00_0000 || i & 0x1f80_0000 == 0x1200_0000 {
        // Logical (shifted register / immediate); ORR from zr is `mov`.
        let opc = (i >> 29) & 3;
        if !((opc == 1 && rn == 31) || (opc == 3 && rd == 31)) {
            out.push(feat(F_OP, 4 + u64::from(opc)));
        }
    } else if i & 0x5f00_0000 == 0x1e00_0000 {
        out.push(feat(F_OP, 8)); // scalar floating point
    }
}

fn x86_features(img: &Image, ins: &iced_x86::Instruction, out: &mut Vec<u64>) {
    use iced_x86::{Mnemonic as M, OpKind, Register};
    let m = ins.mnemonic();
    let class = match m {
        M::Imul | M::Mul => Some(1),
        M::Idiv | M::Div => Some(2),
        M::Shl | M::Shr | M::Sar | M::Rol | M::Ror => Some(3),
        M::And => Some(4),
        M::Or => Some(5),
        M::Xor
            if !(ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register()) =>
        {
            Some(6)
        }
        M::Test => Some(7),
        M::Addsd | M::Subsd | M::Mulsd | M::Divsd | M::Addss | M::Mulss | M::Cvtsi2sd => Some(8),
        _ => None,
    };
    if let Some(c) = class {
        out.push(feat(F_OP, c));
    }
    if !matches!(
        m,
        M::Cmp | M::Mov | M::And | M::Or | M::Xor | M::Test | M::Imul
    ) {
        return;
    }
    let stacky = |r: Register| {
        matches!(
            r.full_register(),
            Register::RSP | Register::RBP | Register::ESP | Register::EBP
        )
    };
    if stacky(ins.op0_register()) || stacky(ins.memory_base()) && m != M::Cmp && m != M::Mov {
        return;
    }
    for k in 0..ins.op_count() {
        let v = match ins.op_kind(k) {
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => ins.immediate(k),
            _ => continue,
        };
        // Sign-extended small negatives: compare the 32-bit pattern.
        let v = v & 0xffff_ffff;
        if keep_imm(img, v) {
            out.push(feat(F_IMM, v));
        }
    }
}

/// Calls/callers that are already matched, in the new binary's address space.
fn neighbour_features(f: &Func, to_new: &dyn Fn(u64) -> Option<u64>, out: &mut Vec<u64>) {
    for &c in f.calls.iter().take(256) {
        if let Some(n) = to_new(c) {
            out.push(feat(F_CALLEE, n));
        }
    }
    for &c in f.called_by.iter().take(256) {
        if let Some(n) = to_new(c) {
            out.push(feat(F_CALLER, n));
        }
    }
}

fn wsum(v: &[u64]) -> f32 {
    v.iter().map(|&h| weight(h & 7)).sum()
}

/// Weighted Jaccard of two sorted feature sets.
fn jaccard(a: &[u64], b: &[u64]) -> f32 {
    let (mut i, mut j, mut inter) = (0, 0, 0f32);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += weight(a[i] & 7);
                i += 1;
                j += 1;
            }
        }
    }
    let uni = wsum(a) + wsum(b) - inter;
    if uni <= 0.0 { 0.0 } else { inter / uni }
}

fn ratio(a: u32, b: u32) -> f32 {
    let (lo, hi) = (a.min(b) as f32, a.max(b).max(1) as f32);
    lo / hi
}

/// Feature lists of unmatched functions, cap per side (bounded work).
const MAX_SIM: usize = 200_000;

fn similarity_match(
    old_img: &Image,
    old: &Analysis,
    new_img: &Image,
    new: &Analysis,
    m_old: &mut [Option<usize>],
    m_new: &mut [Option<usize>],
) {
    let unmatched_old: Vec<usize> = (0..m_old.len())
        .filter(|&i| m_old[i].is_none() && !old.functions[i].is_thunk)
        .take(MAX_SIM)
        .collect();
    let unmatched_new: Vec<usize> = (0..m_new.len())
        .filter(|&j| m_new[j].is_none() && !new.functions[j].is_thunk)
        .take(MAX_SIM)
        .collect();
    if unmatched_old.is_empty() || unmatched_new.is_empty() {
        return;
    }
    let st_old: HashMap<usize, Vec<u64>> = unmatched_old
        .iter()
        .map(|&i| (i, static_features(old_img, old, &old.functions[i])))
        .collect();
    let st_new: HashMap<usize, Vec<u64>> = unmatched_new
        .iter()
        .map(|&j| (j, static_features(new_img, new, &new.functions[j])))
        .collect();
    let idx_of = |a: &Analysis, e: u64| a.functions.binary_search_by_key(&e, |f| f.entry).ok();

    for _round in 0..8 {
        // Full feature sets for this round (static + matched neighbours).
        let full = |a: &Analysis, f: &Func, st: &[u64], to_new: &dyn Fn(u64) -> Option<u64>| {
            let mut v = st.to_vec();
            neighbour_features(f, to_new, &mut v);
            let _ = a;
            v.sort_unstable();
            v.dedup();
            v
        };
        let old_to_new = |e: u64| {
            idx_of(old, e)
                .and_then(|i| m_old[i])
                .map(|j| new.functions[j].entry)
        };
        let new_self = |e: u64| idx_of(new, e).and_then(|j| m_new[j].map(|_| e));
        let fo: Vec<(usize, Vec<u64>)> = unmatched_old
            .iter()
            .filter(|&&i| m_old[i].is_none())
            .map(|&i| (i, full(old, &old.functions[i], &st_old[&i], &old_to_new)))
            .filter(|(_, v)| !v.is_empty())
            .collect();
        let fnw: HashMap<usize, Vec<u64>> = unmatched_new
            .iter()
            .filter(|&&j| m_new[j].is_none())
            .map(|&j| (j, full(new, &new.functions[j], &st_new[&j], &new_self)))
            .filter(|(_, v)| !v.is_empty())
            .collect();
        // Inverted index; very common features carry no identity.
        let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
        for (&j, v) in &fnw {
            for &h in v {
                index.entry(h).or_default().push(j);
            }
        }
        index.retain(|_, v| v.len() <= 64);
        let score = |i: usize, fi: &[u64], j: usize| {
            let fj = &fnw[&j];
            let a = &old.functions[i];
            let b = &new.functions[j];
            0.85 * jaccard(fi, fj) + 0.15 * ratio(a.nblocks, b.nblocks)
        };
        // Best candidate per old function.
        let mut best_old: HashMap<usize, (usize, f32, f32)> = HashMap::new();
        for (i, fi) in &fo {
            let mut cands: HashSet<usize> = HashSet::new();
            for h in fi {
                if let Some(v) = index.get(h) {
                    cands.extend(v.iter().copied());
                }
            }
            let mut top = (usize::MAX, 0f32, 0f32);
            for j in cands {
                let sc = score(*i, fi, j);
                if sc > top.1 {
                    top = (j, sc, top.1);
                } else if sc > top.2 {
                    top.2 = sc;
                }
            }
            if top.0 != usize::MAX {
                best_old.insert(*i, top);
            }
        }
        // Best and runner-up old candidate per new function (mutual-best checks).
        let mut best_new: HashMap<usize, (usize, f32, f32)> = HashMap::new();
        for (&i, &(j, sc, _)) in &best_old {
            let e = best_new.entry(j).or_insert((usize::MAX, 0.0, 0.0));
            if sc > e.1 {
                *e = (i, sc, e.1);
            } else if sc > e.2 {
                e.2 = sc;
            }
        }
        let mut added = 0;
        for (&i, &(j, sc, second)) in &best_old {
            // Mutual best, clearly ahead of the runner-up on both sides.
            let ok_new = best_new
                .get(&j)
                .is_some_and(|&(bi, _, s2)| bi == i && sc - s2 >= 0.05);
            if ok_new && sc >= 0.35 && sc - second >= 0.05 && m_new[j].is_none() {
                m_old[i] = Some(j);
                m_new[j] = Some(i);
                added += 1;
            }
        }
        if added == 0 {
            break;
        }
    }
}
