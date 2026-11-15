//! Lifting analysed functions to the Drishti IR (milestone B2, Days 9–10).
//!
//! Only AArch64 has a lifter so far (`drishti_ir::a64`). A function is
//! lifted from the code ranges the analysis recorded for it, one machine
//! instruction at a time; nothing is lifted until someone asks for a
//! function, and [`LiftCache`] keeps recent results within a byte budget so
//! lifting never grows memory without bound.

use crate::analyze::{Analysis, Func};
use drishti_ir::a64::{self, Lifted};
use drishti_ir::{Insn, Op};
use drishti_loader::Image;
use drishti_model::Arch;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

thread_local! {
    /// Reused lifting buffer: each function is then copied out once at its
    /// exact size, instead of growing (and re-allocating) a fresh vector.
    static SCRATCH: RefCell<Vec<Insn>> = const { RefCell::new(Vec::new()) };
}
/// Scratch kept between calls (larger buffers are released after use).
const SCRATCH_KEEP: usize = 1 << 16;

/// Instructions of one function in IR.
#[derive(Debug, Clone)]
pub struct LiftedFn {
    pub entry: u64,
    pub insns: Vec<Insn>,
    /// Machine instructions read.
    pub machine: u32,
    /// Machine instructions with full semantics (not `INTRINSIC`).
    pub lifted: u32,
}

impl LiftedFn {
    /// Heap bytes held (the `Insn` vector plus boxed intrinsics).
    pub fn heap_bytes(&self) -> usize {
        let boxed: usize = self
            .insns
            .iter()
            .map(|i| match &i.op {
                Op::Intrinsic(b) => {
                    size_of::<drishti_ir::Intrinsic>()
                        + b.name.capacity()
                        + b.ins.capacity() * size_of::<drishti_ir::Var>()
                }
                _ => 0,
            })
            .sum();
        self.insns.capacity() * size_of::<Insn>() + boxed + size_of::<Self>()
    }
}

/// Whether this image's architecture has a lifter.
pub fn supported(img: &Image) -> bool {
    img.arch == Arch::Aarch64
}

/// Code ranges of `f`, clipped to `max_insns` instructions in total.
fn words<'a>(img: &'a Image, f: &'a Func) -> impl Iterator<Item = (u64, u32)> + 'a {
    f.ranges.iter().flat_map(move |&(s, e)| {
        let len = usize::try_from(e.saturating_sub(s)).unwrap_or(0);
        let bytes = img.read(s, len).unwrap_or(&[]);
        bytes.chunks_exact(4).enumerate().map(move |(i, w)| {
            (
                s.wrapping_add(4 * i as u64),
                u32::from_le_bytes([w[0], w[1], w[2], w[3]]),
            )
        })
    })
}

/// Lift the function at `entry` (`None` if there is none or the
/// architecture has no lifter).
pub fn lift_function(img: &Image, a: &Analysis, entry: u64) -> Option<LiftedFn> {
    if !supported(img) {
        return None;
    }
    let f = a.function_at(entry)?;
    let (mut machine, mut lifted) = (0u32, 0u32);
    let insns = SCRATCH.with(|s| {
        let mut buf = s.borrow_mut();
        buf.clear();
        for (pc, w) in words(img, f) {
            machine += 1;
            if a64::lift(w, pc, &mut buf) == Lifted::Ok {
                lifted += 1;
            }
        }
        let out = buf.to_vec();
        buf.clear();
        if buf.capacity() > SCRATCH_KEEP {
            buf.shrink_to(SCRATCH_KEEP);
        }
        out
    });
    Some(LiftedFn {
        entry,
        insns,
        machine,
        lifted,
    })
}

/// Lifter coverage over every analysed function (Day 9).
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Coverage {
    pub functions: u64,
    pub instructions: u64,
    pub lifted: u64,
    /// Unlifted instructions per class (`a64.fp`, `a64.simd`, ...).
    pub by_class: BTreeMap<&'static str, u64>,
    /// Most common unlifted mnemonics, most frequent first.
    pub top_unlifted: Vec<(String, u64)>,
    /// Up to 3 example `(address, word)` per unlifted class.
    pub samples: BTreeMap<&'static str, Vec<(u64, u32)>>,
}

impl Coverage {
    pub fn percent(&self) -> f64 {
        if self.instructions == 0 {
            100.0
        } else {
            100.0 * self.lifted as f64 / self.instructions as f64
        }
    }
}

/// Lift every function once (without keeping the IR) and count.
pub fn coverage(img: &Image, a: &Analysis) -> Option<Coverage> {
    if !supported(img) {
        return None;
    }
    let cs = capstone_a64();
    let mut cov = Coverage::default();
    let mut scratch = Vec::new();
    let mut words_by_mn: HashMap<String, u64> = HashMap::new();
    for f in &a.functions {
        cov.functions += 1;
        for (pc, w) in words(img, f) {
            scratch.clear();
            cov.instructions += 1;
            match a64::lift(w, pc, &mut scratch) {
                Lifted::Ok => cov.lifted += 1,
                Lifted::Intrinsic(class) => {
                    *cov.by_class.entry(class).or_default() += 1;
                    let ex = cov.samples.entry(class).or_default();
                    if ex.len() < 3 {
                        ex.push((pc, w));
                    }
                    let mn = cs
                        .as_ref()
                        .and_then(|cs| {
                            cs.disasm_count(&w.to_le_bytes(), pc, 1).ok().and_then(|v| {
                                v.iter()
                                    .next()
                                    .and_then(|i| i.mnemonic().map(str::to_string))
                            })
                        })
                        .unwrap_or_else(|| format!("{class}?"));
                    *words_by_mn.entry(mn).or_default() += 1;
                }
            }
        }
    }
    let mut top: Vec<(String, u64)> = words_by_mn.into_iter().collect();
    top.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top.truncate(25);
    cov.top_unlifted = top;
    Some(cov)
}

fn capstone_a64() -> Option<capstone::Capstone> {
    use capstone::prelude::*;
    capstone::Capstone::new()
        .arm64()
        .mode(capstone::arch::arm64::ArchMode::Arm)
        .build()
        .ok()
}

/// Least-recently-used cache of lifted functions, capped by **bytes** of
/// IR held rather than by entry count (one huge function must not be able
/// to blow the budget, and many small ones may share it). Day 10.
#[derive(Debug)]
pub struct LiftCache<K: Copy + Eq + std::hash::Hash = u64> {
    cap: usize,
    used: usize,
    map: HashMap<K, Arc<LiftedFn>>,
    /// Keys, least recently used at the front.
    order: VecDeque<K>,
}

impl<K: Copy + Eq + std::hash::Hash> LiftCache<K> {
    pub fn new(cap_bytes: usize) -> Self {
        LiftCache {
            cap: cap_bytes,
            used: 0,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    pub fn used_bytes(&self) -> usize {
        self.used
    }
    pub fn cap_bytes(&self) -> usize {
        self.cap
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn touch(&mut self, key: K) {
        if let Some(i) = self.order.iter().position(|&e| e == key) {
            self.order.remove(i);
        }
        self.order.push_back(key);
    }

    pub fn get(&mut self, key: K) -> Option<Arc<LiftedFn>> {
        let f = self.map.get(&key).cloned();
        if f.is_some() {
            self.touch(key);
        }
        f
    }

    /// Insert under `key`, evicting least-recently-used functions until it
    /// fits. A function larger than the whole budget is not kept (the
    /// caller still has it). Returns whether it was kept.
    pub fn insert_as(&mut self, key: K, f: Arc<LiftedFn>) -> bool {
        let size = f.heap_bytes();
        if let Some(old) = self.map.remove(&key) {
            self.used -= old.heap_bytes();
        }
        if size > self.cap {
            if let Some(i) = self.order.iter().position(|&e| e == key) {
                self.order.remove(i);
            }
            return false;
        }
        while self.used + size > self.cap {
            let Some(victim) = self.order.pop_front() else {
                break;
            };
            if let Some(v) = self.map.remove(&victim) {
                self.used -= v.heap_bytes();
            }
        }
        self.used += size;
        self.map.insert(key, f);
        self.touch(key);
        true
    }

    /// Cached lift under `key`, lifting `entry` (and caching) on a miss.
    pub fn get_or_lift(
        &mut self,
        key: K,
        img: &Image,
        a: &Analysis,
        entry: u64,
    ) -> Option<Arc<LiftedFn>> {
        if let Some(f) = self.get(key) {
            return Some(f);
        }
        let f = Arc::new(lift_function(img, a, entry)?);
        self.insert_as(key, f.clone());
        Some(f)
    }
}

impl LiftCache<u64> {
    /// Insert keyed by the function's entry.
    pub fn insert(&mut self, f: LiftedFn) -> bool {
        self.insert_as(f.entry, Arc::new(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(entry: u64, n: usize) -> LiftedFn {
        let insns = vec![Insn::new(entry, Op::Return); n];
        LiftedFn {
            entry,
            insns,
            machine: n as u32,
            lifted: n as u32,
        }
    }

    #[test]
    fn cache_respects_its_byte_cap() {
        let one = fake(0, 100).heap_bytes();
        let mut c: LiftCache = LiftCache::new(one * 3);
        for e in 0..10u64 {
            assert!(c.insert(fake(e, 100)));
            assert!(c.used_bytes() <= c.cap_bytes(), "over cap after {e}");
        }
        assert_eq!(c.len(), 3);
        // Least recently used went first; touching 7 keeps it over 8.
        assert!(c.get(7).is_some());
        c.insert(fake(10, 100));
        assert!(c.get(7).is_some());
        assert!(c.get(8).is_none());
        // Too big for the whole budget: not kept, nothing evicted.
        let before = c.len();
        assert!(!c.insert(fake(99, 1000)));
        assert_eq!(c.len(), before);
        // Re-inserting the same entry does not double count.
        let used = c.used_bytes();
        c.insert(fake(7, 100));
        assert_eq!(c.used_bytes(), used);
    }
}
