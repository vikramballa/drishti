//! Function discovery and CFG recovery (spec §7.3).
//!
//! Recursive descent from loader seeds (entry, symbols, exports, unwind
//! tables, LC_FUNCTION_STARTS), with jump-table recovery, tail-call and
//! no-return detection, import thunk naming and prologue-based gap scanning.
//!
//! Memory: per-instruction data lives only while a function is explored.
//! The result keeps a compact summary per function (extent, counts, calls);
//! CFGs are rebuilt on demand (`Analysis::cfg`) — deterministic and fast —
//! so a 200 MB binary does not need gigabytes of resident block tables.

use crate::arch::{A64Op, Decoded, Flow, decode_a64, decode_x86};
use crate::xrefs::{XrefTable, Xrefs};
use drishti_loader::Image;
use drishti_model::{Arch, EdgeKind, NameSource, SymbolKind, XrefKind};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub struct Options {
    pub gap_scan: bool,
    pub max_functions: usize,
    pub max_insns_per_function: usize,
    /// Use loader seeds (symbols, unwind tables, function starts). Disable
    /// to benchmark pure recursive descent + gap scanning.
    pub use_hints: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            gap_scan: true,
            max_functions: 1_000_000,
            max_insns_per_function: 200_000,
            use_hints: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub phase: &'static str,
    pub functions: u64,
    pub queued: u64,
    pub instructions: u64,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub insns: u32,
    pub succs: Vec<(u64, EdgeKind)>,
}

/// Compact per-function summary kept after analysis.
#[derive(Debug, Clone)]
pub struct Func {
    pub entry: u64,
    pub name: Box<str>,
    pub name_source: NameSource,
    /// Direct call targets (and tail-call targets); import slots for `call [slot]`.
    pub calls: Box<[u64]>,
    pub called_by: Box<[u64]>,
    /// Covered address ranges, adjacent blocks merged (usually one).
    pub ranges: Box<[(u64, u64)]>,
    /// Extent: max block end − entry.
    pub size: u64,
    pub insns: u32,
    pub nblocks: u32,
    pub nedges: u32,
    pub is_thunk: bool,
    pub noreturn: bool,
    pub discovered_by: Discovery,
}

impl Func {
    pub fn edge_count(&self) -> usize {
        self.nedges as usize
    }
    pub fn block_count(&self) -> usize {
        self.nblocks as usize
    }
    /// McCabe: E − N + 2.
    pub fn cyclomatic(&self) -> u32 {
        (i64::from(self.nedges) - i64::from(self.nblocks) + 2).max(1) as u32
    }
    pub fn contains(&self, a: u64) -> bool {
        self.ranges.iter().any(|&(s, e)| a >= s && a < e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discovery {
    Seed,
    Call,
    TailCall,
    GapScan,
    /// Gap-scan candidate without a prologue (strictly validated).
    GapWeak,
    /// Code pointer found in data or via `lea`/`adrp` (strictly validated).
    DataPtr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrefC {
    pub from: u64,
    pub to: u64,
    pub kind: XrefKind,
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub seeds: u64,
    pub instructions: u64,
    pub jump_tables: u64,
    pub gap_functions: u64,
    /// Callers re-explored after interprocedural no-return propagation.
    pub noreturn_reexplored: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Default)]
pub struct Analysis {
    /// Sorted by entry.
    pub functions: Vec<Func>,
    /// Sorted by `(to, from, kind)`; 12 bytes per xref (see `xrefs.rs`).
    pub xrefs: XrefTable,
    /// Positions in `xrefs` (see `XrefTable::get`), sorted by `from`.
    by_from: Vec<u32>,
    pub stats: Stats,
    opts: Options,
}

impl Analysis {
    /// Rebuild from stored parts (`cache::decode`): sorts and indexes.
    pub fn from_parts(
        mut functions: Vec<Func>,
        mut xrefs: XrefTable,
        stats: Stats,
        opts: Options,
    ) -> Analysis {
        if !functions.is_sorted_by_key(|f| f.entry) {
            functions.sort_unstable_by_key(|f| f.entry);
        }
        functions.dedup_by_key(|f| f.entry);
        xrefs.finish();
        let by_from = xrefs.index_by_from();
        Analysis {
            functions,
            xrefs,
            by_from,
            stats,
            opts,
        }
    }

    /// Options the analysis ran with (needed to rebuild CFGs identically).
    pub fn options(&self) -> &Options {
        &self.opts
    }

    pub fn function_at(&self, entry: u64) -> Option<&Func> {
        self.functions
            .binary_search_by_key(&entry, |f| f.entry)
            .ok()
            .map(|i| &self.functions[i])
    }
    /// Function whose blocks contain `addr`.
    pub fn function_containing(&self, addr: u64) -> Option<&Func> {
        let idx = self.functions.partition_point(|f| f.entry <= addr);
        // Look back a little: functions are laid out mostly contiguously.
        self.functions[..idx]
            .iter()
            .rev()
            .take(64)
            .find(|f| f.contains(addr))
    }
    /// Xrefs whose target is `to`, sorted by `from`.
    pub fn xrefs_to(&self, to: u64) -> Xrefs<'_> {
        self.xrefs.to(to)
    }
    /// Xrefs from `[from_lo, from_hi)`, sorted by `(from, to)`.
    pub fn xrefs_from(&self, from_lo: u64, from_hi: u64) -> Vec<XrefC> {
        let from = |i: u32| self.xrefs.get(i).map_or(u64::MAX, |x| x.from);
        let lo = self.by_from.partition_point(|&i| from(i) < from_lo);
        self.by_from[lo..]
            .iter()
            .filter_map(|&i| self.xrefs.get(i))
            .take_while(|x| x.from < from_hi)
            .collect()
    }

    /// Rebuild the CFG of the function at `entry` (blocks + edges).
    pub fn cfg(&self, img: &Image, entry: u64) -> Option<Vec<Block>> {
        self.function_at(entry)?;
        let mut ctx = Ctx::new(img, &self.opts, Some(&self.functions)).ok()?;
        Some(ctx.explore(entry).blocks)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    #[error("architecture {0:?} is not supported by the core analyser yet")]
    UnsupportedArch(Arch),
    #[error("cancelled")]
    Cancelled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Isa {
    X86(u32),
    A64,
}

/// Decoder façade over the supported ISAs.
pub struct Isadec<'a> {
    img: &'a Image,
    isa: Isa,
    scratch: iced_x86::Instruction,
}

impl<'a> Isadec<'a> {
    pub fn new(img: &'a Image) -> Result<Self, AnalyzeError> {
        let isa = match img.arch {
            Arch::X86_64 => Isa::X86(64),
            Arch::X86 => Isa::X86(32),
            Arch::Aarch64 if img.bits == 64 => Isa::A64,
            a => return Err(AnalyzeError::UnsupportedArch(a)),
        };
        Ok(Isadec {
            img,
            isa,
            scratch: iced_x86::Instruction::default(),
        })
    }
    pub fn decode(&mut self, addr: u64) -> Option<Decoded> {
        let b = self.img.read(addr, 16)?;
        match self.isa {
            Isa::X86(bits) => decode_x86(b, addr, bits, &mut self.scratch),
            Isa::A64 => decode_a64(b, addr),
        }
    }
    /// Mnemonic of the last x86 decode (for jump-table idiom matching).
    fn x86_mnemonic(&self) -> iced_x86::Mnemonic {
        self.scratch.mnemonic()
    }
}

fn norm(name: &str) -> &str {
    let n = name.trim_start_matches('_');
    n.split('@').next().unwrap_or(n)
}

/// Functions that never return; calls to them end a basic block.
pub fn is_noreturn_name(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "exit",
        "Exit",
        "abort",
        "assert_fail",
        "assert_rtn",
        "assert",
        "stack_chk_fail",
        "chk_fail",
        "fortify_fail",
        "Unwind_Resume",
        "cxa_throw",
        "cxa_rethrow",
        "cxa_bad_cast",
        "cxa_bad_typeid",
        "cxa_call_unexpected",
        "cxa_pure_virtual",
        "ZSt9terminatev",
        "libc_start_main",
        "pthread_exit",
        "longjmp",
        "siglongjmp",
        "err",
        "errx",
        "verr",
        "verrx",
        "ExitProcess",
        "ExitThread",
        "FatalExit",
        "FatalAppExitA",
        "FatalAppExitW",
        "fastfail",
        "invalid_parameter_noinfo_noreturn",
        "CxxThrowException",
        "objc_exception_throw",
        "objc_exception_rethrow",
        "objc_terminate",
        "swift_unexpectedError",
        "swift_deletedMethodError",
        "runtime.throw",
        "runtime.gopanic",
        "runtime.fatalthrow",
        "runtime.fatalpanic",
        "rust_panic",
        "rust_start_panic",
        "ZSt17__throw_bad_allocv",
        "ZSt20__throw_length_errorPKc",
        "ZSt24__throw_out_of_range_fmtPKcz",
        "ZSt20__throw_out_of_rangePKc",
        "ZSt19__throw_logic_errorPKc",
        "ZSt25__throw_bad_function_callv",
        "Py_FatalError",
    ];
    let n = norm(name);
    if EXACT.contains(&n) {
        return true;
    }
    n.starts_with("runtime.panic")
        || n.contains("assertionFailure")
        || n.contains("fatalError")
        || n.contains("preconditionFailure")
        || n.contains("core::panicking::")
        || n.contains("core9panicking")
        || n.contains("unwrap_failed")
        || n.contains("expect_failed")
        || n.contains("handle_alloc_error")
        || n.contains("panic_bounds_check")
        || n.contains("index_len_fail")
        || n.contains("ZSt9terminate")
}

struct Insn {
    len: u8,
    flow: Flow,
    /// Falls through to the next instruction (false after no-return calls).
    falls: bool,
}

struct Explored {
    blocks: Vec<Block>,
    calls: Vec<u64>,
    tails: Vec<u64>,
    xrefs: Vec<XrefC>,
    insns: u32,
    bad: bool,
    has_ret: bool,
    /// An exit whose continuation is unknown (unresolved indirect jump,
    /// falling off an extent, branch to unmapped code): may return.
    open_exit: bool,
    jump_tables: u64,
    thunk_import: Option<u32>,
}

impl Explored {
    /// True if no path through the function can reach its caller, given
    /// that every tail-call target in `tails` is itself no-return.
    fn exits_closed(&self) -> bool {
        !self.has_ret && !self.open_exit && !self.bad && self.insns > 0
    }
}

/// Fast hasher for code addresses (folded 64×64→128 multiply). Addresses
/// are not attacker-chosen hash-flooding keys in a meaningful sense: the
/// worst case is a slower analysis of a hostile binary, never a crash.
#[derive(Default, Clone, Copy)]
pub(crate) struct AddrHasher(u64);

impl std::hash::Hasher for AddrHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u64(&mut self, n: u64) {
        let p = u128::from(self.0 ^ n) * 0x9E37_79B9_7F4A_7C15u128;
        self.0 = (p as u64) ^ ((p >> 64) as u64);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

pub(crate) type AddrBuild = std::hash::BuildHasherDefault<AddrHasher>;

/// Per-`explore` working tables, reused between functions.
#[derive(Default)]
struct Scratch {
    insns: HashMap<u64, Insn, AddrBuild>,
    leaders: HashSet<u64, AddrBuild>,
    /// (source instruction, target, kind) in discovery order.
    edges: Vec<(u64, u64, EdgeKind)>,
    order: Vec<u64>,
}

impl Scratch {
    fn reset(&mut self) {
        self.insns.clear();
        self.leaders.clear();
        self.edges.clear();
        self.order.clear();
        // Don't keep the tables of one huge function around forever.
        if self.insns.capacity() > 1 << 16 {
            *self = Scratch::default();
        }
    }
}

struct Ctx<'a> {
    img: &'a Image,
    /// Reusable `explore` tables.
    scratch: Scratch,
    dec: Isadec<'a>,
    opts: &'a Options,
    known: HashSet<u64>,
    /// Final function list (on-demand CFG rebuilds).
    known_sorted: Option<&'a [Func]>,
    sym_names: HashMap<u64, String>,
    thunk_cache: HashMap<u64, Option<u32>>,
    noreturn_cache: HashMap<u64, bool>,
    /// Functions proven no-return by interprocedural propagation.
    noret: HashSet<u64>,
    rejected: HashSet<u64>,
}

impl<'a> Ctx<'a> {
    fn new(
        img: &'a Image,
        opts: &'a Options,
        known_sorted: Option<&'a [Func]>,
    ) -> Result<Self, AnalyzeError> {
        let mut sym_names: HashMap<u64, String> = HashMap::new();
        for s in img.exports.iter().chain(img.symbols.iter()) {
            if matches!(s.kind, SymbolKind::Function | SymbolKind::Export) && !s.name.is_empty() {
                sym_names
                    .entry(s.addr.0)
                    .or_insert_with(|| s.display_name().to_string());
            }
        }
        Ok(Ctx {
            img,
            scratch: Scratch::default(),
            dec: Isadec::new(img)?,
            opts,
            known: HashSet::new(),
            known_sorted,
            sym_names,
            thunk_cache: HashMap::new(),
            noreturn_cache: HashMap::new(),
            noret: HashSet::new(),
            rejected: HashSet::new(),
        })
    }

    fn is_known(&self, a: u64) -> bool {
        self.known.contains(&a)
            || self
                .known_sorted
                .is_some_and(|f| f.binary_search_by_key(&a, |x| x.entry).is_ok())
    }

    fn name_of_target(&mut self, t: u64) -> Option<String> {
        if let Some(n) = self.sym_names.get(&t) {
            return Some(n.clone());
        }
        if let Some(s) = self.img.import_at(t) {
            return Some(s.display_name().to_string());
        }
        let imp = self.peek_thunk(t)?;
        self.img
            .imports
            .get(imp as usize)
            .map(|s| s.display_name().to_string())
    }

    fn is_noreturn(&mut self, t: u64) -> bool {
        self.noret.contains(&t)
            || self.known_sorted.is_some_and(|f| {
                f.binary_search_by_key(&t, |x| x.entry)
                    .is_ok_and(|i| f[i].noreturn)
            })
            || self.is_noreturn_by_name(t)
    }

    /// Name-based no-return test (symbol, import, or import thunk).
    fn is_noreturn_by_name(&mut self, t: u64) -> bool {
        if let Some(&v) = self.noreturn_cache.get(&t) {
            return v;
        }
        let v = self.name_of_target(t).is_some_and(|n| is_noreturn_name(&n));
        self.noreturn_cache.insert(t, v);
        v
    }

    /// If code at `t` is an import thunk (PLT entry, `jmp [IAT]`, AArch64
    /// adrp/ldr/br stub), return the import index.
    fn peek_thunk(&mut self, t: u64) -> Option<u32> {
        if let Some(&v) = self.thunk_cache.get(&t) {
            return v;
        }
        let mut regs = [None::<u64>; 32];
        let mut loaded = [None::<u64>; 32];
        let mut pc = t;
        let mut out = None;
        for _ in 0..6 {
            let Some(d) = self.dec.decode(pc) else { break };
            match d.flow {
                Flow::IndirectJump => {
                    if let Some(slot) = d.mem_ref {
                        out = self.img.import_slots.get(&slot).copied();
                    }
                    if let A64Op::BrReg { rn } = d.a64 {
                        out = loaded[rn as usize]
                            .and_then(|s| self.img.import_slots.get(&s).copied());
                    }
                    break;
                }
                Flow::Next => {}
                _ => break,
            }
            a64_track(&d, &mut regs, &mut loaded);
            // x86: allow only endbr / bnd prefixes / nops before the jump.
            if matches!(self.dec.isa, Isa::X86(_))
                && !(d.is_nop_or_pad
                    || self.dec.x86_mnemonic() == iced_x86::Mnemonic::Endbr64
                    || self.dec.x86_mnemonic() == iced_x86::Mnemonic::Endbr32)
            {
                break;
            }
            pc += u64::from(d.len);
        }
        if out.is_none() {
            out = self.img.stubs.get(&t).copied();
        }
        self.thunk_cache.insert(t, out);
        out
    }

    fn explore(&mut self, entry: u64) -> Explored {
        // Scratch tables are reused across calls (cleared, capacity kept):
        // allocating fresh maps for each of hundreds of thousands of
        // functions fragmented the heap by ~200 MB on Chrome.
        let mut sc = std::mem::take(&mut self.scratch);
        let ex = self.explore_with(entry, &mut sc);
        sc.reset();
        self.scratch = sc;
        ex
    }

    fn explore_with(&mut self, entry: u64, sc: &mut Scratch) -> Explored {
        let Scratch {
            insns,
            leaders,
            edges,
            order,
        } = sc;
        let mut work: Vec<(u64, Option<u64>, Option<u64>)> = vec![(entry, None, None)];
        let mut ex = Explored {
            blocks: Vec::new(),
            calls: Vec::new(),
            tails: Vec::new(),
            xrefs: Vec::new(),
            insns: 0,
            bad: false,
            has_ret: false,
            open_exit: false,
            jump_tables: 0,
            thunk_import: None,
        };
        leaders.insert(entry);
        let code_range = self.img.code_range(entry).map(|c| (c.start, c.end));
        // With an authoritative extent (function starts, .pdata, FDE), jumps
        // leaving it are tail calls, and code past it belongs to others.
        let own = self.img.known_range_at(entry);
        let outside = |t: u64| own.is_some_and(|(s, e)| t < s || t >= e);
        let ptr = u64::from(self.img.bits / 8);

        if let Some(i) = self.peek_thunk(entry) {
            ex.thunk_import = Some(i);
        }

        while let Some((start, bound, lea_in)) = work.pop() {
            let mut pc = start;
            let mut regs = [None::<u64>; 32];
            let mut loaded = [None::<u64>; 32];
            let mut last_cmp = bound;
            let mut last_lea = lea_in;
            let mut recent: [(
                u64,
                Option<u64>,
                Option<crate::arch::X86Table>,
                iced_x86::Mnemonic,
            ); 8] = [(0, None, None, iced_x86::Mnemonic::INVALID); 8];
            let mut rn = 0usize;
            let mut jt = A64Jt::default();
            loop {
                if insns.contains_key(&pc) {
                    leaders.insert(pc);
                    break;
                }
                if pc != entry && self.is_known(pc) {
                    // Ran into another function: treat as a tail transfer.
                    ex.tails.push(pc);
                    break;
                }
                if insns.len() >= self.opts.max_insns_per_function {
                    ex.bad = true;
                    break;
                }
                if outside(pc) {
                    // Falls into whatever follows the extent.
                    ex.open_exit = true;
                    break;
                }
                if !self.img.is_code(pc) {
                    if pc != start {
                        ex.bad = true;
                    }
                    ex.open_exit = true;
                    break;
                }
                let Some(d) = self.dec.decode(pc) else {
                    ex.bad = true;
                    break;
                };
                let next = pc + u64::from(d.len);
                if let Some(v) = d.cmp_imm {
                    last_cmp = Some(v);
                }
                let mn = if matches!(self.dec.isa, Isa::X86(_)) {
                    self.dec.x86_mnemonic()
                } else {
                    iced_x86::Mnemonic::INVALID
                };
                recent[rn % 8] = (pc, d.mem_ref, d.table, mn);
                if mn == iced_x86::Mnemonic::Lea && d.mem_ref.is_some() {
                    last_lea = d.mem_ref;
                }
                rn += 1;

                // Data references.
                if let Some(r) = d.mem_ref
                    && !matches!(d.flow, Flow::IndirectCall | Flow::IndirectJump)
                    && self.img.is_mapped(r)
                {
                    ex.xrefs.push(XrefC {
                        from: pc,
                        to: r,
                        kind: XrefKind::DataRead,
                    });
                }
                if d.raw != 0 {
                    jt.observe(d.raw, &regs);
                }
                if let Some(r) = a64_track(&d, &mut regs, &mut loaded)
                    && self.img.is_mapped(r)
                {
                    ex.xrefs.push(XrefC {
                        from: pc,
                        to: r,
                        kind: XrefKind::DataRead,
                    });
                }

                let mut falls = true;
                let mut stop = false;
                match d.flow {
                    Flow::Next => {}
                    Flow::Call(t) => {
                        ex.calls.push(t);
                        ex.xrefs.push(XrefC {
                            from: pc,
                            to: t,
                            kind: XrefKind::Call,
                        });
                        if self.is_noreturn(t) {
                            falls = false;
                            stop = true;
                        }
                        regs = [None; 32];
                        loaded = [None; 32];
                    }
                    Flow::IndirectCall => {
                        let slot = d.mem_ref.or_else(|| match d.a64 {
                            A64Op::BrReg { rn } => loaded[rn as usize],
                            _ => None,
                        });
                        if let Some(s) = slot.filter(|s| self.img.import_slots.contains_key(s)) {
                            ex.calls.push(s);
                            ex.xrefs.push(XrefC {
                                from: pc,
                                to: s,
                                kind: XrefKind::Call,
                            });
                            if self
                                .img
                                .import_at(s)
                                .is_some_and(|i| is_noreturn_name(&i.name))
                            {
                                falls = false;
                                stop = true;
                            }
                        }
                        regs = [None; 32];
                        loaded = [None; 32];
                    }
                    Flow::Jump(t) => {
                        stop = true;
                        falls = false;
                        if t != entry
                            && (self.is_known(t)
                                || outside(t)
                                || !self.img.is_code(t)
                                || code_range.is_some_and(|(s, e)| t < s || t >= e))
                        {
                            ex.tails.push(t);
                            ex.xrefs.push(XrefC {
                                from: pc,
                                to: t,
                                kind: XrefKind::Jump,
                            });
                        } else {
                            leaders.insert(t);
                            work.push((t, last_cmp, last_lea));
                            edges.push((pc, t, EdgeKind::Jump));
                        }
                    }
                    Flow::CondJump(t) => {
                        stop = true;
                        leaders.insert(next);
                        work.push((next, last_cmp, last_lea));
                        edges.push((pc, next, EdgeKind::False));
                        if t != entry && (self.is_known(t) || outside(t)) {
                            ex.tails.push(t);
                            ex.xrefs.push(XrefC {
                                from: pc,
                                to: t,
                                kind: XrefKind::Jump,
                            });
                        } else if self.img.is_code(t) {
                            leaders.insert(t);
                            work.push((t, last_cmp, last_lea));
                            edges.push((pc, t, EdgeKind::True));
                        } else {
                            ex.open_exit = true;
                        }
                    }
                    Flow::IndirectJump => {
                        stop = true;
                        falls = false;
                        let slot = d.mem_ref.or_else(|| match d.a64 {
                            A64Op::BrReg { rn } => loaded[rn as usize],
                            _ => None,
                        });
                        if let Some(s) = slot.filter(|s| self.img.import_slots.contains_key(s)) {
                            ex.tails.push(s);
                            ex.xrefs.push(XrefC {
                                from: pc,
                                to: s,
                                kind: XrefKind::Jump,
                            });
                        } else {
                            let mut targets = self
                                .jump_table(&d, &recent, rn, last_cmp, last_lea, code_range, ptr);
                            if let (A64Op::BrReg { rn: br }, true) = (d.a64, targets.is_empty()) {
                                targets = jt.targets(self.img, br, pc, last_cmp, code_range);
                            }
                            if targets.is_empty() {
                                ex.open_exit = true;
                            } else {
                                ex.jump_tables += 1;
                                let mut seen = HashSet::new();
                                for t in targets {
                                    if seen.insert(t) {
                                        leaders.insert(t);
                                        work.push((t, None, None));
                                        edges.push((pc, t, EdgeKind::Switch));
                                        ex.xrefs.push(XrefC {
                                            from: pc,
                                            to: t,
                                            kind: XrefKind::Jump,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Flow::Ret => {
                        stop = true;
                        falls = false;
                        ex.has_ret = true;
                    }
                    Flow::Stop => {
                        stop = true;
                        falls = false;
                        // A trap as the very first instruction, or AArch64
                        // `udf` (a zero upper half: usually data such as a
                        // jump table), is no evidence of a no-return function.
                        if pc == entry || (d.raw != 0 && d.raw >> 16 == 0) {
                            ex.open_exit = true;
                        }
                    }
                }
                insns.insert(
                    pc,
                    Insn {
                        len: d.len,
                        flow: d.flow,
                        falls,
                    },
                );
                if stop {
                    break;
                }
                pc = next;
            }
        }

        // Form basic blocks from the instruction map, in address order.
        // Each instruction is decoded once, so its out-edges were pushed
        // contiguously; a stable sort by source keeps their order.
        ex.insns = insns.len() as u32;
        order.extend(insns.keys().copied());
        order.sort_unstable();
        edges.sort_by_key(|e| e.0);
        let mut ei = 0usize;
        let mut cur: Option<Block> = None;
        let mut prev_end = 0u64;
        let mut prev_falls = false;
        for &a in order.iter() {
            let Some(ins) = insns.get(&a) else { continue };
            let new_block = cur.is_none() || leaders.contains(&a) || prev_end != a;
            if new_block {
                if let Some(mut b) = cur.take() {
                    if prev_falls && prev_end == a {
                        b.succs.push((a, EdgeKind::Fallthrough));
                    }
                    ex.blocks.push(b);
                }
                cur = Some(Block {
                    start: a,
                    end: a,
                    insns: 0,
                    succs: Vec::new(),
                });
            }
            if let Some(b) = cur.as_mut() {
                b.end = a + u64::from(ins.len);
                b.insns += 1;
                if ins.flow.ends_block() {
                    while ei < edges.len() && edges[ei].0 < a {
                        ei += 1;
                    }
                    let first = ei;
                    while ei < edges.len() && edges[ei].0 == a {
                        ei += 1;
                    }
                    if ei > first {
                        b.succs = edges[first..ei].iter().map(|e| (e.1, e.2)).collect();
                    }
                }
            }
            prev_end = a + u64::from(ins.len);
            prev_falls = ins.falls && !ins.flow.ends_block();
            if (ins.flow.ends_block() || !ins.falls)
                && let Some(b) = cur.take()
            {
                ex.blocks.push(b);
            }
        }
        if let Some(b) = cur.take() {
            ex.blocks.push(b);
        }
        ex
    }

    /// Recover x86 jump-table targets from the instructions preceding an
    /// indirect jump. Handles absolute tables, GCC/Clang PIC tables
    /// (`lea T; movsxd [T+i*4]; add; jmp`) and MSVC RVA tables.
    #[allow(clippy::too_many_arguments)]
    fn jump_table(
        &mut self,
        d: &Decoded,
        recent: &[(
            u64,
            Option<u64>,
            Option<crate::arch::X86Table>,
            iced_x86::Mnemonic,
        ); 8],
        rn: usize,
        bound: Option<u64>,
        lea_in: Option<u64>,
        code_range: Option<(u64, u64)>,
        ptr: u64,
    ) -> Vec<u64> {
        if !matches!(self.dec.isa, Isa::X86(_)) {
            return Vec::new();
        }
        let Some((cs, ce)) = code_range else {
            return Vec::new();
        };
        let max = bound.map(|b| (b + 1).min(4096)).unwrap_or(512);
        let mut out = Vec::new();
        let in_code = |t: u64| t >= cs && t < ce;
        // Case A: jmp [idx*ptr + T]
        if let Some(t) = d.table.filter(|t| !t.has_base && u64::from(t.scale) == ptr) {
            for k in 0..max {
                match self.img.read_ptr(t.disp + k * ptr) {
                    Some(v) if in_code(v) => out.push(v),
                    _ => break,
                }
            }
            return out;
        }
        let hist: Vec<_> = (1..=rn.min(8)).map(|k| recent[(rn - k) % 8]).collect();
        let image_base = self.img.image_base;
        // Case B/C: look for lea T and a scaled 4-byte load.
        let lea = hist
            .iter()
            .find(|h| h.3 == iced_x86::Mnemonic::Lea && h.1.is_some())
            .and_then(|h| h.1)
            .or(lea_in);
        let load = hist.iter().find(|h| {
            matches!(h.3, iced_x86::Mnemonic::Movsxd | iced_x86::Mnemonic::Mov)
                && h.2.is_some_and(|t| t.scale == 4)
        });
        if let (Some(tbase), Some(ld)) = (lea, load) {
            let tab = ld.2.unwrap_or(crate::arch::X86Table {
                disp: 0,
                scale: 4,
                has_base: true,
            });
            let (table_at, rel_base, signed) = if tbase == image_base && tab.disp != 0 {
                (image_base + tab.disp, image_base, false) // MSVC: RVAs
            } else {
                (tbase.wrapping_add(tab.disp), tbase, true) // PIC: relative to table
            };
            for k in 0..max {
                let Some(e) = self.img.read_u32(table_at + k * 4) else {
                    break;
                };
                let t = if signed {
                    rel_base.wrapping_add(i64::from(e as i32) as u64)
                } else {
                    rel_base.wrapping_add(u64::from(e))
                };
                if !in_code(t) {
                    break;
                }
                out.push(t);
            }
        }
        out
    }
}

/// AArch64 jump-table idiom state (clang/gcc):
/// `adrp+add Xt,table; [adr Xb,base;] ldr{b,h,sw} Wi,[Xt,Xidx,lsl #s]; add Xd,Xb,Xi{,lsl|sxtw #k}; br Xd`.
#[derive(Default, Clone, Copy)]
struct A64Jt {
    /// (dest reg, table address, element size, signed)
    load: Option<(u8, u64, u8, bool)>,
    /// (dest reg, base value, entry reg, shift, sign-extend-word)
    add: Option<(u8, u64, u8, u8, bool)>,
}

impl A64Jt {
    fn observe(&mut self, w: u32, regs: &[Option<u64>; 32]) {
        let rd = (w & 31) as u8;
        let rn = ((w >> 5) & 31) as usize;
        let rm = ((w >> 16) & 31) as u8;
        if w & 0x3f20_0c00 == 0x3820_0800 {
            // LDR (register offset), integer.
            let size = (w >> 30) & 3;
            let opc = (w >> 22) & 3;
            if opc != 0
                && size < 3
                && let Some(t) = regs[rn]
            {
                self.load = Some((rd, t, 1 << size, opc >= 2));
            }
        } else if w & 0xff20_0000 == 0x8b00_0000 && (w >> 22) & 3 == 0 {
            // ADD Xd, Xn, Xm, LSL #imm6
            if let Some(b) = regs[rn] {
                self.add = Some((rd, b, rm, ((w >> 10) & 63) as u8, false));
            }
        } else if w & 0xffe0_0000 == 0x8b20_0000 {
            // ADD Xd, Xn, Wm, (S|U)XTW #imm3
            let option = (w >> 13) & 7;
            if let Some(b) = regs[rn] {
                self.add = Some((rd, b, rm, ((w >> 10) & 7) as u8, option == 6));
            }
        }
    }

    fn targets(
        &self,
        img: &Image,
        br: u8,
        pc: u64,
        bound: Option<u64>,
        code: Option<(u64, u64)>,
    ) -> Vec<u64> {
        let (Some((lrt, table, size, signed)), Some((ard, base, arm, shift, sxtw))) =
            (self.load, self.add)
        else {
            return Vec::new();
        };
        if ard != br || arm != lrt {
            return Vec::new();
        }
        let Some((cs, ce)) = code else {
            return Vec::new();
        };
        let max = bound.map(|b| (b + 1).min(4096)).unwrap_or(64);
        let mut out = Vec::new();
        for k in 0..max {
            let Some(b) = img.read(table + k * u64::from(size), size as usize) else {
                break;
            };
            if b.len() < size as usize {
                break;
            }
            let raw = match size {
                1 => u64::from(b[0]),
                2 => u64::from(u16::from_le_bytes([b[0], b[1]])),
                _ => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            };
            let bits = u32::from(size) * 8;
            let v = if signed || (sxtw && size == 4) {
                sext(raw, bits) as u64
            } else {
                raw
            };
            let t = base.wrapping_add(v << shift);
            if t < cs || t >= ce || t % 4 != 0 || t.abs_diff(pc) > (1 << 24) {
                break;
            }
            out.push(t);
        }
        out
    }
}

#[inline]
fn sext(v: u64, bits: u32) -> i64 {
    let s = 64 - bits;
    ((v << s) as i64) >> s
}

/// Track AArch64 address formation. Returns a data address formed by this
/// instruction (ADD from a known page, or a load/store through one).
fn a64_track(
    d: &Decoded,
    regs: &mut [Option<u64>; 32],
    loaded: &mut [Option<u64>; 32],
) -> Option<u64> {
    match d.a64 {
        A64Op::None => {
            if d.len == 4 && d.flow == Flow::Next {
                // Most A64 data-processing ops write Rd (bits 0..4). Stores and
                // compares also land here; dropping their register is merely
                // conservative (we lose tracking, never invent a reference).
                let rd = (d.raw & 0x1f) as usize;
                regs[rd] = None;
                loaded[rd] = None;
            }
            d.mem_ref.filter(|_| d.len == 4)
        }
        A64Op::SetAddr { rd, value } => {
            regs[rd as usize] = Some(value);
            loaded[rd as usize] = None;
            if d.mem_ref.is_some() {
                Some(value)
            } else {
                None
            }
        }
        A64Op::AddImm { rd, rn, imm } => {
            let v = regs[rn as usize].map(|b| b.wrapping_add(imm));
            regs[rd as usize] = v;
            loaded[rd as usize] = None;
            v
        }
        A64Op::Mem {
            rn,
            imm,
            rt,
            load64,
        } => {
            let a = regs[rn as usize].map(|b| b.wrapping_add(imm));
            if load64 && rt < 32 {
                loaded[rt as usize] = a;
                regs[rt as usize] = None;
            }
            a
        }
        A64Op::BrReg { .. } => None,
    }
}

/// x86 / AArch64 prologue patterns used to validate gap-scan candidates.
fn looks_like_prologue(img: &Image, a: u64) -> bool {
    let Some(b) = img.read(a, 8) else {
        return false;
    };
    match img.arch {
        Arch::X86_64 => {
            b.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa])
                || b.starts_with(&[0x55, 0x48, 0x89, 0xe5])
                || (a.is_multiple_of(16)
                    && (b.starts_with(&[0x55])
                        || b.starts_with(&[0x53])
                        || (b[0] == 0x41
                            && (0x54..=0x57).contains(&b.get(1).copied().unwrap_or(0)))
                        || b.starts_with(&[0x48, 0x83, 0xec])
                        || b.starts_with(&[0x48, 0x81, 0xec])))
        }
        Arch::X86 => {
            b.starts_with(&[0x55, 0x8b, 0xec])
                || b.starts_with(&[0x55, 0x89, 0xe5])
                || b.starts_with(&[0x8b, 0xff, 0x55])
        }
        Arch::Aarch64 => {
            let Some(w) = b
                .get(..4)
                .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            else {
                return false;
            };
            w == 0xd503_237f // pacibsp
                || w == 0xd503_233f // paciasp
                || w == 0xd503_245f // bti c
                || w & 0xffc0_03e0 == 0xa980_03e0 // stp xA, xB, [sp, #-N]!
                || w & 0xff80_03ff == 0xd100_03ff // sub sp, sp, #imm
        }
        _ => false,
    }
}

fn is_padding(img: &Image, a: u64) -> Option<u64> {
    let b = img.read(a, 16)?;
    match img.arch {
        Arch::X86 | Arch::X86_64 => {
            if matches!(b[0], 0xcc | 0x90 | 0x00) {
                return Some(1);
            }
            // Multi-byte NOPs (`nop [rax+rax]`, `xchg ax,ax`, ...).
            let mut ins = iced_x86::Instruction::default();
            let d = decode_x86(b, a, if img.arch == Arch::X86 { 32 } else { 64 }, &mut ins)?;
            (ins.mnemonic() == iced_x86::Mnemonic::Nop).then_some(u64::from(d.len))
        }
        Arch::Aarch64 => {
            let w = u32::from_le_bytes(b.get(..4)?.try_into().ok()?);
            (w == 0 || w == 0xd503_201f || w & 0xffe0_001f == 0xd420_0000).then_some(4)
        }
        _ => matches!(b[0], 0xcc | 0x90 | 0x00).then_some(1),
    }
}

/// True if `a` lies strictly inside an existing function's extent.
fn inside_function(funcs: &BTreeMap<u64, Func>, a: u64) -> bool {
    funcs
        .range(..a)
        .rev()
        .take(32)
        .any(|(_, f)| a < f.entry.saturating_add(f.size) || f.contains(a))
}

fn merge_ranges(blocks: &[Block]) -> Box<[(u64, u64)]> {
    let mut r: Vec<(u64, u64)> = blocks.iter().map(|b| (b.start, b.end)).collect();
    r.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(2);
    for (s, e) in r {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out.into_boxed_slice()
}

/// Pointer-sized values in non-code mapped sections that point into code.
/// Handles raw pointers and Mach-O chained-fixup rebase encodings.
fn code_pointers_in_data(img: &Image) -> Vec<u64> {
    let mut out = Vec::new();
    let ptr = usize::from(img.bits / 8);
    let base = img.image_base;
    for s in &img.sections {
        if s.file_size == 0
            || img.is_code(s.vaddr.0)
            || s.perms.contains('x') && !s.name.contains("const")
        {
            continue;
        }
        let n = s.name.as_str();
        // Skip string pools, symbol tables and unwind data.
        if n.contains("cstring")
            || n.contains("str")
            || n.contains("eh_frame")
            || n.contains("unwind")
            || n.contains("debug")
            || n.contains("sym")
            || n.contains("reloc")
        {
            continue;
        }
        let Some(d) = img.read(s.vaddr.0, s.file_size.min(64 << 20) as usize) else {
            continue;
        };
        for ch in d.chunks_exact(ptr) {
            let v = if ptr == 8 {
                u64::from_le_bytes(ch.try_into().unwrap_or([0; 8]))
            } else {
                u64::from(u32::from_le_bytes(ch.try_into().unwrap_or([0; 4])))
            };
            if v == 0 {
                continue;
            }
            if img.is_code(v) {
                out.push(v);
                continue;
            }
            if img.format == drishti_model::Format::Macho && ptr == 8 && v >> 62 == 0 {
                // DYLD_CHAINED_PTR_64(_OFFSET) / ARM64E rebase: low 36 bits target.
                for t in [
                    v & 0xf_ffff_ffff,
                    base.wrapping_add(v & 0xf_ffff_ffff),
                    base.wrapping_add(v & 0xffff_ffff),
                ] {
                    if img.is_code(t) {
                        out.push(t);
                        break;
                    }
                }
            } else if img.format == drishti_model::Format::Macho
                && ptr == 8
                && v >> 63 == 1
                && (v >> 62) & 1 == 0
            {
                // ARM64E authenticated rebase: low 32 bits = offset from base.
                let t = base.wrapping_add(v & 0xffff_ffff);
                if img.is_code(t) {
                    out.push(t);
                }
            }
        }
    }
    out
}

struct Driver<'a, 'p> {
    ctx: Ctx<'a>,
    img: &'a Image,
    opts: &'a Options,
    queue: VecDeque<(u64, Discovery)>,
    funcs: BTreeMap<u64, Func>,
    /// Functions that cannot return by themselves → their tail targets.
    noret_cands: HashMap<u64, Box<[u64]>>,
    xrefs: XrefTable,
    stats: Stats,
    progress: &'p dyn Fn(Progress),
    cancel: &'p AtomicBool,
}

impl Driver<'_, '_> {
    fn process(&mut self) -> Result<(), AnalyzeError> {
        let img = self.img;
        while let Some((entry, how)) = self.queue.pop_front() {
            if self.funcs.contains_key(&entry)
                || self.funcs.len() >= self.opts.max_functions
                || self.ctx.rejected.contains(&entry)
            {
                continue;
            }
            if self.funcs.len().is_multiple_of(256) {
                if self.cancel.load(Ordering::Relaxed) {
                    return Err(AnalyzeError::Cancelled);
                }
                (self.progress)(Progress {
                    phase: "functions",
                    functions: self.funcs.len() as u64,
                    queued: self.queue.len() as u64,
                    instructions: self.stats.instructions,
                });
            }
            let was_known = !self.ctx.known.insert(entry);
            let ex = self.ctx.explore(entry);
            let reject = match how {
                Discovery::GapScan => ex.bad || ex.insns < 2,
                Discovery::GapWeak | Discovery::DataPtr => {
                    ex.bad
                        || ex.insns < 2
                        || (!ex.has_ret && ex.tails.is_empty() && ex.calls.is_empty())
                        // Must not swallow another function's entry (mid-function pointer).
                        || ex.blocks.iter().any(|b| self.funcs.range(b.start..b.end).next().is_some())
                        || inside_function(&self.funcs, entry)
                        || img.inside_known_range(entry)
                }
                _ => false,
            };
            if reject {
                if !was_known {
                    self.ctx.known.remove(&entry);
                }
                self.ctx.rejected.insert(entry);
                continue;
            }
            self.record(entry, how, ex, true);
        }
        Ok(())
    }

    /// Store an explored function: queue its callees, build the summary,
    /// remember no-return candidates.
    fn record(&mut self, entry: u64, how: Discovery, ex: Explored, fresh: bool) {
        let img = self.img;
        self.stats.instructions += u64::from(ex.insns);
        if fresh {
            self.stats.jump_tables += ex.jump_tables;
        }
        for &c in ex.calls.iter().chain(ex.tails.iter()) {
            if !self.funcs.contains_key(&c)
                && img.is_code(c)
                && !img.import_slots.contains_key(&c)
                && !img.inside_known_range(c)
            {
                self.ctx.known.insert(c);
                self.queue.push_back((
                    c,
                    if ex.tails.contains(&c) {
                        Discovery::TailCall
                    } else {
                        Discovery::Call
                    },
                ));
            }
        }
        let closed = ex.exits_closed();
        if closed {
            let mut t = ex.tails.clone();
            t.sort_unstable();
            t.dedup();
            self.noret_cands.insert(entry, t.into_boxed_slice());
        } else {
            self.noret_cands.remove(&entry);
        }
        let mut calls = ex.calls;
        calls.extend(ex.tails.iter().copied());
        calls.sort_unstable();
        calls.dedup();
        let size = ex
            .blocks
            .iter()
            .map(|b| b.end)
            .max()
            .unwrap_or(entry)
            .saturating_sub(entry);
        let (name, src, is_thunk) = if let Some(n) = self.ctx.sym_names.get(&entry) {
            (n.clone(), NameSource::Symbol, ex.thunk_import.is_some())
        } else if let Some(i) = ex.thunk_import.and_then(|i| img.imports.get(i as usize)) {
            (i.display_name().to_string(), NameSource::Symbol, true)
        } else if Some(entry) == img.entry {
            ("entry".to_string(), NameSource::Engine, false)
        } else {
            (format!("sub_{entry:x}"), NameSource::Engine, false)
        };
        let noreturn = (closed && ex.tails.is_empty() && is_noreturn_name(&name))
            || self.ctx.noret.contains(&entry);
        if noreturn {
            self.ctx.noret.insert(entry);
        }
        if fresh && matches!(how, Discovery::GapScan | Discovery::GapWeak) {
            self.stats.gap_functions += 1;
        }
        self.xrefs.extend(ex.xrefs);
        let nedges = ex.blocks.iter().map(|b| b.succs.len()).sum::<usize>() as u32;
        self.funcs.insert(
            entry,
            Func {
                entry,
                name: name.into_boxed_str(),
                name_source: src,
                calls: calls.into_boxed_slice(),
                called_by: Box::new([]),
                ranges: merge_ranges(&ex.blocks),
                size,
                insns: ex.insns,
                nblocks: ex.blocks.len() as u32,
                nedges,
                is_thunk,
                noreturn,
                discovered_by: how,
            },
        );
    }

    /// Interprocedural no-return propagation. A function becomes no-return
    /// when it cannot return itself (no `ret`, no open exit) and all of its
    /// tail-call targets are no-return. Callers of newly no-return functions
    /// are re-explored, so code after such a call is no longer treated as
    /// fall-through; that can make the callers no-return in turn.
    /// Returns the number of functions re-explored.
    fn propagate_noreturn(&mut self) -> Result<usize, AnalyzeError> {
        let mut reexplored = 0usize;
        let mut dropped: Vec<(u64, u64, u64)> = Vec::new();
        for _round in 0..16 {
            if self.cancel.load(Ordering::Relaxed) {
                return Err(AnalyzeError::Cancelled);
            }
            let mut newly: Vec<u64> = Vec::new();
            loop {
                let pending: Vec<u64> = self
                    .noret_cands
                    .keys()
                    .copied()
                    .filter(|e| !self.ctx.noret.contains(e))
                    .collect();
                let mut changed = false;
                for e in pending {
                    let tails = self.noret_cands.get(&e).cloned().unwrap_or_default();
                    // Name-based no-return targets (imports, thunks) count too.
                    if tails.iter().all(|&t| self.ctx.is_noreturn(t)) && self.ctx.noret.insert(e) {
                        changed = true;
                        if let Some(f) = self.funcs.get_mut(&e) {
                            f.noreturn = true;
                        }
                        // Callers already stop at calls to name-based no-return
                        // functions (exit thunks etc.): no need to revisit them.
                        if !self.ctx.is_noreturn_by_name(e) {
                            newly.push(e);
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
            if newly.is_empty() {
                break;
            }
            let newly: HashSet<u64> = newly.into_iter().collect();
            let callers: Vec<u64> = self
                .funcs
                .values()
                .filter(|f| f.calls.iter().any(|c| newly.contains(c)))
                .map(|f| f.entry)
                .collect();
            for c in callers {
                let Some(old) = self.funcs.remove(&c) else {
                    continue;
                };
                let ex = self.ctx.explore(c);
                self.stats.instructions =
                    self.stats.instructions.saturating_sub(u64::from(old.insns));
                self.record(c, old.discovered_by, ex, false);
                if let Some(f) = self.funcs.get_mut(&c) {
                    f.name = old.name;
                    f.name_source = old.name_source;
                    for &(s, e) in old.ranges.iter() {
                        dropped.push((s, e, c));
                    }
                }
                reexplored += 1;
            }
            self.process()?;
        }
        // Drop xrefs from code the re-explored callers no longer reach.
        if !dropped.is_empty() {
            dropped.sort_unstable();
            let funcs = &self.funcs;
            self.xrefs.retain(|x| {
                let i = dropped.partition_point(|d| d.0 <= x.from);
                !dropped[..i].iter().rev().take(4).any(|&(s, e, owner)| {
                    x.from >= s
                        && x.from < e
                        && !funcs.get(&owner).is_some_and(|f| f.contains(x.from))
                })
            });
        }
        Ok(reexplored)
    }

    /// Scan uncovered code for functions. Each gap is walked once per
    /// round: a candidate is explored immediately and scanning resumes after
    /// what it covered, so back-to-back unreferenced functions need one pass.
    fn gap_scan(&mut self) -> Result<(), AnalyzeError> {
        let img = self.img;
        let align = if img.arch == Arch::Aarch64 { 4 } else { 1 };
        // Reused across rounds: a fresh multi-MB buffer per round is not
        // reliably recycled by macOS malloc and grew the footprint.
        let mut covered: Vec<(u64, u64)> = Vec::new();
        let mut gaps: Vec<(u64, u64, bool)> = Vec::new();
        for _round in 0..4 {
            (self.progress)(Progress {
                phase: "gap-scan",
                functions: self.funcs.len() as u64,
                queued: 0,
                instructions: self.stats.instructions,
            });
            gaps.clear();
            {
                covered.clear();
                let n: usize = self.funcs.values().map(|f| f.ranges.len()).sum();
                covered.reserve(n);
                covered.extend(self.funcs.values().flat_map(|f| f.ranges.iter().copied()));
                covered.sort_unstable();
                for cr in img.code.iter().filter(|c| !c.is_stub) {
                    let mut a = cr.start;
                    let mut ci = covered.partition_point(|&(_, e)| e <= a);
                    while a < cr.end {
                        while ci < covered.len() && covered[ci].1 <= a {
                            ci += 1;
                        }
                        if ci < covered.len() && covered[ci].0 <= a {
                            a = a.max(covered[ci].1);
                            continue;
                        }
                        let gap_end = if ci < covered.len() {
                            covered[ci].0.min(cr.end)
                        } else {
                            cr.end
                        };
                        gaps.push((a, gap_end, a == cr.start));
                        a = gap_end;
                    }
                }
            }
            let before = self.funcs.len();
            for &(gs, ge, at_section_start) in &gaps {
                let mut p = gs;
                let mut weak_ok = true;
                let _ = at_section_start;
                while p < ge {
                    while p < ge {
                        match is_padding(img, p) {
                            Some(k) => p += k,
                            None => break,
                        }
                    }
                    if p >= ge {
                        break;
                    }
                    let mut pick = None;
                    if !self.ctx.rejected.contains(&p)
                        && !img.inside_known_range(p)
                        && !self.funcs.contains_key(&p)
                    {
                        if looks_like_prologue(img, p) {
                            pick = Some((p, Discovery::GapScan));
                        } else if weak_ok {
                            pick = Some((p, Discovery::GapWeak));
                        }
                    }
                    if pick.is_none() {
                        let mut q = p.saturating_add(align);
                        while q < ge && pick.is_none() {
                            if !self.ctx.rejected.contains(&q)
                                && !img.inside_known_range(q)
                                && looks_like_prologue(img, q)
                            {
                                pick = Some((q, Discovery::GapScan));
                            }
                            q += align;
                        }
                    }
                    let Some((c, how)) = pick else { break };
                    self.queue.push_back((c, how));
                    self.process()?;
                    // Resume after the new function's coverage within this gap.
                    match self.funcs.get(&c) {
                        Some(f) => {
                            let end = f
                                .ranges
                                .iter()
                                .filter(|r| r.0 >= c && r.0 < ge)
                                .map(|r| r.1)
                                .max()
                                .unwrap_or(c + align);
                            p = end.max(c + align);
                            weak_ok = true;
                        }
                        None => {
                            // Rejected: only prologue-validated candidates until the next function.
                            p = c + align;
                            weak_ok = false;
                        }
                    }
                }
            }
            if self.funcs.len() == before {
                break;
            }
        }
        Ok(())
    }
}

/// Run discovery over a loaded image.
pub fn analyze(
    img: &Image,
    opts: &Options,
    progress: &dyn Fn(Progress),
    cancel: &AtomicBool,
) -> Result<Analysis, AnalyzeError> {
    let t0 = std::time::Instant::now();
    let hints: Vec<u64> = if opts.use_hints {
        img.function_hints.clone()
    } else {
        img.entry.into_iter().collect()
    };
    let mut seeds: Vec<u64> = hints
        .into_iter()
        .filter(|&a| img.is_code(a) && img.code_range(a).is_none_or(|c| !c.is_stub))
        .collect();
    seeds.sort_unstable();
    seeds.dedup();
    let mut ctx = Ctx::new(img, opts, None)?;
    ctx.known.extend(seeds.iter().copied());
    let mut d = Driver {
        ctx,
        img,
        opts,
        queue: seeds.iter().map(|&a| (a, Discovery::Seed)).collect(),
        funcs: BTreeMap::new(),
        noret_cands: HashMap::new(),
        xrefs: XrefTable::new(xref_base(img), xref_capacity_hint(img)),
        stats: Stats {
            seeds: seeds.len() as u64,
            ..Default::default()
        },
        progress,
        cancel,
    };
    drop(seeds);
    d.process()?;

    // Code pointers: `lea`/`adrp+add` into code, and pointers stored in data.
    progress(Progress {
        phase: "pointers",
        functions: d.funcs.len() as u64,
        queued: 0,
        instructions: d.stats.instructions,
    });
    let mut cands: Vec<u64> = d
        .xrefs
        .iter()
        .filter(|x| x.kind == XrefKind::DataRead && img.is_code(x.to))
        .map(|x| x.to)
        .collect();
    cands.extend(code_pointers_in_data(img));
    cands.sort_unstable();
    cands.dedup();
    let align = if img.arch == Arch::Aarch64 { 4 } else { 1 };
    for c in cands {
        if c % align == 0
            && !d.funcs.contains_key(&c)
            && img.code_range(c).is_some_and(|r| !r.is_stub)
            && !img.inside_known_range(c)
            && !inside_function(&d.funcs, c)
        {
            d.queue.push_back((c, Discovery::DataPtr));
        }
    }
    d.process()?;
    progress(Progress {
        phase: "noreturn",
        functions: d.funcs.len() as u64,
        queued: 0,
        instructions: d.stats.instructions,
    });
    d.stats.noreturn_reexplored += d.propagate_noreturn()? as u64;
    if opts.gap_scan {
        d.gap_scan()?;
        // Gap-scan functions may be no-return themselves (or call one).
        let n = d.propagate_noreturn()?;
        d.stats.noreturn_reexplored += n as u64;
        if n > 0 {
            d.gap_scan()?;
        }
    }

    // Free the exploration state (known/rejected sets, caches, queue) before
    // building the final tables: it is the largest transient at this point.
    let Driver {
        ctx,
        queue,
        noret_cands,
        funcs,
        mut xrefs,
        mut stats,
        ..
    } = d;
    drop((ctx, queue, noret_cands));

    let mut functions: Vec<Func> = funcs.into_values().collect();
    // called_by in two passes (count, then fill exact-size slices): no
    // per-callee Vec growth or hash map over millions of call edges.
    let idx = |functions: &[Func], c: u64| functions.binary_search_by_key(&c, |f| f.entry).ok();
    let mut counts = vec![0u32; functions.len()];
    for f in &functions {
        for &c in f.calls.iter() {
            if let Some(i) = idx(&functions, c) {
                counts[i] += 1;
            }
        }
    }
    let mut lists: Vec<Vec<u64>> = counts
        .iter()
        .map(|&n| Vec::with_capacity(n as usize))
        .collect();
    drop(counts);
    for f in &functions {
        for &c in f.calls.iter() {
            if let Some(i) = idx(&functions, c) {
                lists[i].push(f.entry);
            }
        }
    }
    for (f, mut v) in functions.iter_mut().zip(lists) {
        if !v.is_empty() {
            // Callers are visited in entry order, so `v` is already sorted.
            v.dedup();
            f.called_by = v.into_boxed_slice();
        }
    }
    functions.shrink_to_fit();
    xrefs.finish();
    let by_from = xrefs.index_by_from();
    stats.duration_ms = t0.elapsed().as_millis() as u64;
    progress(Progress {
        phase: "done",
        functions: functions.len() as u64,
        queued: 0,
        instructions: stats.instructions,
    });
    Ok(Analysis {
        functions,
        xrefs,
        by_from,
        stats,
        opts: opts.clone(),
    })
}

/// Initial capacity for the xref table: an upper estimate from the code
/// size. Reserving once avoids growth by `realloc`, which on large binaries
/// briefly holds two copies of a 100+ MB table and leaves the freed copy in
/// malloc's cache (~200 MB of footprint on Chrome). Capacity that is never
/// written costs address space only: large allocations are zero-fill on
/// demand, so untouched pages are not part of the process footprint.
fn xref_capacity_hint(img: &Image) -> usize {
    let code: u64 = img
        .code
        .iter()
        .filter(|c| !c.is_stub)
        .map(|c| c.end.saturating_sub(c.start))
        .sum::<u64>()
        // Section headers are file data: never trust them beyond the file.
        .min(img.slice_len as u64);
    // Measured: 0.024 xrefs per code byte on Electron and Chrome, 0.043 on
    // Telegram; 1/16 leaves headroom. Exceeding it just falls back to
    // normal `Vec` growth.
    usize::try_from(code / 16)
        .unwrap_or(usize::MAX)
        .clamp(1 << 12, 1 << 26)
}

/// Base for the 32-bit xref offsets: the lowest address the image maps
/// (ignoring `__PAGEZERO`-style reservations with no access rights).
fn xref_base(img: &Image) -> u64 {
    img.segments
        .iter()
        .filter(|s| s.vsize > 0 && s.perms != 0)
        .map(|s| s.vaddr)
        .chain(img.code.iter().map(|c| c.start))
        .min()
        .unwrap_or(0)
}

/// Public wrapper so the renderer can annotate adrp/add/ldr sequences.
pub fn a64_track_pub(
    d: &Decoded,
    regs: &mut [Option<u64>; 32],
    loaded: &mut [Option<u64>; 32],
) -> Option<u64> {
    a64_track(d, regs, loaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noreturn_names() {
        assert!(is_noreturn_name("_exit"));
        assert!(is_noreturn_name("__stack_chk_fail"));
        assert!(is_noreturn_name("exit@plt"));
        assert!(is_noreturn_name("core::panicking::panic_fmt"));
        assert!(!is_noreturn_name("printf"));
        assert!(!is_noreturn_name("exit_handler"));
    }
}
