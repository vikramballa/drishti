//! Compact on-disk form of an [`Analysis`] so a restarted server (or a
//! new MCP session) reopens a large binary without re-analysing it.
//!
//! Format: `DRISHTIC` magic, format version, then LEB128 varints with
//! delta-encoded sorted addresses. Telegram (255k functions, 2.8M xrefs)
//! encodes to ~25 MB. Decoding is fully bounds-checked: a truncated or
//! corrupted file yields an error, never a panic, and callers re-analyse.
//!
//! The cache key (see [`cache_key`]) contains the engine version, the
//! analysis revision and a hash of the options; bump [`ANALYSIS_REV`]
//! whenever discovery results change for the same input.

use crate::analyze::{Analysis, Discovery, Func, Options, Stats, XrefC};
use crate::xrefs::XrefTable;
use drishti_model::{NameSource, XrefKind};

const MAGIC: &[u8; 8] = b"DRISHTIC";
/// 2: the xref offset base is stored, so decoding fills the compact table
/// directly (no transient full-width copy).
const FORMAT: u32 = 2;
/// Bump when analysis output changes for identical input and options.
/// 3 (Day 3): xrefs sorted by `(to, from, kind)`, every duplicate removed.
/// 4: an unconditional jump below the function's entry is a tail call.
pub const ANALYSIS_REV: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("not a Drishti analysis cache")]
    Magic,
    #[error("cache format {0} is not supported")]
    Format(u32),
    #[error("cache is truncated or corrupted")]
    Corrupt,
}

/// File-name-safe key: `<sha>-core-<version>-r<rev>-<options hash>`.
pub fn cache_key(sha: &str, opts: &Options) -> String {
    let o = format!("{opts:?}");
    let h = o.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!(
        "{sha}-{}-r{ANALYSIS_REV}-{:08x}",
        crate::ENGINE_VERSION,
        h as u32
    )
}

// ------------------------------------------------------------------ writer

struct W(Vec<u8>);

impl W {
    fn u(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(b);
                return;
            }
            self.0.push(b | 0x80);
        }
    }
    fn i(&mut self, v: i64) {
        self.u(((v << 1) ^ (v >> 63)) as u64);
    }
    fn s(&mut self, s: &str) {
        self.u(s.len() as u64);
        self.0.extend_from_slice(s.as_bytes());
    }
    /// Sorted addresses as deltas from `base`.
    fn addrs(&mut self, base: u64, v: &[u64]) {
        self.u(v.len() as u64);
        let mut prev = base;
        for &a in v {
            self.i(a.wrapping_sub(prev) as i64);
            prev = a;
        }
    }
}

fn name_source(n: NameSource) -> u64 {
    match n {
        NameSource::Symbol => 0,
        NameSource::Engine => 1,
        NameSource::Signature => 2,
        NameSource::User => 3,
        NameSource::Ai => 4,
    }
}
fn discovery(d: Discovery) -> u64 {
    match d {
        Discovery::Seed => 0,
        Discovery::Call => 1,
        Discovery::TailCall => 2,
        Discovery::GapScan => 3,
        Discovery::GapWeak => 4,
        Discovery::DataPtr => 5,
    }
}
fn xref_kind(k: XrefKind) -> u64 {
    match k {
        XrefKind::Call => 0,
        XrefKind::Jump => 1,
        XrefKind::DataRead => 2,
        XrefKind::DataWrite => 3,
        XrefKind::String => 4,
        XrefKind::Pointer => 5,
    }
}

/// Serialise an analysis.
pub fn encode(a: &Analysis) -> Vec<u8> {
    let mut w = W(Vec::with_capacity(
        a.functions.len() * 24 + a.xrefs.len() * 6 + 64,
    ));
    w.0.extend_from_slice(MAGIC);
    w.u(u64::from(FORMAT));
    let st = &a.stats;
    for v in [
        st.seeds,
        st.instructions,
        st.jump_tables,
        st.gap_functions,
        st.noreturn_reexplored,
        st.duration_ms,
    ] {
        w.u(v);
    }
    let o = a.options();
    w.u(u64::from(o.gap_scan));
    w.u(o.max_functions as u64);
    w.u(o.max_insns_per_function as u64);
    w.u(u64::from(o.use_hints));

    w.u(a.functions.len() as u64);
    let mut prev = 0u64;
    for f in &a.functions {
        w.u(f.entry.wrapping_sub(prev));
        prev = f.entry;
        // Generated names are rebuilt from the address: store a flag only.
        let generated =
            f.name_source == NameSource::Engine && *f.name == *format!("sub_{:x}", f.entry);
        if generated {
            w.u(0);
        } else {
            w.u(1);
            w.s(&f.name);
        }
        w.u(name_source(f.name_source));
        w.u(discovery(f.discovered_by));
        w.u(u64::from(f.is_thunk) | u64::from(f.noreturn) << 1);
        w.u(f.size);
        w.u(u64::from(f.insns));
        w.u(u64::from(f.nblocks));
        w.u(u64::from(f.nedges));
        w.addrs(f.entry, &f.calls);
        w.addrs(f.entry, &f.called_by);
        w.u(f.ranges.len() as u64);
        let mut p = f.entry;
        for &(s, e) in f.ranges.iter() {
            w.i(s.wrapping_sub(p) as i64);
            w.u(e.wrapping_sub(s));
            p = e;
        }
    }
    // Xrefs are sorted by `to`: delta-encode `to`, `from` relative to `to`.
    w.u(a.xrefs.len() as u64);
    w.u(a.xrefs.base());
    let mut prev = 0u64;
    for x in a.xrefs.iter() {
        w.u(x.to.wrapping_sub(prev));
        prev = x.to;
        w.i(x.from.wrapping_sub(x.to) as i64);
        w.u(xref_kind(x.kind));
    }
    w.0
}

// ------------------------------------------------------------------ reader

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl R<'_> {
    fn u(&mut self) -> Result<u64, CacheError> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self.b.get(self.p).ok_or(CacheError::Corrupt)?;
            self.p += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(CacheError::Corrupt)
    }
    fn i(&mut self) -> Result<i64, CacheError> {
        let v = self.u()?;
        Ok(((v >> 1) as i64) ^ -((v & 1) as i64))
    }
    fn u32(&mut self) -> Result<u32, CacheError> {
        u32::try_from(self.u()?).map_err(|_| CacheError::Corrupt)
    }
    /// A length that must fit in the remaining input (each element takes at
    /// least `min` bytes), so corrupt counts cannot cause huge allocations.
    fn len(&mut self, min: usize) -> Result<usize, CacheError> {
        let n = usize::try_from(self.u()?).map_err(|_| CacheError::Corrupt)?;
        if n.saturating_mul(min.max(1)) > self.b.len().saturating_sub(self.p) {
            return Err(CacheError::Corrupt);
        }
        Ok(n)
    }
    fn s(&mut self) -> Result<Box<str>, CacheError> {
        let n = self.len(1)?;
        let end = self.p.checked_add(n).ok_or(CacheError::Corrupt)?;
        let bytes = self.b.get(self.p..end).ok_or(CacheError::Corrupt)?;
        self.p = end;
        std::str::from_utf8(bytes)
            .map(Into::into)
            .map_err(|_| CacheError::Corrupt)
    }
    fn addrs(&mut self, base: u64) -> Result<Box<[u64]>, CacheError> {
        let n = self.len(1)?;
        let mut v = Vec::with_capacity(n);
        let mut prev = base;
        for _ in 0..n {
            prev = prev.wrapping_add(self.i()? as u64);
            v.push(prev);
        }
        Ok(v.into_boxed_slice())
    }
}

/// Deserialise an analysis written by [`encode`].
pub fn decode(b: &[u8]) -> Result<Analysis, CacheError> {
    if b.get(..8) != Some(MAGIC.as_slice()) {
        return Err(CacheError::Magic);
    }
    let mut r = R { b, p: 8 };
    let fmt = r.u32()?;
    if fmt != FORMAT {
        return Err(CacheError::Format(fmt));
    }
    let stats = Stats {
        seeds: r.u()?,
        instructions: r.u()?,
        jump_tables: r.u()?,
        gap_functions: r.u()?,
        noreturn_reexplored: r.u()?,
        duration_ms: r.u()?,
    };
    let opts = Options {
        gap_scan: r.u()? != 0,
        max_functions: usize::try_from(r.u()?).map_err(|_| CacheError::Corrupt)?,
        max_insns_per_function: usize::try_from(r.u()?).map_err(|_| CacheError::Corrupt)?,
        use_hints: r.u()? != 0,
    };
    let nf = r.len(12)?;
    let mut functions = Vec::with_capacity(nf);
    let mut prev = 0u64;
    for k in 0..nf {
        let d = r.u()?;
        if k > 0 && d == 0 {
            return Err(CacheError::Corrupt); // entries are strictly increasing
        }
        let entry = prev.checked_add(d).ok_or(CacheError::Corrupt)?;
        prev = entry;
        let name = match r.u()? {
            0 => format!("sub_{entry:x}").into_boxed_str(),
            1 => r.s()?,
            _ => return Err(CacheError::Corrupt),
        };
        let name_source = match r.u()? {
            0 => NameSource::Symbol,
            1 => NameSource::Engine,
            2 => NameSource::Signature,
            3 => NameSource::User,
            4 => NameSource::Ai,
            _ => return Err(CacheError::Corrupt),
        };
        let discovered_by = match r.u()? {
            0 => Discovery::Seed,
            1 => Discovery::Call,
            2 => Discovery::TailCall,
            3 => Discovery::GapScan,
            4 => Discovery::GapWeak,
            5 => Discovery::DataPtr,
            _ => return Err(CacheError::Corrupt),
        };
        let flags = r.u()?;
        let size = r.u()?;
        let insns = r.u32()?;
        let nblocks = r.u32()?;
        let nedges = r.u32()?;
        let calls = r.addrs(entry)?;
        let called_by = r.addrs(entry)?;
        let nr = r.len(2)?;
        let mut ranges = Vec::with_capacity(nr);
        let mut p = entry;
        for _ in 0..nr {
            let s = p.wrapping_add(r.i()? as u64);
            let e = s.checked_add(r.u()?).ok_or(CacheError::Corrupt)?;
            ranges.push((s, e));
            p = e;
        }
        functions.push(Func {
            entry,
            name,
            name_source,
            calls,
            called_by,
            ranges: ranges.into_boxed_slice(),
            size,
            insns,
            nblocks,
            nedges,
            is_thunk: flags & 1 != 0,
            noreturn: flags & 2 != 0,
            discovered_by,
        });
    }
    let nx = r.len(3)?;
    let mut xrefs = XrefTable::new(r.u()?, nx);
    let mut prev = 0u64;
    for _ in 0..nx {
        let to = prev.checked_add(r.u()?).ok_or(CacheError::Corrupt)?;
        prev = to;
        let from = to.wrapping_add(r.i()? as u64);
        let kind = match r.u()? {
            0 => XrefKind::Call,
            1 => XrefKind::Jump,
            2 => XrefKind::DataRead,
            3 => XrefKind::DataWrite,
            4 => XrefKind::String,
            5 => XrefKind::Pointer,
            _ => return Err(CacheError::Corrupt),
        };
        xrefs.push(XrefC { from, to, kind });
    }
    if r.p != b.len() {
        return Err(CacheError::Corrupt);
    }
    Ok(Analysis::from_parts(functions, xrefs, stats, opts))
}

/// Read and decode a cache file; `None` (and the file removed) if it is
/// missing, stale or corrupt.
pub fn load(path: &std::path::Path) -> Option<Analysis> {
    let bytes = std::fs::read(path).ok()?;
    match decode(&bytes) {
        Ok(a) => Some(a),
        Err(_) => {
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

/// Write atomically (temp file + rename). Errors are returned for logging.
pub fn store(path: &std::path::Path, a: &Analysis) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, encode(a))?;
    std::fs::rename(&tmp, path)
}

/// Keep the cache directory under `max_bytes` by deleting the least
/// recently modified files.
pub fn prune(dir: &std::path::Path, max_bytes: u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, u64, std::path::PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            if !m.is_file() {
                return None;
            }
            Some((m.modified().ok()?, m.len(), e.path()))
        })
        .collect();
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    files.sort();
    for (_, len, p) in files {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(&p).is_ok() {
            total = total.saturating_sub(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Analysis {
        let f = |entry: u64, name: &str, src: NameSource| Func {
            entry,
            name: name.into(),
            name_source: src,
            calls: vec![0x2000, entry + 0x40].into_boxed_slice(),
            called_by: vec![0x1000].into_boxed_slice(),
            ranges: vec![(entry, entry + 0x20), (entry + 0x80, entry + 0x90)].into_boxed_slice(),
            size: 0x90,
            insns: 12,
            nblocks: 3,
            nedges: 4,
            is_thunk: false,
            noreturn: entry == 0x3000,
            discovered_by: Discovery::Call,
        };
        let functions = vec![
            f(0x1000, "main", NameSource::Symbol),
            f(0x2000, "sub_2000", NameSource::Engine),
            f(0x3000, "die", NameSource::Symbol),
        ];
        let xrefs = XrefTable::from_vec(
            0x1000,
            vec![
                XrefC {
                    from: 0x1010,
                    to: 0x2000,
                    kind: XrefKind::Call,
                },
                XrefC {
                    from: 0x2004,
                    to: 0x3000,
                    kind: XrefKind::Jump,
                },
                XrefC {
                    from: 0x1000,
                    to: 0x9000,
                    kind: XrefKind::DataRead,
                },
            ],
        );
        Analysis::from_parts(
            functions,
            xrefs,
            Stats {
                seeds: 3,
                instructions: 36,
                ..Default::default()
            },
            Options::default(),
        )
    }

    #[test]
    fn round_trip() {
        let a = sample();
        let b = decode(&encode(&a)).expect("decode");
        assert_eq!(a.functions.len(), b.functions.len());
        for (x, y) in a.functions.iter().zip(&b.functions) {
            assert_eq!(x.entry, y.entry);
            assert_eq!(x.name, y.name);
            assert_eq!(x.name_source, y.name_source);
            assert_eq!(x.calls, y.calls);
            assert_eq!(x.called_by, y.called_by);
            assert_eq!(x.ranges, y.ranges);
            assert_eq!(
                (x.size, x.insns, x.nblocks, x.nedges),
                (y.size, y.insns, y.nblocks, y.nedges)
            );
            assert_eq!(
                (x.is_thunk, x.noreturn, x.discovered_by),
                (y.is_thunk, y.noreturn, y.discovered_by)
            );
        }
        assert_eq!(a.xrefs, b.xrefs);
        assert_eq!(b.xrefs_from(0x2000, 0x2010).len(), 1);
        assert_eq!(b.stats.instructions, 36);
    }

    #[test]
    fn rejects_corruption_without_panicking() {
        let bytes = encode(&sample());
        assert!(matches!(decode(b"nope"), Err(CacheError::Magic)));
        for cut in 0..bytes.len() {
            assert!(decode(&bytes[..cut]).is_err(), "truncated at {cut}");
        }
        // Flip every byte in turn: must error or decode, never panic.
        for k in 8..bytes.len() {
            let mut b = bytes.clone();
            b[k] ^= 0xff;
            let _ = decode(&b);
        }
        let mut b = bytes.clone();
        b.push(0);
        assert!(decode(&b).is_err(), "trailing bytes");
    }

    #[test]
    fn key_changes_with_options() {
        let a = cache_key("ab", &Options::default());
        let b = cache_key(
            "ab",
            &Options {
                gap_scan: false,
                ..Default::default()
            },
        );
        assert_ne!(a, b);
        assert!(a.starts_with("ab-core-"));
    }
}
