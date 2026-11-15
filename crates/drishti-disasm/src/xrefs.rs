//! Compact cross-reference table (Day 3). An xref is stored as two `u32`
//! offsets from a base address (the image's lowest mapped address) plus a
//! one-byte kind: 12 bytes instead of 24. Xrefs that don't fit — an image
//! spanning more than 4 GiB, or a target outside the image — go to a small
//! side table of full [`XrefC`]s, so nothing is lost and the common case
//! pays nothing for the rare one.
//!
//! Both parts are kept sorted by `(to, from, kind)`; iteration merges them,
//! so callers always see one sorted sequence.

use crate::analyze::XrefC;
use drishti_model::XrefKind;
use std::cmp::Ordering;
use std::iter::Peekable;

/// One xref relative to the table's base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Packed {
    to: u32,
    from: u32,
    kind: XrefKind,
}

/// Sort key: `(to, from, kind)`. Including the kind makes the order total,
/// so sorting is deterministic and `dedup` removes every duplicate.
fn key(x: &XrefC) -> (u64, u64, u8) {
    (x.to, x.from, x.kind as u8)
}

#[derive(Debug, Clone, Default)]
pub struct XrefTable {
    base: u64,
    narrow: Vec<Packed>,
    wide: Vec<XrefC>,
}

impl PartialEq for XrefTable {
    /// Same xrefs in the same order, however they are split.
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl Eq for XrefTable {}

impl XrefTable {
    /// An empty table with offsets from `base`, reserving `capacity`
    /// narrow entries.
    pub fn new(base: u64, capacity: usize) -> XrefTable {
        XrefTable {
            base,
            narrow: Vec::with_capacity(capacity),
            wide: Vec::new(),
        }
    }

    /// Build from full xrefs (any order); sorts and deduplicates.
    pub fn from_vec(base: u64, xrefs: Vec<XrefC>) -> XrefTable {
        let mut t = XrefTable::new(base, xrefs.len());
        t.extend(xrefs);
        t.finish();
        t
    }

    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn len(&self) -> usize {
        self.narrow.len() + self.wide.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Xrefs that did not fit the 32-bit form.
    pub fn wide_len(&self) -> usize {
        self.wide.len()
    }
    /// Heap bytes used by the entries (capacity, not length).
    pub fn heap_bytes(&self) -> usize {
        self.narrow.capacity() * size_of::<Packed>() + self.wide.capacity() * size_of::<XrefC>()
    }

    fn off(&self, a: u64) -> Option<u32> {
        a.checked_sub(self.base).and_then(|d| u32::try_from(d).ok())
    }
    fn pack(&self, x: &XrefC) -> Option<Packed> {
        Some(Packed {
            to: self.off(x.to)?,
            from: self.off(x.from)?,
            kind: x.kind,
        })
    }
    fn unpack(&self, p: &Packed) -> XrefC {
        XrefC {
            from: self.base + u64::from(p.from),
            to: self.base + u64::from(p.to),
            kind: p.kind,
        }
    }

    pub fn push(&mut self, x: XrefC) {
        match self.pack(&x) {
            Some(p) => self.narrow.push(p),
            None => self.wide.push(x),
        }
    }

    pub fn extend(&mut self, xs: impl IntoIterator<Item = XrefC>) {
        for x in xs {
            self.push(x);
        }
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&XrefC) -> bool) {
        let base = self.base;
        self.narrow.retain(|p| {
            keep(&XrefC {
                from: base + u64::from(p.from),
                to: base + u64::from(p.to),
                kind: p.kind,
            })
        });
        self.wide.retain(|x| keep(x));
    }

    /// Sort, deduplicate and drop real slack (call once building is done).
    pub fn finish(&mut self) {
        let pk = |p: &Packed| (p.to, p.from, p.kind as u8);
        if !self.narrow.is_sorted_by_key(pk) {
            self.narrow.sort_unstable_by_key(pk);
        }
        self.narrow.dedup();
        if !self.wide.is_sorted_by_key(key) {
            self.wide.sort_unstable_by_key(key);
        }
        self.wide.dedup();
        // Shrinking reallocates (a full copy); only worth it for real slack.
        if self.narrow.capacity() - self.narrow.len() > self.narrow.len() / 16 {
            self.narrow.shrink_to_fit();
        }
        self.wide.shrink_to_fit();
    }

    /// Every xref, sorted by `(to, from, kind)`.
    pub fn iter(&self) -> impl Iterator<Item = XrefC> + '_ {
        Merge::new(
            self.narrow.iter().map(|p| self.unpack(p)),
            self.wide.iter().copied(),
        )
    }

    /// Xref by position in "narrow, then wide" order (the index space used
    /// by [`XrefTable::index_by_from`]).
    pub fn get(&self, i: u32) -> Option<XrefC> {
        let i = i as usize;
        match self.narrow.get(i) {
            Some(p) => Some(self.unpack(p)),
            None => self.wide.get(i - self.narrow.len()).copied(),
        }
    }

    /// Xrefs whose target is `to`, sorted by `from`.
    pub fn to(&self, to: u64) -> Xrefs<'_> {
        let narrow = match self.off(to) {
            Some(o) => {
                let lo = self.narrow.partition_point(|p| p.to < o);
                let hi = lo + self.narrow[lo..].partition_point(|p| p.to <= o);
                &self.narrow[lo..hi]
            }
            None => &[],
        };
        let lo = self.wide.partition_point(|x| x.to < to);
        let hi = lo + self.wide[lo..].partition_point(|x| x.to <= to);
        Xrefs {
            table: self,
            narrow,
            wide: &self.wide[lo..hi],
        }
    }

    /// Positions (see [`XrefTable::get`]) ordered by `(from, to, kind)`.
    pub fn index_by_from(&self) -> Vec<u32> {
        // Positions are u32: 4G xrefs would be ~48 GB, far past any budget.
        let n = u32::try_from(self.len()).unwrap_or(u32::MAX);
        if self.wide.is_empty() {
            // Usual case: (from offset, position) packs into one u64. Narrow
            // positions are already in (to, from, kind) order, so ties on
            // `from` come out ordered by (to, kind). Half the temporary
            // memory of (u64, u32) pairs and a faster sort.
            let mut keys: Vec<u64> = self
                .narrow
                .iter()
                .enumerate()
                .map(|(i, p)| (u64::from(p.from) << 32) | i as u64)
                .collect();
            keys.sort_unstable();
            return keys.into_iter().map(|k| k as u32).collect();
        }
        let mut idx: Vec<u32> = (0..n).collect();
        idx.sort_unstable_by_key(|&i| {
            let x = self.get(i).unwrap_or(XrefC {
                from: 0,
                to: 0,
                kind: XrefKind::Call,
            });
            (x.from, x.to, x.kind as u8)
        });
        idx
    }
}

/// The xrefs to one address (see [`XrefTable::to`]).
#[derive(Clone, Copy)]
pub struct Xrefs<'a> {
    table: &'a XrefTable,
    narrow: &'a [Packed],
    wide: &'a [XrefC],
}

impl<'a> Xrefs<'a> {
    pub fn len(&self) -> usize {
        self.narrow.len() + self.wide.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = XrefC> + 'a {
        let t = self.table;
        Merge::new(
            self.narrow.iter().map(move |p| t.unpack(p)),
            self.wide.iter().copied(),
        )
    }
    pub fn to_vec(&self) -> Vec<XrefC> {
        self.iter().collect()
    }
}

impl<'a> IntoIterator for Xrefs<'a> {
    type Item = XrefC;
    type IntoIter = Box<dyn Iterator<Item = XrefC> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// Merge two `(to, from, kind)`-sorted streams.
struct Merge<A: Iterator<Item = XrefC>, B: Iterator<Item = XrefC>> {
    a: Peekable<A>,
    b: Peekable<B>,
}

impl<A: Iterator<Item = XrefC>, B: Iterator<Item = XrefC>> Merge<A, B> {
    fn new(a: A, b: B) -> Self {
        Merge {
            a: a.peekable(),
            b: b.peekable(),
        }
    }
}

impl<A: Iterator<Item = XrefC>, B: Iterator<Item = XrefC>> Iterator for Merge<A, B> {
    type Item = XrefC;
    fn next(&mut self) -> Option<XrefC> {
        match (self.a.peek(), self.b.peek()) {
            (Some(x), Some(y)) => {
                if key(x).cmp(&key(y)) == Ordering::Greater {
                    self.b.next()
                } else {
                    self.a.next()
                }
            }
            (Some(_), None) => self.a.next(),
            (None, _) => self.b.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (a, ah) = self.a.size_hint();
        let (b, bh) = self.b.size_hint();
        (a + b, ah.zip(bh).map(|(x, y)| x + y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x(from: u64, to: u64, kind: XrefKind) -> XrefC {
        XrefC { from, to, kind }
    }

    #[test]
    fn packed_is_twelve_bytes() {
        assert_eq!(size_of::<Packed>(), 12);
        assert_eq!(size_of::<XrefC>(), 24);
    }

    /// The table must answer exactly like a plain sorted `Vec<XrefC>`.
    #[test]
    fn matches_plain_vec() {
        let base = 0x1_0000_0000u64;
        let raw = vec![
            x(base + 0x10, base + 0x2000, XrefKind::Call),
            x(base + 0x10, base + 0x2000, XrefKind::DataRead),
            x(base + 0x10, base + 0x2000, XrefKind::Call), // duplicate
            x(base + 0x40, base + 0x2000, XrefKind::Jump),
            x(base + 0x20, 0x10, XrefKind::Call), // target below base
            x(base + 0x30, u64::MAX - 4, XrefKind::Jump), // target far above
            x(base + (5 << 32), base + 0x2000, XrefKind::Call), // from > 4 GiB
            x(base + 0x50, base + 0x3000, XrefKind::DataRead),
        ];
        let t = XrefTable::from_vec(base, raw.clone());
        assert_eq!(t.wide_len(), 3);

        let mut want = raw.clone();
        want.sort_unstable_by_key(key);
        want.dedup();
        assert_eq!(t.len(), want.len());
        assert_eq!(t.iter().collect::<Vec<_>>(), want);

        for to in [base + 0x2000, 0x10, u64::MAX - 4, base + 0x3000, 7] {
            let got = t.to(to).to_vec();
            let exp: Vec<XrefC> = want.iter().copied().filter(|r| r.to == to).collect();
            assert_eq!(got, exp, "to {to:#x}");
        }

        let order: Vec<XrefC> = t
            .index_by_from()
            .into_iter()
            .filter_map(|i| t.get(i))
            .collect();
        let mut exp = want.clone();
        exp.sort_by_key(|r| (r.from, r.to, r.kind as u8));
        assert_eq!(order, exp);

        // Whole-table equality ignores how entries are split.
        assert_eq!(t, XrefTable::from_vec(0, raw));
    }

    #[test]
    fn narrow_index_orders_ties_like_wide_path() {
        let base = 0x4000u64;
        let raw = vec![
            x(base + 8, base + 0x30, XrefKind::Call),
            x(base + 8, base + 0x10, XrefKind::DataRead),
            x(base, base + 0x20, XrefKind::Jump),
        ];
        let t = XrefTable::from_vec(base, raw);
        assert_eq!(t.wide_len(), 0);
        let froms: Vec<(u64, u64)> = t
            .index_by_from()
            .into_iter()
            .filter_map(|i| t.get(i))
            .map(|r| (r.from, r.to))
            .collect();
        assert_eq!(
            froms,
            vec![
                (base, base + 0x20),
                (base + 8, base + 0x10),
                (base + 8, base + 0x30)
            ]
        );
    }

    #[test]
    fn retain_works_on_both_parts() {
        let mut t = XrefTable::from_vec(
            0x1000,
            vec![
                x(0x1000, 0x2000, XrefKind::Call),
                x(0x1004, 0x10, XrefKind::Call),
            ],
        );
        t.retain(|r| r.from != 0x1004);
        assert_eq!(t.len(), 1);
        assert_eq!(t.wide_len(), 0);
        assert!(t.to(0x10).is_empty());
    }
}
