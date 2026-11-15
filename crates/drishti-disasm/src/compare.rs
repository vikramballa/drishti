//! Multi-engine comparison (spec §7.8, ROADMAP C4, Day 13): line up the
//! functions Drishti, Ghidra and radare2 found in the same file and score
//! where they disagree.
//!
//! Functions are matched by entry address. For every function at least one
//! engine found:
//! - **boundary agreement**: every engine that found it gives the same
//!   extent (last byte − entry, the definition all three share);
//! - **block difference**: largest − smallest basic-block count;
//! - **call Jaccard**: the smallest pairwise |A∩B| / |A∪B| of the direct
//!   call-target sets (two empty sets count as identical). Only targets
//!   that are a function entry in at least one engine's list count, so the
//!   engines' different bookkeeping for import stubs (Drishti records the
//!   import slot a stub jumps through, a data address) isn't a disagreement;
//! - **disagreement score** 0–100 = 50·missing + 20·size + 10·blocks +
//!   20·calls, where `missing` is the share of the other engines that did
//!   not find the function, `size` is 1 − smallest/largest extent,
//!   `blocks` is (largest − smallest)/largest block count and `calls` is
//!   1 − call Jaccard. A function only one engine found scores 50; one all
//!   engines agree on scores 0.
//!
//! Engine-agnostic and pure, so it is unit-tested here; the server feeds it
//! the lists the external tools produce (`drishti-server/src/tools/compare.rs`).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One function as an engine sees it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineFn {
    pub entry: u64,
    /// Extent in bytes: (last byte + 1) − entry.
    pub size: u64,
    pub blocks: u32,
    /// Direct call targets (any order, duplicates allowed).
    pub calls: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Every function one engine found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineList {
    pub engine: String,
    pub functions: Vec<EngineFn>,
}

/// What one engine says about a matched function.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Seen {
    pub size: u64,
    pub blocks: u32,
    pub calls: usize,
}

/// One function across engines.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub entry: u64,
    pub name: Option<String>,
    /// Engine → what it found (`None`: the engine didn't find a function here).
    pub engines: BTreeMap<String, Option<Seen>>,
    pub found_by: usize,
    pub boundary_agree: bool,
    pub block_diff: u32,
    pub call_jaccard: f32,
    pub score: u8,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub functions: usize,
    /// Found by every engine.
    pub found_by_all: usize,
    /// Found by every engine with the same extent.
    pub boundaries_agree: usize,
    /// Mean call Jaccard over functions found by 2+ engines.
    pub mean_call_jaccard: f32,
    /// Engine → functions only that engine found.
    pub only: BTreeMap<String, usize>,
    /// Functions scoring 50 or more.
    pub high_disagreement: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub engines: Vec<String>,
    pub summary: Summary,
    /// Sorted by entry address.
    pub rows: Vec<Row>,
}

fn jaccard(a: &BTreeSet<u64>, b: &BTreeSet<u64>) -> f32 {
    let union = a.union(b).count();
    if union == 0 {
        return 1.0;
    }
    a.intersection(b).count() as f32 / union as f32
}

/// Compare the engines' function lists (the first list's names win).
pub fn compare(lists: &[EngineList]) -> Comparison {
    let engines: Vec<String> = lists.iter().map(|l| l.engine.clone()).collect();
    let n = lists.len();
    // entry → per-engine function (index into `lists`).
    let mut by_entry: BTreeMap<u64, Vec<Option<&EngineFn>>> = BTreeMap::new();
    for (i, l) in lists.iter().enumerate() {
        for f in &l.functions {
            let slot = by_entry.entry(f.entry).or_insert_with(|| vec![None; n]);
            // Duplicate entries in one list: keep the first.
            if slot[i].is_none() {
                slot[i] = Some(f);
            }
        }
    }
    // Call targets that are functions to some engine (see module docs).
    let is_fn = |a: &u64| by_entry.contains_key(a);
    let mut summary = Summary::default();
    let mut jac_sum = 0.0f64;
    let mut jac_n = 0usize;
    let mut rows = Vec::with_capacity(by_entry.len());
    for (&entry, per) in &by_entry {
        let found: Vec<&EngineFn> = per.iter().flatten().copied().collect();
        let k = found.len();
        let sets: Vec<BTreeSet<u64>> = found
            .iter()
            .map(|f| f.calls.iter().copied().filter(is_fn).collect())
            .collect();
        let (mut smin, mut smax) = (u64::MAX, 0u64);
        let (mut bmin, mut bmax) = (u32::MAX, 0u32);
        for f in &found {
            smin = smin.min(f.size);
            smax = smax.max(f.size);
            bmin = bmin.min(f.blocks);
            bmax = bmax.max(f.blocks);
        }
        let mut jac = 1.0f32;
        for i in 0..k {
            for j in i + 1..k {
                jac = jac.min(jaccard(&sets[i], &sets[j]));
            }
        }
        let missing = if n > 1 {
            (n - k) as f32 / (n - 1) as f32
        } else {
            0.0
        };
        let size_d = if k > 1 && smax > 0 {
            1.0 - smin as f32 / smax as f32
        } else {
            0.0
        };
        let block_d = if k > 1 && bmax > 0 {
            (bmax - bmin) as f32 / bmax as f32
        } else {
            0.0
        };
        let call_d = if k > 1 { 1.0 - jac } else { 0.0 };
        let score =
            (100.0 * (0.5 * missing + 0.2 * size_d + 0.1 * block_d + 0.2 * call_d)).round() as u8;
        let boundary_agree = k > 0 && smin == smax;
        if k == n {
            summary.found_by_all += 1;
            if boundary_agree {
                summary.boundaries_agree += 1;
            }
        }
        if k == 1
            && n > 1
            && let Some(i) = per.iter().position(Option::is_some)
        {
            *summary.only.entry(engines[i].clone()).or_default() += 1;
        }
        if k > 1 {
            jac_sum += f64::from(jac);
            jac_n += 1;
        }
        if score >= 50 {
            summary.high_disagreement += 1;
        }
        let name = per.iter().flatten().find_map(|f| f.name.clone());
        let engines_map = engines
            .iter()
            .zip(per.iter())
            .map(|(e, f)| {
                (
                    e.clone(),
                    f.map(|f| Seen {
                        size: f.size,
                        blocks: f.blocks,
                        calls: f
                            .calls
                            .iter()
                            .filter(|a| is_fn(a))
                            .collect::<BTreeSet<_>>()
                            .len(),
                    }),
                )
            })
            .collect();
        rows.push(Row {
            entry,
            name,
            engines: engines_map,
            found_by: k,
            boundary_agree,
            block_diff: if k > 1 { bmax - bmin } else { 0 },
            call_jaccard: if k > 1 { jac } else { 1.0 },
            score,
        });
    }
    summary.functions = rows.len();
    summary.mean_call_jaccard = if jac_n > 0 {
        (jac_sum / jac_n as f64) as f32
    } else {
        1.0
    };
    Comparison {
        engines,
        summary,
        rows,
    }
}

/// Sort rows for "where do the engines disagree?": score, then address.
pub fn sort_by_disagreement(rows: &mut [Row]) {
    rows.sort_by(|a, b| b.score.cmp(&a.score).then(a.entry.cmp(&b.entry)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(entry: u64, size: u64, blocks: u32, calls: &[u64]) -> EngineFn {
        EngineFn {
            entry,
            size,
            blocks,
            calls: calls.to_vec(),
            name: None,
        }
    }
    fn list(e: &str, fs: Vec<EngineFn>) -> EngineList {
        EngineList {
            engine: e.into(),
            functions: fs,
        }
    }

    #[test]
    fn full_agreement_scores_zero() {
        let a = vec![f(0x100, 40, 3, &[0x200, 0x200]), f(0x200, 8, 1, &[])];
        let c = compare(&[
            list("drishti", a.clone()),
            list("ghidra", a.clone()),
            list("radare2", a),
        ]);
        assert_eq!(c.rows.len(), 2);
        for r in &c.rows {
            assert_eq!(r.score, 0);
            assert!(r.boundary_agree);
            assert_eq!(r.call_jaccard, 1.0);
            assert_eq!(r.found_by, 3);
        }
        assert_eq!(c.summary.found_by_all, 2);
        assert_eq!(c.summary.boundaries_agree, 2);
        assert!(c.summary.only.is_empty());
        // Duplicate call targets count once.
        assert_eq!(
            c.rows[0].engines["ghidra"].as_ref().map(|s| s.calls),
            Some(1)
        );
    }

    #[test]
    fn disagreements_are_scored() {
        let d = list(
            "drishti",
            vec![
                f(0x100, 40, 4, &[0x200, 0x500]),
                f(0x200, 8, 1, &[]),
                f(0x900, 4, 1, &[]),
            ],
        );
        let g = list(
            "ghidra",
            vec![
                f(0x100, 80, 2, &[0x200]),
                f(0x200, 8, 1, &[]),
                f(0x500, 16, 2, &[]),
            ],
        );
        let c = compare(&[d, g]);
        let at = |e: u64| c.rows.iter().find(|r| r.entry == e).expect("row");
        // 0x100: size 40 vs 80 (0.5), blocks 4 vs 2 (0.5), calls {200,500} vs {200} (J = 0.5).
        let r = at(0x100);
        assert!(!r.boundary_agree);
        assert_eq!(r.block_diff, 2);
        assert_eq!(r.call_jaccard, 0.5);
        assert_eq!(r.score, 25); // 20·0.5 + 10·0.5 + 20·0.5
        assert_eq!(at(0x200).score, 0);
        // Found by one of two engines: missing = 1.
        assert_eq!(at(0x500).score, 50);
        assert_eq!(at(0x900).found_by, 1);
        assert_eq!(c.summary.only.get("drishti"), Some(&1));
        assert_eq!(c.summary.only.get("ghidra"), Some(&1));
        assert_eq!(c.summary.high_disagreement, 2);
        let mut rows = c.rows.clone();
        sort_by_disagreement(&mut rows);
        assert_eq!(
            rows.iter().map(|r| r.entry).collect::<Vec<_>>(),
            [0x500, 0x900, 0x100, 0x200]
        );
    }

    #[test]
    fn non_function_call_targets_are_ignored() {
        // Drishti's stub "calls" its import slot (a data address); the other
        // engine records no call. Same function, no disagreement.
        let d = list("drishti", vec![f(0x100, 12, 1, &[0x9000])]);
        let g = list("ghidra", vec![f(0x100, 12, 1, &[])]);
        let c = compare(&[d, g]);
        assert_eq!(c.rows[0].score, 0);
        assert_eq!(
            c.rows[0].engines["drishti"].as_ref().map(|s| s.calls),
            Some(0)
        );
    }

    #[test]
    fn three_engines_missing_is_a_share() {
        let one = vec![f(0x10, 4, 1, &[])];
        let c = compare(&[list("a", one.clone()), list("b", one), list("c", vec![])]);
        // Two of three found it: missing = 1/2 → 25.
        assert_eq!(c.rows[0].score, 25);
        assert_eq!(c.summary.found_by_all, 0);
        assert!(c.rows[0].engines["c"].is_none());
    }
}
