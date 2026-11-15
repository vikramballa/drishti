# Daily plan

Started 2026-11-14. One day = one small, finished, tested step. Tick the box when its "done when" is true.
Big-picture order and reasons: [ROADMAP.md](ROADMAP.md). Finished work: [PROGRESS.md](PROGRESS.md).

**Rules for every day**
- `make check` is green before the box is ticked.
- If the step touches analysis or memory: measure Telegram with `DRISHTI_MEMSTAT=1` (no regression > 10%).
- Write one line in PROGRESS.md (and DECISIONS.md if a choice was made).
- Don't start the next day's step while today's is red.

---

## Week 1 — Save, shrink, trust

- [x] **Day 1 — Save the work** ✅ 2026-11-14
  - [x] First git commit of the whole project, pushed to github.com/vikramballa/drishti (2026-11-14, `994e8d9`)
  - [x] Re-run the fuzz targets (1 h each, 17.0 M runs, 0 crashes) and record the result in PROGRESS.md
  - [x] Tag `v0.1.0`
  - Done when: `git log` shows the commit, the tag exists, and PROGRESS.md has a real fuzz result

- [x] **Day 2 — Shrink the IR (before writing the lifter)** ✅ 2026-11-15
  - [x] Registers become `u16` ids from a per-architecture table (no `String`)
  - [x] Constants become `u64` (rare wide variant for anything bigger)
  - [x] Remove `Var::Mem` (`Load`/`Store` already cover memory); destinations are a typed `Place`
  - [x] Add a size test: `Var` ≤ 16 B, `Insn` ≤ 56 B (now exactly 16 B / 56 B)
  - [x] Update `docs/IR.md`
  - Done when: size test passes and all IR interpreter tests pass (today: Var 32 B, Insn 128 B + heap)

- [x] **Day 3 — Smaller xrefs** ✅ 2026-11-15
  - [x] `XrefC` stores `u32` offsets from the image's lowest address + `u8` kind, with a fallback for images spanning more than 4 GiB
  - [x] Bump `ANALYSIS_REV` (cache format changes) → rev 3, cache format 2
  - Result: byte-identical on 45 corpus files + Telegram + Chrome; Chrome peak heap 589 → 434 MB, peak footprint 488 → 419 MB (now under the 450 MB budget); Telegram 224 → 178 MB heap
  - Done when: output is byte-identical on corpus, Telegram and Chrome, and Chrome peak memory is measured and written down

- [x] **Day 4 — AI gives checkable claims** ✅ 2026-11-15
  - [x] AI answers carry structured claims (kind: calls / imports / string / address / function, plus the cited thing)
  - [x] Old free-text answers still display
  - Done when: a test shows a sample answer parsed into claims

- [x] **Day 5 — AI claim checker** ✅ 2026-11-15
  - [x] Each claim checked against the call graph, imports, strings and addresses
  - [x] VERIFIED / REFUTED / UNVERIFIED badges in the UI; unchecked answers say "unverified"
  - Done when: unit tests cover a true claim, a false claim and an uncheckable claim

## Week 2 — The translator (AArch64 lifter, ROADMAP B2)

- [x] **Day 6 — Lifter: arithmetic and logic** ✅ 2026-11-15
  - [x] add/sub/and/orr/eor/mov/shifts, with flags for the `s` forms
  - Done when: unit tests per instruction pass

- [x] **Day 7 — Lifter: memory** ✅ 2026-11-15
  - [x] ldr/str families, pre/post-index, pairs (ldp/stp)
  - Done when: unit tests pass

- [x] **Day 8 — Lifter: control flow** ✅ 2026-11-15
  - [x] b/bl/br/blr/ret/cbz/tbz/b.cond; anything unknown becomes `INTRINSIC`
  - Done when: unit tests pass

- [x] **Day 9 — Lifter coverage** ✅ 2026-11-15
  - [x] Coverage report: % of instructions lifted (not `INTRINSIC`) — `drishti lift F --coverage`
  - Result: corpus arm64 -O2 100% (netclient 305/305, switches 222/222); Telegram 97.99% (15.62M of 15.94M; rest is FP/SIMD arithmetic + `brk`)
  - Done when: ≥ 95% on corpus -O2 and on Telegram

- [x] **Day 10 — Lift on demand with a memory cap** ✅ 2026-11-15
  - [x] Lift per function when asked; LRU cache capped by **bytes**, not entries (`GET …/functions/{addr}/ir`, `DRISHTI_LIFT_CACHE_MB`, default 64)
  - Result: Telegram `functions` heap peak 178 MB / footprint 188 MB (Day 3: 178 / 187); 64 MB cap, every function lifted twice: peak held 64.0 MB, 0 over-cap events
  - Done when: Telegram peak memory unchanged when lifting is not used; cap respected under load

## Week 3 — Prove it correct, quick wins, release

- [x] **Day 11 — Unicorn test setup** ✅ 2026-11-15
  - [x] `unicorn-engine` as a **dev-dependency only** (GPL-2.0: never in the shipped binary); DECISIONS.md line
  - Done when: one hand-written instruction runs the same in Unicorn and in the IR interpreter

- [x] **Day 12 — Random differential tests** ✅ 2026-11-15
  - [x] `proptest` random register/memory states through both, for every lifted instruction
  - Done when: 0 mismatches (bugs found are fixed with a regression test)

- [ ] **Day 13 — Compare engine (backend)**
  - [ ] Per function: Drishti vs Ghidra vs radare2 boundary agreement, call-set Jaccard, disagreement score
  - Done when: API returns scores for a corpus binary

- [ ] **Day 14 — Compare tab (UI)**
  - [ ] Side-by-side view, function list sortable by "engines disagree"
  - Done when: E2E journey opens the Compare tab

- [ ] **Day 15 — Public release**
  - [ ] README install steps, screenshots, macOS arm64 tarball on GitHub Releases
  - [ ] AI answers labelled "unverified" where not checked
  - Done when: a fresh download runs on a clean Mac account

## Later (broken into days when we get there)

- [ ] SSA + dataflow (ROADMAP B4)
- [ ] Weak spots upgrade: real data-flow from input to dangerous calls, starting from the sink call sites only (never the whole binary), with a work budget
- [ ] Decide: own decompiler (B5–B7) vs more depth (FLIRT-style signatures, ARM32 with its lifter, Office provenance)
- [ ] Linux sandbox (bubblewrap / landlock + seccomp) before advertising Linux
- [ ] Published OpenAPI + short Python client example (scripting without a plugin language)

**Not planned:** debugger (would run the input; breaks the "never execute" rule), embedded plugin language, team logins.
