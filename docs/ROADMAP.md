# Roadmap — next big steps

Updated 2026-11-12. Status of finished work: [PROGRESS.md](PROGRESS.md). Design choices: [DECISIONS.md](DECISIONS.md).
Phase numbers refer to `PROJECT_SPEC.md` §10.

The order is deliberate. The machine is a 16 GB Apple Silicon Mac where Docker isn't running. That makes an in-process Rust decompiler the highest-value next feature. Docker-based engines come after it, and AI only becomes useful once there is decompiled code to reason about.

Every milestone keeps the same rules: `make check` stays green, and memory gets measured on the reference apps (Telegram, Electron Framework, Chrome Framework) with no regression beyond 10%. Spec deviations go in DECISIONS.md.

---

## A. Quality debts ✅ done 2026-11-12 (details in PROGRESS.md)

| # | Task | Done when |
|---|---|---|
| A1 | Unit tests for behaviours, IOC extraction, hardening (fixtures from the corpus), the diff matcher, and the MCP JSON-RPC loop (stdio round-trip test) | `cargo test` covers each; MCP test spawns `drishti mcp` |
| A2 | Playwright E2E: upload → overview → function → graph → rename, at 1400 px and 390 px | `make e2e` runs headless and is in CI |
| A3 | Interprocedural no-return propagation: functions whose every exit is a no-return call become no-return, then re-explore their callers | `die()` in the corpus is marked noreturn; no fall-through blocks after calls to it |
| A4 | Diff matching v2: call-graph neighbourhood + basic-block-count similarity for unnamed functions | O0↔O2 corpus pairs match ≥ 80% of functions |
| A5 | Persist the analysis cache (compact binary format, `bincode`-style) keyed by `(sha, engine version, options)` | Server restart reopens Telegram in < 300 ms, without re-analysis |
| A6 | Run the 1-hour fuzz job per target (`cargo +nightly fuzz`), triage crashes, schedule it weekly in CI | Zero crashes, recorded in PROGRESS.md |
| A7 | PE test samples: cross-compile with `zig cc -target x86_64-windows` (no MSVC needed) and add them to the corpus | PE hardening and IAT tests run in CI |

## B. Own IR, lifter and decompiler (spec phases 5–6)

This is the portfolio centrepiece: C-like pseudocode inside Drishti, with no Java or Python required.

| # | Task | Done when |
|---|---|---|
| B1 ✅ | `drishti-ir` crate: varnodes (`Reg`/`Mem`/`Const`/`Temp`) and the op set from spec §7.4; `docs/IR.md` | **done 2026-11-12**: IR types, pretty-printer, reference interpreter, 7 tests |
| B2 | **AArch64 lifter first** (the user's platform), then the x86-64 integer subset; anything else lifts to `INTRINSIC` | ≥ 95% of instructions lifted (by count) on corpus -O2 and on Telegram |
| B3 | Differential tests: Unicorn (`unicorn-engine` crate) vs the IR interpreter, from random states via `proptest` | 0 mismatches on the covered instruction set |
| B4 | `drishti-analysis`: dominators (Cooper–Harvey–Kennedy), loops, SSA (Cytron), const/copy propagation, DCE including dead flags | SSA verifier passes on every corpus function |
| B5 | Stack frames + calling conventions (AAPCS64, SysV AMD64, Win x64); argument/return recovery | Corpus function signatures match DWARF ≥ 80% |
| B6 | Type recovery v1 + libc / Foundation / Win32 signature database | `strlen(char *)` etc. typed at call sites |
| B7 | `drishti-decompile`: Phoenix-style structuring → C AST → printer with `line_map` | Output for ≥ 95% of corpus functions at -O0 with no crash |
| B8 | ObjC/Swift readability: resolve `objc_msgSend` selectors (`__objc_selrefs`), class names, Swift demangling | Telegram pseudocode shows `[NSString stringWithFormat:]`-style calls |
| B9 | UI: **Decompiler tab**, with a line ↔ disassembly ↔ CFG sync and an IR toggle | Clicking a C line highlights its instructions |
| B10 | Benchmark: recompilability + behaviour harness vs Ghidra/angr (when available) | `bench/report.md` is published |

Memory note: lift and decompile per function, on demand, and cache them in an LRU. Never decompile the whole binary up front.

## C. External engines and comparison (spec phases 3–4)

Partly done 2026-11-12 as **local sandboxed tools** instead of Docker workers (DECISIONS #33–35): Ghidra and radare2 per-function decompilation (C3, without angr), JADX, ILSpy, WABT, binwalk (scan only), oletools, YARA, ClamAV, capa, FLOSS, ExifTool, ipsw (C5), and the Electron `app.asar` browser (C7). Still open: the comparison engine and Compare tab (C4), container children analysis (C6), angr, Docker images for server mode (C2).

| # | Task | Done when |
|---|---|---|
| C1 | Adapter base (`python/drishti_adapters`, `uv`) + the worker contract + schema validation | `python -m drishti_adapters.<engine>` writes valid normalized.json |
| C2 | Docker images with the §8 sandbox (no network, read-only filesystem, seccomp, limits); the scheduler gets per-engine concurrency and timeouts. Docker starts only when an external engine is requested | An integration test confirms there is no network inside workers |
| C3 | Ghidra (PyGhidra headless) and angr adapters, decompiling on demand per function | Side-by-side Ghidra / angr / core pseudocode |
| C4 | Comparison engine (§7.8): boundary agreement, call-set Jaccard, disagreement score; **Compare tab** with synced scrolling | Function list sortable by "engines disagree" |
| C5 | JADX (APK/DEX/JAR), ILSpy (.NET), wabt (WASM), binwalk (firmware), oletools (Office), YARA | The sample APK browsable as Java; .NET DLL shown as C# |
| C6 | Container children: analyse each APK `lib/*/*.so` and fat slice as a linked child binary; full extraction with the §8.4 zip-bomb and traversal guards | APK native libraries open from the Overview "Contents" list |
| C7 | Electron apps: extract `app.asar` and show a JS source tree (with a source-map aware viewer) | Open Claude.app → browse its bundled JS |

## D. AI layer with verification (spec phase 7)

Partly done 2026-11-12: D1 (local Ollama/OpenAI-compatible and cloud Anthropic/OpenAI/Gemini/OpenRouter/Groq with server-side keys), D6 (local by default, consent for cloud, per-file "keep private"), a first D2/D4 slice (streaming Q&A, "Explain function", answer levels) and a first D3 step (numbered facts with citations the person can open; claims are not machine-verified yet). See DECISIONS #31, #37, #38.

| # | Task | Done when |
|---|---|---|
| D1 | Provider abstraction: Anthropic, OpenAI-compatible local (Ollama/llama.cpp), and Null; keys stored server-side only | Every non-AI feature still works with AI off |
| D2 | Tasks: name function, name variables, summarise, explain selection, triage report; structured JSON with `claims` | Prompts versioned in `prompts/`, results cached by hash |
| D3 | Verifier: check claims against xrefs, imports and strings; emulation (`drishti-emu`, Unicorn) for `returns_constant` | VERIFIED / REFUTED / UNVERIFIED badges in the UI |
| D4 | AI panel: accept/reject suggestions, auto-accept verified ones, cost tracking | Accepted names become annotations |
| D5 | MCP: add `decompile`, `compare_engines`, `emulate`, `verify_claim` tools; HTTP/SSE transport | Claude Code can decompile and verify through MCP |
| D6 | Local-model option (Ollama) with the "sensitive file = local only" policy | Toggle in Settings |

## E. Packaging and platforms (spec phase 8)

| # | Task | Done when |
|---|---|---|
| E1 | Tauri 2 desktop app (macOS universal, Windows, Linux) with `drishti` as a sidecar; notarised macOS build | A `.dmg` installs and runs offline |
| E2 | Homebrew formula / tap (`brew install drishti`) | One-line install |
| E3 | Mobile lite (Android first): loader + disassembly in-app, plus "connect to server" | Triage works offline on a phone |
| E4 | `.drishti` project export/import (annotations + results) | Round-trip test |
| E5 | Server hardening: rate limits, multiple users, OIDC | Server mode is documented behind HTTPS |
| E6 | More architectures in analysis: ARM32/Thumb, RISC-V64, MIPS (currently display-only) | Function-detection metrics reported per architecture |

## F. Stretch (spec phase 9 and beyond)

- Debugger integration (GDB remote / LLDB) and trace recording; the static view gets annotated with runtime values.
- Deobfuscation: control-flow-flattening recovery, opaque predicates via SMT.
- Type recovery v2 (Retypd/BinSub-style), FLIRT-like signatures for static libraries (detect inlined libc / Rust std / Go runtime).
- Collaboration: shared projects with live annotations over the existing WebSocket.
- Vulnerability helpers: dangerous-call audit (`strcpy`, `system` with user input), taint from network to sink. **First slice done 2026-11-12** (`drishti-disasm::vuln`, DECISIONS #46): call-graph reachability from input sources to dangerous sinks, surfaced via the `find_vulns` MCP tool, `/vulns` API and the "Weak spots" UI page. Upgrade to value-level taint once B2/B4 (lifter + dataflow) land.
- Natural-language helpers: plain-English → function query **done 2026-11-12** (`drishti-disasm::nlq`, DECISIONS #47); AI-assisted translation (using `nlq::SYSTEM_PROMPT`) is the follow-up.
- Autonomous agent workflows over MCP (triage → find_vulns → nl_query) **first slice done 2026-11-12** (DECISIONS #48–49).

---

## Suggested next session

Milestone A is done and **B1 (the IR) landed 2026-11-12**. Start **B2 (AArch64 lifter first) → B3 (Unicorn differential tests)** on top of `drishti-ir`: lift the AArch64 integer subset into the IR, with everything else going to `INTRINSIC`, then `proptest` random states through both Unicorn and `drishti_ir::State` and require a match. Once dataflow (B4) exists, upgrade `drishti-disasm::vuln` from call-graph reachability to value-level taint. A small memory item can go alongside: shrink `XrefC` from 24 to 16 bytes to bring Chrome-scale binaries back under 450 MB.
