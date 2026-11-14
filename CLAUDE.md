# Drishti — agent guide

Full spec: PROJECT_SPEC.md (read the relevant section before each task).
Progress: docs/PROGRESS.md · Daily checklist: docs/DAILY_PLAN.md · Next steps: docs/ROADMAP.md · Decisions: docs/DECISIONS.md · Architecture: docs/ARCHITECTURE.md

## Current state (2026-11-12)
Phases 0–2 done + insights round + ROADMAP milestone A + plain-language round (DECISIONS #29–31) + tools/UX round: sandboxed external tools (Ghidra, radare2, capa, FLOSS, YARA, ClamAV, ExifTool, oletools, binwalk, JADX, ILSpy, WABT, ipsw), cloud AI with user keys, opt-in online lookups, plain-language verdict/permissions/SDK report, My Mac checks, Simple/Expert UI redesign (DECISIONS #32–43) + advanced search (DECISIONS #44–45) + agent-analysis round (DECISIONS #46–51): static Vuln Hunter (`drishti-disasm/src/vuln.rs`, call-graph input→sink reachability, analysis-only), plain-English function search (`nlq.rs`), triage briefing, 3 new MCP tools (`triage`/`find_vulns`/`nl_query`), `/vulns` + `/nl-query` API, Weak-spots UI, and the `drishti-ir` crate (milestone B1: typed IR + interpreter, `docs/IR.md`). Next: ROADMAP.md milestone B2 (AArch64 lifter) → B3 (Unicorn diff tests) → decompiler; then value-level taint to upgrade the Vuln Hunter.

## Commands
- `make check`   fmt + clippy (-D warnings) + web typecheck + all tests + schema freshness
- `make release` build the UI and the single `drishti` binary (target/release/drishti)
- `make corpus` / `make bench`  build test binaries / function-detection report
- `make e2e`     Playwright journey (desktop + phone) against the release binary
- `make fuzz-all` all fuzz targets, FUZZ_SECONDS each (default 3600; needs nightly + cargo-fuzz)
- `make schema`  regenerate schema/drishti.schema.json
- `make serve`   run the server + UI on http://127.0.0.1:7878
- `drishti doc F` PDF provenance + safety, download origin
- `drishti search F Q -m text|hex|regex|number|insn` advanced search (engine: drishti-disasm/src/search.rs)
- `drishti mcp`   MCP server on stdio (Claude Code: `claude mcp add drishti -- drishti mcp`)
- `drishti engines` which optional tools are installed (+ install commands)

## Non-negotiables
- Work phase by phase (spec §10); update docs/PROGRESS.md at the end of each session.
- Never execute input binaries natively; external tools only run under `tools::run` (sandbox, no network) (spec §8, DECISIONS #33).
- API keys only via `secrets.rs`; never log them, never return them, never put them on a command line (curl reads them from stdin).
- No real malware in the repo. No unwrap() on file-derived data in Rust.
- The normalized schema is the only contract between engines and the rest.
- Verify third-party APIs against installed versions (~/.cargo/registry/src) before using them.
- New dependency or scope change → one line in docs/DECISIONS.md.
- Memory budget matters: measure with `DRISHTI_MEMSTAT=1 drishti functions <big binary>`.
