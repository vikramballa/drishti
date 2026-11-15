# Drishti — agent guide

Full spec: PROJECT_SPEC.md (read the relevant section before each task).
Progress: docs/PROGRESS.md · Daily checklist: docs/DAILY_PLAN.md · Next steps: docs/ROADMAP.md · Decisions: docs/DECISIONS.md · Architecture: docs/ARCHITECTURE.md

## Current state (2026-11-15)
Phases 0–2 done + insights round + ROADMAP milestone A + plain-language round (DECISIONS #29–31) + tools/UX round (DECISIONS #32–43) + advanced search (#44–45) + agent-analysis round (#46–51: Vuln Hunter, NL query, triage, MCP tools, `drishti-ir` B1). Daily plan (docs/DAILY_PLAN.md): Days 1–4 done — v0.1.0 tag, IR shrunk to `Var` 16 B / `Insn` 56 B with `RegId` tables (#52), xrefs 12 B via `drishti-disasm/src/xrefs.rs` (#53, Chrome back under budget), AI answers carry `<claims>` parsed by `drishti-server/src/claims.rs` (#54). Next: Day 5 (claim checker), then the AArch64 lifter (Days 6–10).

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
