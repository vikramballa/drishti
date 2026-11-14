# Progress

Updated 2026-11-12 (tools + UI round).

## Phase 0 — Foundations ✅ (adapted)
- [x] Rust workspace (`crates/*`), web app, `Makefile` (instead of `justfile`)
- [x] CI workflow: fmt, clippy `-D warnings`, tests, web typecheck, schema freshness, audits
- [x] `drishti-model` types → `schema/drishti.schema.json` (generated, freshness checked by `make schema-check`)
- [ ] TypeScript/Pydantic types generated from the schema (UI currently hand-types its API subset; Python arrives in phase 3)
- [x] `docs/DECISIONS.md`, `docs/ARCHITECTURE.md`, `CLAUDE.md`

## Phase 1 — Detection + loader + triage CLI ✅
- [x] Detector: ELF, PE, PE .NET, Mach-O, fat Mach-O vs Java class, DEX, APK/IPA/JAR/OOXML/ZIP, WASM, OLE, PDF, Electron asar, `ar`
- [x] Loader: ELF/PE/Mach-O (thin + fat/universal, arm64e), sections, symbols, imports (GOT/IAT/stubs incl. chained-fixup binaries), exports, entry, memory map, entropy, packer heuristics, demangling
- [x] Function hints: symbols, exports, `.pdata`, TLS callbacks, init/fini arrays, `.eh_frame`, `LC_FUNCTION_STARTS`, compact unwind
- [x] Strings (ASCII + UTF-16LE) with VA mapping
- [x] `drishti info`, `drishti strings` with `--json`
- [x] Robustness tests (truncation, header corruption, random input) in `cargo test`
- [x] Fuzz targets (`fuzz/`: detect, loader, disasm); 1 h/target runs in milestone A6, weekly in CI (`make fuzz-all`)
- [x] Corpus build script (clang, arm64 + x86_64, O0–Os)
- [x] Sample PE files in the test set (clang + rust-lld, milestone A7)

## Phase 2 — Disassembler, functions, CFG, API, UI ✅
- [x] x86/x86-64 (iced) + AArch64 decoding; recursive descent; tail calls; no-return calls; thunk naming
- [x] Jump tables: x86 absolute, GCC/Clang PIC, MSVC RVA; AArch64 `ldr{b,h,sw}`+`add`+`br`
- [x] Gap scanning (prologue + strictly validated post-terminator candidates), code pointers in data/`lea`/`adrp`
- [x] CFG, call graph, xrefs; `drishti analyze` / `drishti worker` write `normalized.json`
- [x] API server: upload (streaming), open-in-place, jobs + WebSocket progress, FileInfo, functions, function detail, disasm, xrefs, strings, imports/exports, bytes, call graph, resolve, annotations, settings, engines
- [x] Live re-analysis when an in-place file changes
- [x] Web UI: home/upload, triage dashboard, functions (virtualized, paged), disassembly, CFG, call graph, hex + inspector, strings, imports/exports, notes, settings; responsive to 360 px with bottom tab bar
- [x] Benchmark: `drishti bench`, `make bench`; corpus test asserts thresholds
- [x] Playwright E2E (`make e2e`, milestone A2)

### Measured (Apple Silicon, release build)
| Binary | Size | Functions | Time | Peak footprint |
|---|---|---|---|---|
| `/bin/ls` (arm64e) | 250 KB | 134 | < 1 ms | 2 MB |
| corpus `switches` all opt levels | — | P/R 100 % / 100 % (with and without loader hints) | | |
| Docker backend (Go) | 214 MB | 180 k | 2.4 s | 248 MB |
| Telegram | 189 MB | 255 k | 2.3 s | 231 MB |
| Electron Framework | 206 MB | 462 k | 7.1 s | 359 MB |
| Chrome Framework 157.0.8103.38 / .52 | 531 MB | 695 k | 10.6 s | 527 MB |

Re-measured 2026-11-12 with no background load (`/usr/bin/time -l`, peak footprint). Since phase 2 the
analyser finds more functions (gap scan + no-return propagation: Chrome 500 k → 695 k), which costs
time; memory per function went down (Chrome 0.87 → 0.76 KB/function) after the allocator-slack fixes
in DECISIONS #26 (before them, the same runs peaked at 265 / 492 / 754 MB).

## Insights and usability round ✅ (2026-11-11, beyond the phase plan)
- [x] Security hardening checks (Mach-O / ELF / PE), Mach-O code-signing details and entitlements
- [x] Behaviour rules (28, capa-style) with the functions that reference the matching imports
- [x] Indicators from strings (URLs, IPs, e-mail, paths, registry, commands), crypto-constant scan
- [x] Plain-language summary; Markdown report export (`/binaries/{sha}/report.md`)
- [x] Byte-pattern (`??` wildcards) and text search
- [x] Binary diff (`/binaries/{sha}/diff?other=`): name → fingerprint → positional matching
- [x] MCP server on stdio (`drishti mcp`, 10 tools) — brings spec phase 7's agent access forward, in-process
- [x] UI: installed-app picker, instruction hints, help/shortcuts overlay, Search and Changes tabs, auto-analysis on open
- [ ] Unit tests for behaviours, diff and the MCP loop (verified manually on Telegram, `/bin/ls` and the corpus)
- [ ] Diff pairs unnamed functions only when the unmatched runs have equal length; heavily re-optimised stripped builds show as added/removed

## Milestone A — quality debts ✅ (2026-11-12)
- [x] A1 Tests: behaviours, IOCs, hardening, crypto, diff, no-return (`drishti-disasm/tests/insights.rs`), PE (`tests/pe.rs`), MCP stdio round trip (`drishti-cli/tests/mcp.rs`); new corpus program `corpus/src/netclient.c`
- [x] A2 Playwright E2E (`make e2e`): upload → overview → function → graph → rename at 1400 px and 390 px (no sideways scroll, no console errors); runs on the macOS CI job
- [x] A3 Interprocedural no-return propagation (`die`, `usage`, wrapper chains); `noreturn` in the schema
- [x] A4 Diff v2: similarity + call-graph matching; O0↔O2 corpus 32/34 = 94 % (was 0 %); `drishti diff OLD NEW`
- [x] A5 Persisted analysis cache (`drishti-disasm/src/cache.rs`, `data/cache/`); Telegram reopens after restart in ~260 ms; shared with `drishti mcp`
- [x] A6 Fuzzing. The runs found 4 bugs, all fixed, with regression fixtures in `drishti-loader/tests/fixtures/fuzz/` (run by the loader and disasm robustness tests, debug and release, with a 5 s time bound):
  - goblin export-trie panic on a bad re-export ordinal, and a stack overflow from its recursive trie walk → own iterative walker (DECISIONS #24)
  - 9.6 s (164 s under the fuzzer) on a 10 KB Mach-O claiming ~4 billion symbols → symbol iteration capped by file size
  - analysis hang (> 5 min) on a 26 KB Mach-O claiming a 9.2×10¹⁸-byte code section → code ranges clipped to file data (DECISIONS #28); this input had stalled the disasm fuzzer at < 1 000 executions
  - The fuzzers now use `-timeout=10`, so slow inputs fail fast instead of stalling a run. Clean re-run: see "Fuzz run" below. Weekly CI job (`fuzz`, Sundays) runs `make fuzz-all`
- [x] A7 PE samples via clang + rust-lld (`corpus/build-pe.sh`): x86-64/ARM64/x86, hardened + weak; ARM64 `.pdata` and PE /GS-cookie detection fixed
- [x] Analysis memory pass (DECISIONS #26): peak footprint −13 % Telegram, −27 % Electron, −30 % Chrome; output byte-identical on all three
- [x] Server fixes found by testing on Telegram (DECISIONS #27): concurrent requests loaded the same binary several times (peak 366 → 199 MB on reopen); reopening an unchanged in-place file no longer re-hashes it (1 s → 1 ms). Covered by `drishti-cli/tests/server.rs`
- [x] `make check` green; schema regenerated (`noreturn`); DECISIONS #21–28

### Fuzz run
FUZZ_RESULT_PLACEHOLDER

## Plain-language round (2026-11-12): documents, download origin, local AI
- [x] PDF provenance + safety (`drishti doc FILE [--json]`, Overview cards, report.md, MCP `document_report`): producing software/device, author, created/modified with time zone → region hint, revisions and signature-only saves, IDs, XMP history, earlier-revision metadata, signer/issuer from certificates, page size, fonts, scan detection, links, attachments, scripts/auto-actions/launch/XFA with `#xx` de-obfuscation, document-level JS name trees. Tested on 55 real PDFs (Word, Google Docs, Chrome, Canva, LaTeX, ReportLab, WeasyPrint, jsPDF, iText/JasperReports, Illustrator, PandaDoc, e-signed): ~10 ms and ≤ 15 MB each. Fuzz target `pdf` (2 min, 96 578 runs, 0 crashes)
- [x] Download origin for in-place files (Safari/Chrome URL + referring page, WhatsApp/Mail, time) from macOS xattrs
- [x] Local AI assistant: "Ask Drishti" on the Overview (suggested questions per file type, streaming answers, follow-ups), "Explain" in the Code view (function context), AI card in Settings (model picker, server URL, on/off), setup help when Ollama is missing. Default model `qwen3:4b-instruct`; cloud models never auto-picked
- [x] Non-native files show only the views that apply (Overview, Hex, Strings, Search, Notes); friendlier home/help copy
- [x] `make check` green; schema regenerated (`DocumentReport`, `FileOrigin`); DECISIONS #29–31

## External tools, cloud AI, online checks and UI redesign (2026-11-12)
User request: add external tools (Ghidra etc.), API-key AI, and fix the UX for non-experts. DECISIONS #32–43.
- [x] Tool framework (`drishti-server/src/tools/`): registry of 13 tools, detection on PATH + Homebrew/uv/dotnet folders, versions, macOS sandbox (no network, writes only to the work dir; verified), timeouts with process-group kill, capped output, heavy-tool queue, results cached per (sha, tool, version, rules), 4 GB cap
- [x] Runners + plain-language parsers, each run on real files: YARA + YARA-Forge core (5 132 rules; Telegram 1.7 s), ClamAV (Telegram 12 s), capa 10 + rules/sigs (PE 5 s), FLOSS (PE 2 s), ExifTool (GPS → map link, device serials, authors), oletools (macros), binwalk (scan only), JADX (jar → Java + Android permissions), WABT (`wasm2wat` + imports/exports), ipsw (Telegram: 11 523 classes in 7 s), ILSpy (untested, no .NET SDK)
- [x] Rule/database setup from the UI: YARA-Forge download + `yarac`, capa rules + signatures matching the installed capa, `freshclam`; safe zip extraction
- [x] Decompiler: Ghidra 12.2 headless per function (Telegram first function 9 s incl. import, then ~3 s; small programs get full auto-analysis) and radare2 (`pdc`, `pdg` with r2ghidra). "Readable code" toggle in the Code view
- [x] Electron apps: `app.asar` file browser (own reader, `drishti_loader::asar_read`, unit-tested), also from an opened `.app`
- [x] Cloud AI: Anthropic / OpenAI / Gemini / OpenRouter / Groq with the user's key (curl over stdin config), consent step, per-file "keep private", answer level (very simple / normal / technical), numbered facts with clickable citations, tool and lookup results + decompiled code in the facts
- [x] Online lookups (opt-in): VirusTotal, MalwareBazaar (hash only), URLhaus (domains), AbuseIPDB (public IPs)
- [x] Plain-language report: verdict + reasons, who made it (codesign / Authenticode / document metadata), what it can access (entitlements + the developer's own `NS…UsageDescription` text + behaviours), who it talks to (grouped), ~50 SDK/tracker signatures, A–F grades; in the Markdown report too; `/trust` full signature verification
- [x] My Mac: startup items (launch agents/daemons, signer, leftovers, Homebrew) and a scan of installed apps (signer, notarization, permissions, kits)
- [x] UI redesign: Simple/Expert modes, side navigation, Summary / Ask / Safety checks / Hidden details / Look inside / My Mac / sectioned Settings, glossary tooltips, first-run tour, inline icon set, skeleton loaders, light + dark, phone layout
- [x] Tests: `drishti-cli/tests/safety.rs` (keys never returned, 0600 file, bad keys refused, online checks off by default, no path traversal in the source browser, plain report present), unit tests for curl config quoting, key validation, YARA output parsing, plist XML parsing, host grouping, SDK/brand matching, asar reading; Playwright journey rewritten (tour; summary → checks → Expert → function → graph → rename; desktop + phone) — 3/3 pass; `make check` green
- [x] Memory: Telegram opened + analysed + insights/plain report + tools list: peak footprint 244 MB (budget ~250 MB). Tools run in their own processes (Ghidra JVM capped at 2 GB, one heavy tool at a time)

- ILSpy fix: `ilspycmd` is a .NET app host that only finds Homebrew's runtime via `DOTNET_ROOT`; `tools::run` now sets it (`dotnet_root()`), verified by decompiling a test .NET DLL to 3 C# files. All 13 tools available on the dev Mac; capa rules 10.0.0, YARA-Forge core and ClamAV database downloaded.

## Advanced search (2026-11-12)

- One engine (`drishti_disasm::search`) behind the API, the CLI (`drishti search`) and MCP (`search_bytes` upgraded, new `search_code`, query language in `list_functions`). DECISIONS #44–45.
- Modes: text (case-insensitive, UTF-8/UTF-16LE/BE), YARA-style hex, regex over bytes, numbers (int widths + floats, byte order), instruction patterns with `;` sequences (numbers match in either base: `0x1` ≡ `#1`). Scope: whole file, code, data or one section. Paging, per-kind counts, CSV/JSON export, "Copy as YARA", recent searches, search across every file in the library (`GET /api/v1/search`).
- Functions list: query language (`calls:` `callers:` `str:` `refs:` `name:/re/` `size>` `callers=0` `is:leaf|thunk|unreferenced|recursive|named|renamed|noreturn` `section:` `-term`) with inline help. Strings: `/regex/`, kind, minimum length, "used by code"; tables accept `/regex/`.
- Verified: YARA (4.x) agrees exactly with Drishti on the same hex/text patterns (88/88 hits on /bin/ls). WhatsApp (443 MB): byte searches 0.15–1 s; instruction search over 1M functions / 30.5M instructions ≈ 4 s after analysis (was 60 s+ before the allocator fix + bounded rendering + threads).
- Fix: the `DRISHTI_MEMSTAT` counting allocator now only counts when the variable is set; its atomics were slowing every multi-threaded path.
- Tests: 6 new engine unit tests; E2E journey gains an instruction search that jumps to code.

## Known gaps / next steps
Full ordered plan with acceptance criteria: [ROADMAP.md](ROADMAP.md).

- ARM32/Thumb, MIPS, RISC-V, PPC: display-only (capstone); no analysis yet.
- AArch64 jump-table variants without a preceding `cmp` bound are capped at 64 entries.
- Chrome-scale binaries are above the 450 MB budget (527 MB, with 40 % more functions than when the budget was set). Next lever: smaller xref records (24 → 16 bytes) and the per-function `Func` summary.
- Corpus binaries only build on macOS (`clang -arch`), so Linux CI skips corpus-based tests and E2E.
- Phase 3: adapter base, Ghidra/angr workers in Docker with sandbox, comparison engine.
- Documents: encrypted PDFs (even with an empty password) hide Info strings; Office (OOXML `docProps`, OLE summary info) provenance is the natural next step; no certificate-chain validation for signatures.
- AI: no claim verifier yet (D3); answers aren't cached; not added to the Playwright journey (needs a model in CI).

## Agent analysis round (2026-11-12): Vuln Hunter, NL query, Triage, IR B1
Requested features (6) analysed; built the three that reuse existing infra end-to-end, plus the IR foundation. Binary rewriting kept analysis-only (user choice). DECISIONS #46–51.
- [x] **Vuln Hunter** (`drishti-disasm/src/vuln.rs`, feature 1 SAST + feature 5 analysis): static input→sink **reachability** over the call graph. Sources (recv/read/fread/getenv/accept/…) → sinks (system/exec/strcpy/sprintf/memcpy/scanf/printf-family/dlopen/…), confidence high/medium/low, call paths, honest "not proof" caveat. Fortified `_chk` variants matched + down-ranked. Tests: `drishti-disasm/tests/vuln.rs` (input→strcpy/system path found; clean program has no highs). Telegram: 255k fns, 44 findings, < 1 s, peak footprint 209 MB (= open-only, +0 MB).
- [x] **Natural-language function search** (`drishti-disasm/src/nlq.rs`, feature 6): keyword→`FnQuery` translator, transparent (shows the query), offline (no model needed); `SYSTEM_PROMPT` ready for an AI translator. Unit tests for json+file, shell+complex, size hints, unknown.
- [x] **Triage briefing** (feature 1 triage specialist): MCP `triage` composes verdict + facts + behaviours + IOCs + weak-spot counts + hardening.
- [x] **MCP** (now 16 tools): `triage`, `find_vulns`, `nl_query` — the "autonomous RE team" surface (verified via JSON-RPC round trip on /bin/ls and Telegram).
- [x] **API**: `GET /binaries/{sha}/vulns`, `POST /binaries/{sha}/nl-query` (tested live on the release server).
- [x] **UI**: "Weak spots" page (Simple + Expert, links to code, plain language) and a plain-English box in Functions. Verified in a real browser (Playwright): weak spots render with confidence badges + paths; NL box translates "large complex functions that format strings" → `calls:printf complexity>20` → 3 matches. E2E journey extended with both.
- [x] **`drishti-ir` crate (milestone B1)**: typed P-code-like IR (varnodes, spec §7.4 op set), pretty-printer, reference interpreter; `docs/IR.md`. 7 unit tests (add/carry, signed overflow, load/store, concat/extract, cbranch). B2 (AArch64/x86-64 lifters) and B3 (Unicorn diff tests) are next.
- [x] `make check` green (fmt, clippy -D warnings, web typecheck, all tests, schema fresh). Not committed (user hasn't asked).
