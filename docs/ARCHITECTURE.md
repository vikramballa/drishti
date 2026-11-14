# Architecture (living version of spec §3)

```
            browser / phone (PWA)        CLI          agents (MCP, phase 7)
                     │                    │                 │
                     ▼                    ▼                 ▼
 ┌───────────────── drishti (one Rust binary, ~11 MB) ─────────────────┐
 │  axum REST + WebSocket  ──  embedded Preact UI (26 KB gzip)         │
 │  job scheduler (tokio, bounded blocking pool, cancel, live events)  │
 │  sessions LRU (3)  ──  SQLite: binaries, jobs, annotations, settings│
 │                                                                     │
 │  drishti-loader   detect · ELF/PE/Mach-O · containers · strings     │
 │  drishti-disasm   decoders · discovery · CFG · xrefs · rendering    │
 │  drishti-model    normalized schema (serde + schemars)              │
 └─────────────────────────────────────────────────────────────────────┘
        │ on demand: local tools under sandbox-exec (no network, writes only to their work dir)
        ▼
   Ghidra · radare2 · capa · FLOSS · YARA · ClamAV · ExifTool · oletools · binwalk · JADX · ILSpy · WABT · ipsw
        │ opt-in, via system curl (keys on stdin)
        ▼
   Cloud AI (Anthropic, OpenAI, Gemini, OpenRouter, Groq) · VirusTotal · MalwareBazaar · URLhaus · AbuseIPDB
```

## Crates
| Crate | Role |
|---|---|
| `drishti-model` | Schema types; `drishti schema` emits `schema/drishti.schema.json`. Addresses are `u64` serialized as hex strings. |
| `drishti-loader` | Magic-byte detection, loaders, memory map (`Image::read`), import slots/stubs, function hints and authoritative extents, triage findings, strings. Input is memory-mapped. |
| `drishti-disasm` | `arch` (per-instruction flow semantics), `analyze` (discovery driver), `render` (text + model conversion), `normalize` (`AnalysisResult`), `search` (byte/insn/function queries), `vuln` (static input→sink reachability audit), `nlq` (plain-English → function query). |
| `drishti-ir` | Milestone B: typed P-code-like IR (varnodes, op set), pretty-printer, reference interpreter (`docs/IR.md`). Foundation for the lifter/decompiler; not yet wired into analysis. |
| `drishti-server` | API, jobs, sessions, storage, watcher, embedded UI. Adds `/vulns` (weak spots) and `/nl-query` (plain-English search). |
| `drishti-cli` | `drishti` binary: info, strings, disasm, functions, analyze, worker, bench, serve, schema, engines. |

## Analysis pipeline (core)
1. **Seeds**: entry, symbols, exports, `.pdata`, TLS callbacks, init arrays, `.eh_frame`, `LC_FUNCTION_STARTS`, compact unwind.
2. **Recursive descent** per function: linear decode until a terminator; conditional/unconditional edges, jump tables (x86 + AArch64 idioms), tail calls (jump to a known start or out of an authoritative extent), no-return calls (name list), import thunks.
3. **Code pointers** from `lea`/`adrp+add` into code and from data sections (raw and Mach-O chained-fixup encodings) — strictly validated.
4. **Gap scan**: one pass per gap; prologue candidates and post-terminator candidates, rejected if they decode badly, never return, swallow another function, or lie inside a known extent.
5. **Result**: compact `Func` summaries + xrefs (sorted by `to`, indexed by `from`). CFGs are rebuilt on demand.

## Request flow
`POST /binaries` (stream + hash) or `POST /binaries/open` (in place) → `register` → job → `spawn_blocking(analyze)` with throttled progress → `broadcast` → WebSocket `/events` → UI invalidates its cache for that binary.

## Server modules added in the tools round (2026-11-12)
| Module | Role |
|---|---|
| `tools/mod.rs` | Tool registry, detection, sandboxed runner, background tasks, result cache, rule/database setup endpoints |
| `tools/runners.rs` | Per-tool commands and plain-language parsers (YARA, ClamAV, capa, FLOSS, ExifTool, oletools, binwalk) + rule downloads |
| `tools/decompile.rs` | Ghidra (per-file project, `scripts/DrishtiDecompile.java`) and radare2 per-function decompilation |
| `tools/source.rs` | JADX / ILSpy / WABT / ipsw output trees and the `app.asar` browser (path-confined) |
| `plain.rs` | Verdict, maker, permissions, network groups, SDK table, grades |
| `bundle.rs` | `.app` Info.plist (plutil) and code signature (codesign) facts |
| `mac.rs` | Startup items and installed-app scan |
| `lookup.rs` | Opt-in online reputation checks |
| `net.rs` / `secrets.rs` | HTTPS via curl; API keys (0600 file, env override, never returned) |
