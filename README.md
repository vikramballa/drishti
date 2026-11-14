# Drishti

Drishti opens compiled programs and documents and shows what's inside: format, sections, imports, strings, functions, disassembly, control-flow graphs and cross-references. It also explains in plain language where a file came from and whether it looks safe. It runs as a fast local tool on your Mac and works in any browser, phone included.

- **One binary, about 11 MB.** It contains the CLI, the API server, the analysis engine and the web UI. You don't need Docker, a JVM or Python to run it.
- **Light and fast.** Inputs are memory-mapped and CFGs are rebuilt on demand. Telegram (189 MB) analyses in about 2 s with a peak footprint of about 245 MB. Chromium-sized frameworks (500k functions) take under 8 s and stay below 450 MB.
- **Built for modern apps.** It handles universal and arm64e Mach-O (chained fixups, `__auth_stubs`, `LC_FUNCTION_STARTS`, compact unwind), Swift/ObjC/Go/Rust/Electron/Flutter detection, Electron `app.asar`, APK/IPA/JAR listing, ELF (PLT/GOT, `.eh_frame`) and PE (IAT, `.pdata`, TLS, .NET detection).
- **Live.** Analysis progress streams over a WebSocket. Files you open in place are watched and re-analysed when they change, for example when you rebuild them.
- **Explains what it finds.** A plain-English summary, security hardening checks, code-signing and entitlements, detected behaviours with the functions responsible, indicators (URLs, IPs, paths) and crypto constants.
- **Where did this file come from?** For PDFs it shows the software and device that made the file, the author, dates and time zone, edit history and revisions, who signed it, links, attachments, and risky features such as scripts and auto-run actions. For files opened by path it also shows the website or app they were downloaded from.
- **A verdict first.** Every file opens with a green / amber / red verdict and its reasons, then who made it (verified signature or not), what it can access (with the developer's own explanation for each permission), who it talks to, and which analytics, ad or crash-reporting kits it bundles. Simple mode hides the technical views; Expert mode shows everything.
- **Ask in plain English.** An optional assistant answers questions like "Is this safe?" or "What does this function do?" with links to the facts behind each sentence. It uses a model on your computer (Ollama) by default, or a cloud model (Claude, GPT, Gemini, OpenRouter, Groq) with your own key if you choose to.
- **Free security tools, safely.** If installed, Drishti runs Ghidra and radare2 (readable C-like code), YARA with thousands of community malware rules, ClamAV, capa, FLOSS, ExifTool (photo GPS, authors), oletools (Office macros), binwalk, JADX (Android/Java), ILSpy (.NET), WABT (WebAssembly) and ipsw (Mac app classes). Each runs in a macOS sandbox with no internet and can only write to its own folder.
- **Optional online checks.** VirusTotal and MalwareBazaar (sends only the file's fingerprint), URLhaus and AbuseIPDB (addresses found in the file). Off until you turn them on.
- **Check your whole Mac.** What starts automatically, and who made each installed app.
- **Advanced search.** Text in any letter case and in UTF-8 or UTF-16; YARA-style hex patterns (`48 8b ?? [2-4] ( e8 | e9 )`); regular expressions over raw bytes; numbers and constants (`0xdeadbeef`, `-1`, `3.14`) in every width and byte order; instruction patterns across all functions (`mov edi, *; call *malloc`). Narrow to code, data or one section, search every file you've opened at once, export results to CSV/JSON or copy them as a YARA rule.
- **Function queries.** `calls:SecItemCopyMatching size>200 -is:thunk`, `str:password`, `callers=0`, `name:/^sub_/` and more in the Functions list (press `?` there for the syntax). The strings list takes `/regex/` filters, kind, minimum length and "used by code".
- **Compare versions.** A "what changed" view between two versions of a program.
- **Agent-ready.** `drishti mcp` lets Claude Code inspect binaries directly.
- **Safe.** Input is only parsed and decoded, never executed.

## Quick start

```sh
make release                    # builds web UI + target/release/drishti
make install                    # optional: copies to ~/.local/bin/drishti

drishti serve                   # http://127.0.0.1:7878
```

Open the page, then drop a file, or type a path such as `/Applications/Telegram.app` to analyse it in place.

## AI assistant (optional)

```sh
# install Ollama from ollama.com, then:
ollama pull qwen3:4b-instruct   # 2.5 GB, fine on a 16 GB Mac
```

Drishti finds it at `http://127.0.0.1:11434` automatically. Settings lets you choose another model or point to a llama.cpp or LM Studio server. Everything else works without AI.

## Optional tools

Install whichever you want; Drishti finds them automatically (Settings → Tools shows what's missing and the command to copy):

```sh
brew install ghidra radare2 yara clamav exiftool binwalk jadx wabt blacktop/tap/ipsw
uv tool install flare-capa && uv tool install flare-floss && uv tool install oletools
```

Then use **Settings → Tools** to download the YARA-Forge rules, the capa rules and the ClamAV database. Ghidra needs Java 25 (`brew install openjdk@25`, which Homebrew installs with it).

## Cloud AI and online checks (optional)

Add keys in **Settings → AI** and **Settings → Online checks**, or set environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY`, `VT_API_KEY`, `ABUSECH_AUTH_KEY`, `ABUSEIPDB_API_KEY`). Keys stay in `~/.drishti/secrets.json` (owner-only) and are never sent back to the browser. Cloud AI receives a summary of the file, never the file itself; files marked private always use the local model.

## CLI

```sh
drishti info /bin/ls                       # triage: format, arch, hashes, sections, findings
drishti doc ~/Downloads/file.pdf           # where a document came from + is it safe
drishti strings app.exe --min 6
drishti search app "password"                          # text, any case, UTF-8 + UTF-16
drishti search app "48 8b ?? [2-4] e8" -m hex --scope code
drishti search app 'https?://[\w.-]+' -m regex
drishti search app 0x5be0cd19 -m number --endian both
drishti search app "bl *SecItemCopyMatching" -m insn   # instruction patterns
drishti functions /bin/ls                  # function discovery
drishti disasm /bin/ls --addr 0x100000960 --count 40
drishti analyze app --out normalized.json  # full normalized-schema result
drishti worker --input F --out DIR         # engine worker contract (spec §7.7)
drishti bench prog --stripped prog.stripped [--no-hints]   # precision / recall vs symbols
drishti mcp                                # MCP server on stdio for AI agents
drishti schema                             # JSON Schema of the normalized format
drishti engines
```

Use `--arch x86_64|arm64` to pick a slice of a universal binary.

## Web UI

- **Overview**: identity and hashes, section entropy, findings, capabilities grouped from imports, libraries, and container contents.
- **Functions**: virtualized list with search and sort by size, blocks, callers or complexity.
- **Code** and **Graph**: linear listing and CFG. Click targets to follow them. Press `Space` to toggle between the two views and `g` for "Go to".
- **Calls**, **Hex** (with a data inspector), **Strings** (with xrefs), **Imports/Exports**, and **Notes**, where renames and comments are stored separately from engine results.

Phones get a single-pane layout with a bottom tab bar. The UI can be installed as a PWA.

## Use it from Claude Code

```sh
claude mcp add drishti -- drishti mcp      # after `make install`
```

Claude then has tools to open a binary, list and read functions, follow cross-references, search strings and bytes, and save renames and comments that also appear in the UI.

## Server mode

Run `DRISHTI_TOKEN=secret drishti serve --host 0.0.0.0` to use it from other devices. A token is required whenever Drishti binds to a non-loopback address. Put it behind HTTPS (a reverse proxy) and enter the token under Settings in the UI. In server mode, opening server-side paths is disabled.

## Development

```sh
make check      # rustfmt, clippy -D warnings, web typecheck, tests, schema freshness
make bench      # corpus function-detection report
cd web && npm run dev   # UI dev server proxying to :7878
```

See `PROJECT_SPEC.md` for the full plan, `docs/PROGRESS.md` for status, and `docs/DECISIONS.md` for design choices and spec deviations.

## Legal and ethical use

Drishti is for education, security research, malware analysis, interoperability, and analysis of software you own or are permitted to analyse. Licence agreements, copyright and anti-circumvention laws may restrict reverse engineering, and they vary by country. You are responsible for complying with them. Drishti does not include features for removing licence checks or DRM, or for decrypting protected app-store binaries.
