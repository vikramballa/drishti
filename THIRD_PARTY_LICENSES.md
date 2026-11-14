# Third-party components

Bundled in the `drishti` binary (verify before each release with `cargo about` or `cargo license`):

| Component | Licence |
|---|---|
| goblin | MIT |
| iced-x86 | MIT |
| capstone / capstone-rs | BSD-3-Clause / MIT |
| axum, tokio, tower, hyper | MIT |
| serde, serde_json, schemars | MIT OR Apache-2.0 |
| rusqlite + SQLite | MIT / public domain |
| memmap2, zip, flate2, zlib-rs | MIT OR Apache-2.0 / Zlib |
| sha2, md-5 (RustCrypto) | MIT OR Apache-2.0 |
| cpp_demangle, rustc-demangle, msvc-demangler | MIT OR Apache-2.0 / MIT |
| rust-embed, mime_guess, clap, tracing | MIT OR Apache-2.0 / MIT |
| regex, regex-automata, regex-syntax, aho-corasick, memchr | MIT OR Apache-2.0 / Unlicense OR MIT |
| Preact, @preact/signals (web UI) | MIT |

External engines (phase 3+) are invoked as separate processes and are not bundled:
Ghidra (Apache-2.0), radare2/Rizin (LGPL-3.0), angr (BSD-2), JADX (Apache-2.0),
ILSpy (MIT), wabt (Apache-2.0), binwalk (MIT), oletools (BSD-2).
