# Test corpus

Small, benign C programs (`src/`) compiled by `build.sh` into `out/` (not committed)
for arm64 and x86_64 at -O0, -O1, -O2, -O3 and -Os, each with debug info plus a
stripped copy. Symbols of the unstripped build are the ground truth for
function-detection benchmarks (`make bench`, `cargo test --test corpus`).

**No real malware is ever committed or downloaded here.**

`build-pe.sh` cross-compiles `pe/sample.c` into Windows PE executables for
x86-64, ARM64 and x86 (hardened and weak variants) with clang + lld-link —
the `rust-lld` shipped with the Rust toolchain is enough, no Windows SDK or
CRT is needed. Import libraries are generated from `.def` files. The PE
tests (`cargo test --test pe`) build them on the fly; set
`DRISHTI_REQUIRE_PE=1` to fail instead of skipping when the tools are missing.
