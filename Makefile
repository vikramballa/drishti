# Drishti task runner (spec §5 allows `make` in place of `just`).
.PHONY: all web build release check fmt lint test schema schema-check corpus bench serve install e2e fuzz fuzz-all clean difftest

BIN := target/release/drishti

all: release

web:
	cd web && npm ci --no-fund --no-audit && npm run build

build: web
	cargo build

release: web
	cargo build --release
	@ls -lh $(BIN)

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	@if command -v cmake >/dev/null; then cargo clippy -p drishti-difftest --all-targets -- -D warnings; fi
	cd web && npm run typecheck

test:
	cargo test --release --no-fail-fast

# fmt + lint + all tests + schema freshness (must be green before finishing a task)
check: lint test schema-check difftest

# AArch64 lifter vs Unicorn (test-only crate; Unicorn's C build needs cmake).
# Longer run: DIFF_PER_GROUP=2000 PROPTEST_CASES=20000 make difftest
difftest:
	@if command -v cmake >/dev/null; then cargo test --release -p drishti-difftest; else echo "difftest skipped: cmake not installed"; fi

schema:
	cargo run -q --release -- schema > schema/drishti.schema.json

schema-check:
	cargo run -q --release -- schema | diff -q - schema/drishti.schema.json

corpus:
	./corpus/build.sh
	./corpus/build-pe.sh || [ $$? -eq 2 ]

bench: corpus
	@for f in corpus/out/*-O[0-3s]; do printf "%-36s " $$f; $(BIN) bench $$f --stripped $$f.stripped | sed -n 2p; done

serve: release
	$(BIN) serve

install: release
	mkdir -p $(HOME)/.local/bin && cp $(BIN) $(HOME)/.local/bin/drishti
	@echo "installed to ~/.local/bin/drishti"

# Browser end-to-end journey (desktop 1400 px + phone 390 px) against the
# release binary. Uses a sample from corpus/out when built (`make corpus`).
e2e: release
	cd web && npx playwright test

fuzz:
	cd fuzz && cargo +nightly fuzz run loader -O -- -max_total_time=3600 -timeout=10

# All fuzz targets for FUZZ_SECONDS each (default 1 h), one after another.
FUZZ_SECONDS ?= 3600
fuzz-all:
	cd fuzz && for t in detect loader disasm pdf; do \
		cargo +nightly fuzz run $$t -O -- -max_total_time=$(FUZZ_SECONDS) -rss_limit_mb=4096 -timeout=10 || exit 1; \
	done

clean:
	cargo clean
	rm -rf web/dist web/node_modules web/test-results web/playwright-report corpus/out
