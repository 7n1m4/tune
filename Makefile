.PHONY: all check test coverage coverage-html coverage-ci clean

all: check test

# ── Lint / Build Check ────────────────────────────────────────────────

check:
	cargo check --workspace --all-targets
	cargo fmt --check
	cargo clippy --workspace --all-targets -- -D warnings

# ── Tests ─────────────────────────────────────────────────────────────

test:
	cargo test --workspace

# ── Code Coverage (cargo-llvm-cov) ────────────────────────────────────
#
# Dependencies: cargo install cargo-llvm-cov
# Reports land in target/llvm-cov/html/

coverage:
	cargo llvm-cov --workspace --html

coverage-open: coverage
	xdg-open target/llvm-cov/html/index.html 2>/dev/null || \
		open target/llvm-cov/html/index.html 2>/dev/null || \
		echo "Open target/llvm-cov/html/index.html in your browser"

coverage-ci:
	cargo llvm-cov --workspace --lcov --output-path target/llvm-cov/lcov.info

# ── Cleanup ───────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf target/llvm-cov
