# AGENTS.md — Repository Guidelines for animaksm

## What this is

`animaksm` is a Rust-based userspace daemon that drives Linux's Kernel Samepage
Merging (KSM) subsystem with a PSI-aware governor, marks other processes'
anonymous pages KSM-eligible by ptrace-injecting `prctl(PR_SET_MEMORY_MERGE)`,
and logs the resulting KSM statistics. It reduces memory use in cloud,
container, and embedded workloads where many processes share identical pages.

It is a KSM tool and nothing else. It writes only `/sys/kernel/mm/ksm/*`.

## Structure

```
animaksm/
├── Cargo.toml [workspace]
├── crates/
│   ├── common/      # Shared: config, procfs, PSI, KSM, error
│   └── daemon/      # animaksm main binary
├── config/
│   └── animaksm.toml  # Runtime configuration
├── systemd/            # Service units
├── Makefile            # check, test, coverage targets
```

## Build / test / run

```bash
# Mandatory commands
cargo build --workspace
make check          # cargo check + fmt + clippy
make test           # cargo test --workspace
make coverage       # HTML report in target/llvm-cov/html/
make coverage-ci    # LCOV → target/llvm-cov/lcov.info

# Exercise daemon locally
cargo run -p animaksm-daemon -- run --config config/animaksm.toml --dry-run
```

## Architecture landmines

- **Kernel/sysfs**: `/sys/kernel/mm/ksm`, `/proc` — dry-run only in local dev
- **Systemd**: Service units in `systemd/` — document new capabilities
- **Config**: `config/animaksm.toml` — keep defaults conservative

## Testing rules

- All tests live next to code (`#[cfg(test)]` mods)
- Async tests: `#[tokio::test]`
- Filesystem: use `tempfile` scoped to test
- **Before PR**: `make test` + `make coverage`
- **Known flake**: `TestFetchSubscriptionTimeout` (timing-sensitive)

## Git rules

**Branch model**: GitHub flow — `main` branch, feature/user branches off `main`.

**Conventional Commits**:

```
feat(scope): description
fix(scope): description
test(scope): description
```

**Sync procedure**:

```bash
# 1. Branch
# 2. Edit → commit → push → PR
# 3. After merge → delete local + remote → rebase main
```

## Security

- The daemon injects syscalls into other processes, so it needs
  `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The systemd unit compensates
  with `ProtectSystem=strict`, `NoNewPrivileges=yes` and
  `ReadWritePaths=/var/lib/animaksm /sys/kernel/mm/ksm`.
- Never widen the write surface beyond the KSM sysfs directory.

## Rust gotchas

- Async runtime: only Tokio v1 (installed in the workspace)
- `unsafe` is confined to the low-level kernel interfaces: the ptrace/prctl
  injection and `process_madvise` calls in `crates/daemon/src/madvise.rs` (5
  sites) and the PSI trigger fd handling in `crates/common/src/psi.rs` (6
  sites). Do not add it elsewhere.

## No secrets

No API keys or secrets are in scope. Dry-run mode is sufficient for local testing.
