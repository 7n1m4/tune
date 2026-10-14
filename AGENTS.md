# AGENTS.md — tune

Context for AI coding agents and maintainers working in this repository.

`tune` is a Cargo workspace holding **two independent Rust binaries that both act
on Linux kernel memory reclaim**. They are deliberately *not* fused: they have
different runtime models and different hard constraints, and one is required to
have zero dependencies.

| Crate | Binary | Target | Constraint |
|---|---|---|---|
| `crates/daemon` (+ `crates/common`) | `animaksm` | KSM: governor + ptrace scanner | `unsafe` confined to two files; tokio v1 only |
| `crates/zswap-tune` | `zswap-tune` | zswap: `max_pool_percent` | **std-only, zero third-party crates**; decision semantics frozen |

Build/test the whole workspace with `cargo build --workspace` / `cargo test
--workspace`. Each crate's guidance lives in the sections below and applies to
that crate only.

---

## animaksm

`animaksm` is a Rust-based userspace daemon that drives Linux's Kernel Samepage
Merging (KSM) subsystem with a PSI-aware governor, marks other processes'
anonymous pages KSM-eligible by injecting `prctl(PR_SET_MEMORY_MERGE)`, and logs
the resulting KSM statistics. It reduces memory use in cloud, container, and
embedded workloads where many processes share identical pages.

It is a KSM tool and nothing else. It writes only `/sys/kernel/mm/ksm/*`.

### Structure

```
tune/
├── Cargo.toml [workspace]
├── crates/
│   ├── common/      # Shared: config, procfs, PSI, KSM, error
│   ├── daemon/      # animaksm main binary
│   └── zswap-tune/  # zswap-tune main binary (std-only)
├── config/
│   └── animaksm.toml  # Runtime configuration
├── docs/            # Design notes
└── systemd/         # Service units
```

### Build / test / run

```console
$ cargo build --workspace
$ make check          # cargo check + fmt + clippy
$ make test           # cargo test --workspace
$ cargo run -p animaksm-daemon -- run --config config/animaksm.toml --dry-run
```

### Architecture landmines

- **Kernel/sysfs**: `/sys/kernel/mm/ksm`, `/proc` — dry-run only in local dev
- **Systemd**: Service units in `systemd/` — document new capabilities
- **Config**: `config/animaksm.toml` — keep defaults conservative

### Testing rules

- All tests live next to code (`#[cfg(test)]` mods)
- Async tests: `#[tokio::test]`
- Filesystem: use `tempfile` scoped to test
- **Before PR**: `make test` + `make coverage`
- **Known flake**: `TestFetchSubscriptionTimeout` (timing-sensitive)

### Rust gotchas

- Async runtime: only Tokio v1 (installed in the workspace)
- `unsafe` is confined to the low-level kernel interfaces: the ptrace/prctl
  injection and `process_madvise` calls in `crates/daemon/src/madvise.rs` (5
  sites) and the PSI trigger fd handling in `crates/common/src/psi.rs` (2
  sites). Do not add it elsewhere.
- `animaksm-daemon` is a binary crate, not a library — `cargo run --example`
  cannot `use animaksm_daemon::…`. Probe behaviour through the live daemon with
  `RUST_LOG`.

### Security

The daemon injects syscalls into other processes, so it needs
`CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The systemd unit compensates
with `ProtectSystem=strict`, `NoNewPrivileges=yes` and
`ReadWritePaths=/var/lib/animaksm /sys/kernel/mm/ksm`.

Never widen the write surface beyond the KSM sysfs directory.

### Browser blocklist (settled decision, do not revert)

Browsers are **blocklisted by default**, not by configuration:
`chrome, chromium, firefox, msedge, brave, opera, vivaldi, electron`.

Verified cause (2026-10-14): `PR_SET_MEMORY_MERGE` marks executable VMAs
mergeable, and the kernel's `ksm_compatible()` does **not** exclude `VM_EXEC`,
so merged `.text` pages SIGILL chromium renderers. A userspace
`MADV_UNMERGEABLE` guard was implemented and built, but **failed live** —
on the target that crashed, 0 of 76 executable VMAs were protected. The
daemon named the exact PID that trapped 400 ms later (`protected=0
unprotected=76`), which is how the causal link was established rather than
inferred. Firefox marked with 176/177 protected and did **not** crash, so the
asymmetry is unexplained — but it is not a reason to unblock.

Two consequences an agent must respect:

1. **A configured `blocklist` replaces the default list** — dropping it
   silently drops browser protections and re-opens the crash. Documented in
   README.
2. **Clearing `run=0` does not make a flagged tree safe** — but neither does it
   require restart: the poison is inert without scanning (`full_scans` flat,
   flagged processes kept running normally for 38 min). SIGILL is
   unrecoverable, so a trap shortly after a stop is a process that already
   took the fault, not evidence of a self-sustaining loop.

### No secrets

No API keys or secrets are in scope. Dry-run mode is sufficient for local testing.

---

## zswap-tune

A dependency-free (std-only) Rust binary that live-tunes one kernel parameter:
`/sys/module/zswap/parameters/max_pool_percent`. The kernel re-reads that value
on every zswap store, so the change takes effect immediately — no reboot, no
module reload, no swap cycle.

It exists to answer one question: **does raising the zswap ceiling buy RAM at an
acceptable cost in flash writes?** The daemon both acts and records, and
`--report` turns the recording into an evidence-backed verdict.

### Non-negotiable constraints

| Constraint | Why |
|---|---|
| **Zero third-party crates** | Deliberate. `crates/zswap-tune/Cargo.toml` has an empty `[dependencies]`. It must not inherit `workspace.dependencies` either. |
| **Never blocks or panics** | A transient `/proc` or debugfs read failure is logged and skipped. The decision poll never stalls on a failed read. |
| **Writes exactly one path** | `/sys/module/zswap/parameters/max_pool_percent`. Nothing else, ever. |
| **Decision semantics frozen** | `decide()`, the 15 s poll, the 10 pp step and the `[25, 50]` clamp are pinned by the original 15 unit tests. Do not change them. |

### Layout

Single file by design — the whole tool is `crates/zswap-tune/src/main.rs`
(~2160 lines):

| Region | Contents |
|---|---|
| `1–80` | Constants: paths, limits (`MIN_LIMIT`/`MAX_LIMIT`/`STEP`), policy thresholds, the usage text |
| the rest | as per the region table in `crates/zswap-tune/README.md` |

Region numbering is preserved from the standalone crate; the file itself moved
verbatim, so line numbers still hold.

### Key behaviours an agent must not "fix"

**A missing counter is `n/a`; a real `0` is `0`.** `ZswapCounters` is
`Option<u64>` per field and `print_stats` renders absence via `opt()`. Do not
collapse these into `0` — an absent counter and a genuine zero mean different
things.

**Device name mismatch is intentional.** `/proc/swaps` names devices as
`/dev/md0`; `/proc/diskstats` names them `md0`. They are joined by basename
(`kernel_name` in both the recorder and `parse_records`). This was a real bug
before the join existed.

**`--report` skips negative deltas.** An interval whose `stored_pages` or
`written_back_pages` moved backwards is dropped, not clamped. A counter going
backwards means a zswap reset or daemon restart, and such an interval carries no
evidence. This is why an idle machine legitimately yields `insufficient data`
rather than a made-up verdict — **do not manufacture a result to fill the table.**

**`--report` also drops intervals that cross a discontinuity.** Two samples
further apart than `RECORD_GAP_MAX` (300 s) come from different daemon runs, and
an interval whose endpoints name different ceilings was never spent under either
one. Both are dropped rather than attributed to the ceiling that opened them.
Dropping them is why `samples` in the table is an interval count, not a record
count.

**zram is excluded from write evidence.** Its "writes" are RAM compressions, not
the flash endurance cost the verdict is about. `WRITE_EVIDENCE_DEVICES` is
`/dev/md0` + `/dev/sda1` only.

**`--stats` never exits non-zero for unreadable debugfs.** `/sys/kernel/debug/zswap`
is `drwx------`, so an unprivileged reader gets `EACCES`; the tool degrades to the
meminfo/parameter view plus one explanatory line and still exits 0.

### Policy (do not alter without updating README + the 15 original tests)

Raise when `MemAvailable >= 25 %` **and** ratio `>= 2.2`; lower when ratio
`< 1.5`, debounced over 3 consecutive readings, converging to 25 %; deadband in
`[1.5, 2.2)` is inert. A change is at most 10 pp, clamped to `[25, 50]`. The limit
is a **ceiling, not a reservation** — lowering it never frees RAM.

### CLI surface

```console
$ zswap-tune                    # daemon: 15 s decision poll, 60 s JSONL record
$ zswap-tune --once             # one poll, apply, print, exit
$ zswap-tune --once --dry-run   # report the decision, never write sysfs
$ zswap-tune --stats            # live snapshot
$ zswap-tune --report [PATH]    # per-ceiling deltas + verdict
```

`ZSWAP_TUNE_RECORD_INTERVAL=<seconds>` shortens the 60 s cadence for testing.
`/run/zswap-tune.pin` holding an integer in `[25, 50]` replaces the decision path;
it is honoured verbatim, never clamped; removing it restores `decide()`.

### Operating note (this machine)

The systemd unit `zswap-tune.service` is **enabled** and currently **running**
(it starts at boot). Any local run of the binary alongside it will contend for
the same sysfs path — prefer `--once`/`--stats`/`--report`, which do not conflict.

Do not `swapoff`/`swapon`, mount/unmount debugfs, or touch any kernel command
line, initramfs, dracut, modprobe, fstab, grub or sysctl config. Memory-pressure
generation (`stress-ng` etc.) is out of scope — it would not represent the real
workload.

### Verifying a change

```console
$ cargo test -p zswap-tune                          # all pass
$ cargo run -p zswap-tune -- --stats                # unprivileged: degraded, exit 0
$ sudo cargo run -p zswap-tune -- --report crates/zswap-tune/tests/fixtures/report.jsonl
```

The fixture-driven tests are the deterministic proof of the analysis math; live
data is not required to validate `analyse`/`verdict`.

### Collecting a real 50-vs-25 verdict

The unit tests prove the analysis math; they cannot produce a verdict from this
machine's workload. `crates/zswap-tune/TESTING.md` covers the full collection
procedure, the drop rules that shrink a group, and a mid-flight progress script.
Read it before attempting a live measurement — an idle pool drains, and a drained
pool yields `insufficient data` rather than a number, by design.

---

## Shared operating notes

### Git rules

**Branch model**: GitHub flow — `main` branch, feature/user branches off `main`.

**Conventional Commits**:

```
feat(scope): description
fix(scope): description
```

`scope` is the crate: `animaksm` or `zswap-tune`.

### Merge provenance

`main` contains both projects' histories joined by an unrelated-history merge
commit (animaksm 58 commits, zswap-tune 7 commits). Use `git log --follow` on a
file that moved to see its pre-merge history.
