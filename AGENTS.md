# AGENTS.md — tune

Context for AI coding agents and maintainers working in this repository.

`tune` is a Cargo workspace whose single binary `tuned` (`crates/tuned`) acts on
Linux kernel memory reclaim along **two independent axes**: KSM merging, and the
zswap `max_pool_percent` ceiling.

The axes are fused into one process, one systemd unit and one config file, but
**not into one module**. They have different runtime models and different hard
constraints, and the zswap half is required to have zero dependencies. The
façade therefore keeps the split: `crates/tuned` owns the async runtime and the
CLI, and calls into `crates/tuned-zswap` as a dependency-free library.

| Crate | Role | Target | Constraint |
|---|---|---|---|
| `crates/tuned` (+ `crates/tuned-common`) | `tuned` | KSM governor + ptrace scanner **and** the zswap driver loop | `unsafe` confined to two files; tokio v1 only |
| `crates/tuned-zswap` | `tuned_zswap` **library** + thin `tuned-zswap` binary | zswap: `max_pool_percent` | **std-only, zero third-party crates**; decision semantics frozen |

`crates/tuned-zswap` may gain `pub` items and must not gain dependencies. It must
never know the daemon exists. The dependency is one-directional.

Build/test the whole workspace with `cargo build --workspace` / `cargo test
--workspace`. Each crate's guidance lives in the sections below and applies to
that crate only.

---

## The fused daemon (`tuned`)

`tuned` is a Rust-based userspace daemon. It drives Linux's Kernel Samepage
Merging (KSM) subsystem with a PSI-aware governor, marks other processes'
anonymous pages KSM-eligible by injecting `prctl(PR_SET_MEMORY_MERGE)`, tunes the
zswap pool ceiling with the frozen `decide()` policy, and records both to
evidence files.

It writes exactly two sysfs paths: `/sys/kernel/mm/ksm/*` and
`/sys/module/zswap/parameters/max_pool_percent`. Nothing else.

### Structure

```
tune/
├── Cargo.toml [workspace]
├── crates/
│   ├── tuned-common/  # Shared: config, procfs, PSI, KSM, error (+ the [zswap] section)
│   ├── tuned/         # `tuned` main binary: governor, scanner, zswap.rs driver
│   └── tuned-zswap/   # tuned_zswap library + `tuned-zswap` binary (std-only)
├── config/
│   └── tuned.toml   # Runtime configuration, includes [zswap]
└── systemd/         # tuned.service + tuned-logrotate.conf
```

### Build / test / run

```console
$ cargo build --workspace
$ make check          # cargo check + fmt + clippy
$ make test           # cargo test --workspace
$ cargo run -p tuned-daemon -- run --config config/tuned.toml --dry-run
```

### Architecture landmines

- **Kernel/sysfs**: `/sys/kernel/mm/ksm`, `/sys/module/zswap/parameters`,
  `/proc`, `/sys/kernel/debug/zswap` — dry-run only in local dev
- **Systemd**: `systemd/tuned.service` — document new capabilities
- **Config**: `config/tuned.toml` — keep defaults conservative
- **The zswap poll is blocking inside an async task.** `zswap_tune::poll_once`
  is synchronous std code doing file I/O, so `crates/tuned/src/zswap.rs` runs it
  through `tokio::task::block_in_place`. Do not call it directly from the async
  loop, and do not make the zswap library async to "fix" this.
- **The `Debounce` outlives a single poll.** The lowering rule needs three
  consecutive low-ratio readings, so the debounce state is created once outside
  the loop behind one `parking_lot::Mutex`.

### Testing rules

- All tests live next to code (`#[cfg(test)]` mods)
- Async tests: `#[tokio::test]`
- Filesystem: use `tempfile` scoped to test
- **Before PR**: `make test` + `make coverage`
- **Known flake**: `TestFetchSubscriptionTimeout` (timing-sensitive)

### Rust gotchas

- Async runtime: only Tokio v1 (installed in the workspace)
- `unsafe` is confined to the low-level kernel interfaces: the ptrace/prctl
  injection and `process_madvise` calls in `crates/tuned/src/madvise.rs` (5
  sites) and the PSI trigger fd handling in `crates/tuned-common/src/psi.rs` (2
  sites). Do not add it elsewhere.
- `tuned-daemon` produces the `tuned` binary. It is a bin crate, not a
  library — `cargo run --example` cannot `use tuned_daemon::…`. Probe
  behaviour through the live daemon with `RUST_LOG` (note that a poll which
  succeeds but holds is `debug`, so `RUST_LOG=tuned=debug` is needed to see it).

### Security

The daemon injects syscalls into other processes, so it needs
`CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. The systemd unit compensates
with `ProtectSystem=strict`, `NoNewPrivileges=yes` and
`ReadWritePaths=/var/lib/tuned /var/log/tuned-zswap /sys/kernel/mm/ksm /sys/module/zswap/parameters`.

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
3. **Blocklist matching is by `/proc/PID/comm` substring, which is 15 chars and
   user-writable.** Chromium happens to set it to `chrome`, but a process can
   rename itself via `prctl(PR_SET_NAME)` to something that does not match any
   entry, and the daemon will mark it. The blocklist is a strong heuristic, not
   a security boundary — do not write anything that treats it as one, and do not
   "tighten" it by adding more names; the executable-VMA guard is what actually
   protects an unlisted process.

### No secrets

No API keys or secrets are in scope. Dry-run mode is sufficient for local testing.

---

## tuned-zswap

A dependency-free (std-only) Rust **library** that live-tunes one kernel
parameter: `/sys/module/zswap/parameters/max_pool_percent`. The kernel re-reads
that value on every zswap store, so the change takes effect immediately — no
reboot, no module reload, no swap cycle. `crates/tuned-zswap/src/bin/main.rs`
exposes the same code as a standalone `tuned-zswap` binary.

It exists to answer one question: **does raising the zswap ceiling buy RAM at an
acceptable cost in flash writes?** The daemon both acts and records, and
`--report` turns the recording into an evidence-backed verdict.

### Non-negotiable constraints

| Constraint | Why |
|---|---|
| **Zero third-party crates** | Deliberate. `crates/tuned-zswap/Cargo.toml` has an empty `[dependencies]`. It must not inherit `workspace.dependencies` either. |
| **Never blocks or panics** | A transient `/proc` or debugfs read failure is logged and skipped. The decision poll never stalls on a failed read. |
| **Writes exactly one path** | `/sys/module/zswap/parameters/max_pool_percent`. Nothing else, ever. |
| **Decision semantics frozen** | `decide()`, the 15 s poll, the 10 pp step and the `[25, 50]` clamp are pinned by the original 15 unit tests. Do not change them. |
| **No async, no dependency on the daemon** | The library is synchronous std code. `crates/tuned` bridges to it via `block_in_place`; the library must never gain a runtime or import from the daemon. |

### Layout

Logic lives in `crates/tuned-zswap/src/lib.rs` (~2240 lines); the CLI was split
out to `crates/tuned-zswap/src/bin/main.rs` (~90 lines):

| Region | Contents |
|---|---|
| `lib.rs` `1–80` | Constants: paths, limits (`MIN_LIMIT`/`MAX_LIMIT`/`STEP`), policy thresholds |
| the rest | as per the region table in `crates/tuned-zswap/README.md` |

Region numbering is preserved from the standalone crate. Verify a change with the
existing tests, not by diffing token streams — rustfmt re-wraps punctuation.

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

The standalone helper keeps its original flag surface, prefixed `tuned-zswap`.
The fused daemon uses subcommands instead of flags.

```console
$ tuned-zswap                    # daemon: 15 s decision poll, 60 s JSONL record
$ tuned-zswap --once             # one poll, apply, print, exit
$ tuned-zswap --once --dry-run   # report the decision, never write sysfs
$ tuned-zswap --stats            # live snapshot
$ tuned-zswap --report [PATH]    # per-ceiling deltas + verdict

$ tuned zswap-stats              # same snapshot, from the fused daemon
$ tuned zswap-verdict [PATH]     # same report; no PATH = configured stats_path
$ tuned zswap-once [--dry-run]   # one poll from the fused daemon
$ tuned run                      # both subsystems, one process
```

`TUNED_ZSWAP_RECORD_INTERVAL=<seconds>` shortens the 60 s cadence for testing.
`/run/tuned-zswap.pin` holding an integer in `[25, 50]` replaces the decision path;
it is honoured verbatim, never clamped; removing it restores `decide()`.

### Operating note (this machine)

The boot unit `zswap-tune.service` (the **pre-rename** name) is still
**enabled and active** on this machine from an earlier install, while the
workspace's `tuned` has not been installed as a unit. So a local `tuned run`
without `--dry-run` contends with that old daemon for the same sysfs path —
prefer `tuned run --dry-run`, `tuned zswap-stats`, `tuned zswap-verdict` and
`tuned zswap-once`, which write nothing. Installing `tuned.service` is a
deliberate deployment step that also requires stopping and removing that old
unit.

Do not `swapoff`/`swapon`, mount/unmount debugfs, or touch any kernel command
line, initramfs, dracut, modprobe, fstab, grub or sysctl config. Memory-pressure
generation (`stress-ng` etc.) is out of scope — it would not represent the real
workload.

### Verifying a change

```console
$ cargo test -p tuned-zswap                          # all pass
$ cargo run -p tuned-zswap -- --stats                # unprivileged: degraded, exit 0
$ sudo cargo run -p tuned-zswap -- --report crates/tuned-zswap/tests/fixtures/report.jsonl
```

The fixture-driven tests are the deterministic proof of the analysis math; live
data is not required to validate `analyse`/`verdict`.

### Collecting a real 50-vs-25 verdict

The unit tests prove the analysis math; they cannot produce a verdict from this
machine's workload. `crates/tuned-zswap/TESTING.md` covers the full collection
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

`scope` is the subsystem: `ksm` or `zswap`.

### Merge provenance

`main` contains both projects' histories joined by an unrelated-history merge
commit (58 commits from the KSM lineage, 7 from the zswap lineage). Use `git log --follow` on a
file that moved to see its pre-merge history.
