# AGENTS.md — zswap-tune

Context for AI coding agents and maintainers working in this repository.

## What this is

A dependency-free (std-only) Rust binary that live-tunes one kernel parameter:
`/sys/module/zswap/parameters/max_pool_percent`. The kernel re-reads that value on
every zswap store, so the change takes effect immediately — no reboot, no module
reload, no swap cycle.

It exists to answer one question: **does raising the zswap ceiling buy RAM at an
acceptable cost in flash writes?** The daemon both acts and records, and `--report`
turns the recording into an evidence-backed verdict.

## Non-negotiable constraints

| Constraint | Why |
| --- | --- |
| **Zero third-party crates** | Deliberate. `Cargo.toml` must have no `[dependencies]`. `Cargo.lock` is committed (binary crate, trivially stable). |
| **Never blocks or panics** | A transient `/proc` or debugfs read failure is logged and skipped. The decision poll never stalls on a failed read. |
| **Writes exactly one path** | `/sys/module/zswap/parameters/max_pool_percent`. Nothing else, ever. |
| **Decision semantics frozen** | `decide()`, the 15 s poll, the 10 pp step and the `[20, 50]` clamp are pinned by the original 15 unit tests. Do not change them. |

## Layout

Single file by design — the whole tool is `src/main.rs` (~2000 lines):

| Region | Contents |
| --- | --- |
| `1–80` | Constants: paths, limits (`MIN_LIMIT`/`MAX_LIMIT`/`STEP`), policy thresholds, the usage text |
| `109–178` | `clamp`, `decide`, `Debounce` — the tuning policy |
| `179–300` | `MemInfo` (from `/proc/meminfo`), `read_limit`, `write_limit` (verifies by reading back) |
| `301–430` | `Override` (the pin file), `ZswapCounters` (debugfs, `Option` per field) |
| `432–700` | `Sample`/`DeviceLine`, recording, `poll`, `record_tick`, `run_daemon`, `run_once` |
| `776–930` | `parse_records`, `WRITE_EVIDENCE_DEVICES`, `json_num`, `json_device_bytes` |
| `932–1175` | `analyse`, `verdict`, `print_report` — the report path |
| `1175–1246` | `opt`, `print_stats` |
| `1246–end` | `Args` parsing + `main` |
| tests | `mod tests` at the end of `src/main.rs` |

## Key behaviours an agent must not "fix"

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
evidence. This is why an idle machine legitimately yields
`insufficient data` rather than a made-up verdict — **do not manufacture a
result to fill the table.**

**zram is excluded from write evidence.** Its "writes" are RAM compressions, not
the flash endurance cost the verdict is about. `WRITE_EVIDENCE_DEVICES` is
`/dev/md0` + `/dev/sda1` only.

**`--stats` never exits non-zero for unreadable debugfs.** `/sys/kernel/debug/zswap`
is `drwx------`, so an unprivileged reader gets `EACCES`; the tool degrades to the
meminfo/parameter view plus one explanatory line and still exits 0.

## Policy (do not alter without updating README + the 15 original tests)

Raise when `MemAvailable >= 25 %` **and** ratio `>= 2.2`; lower when ratio
`< 1.5`, debounced over 3 consecutive readings, converging to 20 %; deadband in
`[1.5, 2.2)` is inert. A change is at most 10 pp, clamped to `[20, 50]`. The limit
is a **ceiling, not a reservation** — lowering it never frees RAM.

## CLI surface

```console
$ zswap-tune                    # daemon: 15 s decision poll, 60 s JSONL record
$ zswap-tune --once             # one poll, apply, print, exit
$ zswap-tune --once --dry-run   # report the decision, never write sysfs
$ zswap-tune --stats            # live snapshot
$ zswap-tune --report [PATH]    # per-ceiling deltas + verdict
```

`ZSWAP_TUNE_RECORD_INTERVAL=<seconds>` shortens the 60 s cadence for testing.
`/run/zswap-tune.pin` holding an integer in `[20, 50]` replaces the decision path;
it is honoured verbatim, never clamped; removing it restores `decide()`.

## Operating note (this machine)

The systemd unit `zswap-tune.service` is **enabled but deliberately not started**,
so any local run of the binary alongside it will contend for the same sysfs path.
Run `--once`/`--stats`/`--report` freely; do not start the service, and do not
`swapoff`/`swapon`, mount/unmount debugfs, or touch any kernel command line,
initramfs, dracut, modprobe, fstab, grub or sysctl config. Memory-pressure
generation (`stress-ng` etc.) is out of scope — it would not represent the real
workload.

## Verifying a change

```console
$ cargo build --release 2>&1 | tee /tmp/build.log   # exit 0, zero warnings
$ cargo test --release                              # all 39 pass
$ sudo cargo run --release -- --stats               # root: live table, exit 0
$ cargo run --release -- --stats                    # unprivileged: degraded, exit 0
$ sudo cargo run --release -- --report tests/fixtures/report.jsonl
```

The fixture-driven tests are the deterministic proof of the analysis math; live
data is not required to validate `analyse`/`verdict`.
