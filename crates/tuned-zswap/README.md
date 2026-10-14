# tuned-zswap

The zswap tuner as a dependency-free library (`tuned_zswap`), plus the
standalone `tuned-zswap` binary. See the
[top-level README](../../README.md) for how it fits into `tuned`.

> **Save every megabyte.** Consumer hardware runs AI agents, browsers and
> container fleets that were sized for a datacenter, and RAM is the one resource
> a developer cannot stripe across a RAID of NVMe drives. This tool compresses
> swap instead of pretending the hardware is bigger.

A tiny, dependency-free Rust daemon that live-tunes one kernel parameter:
`/sys/module/zswap/parameters/max_pool_percent`.

The kernel re-reads that value on every zswap store, so adjusting it from user
space takes effect **immediately**. There is nothing to reboot.

## What it does

Every 15 seconds the daemon:

1. reads `/proc/meminfo` (`MemTotal`, `MemAvailable`, `Zswap`, `Zswapped`);
2. reads the current `max_pool_percent` from sysfs;
3. computes the free-memory headroom and the compression ratio
   (`Zswapped / Zswap`);
4. adjusts the limit by at most 10 percentage points, and only inside a fixed
   range.

Every 60 seconds it additionally appends one JSON record to
`/var/log/tuned-zswap/stats.jsonl`, capturing the ceiling in force together with
the kernel's own zswap counters (`/sys/kernel/debug/zswap/*`), memory
availability, the compression ratio and the write volume of the swap-backed
devices. Those records are what `--report` analyses.

## Tuning policy

| Quantity | Value |
| --- | --- |
| Minimum limit | 25 % of RAM |
| Maximum limit | 50 % of RAM |
| Step size | at most 10 percentage points per change |
| Raise when | `MemAvailable >= 25 %` of RAM **and** ratio `>= 2.2` |
| Lower when | ratio `< 1.5`, debounced over 3 consecutive readings, converging to 25 % |
| Deadband | ratio in `[1.5, 2.2)` → no action (prevents oscillation) |

Rationale: raising the ceiling only helps when the pool actually compresses
(ratio >= 2.2 means ~2.2x less RAM than disk writes would have cost) and there
is still plenty of free RAM to spend. A pool that barely compresses (ratio <
1.5) burns RAM on compression metadata for no benefit, so the limit is pulled
back towards 25 %. The deadband in between is deliberately inert so the daemon
does not oscillate.

## Important: the limit is a ceiling, not a reservation

`max_pool_percent` is an upper bound, **not** a pre-allocation. zswap will still
only use as much RAM as it actually compresses. Consequently:

* lowering it **never frees RAM** — pages already in the pool stay there until
  they are written back or invalidated;
* raising it only *permits* future stores to use more memory.

This daemon can therefore only act prospectively.

## Scope

It writes **exactly one** thing: `max_pool_percent`. It does not:

* touch zswap enablement, the compressor, or the shrinker (zswap is already on,
  already using zstd, already with the shrinker enabled on this machine);
* touch swap devices, `/etc/fstab`, `zram`, `md`, or any other subsystem;
* modify the kernel command line, `/efi`, the initramfs, dracut, or modprobe
  configuration. No reboot or module reload is ever required.

## Manual override: `/run/tuned-zswap.pin`

While `/run/tuned-zswap.pin` exists and holds an integer in `[25, 50]`, the
daemon uses that value as the limit and writes it to sysfs instead of consulting
the decision path. Remove the file to hand control back:

```console
$ sudo sh -c 'echo 50 > /run/tuned-zswap.pin'   # force ceiling 50
$ sudo rm /run/tuned-zswap.pin                  # back to automatic tuning
```

The pin is honoured exactly as written — a value outside `[25, 50]` or one that
is not an integer is ignored, not clamped.

## Usage

The crate ships two entry points. `tuned-zswap` is the original standalone
binary; the fused daemon exposes the same operations as subcommands.

```console
$ tuned-zswap --once            # one poll, apply, print report, exit
$ tuned-zswap --once --dry-run  # same, but never write sysfs
$ tuned-zswap                   # daemon mode, poll every 15s forever
$ tuned-zswap --stats           # live snapshot of ceiling, pool size, eviction
$ tuned-zswap --report          # judge the ceilings from the recorded history
$ tuned-zswap --help
```

From the fused `tuned` binary:

```console
$ tuned zswap-once [--dry-run]
$ tuned zswap-stats
$ tuned zswap-verdict [PATH]
$ tuned run                     # both subsystems in one process
```

Flags:

* `--once` — perform a single poll, decide and apply, then exit. Exits non-zero
  if the sysfs write fails or cannot be verified by reading back.
* `--dry-run` — only valid together with `--once`; reports what it *would* write
  and leaves sysfs untouched.
* `--stats` — print the current ceiling, the pool's RAM footprint, the
  compression ratio, the eviction rate since boot and the reject counters, then
  exit. The kernel's counters live in debugfs and are only readable by root; as
  an unprivileged user the table degrades to the meminfo and parameter view
  plus an explicit note that the counters are unavailable, and still exits 0.
* `--report [PATH]` — read a recorded stats file (default
  `/var/log/tuned-zswap/stats.jsonl`), compute per-interval deltas, group them
  by the ceiling that was in force and print one table plus a verdict. An
  interval is evidence only if it was spent contiguously under one ceiling:
  samples spaced more than `RECORD_GAP_MAX` apart (300 s) belong to different
  daemon runs, and an interval whose endpoints name different ceilings measured
  neither. Both are dropped, as are intervals whose counters moved backwards.
  Consequently the `samples` column counts intervals, not records — a file of 11
  records can legitimately yield no rows at all. Group a comparison only against
  groups with at least 200 MiB of stored growth; anything smaller is reported as
  insufficient data rather than judged.
* `-h`, `--help` — usage text.

`--stats` and `--report` are mutually exclusive with each other and with
`--once`.

Logging goes to stdout/stderr, which systemd's journal captures. A bad read
(transient `/proc` or permission failure) is logged and skipped; the daemon
never panics. The recorded history is rotated daily by
`systemd/tuned-logrotate.conf` (installed as `/etc/logrotate.d/tuned-zswap`), keeping 14 compressed generations.

## Judging the ceilings

`--report` answers one question: does a higher ceiling buy RAM at the cost of
extra flash writes? It groups the recorded intervals by ceiling and compares:

* **eviction ratio** — `written_back_pages / stored_pages`, the fraction of the
  pool's history that had to be pushed back out to swap;
* **Δ NVMe write** — the recorded write volume of the swap-backed devices
  (`md0`, `sda1`), as corroboration that extra eviction really reached disk.

The verdict compares ceiling 50 against ceiling 25 and reports `PASS` only when
the eviction ratio at 50 is at least 25 % lower than at 25. If either ceiling
lacks 200 MiB of stored growth the comparison is reported as
`insufficient data` instead of being guessed at.

Collecting that verdict from a live machine takes real workload, not synthetic
pressure: see [TESTING.md](TESTING.md) for the procedure, the interval drop rules,
and a progress script to check mid-run whether either ceiling has reached the
200 MiB bar.

## Building

```console
$ cargo build --release -p tuned-zswap
```

No third-party crates — std only. Install with:

```console
$ sudo install -m 755 target/release/tuned-zswap /usr/local/bin/tuned-zswap
```

Run as root (as a systemd unit, for example), since writing to
`/sys/module/zswap/parameters/max_pool_percent` requires it.
