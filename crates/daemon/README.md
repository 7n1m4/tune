<div align=center>

# [A](https://github.com/animaios/anima)KSMD

<img width="256" height="384" alt="AnimAIOS mascot" src="https://github.com/user-attachments/assets/8d548058-3363-481b-90d6-09f4620f70f7" />


### The spiritual successor to uksmd — a modern, Rust-based userspace KSM daemon with PTrace-powered process-wide KSM eligibility

<!--
[![Crates.io](https://img.shields.io/crates/v/animaksm-daemon.svg)](https://crates.io/crates.io/crates/animaksm-daemon)
[![Documentation](https://docs.rs/animaksm-daemon/badge.svg)](https://docs.rs/animaksm-daemon)
[![Build Status](https://github.com/animaios/animaksm/workflows/CI/badge.svg)](https://github.com/animaios/animaksm/actions)
-->

[![DeepSource](https://app.deepsource.com/gh/animaios/aksmd.svg/?label=code+coverage&show_trend=true&token=iBvsQ1aAT0R9zi6jTngKW_VR)](https://app.deepsource.com/gh/animaios/aksmd/)
[![DeepSource](https://app.deepsource.com/gh/animaios/aksmd.svg/?label=active+issues&show_trend=true&token=iBvsQ1aAT0R9zi6jTngKW_VR)](https://app.deepsource.com/gh/animaios/aksmd/)
[![DeepSource](https://app.deepsource.com/gh/animaios/aksmd.svg/?label=resolved+issues&show_trend=true&token=iBvsQ1aAT0R9zi6jTngKW_VR)](https://app.deepsource.com/gh/animaios/aksmd/)

---

## Why AKSMD?

I used to run **uksmd** (the userspace KSM daemon from the CachyOS project) on my desktop. It was brilliant — a userspace daemon that proactively scanned processes and made their anonymous memory KSM-eligible so the kernel's KSM (Kernel Samepage Merging) could deduplicate identical pages. It traded a little CPU for massive RAM savings.

Then uksmd went unmaintained. The repo was archived. Worse, the kernel half of its trick never made it upstream: `MMF_VM_MERGE_ANY` and the `process_ksm_enable()` syscall lived only in the pf-kernel branch, so a userspace daemon could not reach another process's memory the way uksmd did. What mainline *did* gain — `process_madvise()` with `MADV_COLLAPSE` and `MADV_COLD` — pointed the other way: it never accepted `MADV_MERGEABLE`.

The kernel has since caught up. **`PR_SET_MEMORY_MERGE` (prctl 67) is the mainline equivalent of what uksmd was reaching for** — a process-wide KSM eligibility flag, no per-region marking, no kernel patch. AKSMD is built on that, and on `ptrace(2)` to set it on processes the daemon does not own.

I missed uksmd. I wanted it back — but modernized, safer, and with features the original never had.

**AKSMD is that revival.**

---

## What It Does

| Feature | Description |
|---------|-------------|
| **PSI-Aware Governor** | Dynamically tunes KSM aggressiveness based on memory pressure (PSI) — backs off when system is under pressure, ramps up when idle |
| **Process Scanner** | Proactively finds processes with high anonymous RSS and makes every mapping of them KSM-eligible |
| **PTrace `PR_SET_MEMORY_MERGE` Injection** | Uses `ptrace(2)` to inject `prctl(PR_SET_MEMORY_MERGE, 1)` into target processes — the only way to enable process-wide KSM eligibility on a process you do not own |
| **MADV_COLLAPSE Support** | Opportunistically promotes memory to Transparent Huge Pages after KSM unmerges pages (breaks THP) |
| **KSM Advisor Mode** | Runs in kernel's "scan-time" advisor mode — biases bounds only, lets kernel do the scanning |
| **Full State Snapshotting** | Atomically snapshots KSM config on startup, restores on shutdown — zero config drift |
| **Structured Logging** | Emits KSM statistics as structured logs (journald/JSON) for scraping by your own collector |
| **Systemd Integration** | Ships with hardened systemd unit (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, ProtectSystem=strict) |

---

## How It Works (The PTrace Magic)

`PR_SET_MEMORY_MERGE` (prctl option 67) sets `MMF_VM_MERGE_ANY` on a process's
`struct mm_struct`, which makes **every** mapping of that process eligible for
KSM — including VMAs created after the call. This is the capability uksmd got
from its pf-kernel `process_ksm_enable()` syscall, now available in mainline
with no patch required.

`prctl` can only ever act on the *calling* process, so there is no userspace
call that reaches another process's `mm`. AKSMD therefore injects the syscall
directly:

```
1. PTRACE_ATTACH to target PID → waitpid(WSTOPPED)
2. GETREGS → save ALL registers (syscall clobbers RCX/R11)
3. Find `syscall` instruction (0x0F 0x05) in target's vDSO
4. Set RIP → vDSO syscall addr, RAX=157 (prctl), RDI=67, RSI=1
5. PTRACE_SYSCALL → waitpid (entry stop) → PTRACE_SYSCALL → waitpid (exit stop)
6. GETREGS → read RAX for return value
7. Restore ALL original registers → PTRACE_DETACH
```

Because the flag lives on `mm_struct`, it is **inherited across `fork` and
`execve`** — both verified on a live 7.3 kernel. Marking a long-lived shell or
init would therefore mark everything it ever spawns, so the blocklist and
`max_candidates_per_cycle` are the guard, not an optimisation.

### Why executable VMAs are withdrawn

`PR_SET_MEMORY_MERGE` accepts every mapping, and the kernel's own gate
(`ksm_compatible()` in `mm/ksm.c`) excludes only `VM_SHARED`, `VM_HUGETLB` and a
small set of "special" mappings — **`VM_EXEC` is not among them**. Marking a
process therefore makes its code mergeable, which the userspace
`madvise(MADV_MERGEABLE)` API used to prevent implicitly (it was never called
against a code mapping).

This was measured, not theorised. The first version of this injection path did
not guard against it, and Chromium died 90 seconds after being marked:

```text
traps: chrome[1178241] trap invalid opcode ip:559b3271e0c0 sp:7ffc95e99410
error:0 in chrome[6d9d0c0,559b2d01c000+e32d000]
```

The faulting address resolves to offset `0x6d9e0c0` of the chrome binary
(V8/Blink `.text`), the same in all four renderer crashes.

So AKSMD injects `madvise(MADV_UNMERGEABLE)` on every `r-xp` mapping right after
setting the flag. That has to be injected too: `process_madvise(2)` refuses KSM
advices on a remote `mm` — `process_madvise_remote_valid()` allows only COLD,
PAGEOUT, WILLNEED and COLLAPSE. `ScannerStats::exec_vmas_protected` reports the
count at marking time, `exec_vmas_reprotected` reports it on later cycles, so
coverage is observable rather than assumed.

`ScannerStats::exec_vmas_unprotected` reports the VMAs that could **not** be
withdrawn. The two counters must be read together, because they were not at
first: `unmerge_executable_vmas` used to report `(withdrawn, found)`, and a
caller that read only the first element could not distinguish "no executable
mappings" from "every injection refused". A live run hit exactly the latter —
the `prctl` succeeded, then all nine `MADV_UNMERGEABLE` attaches returned
`EPERM`:

```text
Enabled process-wide KSM eligibility pid=1284938 withdrawn=0 exec_vmas=9
MADV_UNMERGEABLE skipped for executable VMA pid=1284938
  error=ptrace attach failed: EPERM: Operation not permitted
```

That process was marked and entirely unprotected, and the metric said nothing.
The contract is now `(withdrawn, failed)` on both paths, the cycle line carries
`exec_vmas_unprotected`, and a marked-but-unprotected target logs at `warn`.
A non-zero `exec_vmas_unprotected` is not a tuning signal, it is an open crash.

This was not the cause of the crashes below — it fired once, on one short-lived
non-browser process, long after Chromium last faulted. It is reported because it
was invisible, and an invisible failure of the guard is what made the earlier
crashes impossible to reason about.

**But the withdrawal is not sufficient, and browsers are blocked by default.**

A supervised live run with both counters firing (`exec_vmas_protected=403`,
`exec_vmas_reprotected=96`) still produced the identical crash 60 seconds in:

```text
traps: chrome[1228652] trap invalid opcode ip:560f6177d0c0 sp:7ffc9523a490
error:0 in chrome[6d9d0c0,560f5c07b000+e32d000]
```

Same binary, same `0x6d9e0c0` offset, same stack pointer as the unguarded
crashes. So `MADV_UNMERGEABLE` on every `r-xp` VMA did not prevent it. Candidate
explanations, none confirmed against the crash-time VMA state: `MADV_UNMERGEABLE`
may only stop *future* scans and leave already-merged pages pointed at their
shared copy; a renderer's fresh JIT region may be created and faulted before the
next 30 s pass; and ptrace injection into a sandboxed renderer may be refused.

Rather than keep guessing, browsers are in the default blocklist. Their
anonymous memory is JIT-heavy and fork-heavy by construction, which is precisely
the profile where a userspace guard cannot keep up. The blocked set is
`chrome`, `chromium`, `firefox`, `msedge`, `brave`, `opera`, `vivaldi` and
`electron`.

The guard remains — it protects ordinary processes, where the exec surface is
static at startup — but it is not claimed as browser-safe. Removing an entry
from the blocklist is a deliberate, at-your-own-risk override.

One injection replaces what used to be one `madvise()` per eligible region, and
no address/length pair is needed for the marking itself. `/proc/PID/maps` is
still read — but only to find the executable mappings to withdraw, which is a
few dozen reads per process rather than one per merged region, and it is never
used to enumerate the merge population.

---

## Quick Start

### Install (Arch Linux / CachyOS)
```bash
# From AUR
yay -S animaksmd-git

# Or build from source
cargo install --locked animaksm-daemon --git https://github.com/animaios/animaksmd
```

### Install (Other Distros)
```bash
# Build from source (requires Rust 1.75+)
git clone https://github.com/animaios/animaksmd
cd animaksmd
cargo build --release --bin animaksm
  
# Install the binary
sudo cp target/release/animaksm /usr/local/bin/
  
# Install the config file. The repo ships a fully-commented example at
# config/animaksm.toml; there is no /etc/animaksm.toml and no `make install`
# target, so copy it into place yourself.
sudo mkdir -p /var/lib/animaksm
sudo cp config/animaksm.toml /etc/animaksm.toml
  
# Install the systemd unit (its ExecStart expects /usr/local/bin/animaksm
# and /etc/animaksm.toml) and reload systemd
sudo cp systemd/animaksm.service /etc/systemd/system/
sudo systemctl daemon-reload
```

> In the merged `tune` workspace, `config/` and `systemd/` live at the **workspace
> root**, not in this crate. Run the install commands above from the workspace
> root, and build with `cargo build -p animaksm-daemon --release`.

> **A missing config file is not an error.** If the path passed to `--config`
> does not exist, the daemon logs `Config file not found, using defaults` and
> runs entirely on built-in defaults — so forgetting to copy
> `config/animaksm.toml` to `/etc/animaksm.toml` silently gives you a
> default-tuned daemon instead of a failure. The systemd unit only gets
> read access to `/etc/animaksm.toml` under its `ProtectSystem=strict`
> sandbox, so that path must exist and be readable.

### Configure
```toml
# /etc/animaksm.toml — every key below is a real key; unknown keys are ignored.

[general]
log_level = "info"               # tracing filter: error | warn | info | debug | trace
poll_interval_ms = 2000          # main loop tick, in milliseconds
state_dir = "/var/lib/animaksm"  # where the KSM state snapshot is kept

[governor]
enabled = true                   # tune /sys/kernel/mm/ksm/* parameters
use_advisor = true               # true: kernel advisor sets scan rate, governor only biases bounds
psi_some_threshold = 5.0         # PSI some avg10 (%) that ramps aggressiveness up
psi_full_threshold = 2.0         # PSI full avg10 (%) treated as critical
advisor_scan_time_range = [30, 600]      # bounds on the advisor scan-time window; min must be < max
max_page_sharing_range = [256, 1024]     # bounds on max_page_sharing; min must be < max
hysteresis_readings = 4          # consecutive readings before changing level (up and down)
min_level_duration_secs = 30     # cooldown after a down-step before stepping down again
stabilization_secs = 30          # min seconds between repeated actions in the same tier
ksm_path = "/sys/kernel/mm/ksm"  # KSM sysfs directory (the only thing written to)

[scanner]
enabled = true                   # enable process-wide KSM eligibility on other processes
interval_secs = 30               # how often to scan processes, in seconds
min_anon_rss_mb = 100            # only consider processes above this anonymous RSS, in MiB
duplicate_ratio_threshold = 0.15 # fraction (0,1] of anon pages that look duplicated
max_candidates_per_cycle = 5     # top-K processes marked per scan cycle
blocklist = ["animaksm", "ksmd", "systemd", "sshd"]  # replaces the default list
target_cgroups = []              # empty = scan all user processes
```

> **Unrecognised keys are silently ignored.** The config is deserialized with
> `#[serde(default)]` and no `deny_unknown_fields`, so a typo'd or renamed key
> has **no effect and produces no warning** — a misspelled `max_candidates`
> just quietly leaves `max_candidates_per_cycle` at its default. Check key
> names against `crates/common/src/config.rs`, and remember that list-valued
> keys like `blocklist` *replace* the default list rather than extending it.
>
> **That replacement has teeth.** The default `blocklist` contains the browsers
> (`chrome`, `chromium`, `firefox`, `msedge`, `brave`, `opera`, `vivaldi`,
> `electron`). Writing your own `blocklist` — even the four lines shown above —
> silently drops all of them and re-opens the SIGILL crash. Copy the full list
> from `config/animaksm.toml` into your config.

### Run
```bash
# One-shot stats (like uksmdstats)
animaksm stats

# Show current status
animaksm status

# Restore the KSM parameters captured in the state snapshot
animaksm restore-ksm

# Dry-run to see what it would do (no sysfs writes, no madvise calls)
animaksm run --dry-run

# Point any subcommand at a non-default config file
animaksm run --config /etc/animaksm.toml

# Run as daemon (systemd)
sudo systemctl enable --now animaksm
```

Every subcommand (`run`, `status`, `stats`, `restore-ksm`) takes
`--config <path>`, defaulting to `/etc/animaksm.toml`; only `run` has
`--dry-run`.

### Field-testing a live run

Before trusting the daemon on a machine you use, do a supervised run and watch
three things.

**1. Confirm KSM actually gets enabled.** The daemon snapshots `/sys/kernel/mm/ksm/run`
before it starts and restores it on SIGTERM — even to `run=0`.

```bash
$ cat /sys/kernel/mm/ksm/run          # baseline, before starting the daemon
```

**2. Watch the scanner cycle logs.** These are the lines that prove the guard is
live rather than theoretically present:

```bash
$ journalctl -u animaksm -f | grep 'scanner cycle'
```

`exec_vmas_protected` should be non-zero the first time a process is marked, and
`exec_vmas_reprotected` should start becoming non-zero on later cycles once a
browser or JIT-using process is flagged.

`exec_vmas_unprotected` should stay **zero**. It is the one counter with no
acceptable non-zero reading: it counts executable VMAs that stayed mergeable
because the withdrawal was refused. If it climbs, stop the daemon and restart
the affected process — the flag is sticky, so it does not clear by itself.

```bash
$ sudo systemctl stop animaksm     # restores KSM state from the snapshot
```

**3. Check for the failure the guard prevents** — the whole point of the run:

```bash
$ sudo dmesg -wT | grep -i 'trap invalid opcode'
```

Any hit here involving your browser is the executable-VMA guard failing to keep
up, not a coincidence. Stop the daemon, restart the browser, and file an issue.

```bash
$ sudo systemctl stop animaksm        # restores KSM state from the snapshot
```

The browser does not need restarting to clear the flag after the fixed code is
in place — but if you ever ran an unfixed build, restart it anyway: the flag is
sticky and inherited.

---

## Example Output

```bash
$ animaksm stats
======================================================
AKSMD with KSM statistics support
======================================================
Full scans:                 175864
Interval:                   100 ms
Max page sharing ratio:     768
Pages to scan:              30000
Pages over ratio:           0
Duplicated pages:           0
Use zero pages:             0

Sharing/shared ratio:       20.7500
Unshared/sharing ratio:     3.1084

Pages sharing:              0.6 MiB
Pages shared:               0.0 MiB
Pages unshared:             2.0 MiB

General profit:             0.4 MiB
```

---

## Observability

AKSMD does not expose an HTTP endpoint. Every 60 seconds it logs the live KSM
counters and governor state as structured records, which journald (or your JSON
collector) can pick up directly:

```
animaksm: ksm pages_shared=0 pages_sharing=0 general_profit=0 full_scans=0
animaksm: governor level=3 pressure=medium target=3 psi_some=0.66 psi_full=0.65
animaksm: scanner targeted=3 processes_marked=3 exec_vmas_protected=104 \
          exec_vmas_unprotected=0 exec_vmas_reprotected=0 thp_collapsed=0 cycles=4
```

`exec_vmas_protected` counts executable VMAs withdrawn at marking time;
`exec_vmas_reprotected` counts those withdrawn again on processes already
holding the flag, because a browser keeps mapping new `r-xp` regions (JIT,
fresh renderers) after it was flagged. A healthy long-running daemon shows the
second number non-zero — if it is permanently zero while browsers are targeted,
the guard is not re-running and the process is unprotected again.

`exec_vmas_unprotected` counts the VMAs that could **not** be withdrawn at all.
It should stay at zero. Anything else means a target was marked and left
mergeable through its code — `prctl` succeeded while the withdrawals were
refused — which is the crash shape, so treat it as a page-worthy alert, not a
metric to trend.

To alert on KSM effectiveness, watch `general_profit` (saved memory minus
overhead) and `pages_sharing` — the two numbers that say whether KSM is
actually earning its CPU.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      AKSMD Daemon                       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ PSI Monitor  │  │   Governor   │  │    Scanner       │  │
│  │ (Pressure)   │──▶│ (Aggressiveness)│──▶│ (Process Hunt)   │  │
│  └──────────────┘  └──────────────┘  └────────┬─────────┘  │
│                                                │             │
│                         ┌──────────────────────▼──────────┐  │
│                         │     Eligibility Injector (PTrace) │
│                         │  • Attach → vDSO syscall → Detach │
│                         │  • PR_SET_MEMORY_MERGE injection │
│                         │  • MADV_UNMERGEABLE on r-xp VMAs │
│                         │  • MADV_COLLAPSE (process_madvise)│ │
│                         └──────────────┬──────────────────┘  │
│                                        │                      │
│                         ┌──────────────▼──────────────────┐  │
│                         │       KSM Controller             │  │
│                         │  • /sys/kernel/mm/ksm/*          │  │
│                         │  • Advisor mode, snapshots       │  │
│                         └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Requirements

- **Linux 5.10+** (PSI, process_vm_readv, KSM advisor mode)
- **Root privileges** (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH)
- **KSM enabled in kernel** (`CONFIG_KSM=y`)
- **Rust 1.75+** to build from source

---

## Comparison

| Feature | uksmd (original) | AKSMD |
|---------|------------------|-----------|
| Language | C | **Rust** (memory safe) |
| Process-wide eligibility | `process_ksm_enable()` (pf-kernel only) | **`PR_SET_MEMORY_MERGE` via ptrace — mainline, no patch** |
| MADV_COLLAPSE | ❌ | ✅ |
| PSI-aware governor | Basic | **Advanced (hysteresis, stabilization)** |
| KSM Advisor mode | ❌ | ✅ |
| State snapshotting | ❌ | ✅ |
| Systemd hardening | Basic | **Strict (ProtectSystem=strict)** |
| Maintenance | Archived (2025) | **Active** |

---

## FAQ

### Why not just use `ksmtuned`?
`ksmtuned` is deprecated and only adjusts KSM parameters reactively. AKSMD **proactively hunts processes** and **enables process-wide KSM eligibility** via ptrace — something `ksmtuned` never did.

### Does it work with containers (Docker/Podman)?
Yes! The scanner finds processes by PID namespace. For container workloads, run AKSMD on the host — it sees all container processes and can enable KSM eligibility in them.

### Is it safe to run on production?
Yes. AKSMD:
- Runs with minimal capabilities (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH)
- Uses `ProtectSystem=strict`, `NoNewPrivileges=yes`
- Snapshots KSM state on startup, restores on shutdown
- Dry-run mode for safe testing (`animaksm run --dry-run`)
- Graceful shutdown on SIGTERM/SIGINT

---

## Contributing

```bash
# Run tests
cargo test --workspace

# Format & lint
cargo fmt --all --check
cargo clippy --workspace -- -D warnings

# Build release
cargo build --release --workspace
```

PRs welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

Dual-licensed under **MIT** or **Apache-2.0** at your option.

---

## Acknowledgments

- **uksmd** (CachyOS) — the original inspiration
- **pf-kernel** — for `process_madvise` and KSM advisor mode
- **Linux KSM developers** — for the amazing kernel feature
- **Rust community** — for making systems programming safe and enjoyable

---

## Tags / Keywords

`ksm` `kernel-samepage-merging` `memory-deduplication` `memory-optimization` `userspace-daemon` `ptrace` `madvise` `process-madvise` `psi` `memory-pressure` `structured-logging` `systemd` `rust` `linux-kernel` `cachyOS` `uksmd` `uksmdstats` `memory-savings` `transparent-huge-pages` `thp` `madvise-mergeable` `process-injection` `linux-systems-programming`

---

## Links

- **Repository**: https://github.com/animaios/animaksmd
- **Issues**: https://github.com/animaios/aksmd/issues

<!--
- **Discussions**: https://github.com/animaios/aksmd/discussions
- **Matrix Chat**: https://matrix.to/#/#animaksm:matrix.org
- **Crates.io**: https://crates.io/crates/animaksm-daemon
- **Documentation**: https://docs.rs/animaksm-daemon
-->

---

*Made with ❤️ by the AKSMD team. Reviving uksmd, one page at a time.*
