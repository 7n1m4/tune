<div align=center>

# [A](https://github.com/animaios/anima)KSMD

<img width="256" height="384" alt="AnimAIOS mascot" src="https://github.com/user-attachments/assets/8d548058-3363-481b-90d6-09f4620f70f7" />


### The spiritual successor to uksmd — a modern, Rust-based userspace KSM daemon with PTrace-powered MADV_MERGEABLE injection

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

I used to run **uksmd** (the userspace KSM daemon from the CachyOS project) on my desktop. It was brilliant — a userspace daemon that proactively scanned processes and marked their anonymous memory as `MADV_MERGEABLE` so the kernel's KSM (Kernel Samepage Merging) could deduplicate identical pages. It traded a little CPU for massive RAM savings.

Then uksmd went unmaintained. The repo was archived. The kernel evolved — `process_madvise()` gained support for `MADV_COLLAPSE` and `MADV_COLD`, but **never for `MADV_MERGEABLE`**. The old `pidfd` + `process_madvise` approach hit a wall.

I missed uksmd. I wanted it back — but modernized, safer, and with features the original never had.

**AKSMD is that revival.**

---

## What It Does

| Feature | Description |
|---------|-------------|
| **PSI-Aware Governor** | Dynamically tunes KSM aggressiveness based on memory pressure (PSI) — backs off when system is under pressure, ramps up when idle |
| **Process Scanner** | Proactively finds processes with high anonymous RSS and marks their memory for KSM merging |
| **PTrace MADV_MERGEABLE Injection** | Uses `ptrace(2)` to inject `madvise(MADV_MERGEABLE)` into target processes — the **only way** to mark another process's memory as mergeable cross-process |
| **MADV_COLLAPSE Support** | Opportunistically promotes memory to Transparent Huge Pages after KSM unmerges pages (breaks THP) |
| **KSM Advisor Mode** | Runs in kernel's "scan-time" advisor mode — biases bounds only, lets kernel do the scanning |
| **Full State Snapshotting** | Atomically snapshots KSM config on startup, restores on shutdown — zero config drift |
| **Structured Logging** | Emits KSM statistics as structured logs (journald/JSON) for scraping by your own collector |
| **Systemd Integration** | Ships with hardened systemd unit (CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, ProtectSystem=strict) |

---

## How It Works (The PTrace Magic)

Since Linux's `process_madvise(2)` **does not support `MADV_MERGEABLE`** for cross-process operations (only `MADV_COLD`, `MADV_COLLAPSE`, `MADV_PAGEOUT`, `MADV_WILLNEED`), AKSMD uses `ptrace(2)` to inject the syscall directly:

```
1. PTRACE_ATTACH to target PID → waitpid(WSTOPPED)
2. GETREGS → save ALL registers (syscall clobbers RCX/R11)
3. Find `syscall` instruction (0x0F 0x05) in target's vDSO
4. Set RIP → vDSO syscall addr, RAX=28 (madvise), RDI=addr, RSI=len, RDX=12 (MADV_MERGEABLE)
4. PTRACE_SYSCALL → waitpid (entry stop) → PTRACE_SYSCALL → waitpid (exit stop)
5. GETREGS → read RAX for return value
6. Restore ALL original registers → PTRACE_DETACH
```

This is the **only way** to mark another process's memory as `MADV_MERGEABLE` from userspace. AKSMD does it safely: full register save/restore, SIGTRAP verification, vDSO syscall instruction discovery per-PID, and graceful error handling.

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
enabled = true                   # inject MADV_MERGEABLE into other processes
interval_secs = 30               # how often to scan processes, in seconds
min_anon_rss_mb = 100            # only consider processes above this anonymous RSS, in MiB
duplicate_ratio_threshold = 0.15 # fraction (0,1] of anon pages that look duplicated
max_mergeable_per_process_mb = 512  # per-process cap, in MiB, to avoid over-marking
max_candidates_per_cycle = 5     # top-K processes marked per scan cycle
blocklist = ["animaksm", "ksmd", "systemd", "sshd"]  # process names never touched (replaces the default list)
target_cgroups = []              # empty = scan all user processes
```

> **Unrecognised keys are silently ignored.** The config is deserialized with
> `#[serde(default)]` and no `deny_unknown_fields`, so a typo'd or renamed key
> has **no effect and produces no warning** — a misspelled `max_candidates`
> just quietly leaves `max_candidates_per_cycle` at its default. Check key
> names against `crates/common/src/config.rs`, and remember that list-valued
> keys like `blocklist` *replace* the default list rather than extending it.

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
animaksm: scanner targeted=3 marked_mib=291 cycles=4
```

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
│                         │     MADV Injector (PTrace)      │  │
│                         │  • Attach → vDSO syscall → Detach │  │
│                         │  • MADV_MERGEABLE injection      │  │
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
| MADV_MERGEABLE | pidfd + process_madvise (broken) | **PTrace injection (works)** |
| MADV_COLLAPSE | ❌ | ✅ |
| PSI-aware governor | Basic | **Advanced (hysteresis, stabilization)** |
| KSM Advisor mode | ❌ | ✅ |
| State snapshotting | ❌ | ✅ |
| Systemd hardening | Basic | **Strict (ProtectSystem=strict)** |
| Maintenance | Archived (2025) | **Active** |

---

## FAQ

### Why not just use `ksmtuned`?
`ksmtuned` is deprecated and only adjusts KSM parameters reactively. AKSMD **proactively hunts processes** and **injects MADV_MERGEABLE** via ptrace — something `ksmtuned` never did.

### Does it work with containers (Docker/Podman)?
Yes! The scanner finds processes by PID namespace. For container workloads, run AKSMD on the host — it sees all container processes and can inject MADV_MERGEABLE into them.

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
