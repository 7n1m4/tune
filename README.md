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
| **Prometheus Metrics** | Exposes `/metrics` for Grafana/Prometheus dashboards |
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
sudo cp target/release/animaksm /usr/local/bin/
sudo cp systemd/animaksm.service /etc/systemd/system/
```

### Configure
```toml
# /etc/animaksm.toml
[general]
state_dir = "/var/lib/animaksm"

[governor]
ksm_path = "/sys/kernel/mm/ksm"
use_advisor = true           # Use kernel's scan-time advisor mode
stabilization_secs = 30      # Seconds to wait before ramping down

[scanner]
interval_secs = 30           # Scan interval
min_anon_rss_mb = 100        # Minimum anonymous RSS to consider
max_candidates = 5           # Max processes per scan cycle

[metrics]
enabled = true
listen_addr = "0.0.0.0:9090"
```

### Run
```bash
# One-shot stats (like uksmdstats)
animaksm stats

# Show current status
animaksm status

# Run as daemon (systemd)
sudo systemctl enable --now animaksm

# Dry-run to see what it would do
animaksm run --dry-run
```

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

## Metrics & Dashboards

AKSMD exposes Prometheus metrics at `http://localhost:9090/metrics`:

```prometheus
# HELP animaksm_ksm_pages_shared Total pages shared by KSM
# TYPE animaksm_ksm_pages_shared gauge
animaksm_ksm_pages_shared 15

# HELP animaksm_ksm_pages_sharing Pages currently being shared
# TYPE animaksm_ksm_pages_sharing gauge
animaksm_ksm_pages_sharing 409

# HELP animaksm_ksm_general_profit Memory saved (bytes) minus overhead
# TYPE animaksm_ksm_general_profit gauge
animaksm_ksm_general_profit -1096064

# HELP animaksm_governor_level Current governor aggressiveness level (0-4)
# TYPE animaksm_governor_level gauge
animaksm_governor_level 1

# HELP animaksm_psi_pressure Current memory pressure level
# TYPE animaksm_psi_pressure gauge
animaksm_psi_pressure{level="low"} 1
```
<!--
**Grafana Dashboard**: Import [AKSMD Dashboard](https://grafana.com/grafana/dashboards/animaksm) (JSON available in `grafana/animaksm-dashboard.json`)
-->
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
| Prometheus metrics | ❌ | ✅ |
| State snapshotting | ❌ | ✅ |
| Systemd hardening | Basic | **Strict (ProtectSystem=strict)** |
| Maintenance | Archived (2025) | **Active** |

---

## FAQ

### Why not just use `ksmtuned`?
`ksmtuned` is deprecated and only adjusts KSM parameters reactively. AKSMD **proactively hunts processes** and **injects MADV_MERGEABLE** via ptrace — something `ksmtuned` never did.

### Does it work with containers (Docker/Podman)?
Yes! The scanner finds processes by PID namespace. For container workloads, run AKSMD on the host — it sees all container processes and can inject MADV_MERGEABLE into them.

### What about ZRAM / zswap?
AKSMD does not implement its own swap device. For compressed, deduplicated swap, use zram's built-in same-page merging — forking zram itself is the better path than a hacky userspace swap layer.

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

`ksm` `kernel-samepage-merging` `memory-deduplication` `memory-optimization` `userspace-daemon` `ptrace` `madvise` `process-madvise` `psi` `memory-pressure` `prometheus-metrics` `systemd` `rust` `linux-kernel` `cachyOS` `uksmd` `uksmdstats` `memory-savings` `transparent-huge-pages` `thp` `madvise-mergeable` `process-injection` `linux-systems-programming`

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
