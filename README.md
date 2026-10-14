# tune

One Rust daemon, one workspace, one job: **act on Linux kernel memory reclaim
and record the evidence.**

`tuned` drives two independent subsystems — KSM merging and the zswap `max_pool_percent`
ceiling — from a single process, a single systemd unit and a single config file.
The two subsystems stay independent *inside* the workspace: they share nothing but
the process boundary, and the zswap half remains auditable on its own.

| Crate | Role | Constraints |
|---|---|---|
| [`crates/tuned-zswap`](crates/tuned-zswap/README.md) | zswap tuner **as a library** (`tuned_zswap`) plus a standalone `tuned-zswap` binary | **std-only, zero third-party crates**; decision semantics frozen |
| [`crates/tuned`](crates/tuned/README.md) | the `tuned` binary: KSM governor + ptrace scanner + a driver loop for the zswap library | `unsafe` confined to `madvise.rs`/`psi.rs`; tokio v1 |

`crates/tuned` depends on `crates/tuned-zswap` by path; the dependency is
one-directional. The zero-dependency rule attaches to the `tuned_zswap` crate and
is provable — `cargo tree -p tuned-zswap --edges normal` prints only the crate
itself. `crates/tuned-common` holds the config, procfs, PSI and KSM support the daemon
shares, including the `[zswap]` section.

## Build

```console
$ cargo build --workspace           # tuned + the standalone tuned-zswap helper
$ cargo build -p tuned-daemon --release   # just the daemon
$ cargo build -p tuned-zswap --release        # just the standalone zswap helper
```

## Test

```console
$ cargo test --workspace
$ make check                       # check + fmt + clippy
$ make test
```

## Layout

```
tune/
├── crates/
│   ├── tuned-zswap/   # std-only lib.rs (frozen decide()) + thin bin
│   ├── tuned-common/  # shared config, procfs, PSI, KSM
│   └── tuned/         # the `tuned` binary
├── config/
│   └── tuned.toml   # includes the [zswap] section
├── systemd/
│   ├── tuned.service
│   └── tuned-logrotate.conf
└── Makefile
```

The daemon writes to exactly two sysfs paths (`/sys/kernel/mm/ksm` and
`/sys/module/zswap/parameters/max_pool_percent`) and degrades rather than
panicking when a `/proc` or debugfs read fails. Full constraints, including the
behaviours an agent must not "fix", are in [AGENTS.md](AGENTS.md).

## Provenance

`main` is the joined history of the two predecessor repos (58 KSM commits,
7 zswap commits),
merged with `--allow-unrelated-histories`. `git log --follow` on a moved file
surfaces its pre-merge history.

## Licence

MIT for the whole workspace — see `LICENSE`.
