# tune

Two Rust binaries, one workspace, one job: **act on Linux kernel memory reclaim
and record the evidence.**

They are deliberately separate. They target different kernel subsystems, have
different runtime models, and one of them is required to have zero
dependencies. Fusing them would break that.

| Crate | Binary | What it tunes | Constraints |
|---|---|---|---|
| [`crates/zswap-tune`](crates/zswap-tune/README.md) | `zswap-tune` | zswap `max_pool_percent` — does raising the ceiling buy RAM at an acceptable cost in flash writes? | **std-only, zero third-party crates**; decision semantics frozen |
| [`crates/daemon`](crates/daemon/README.md) | `animaksm` | KSM — process-wide merge eligibility + a PSI-aware governor | `unsafe` confined to `madvise.rs`/`psi.rs`; tokio v1 |

`crates/common` is the shared crate `animaksm` uses (config, procfs, PSI, KSM,
error). `zswap-tune` shares nothing by design — it does not even inherit
`workspace.dependencies`.

## Build

```console
$ cargo build --workspace          # both binaries
$ cargo build -p animaksm-daemon --release
$ cargo build -p zswap-tune --release
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
│   ├── zswap-tune/   # std-only, single main.rs, frozen decide()
│   ├── common/       # shared animaksm support
│   └── daemon/       # animaksm main binary
├── config/
│   └── animaksm.toml
├── systemd/
│   ├── animaksm.service
│   ├── zswap-tune.service
│   └── logrotate-zswap-tune.conf
├── docs/             # design notes
└── Makefile
```

Both tools write to exactly one sysfs path each and degrade rather than panics
when a `/proc` or debugfs read fails. Full constraints, including the behaviours
an agent must not "fix", are in [AGENTS.md](AGENTS.md).

## Provenance

`main` is the joined history of both repos (animaksm 58 commits, zswap-tune 7),
merged with `--allow-unrelated-histories`. `git log --follow` on a moved file
surfaces its pre-merge history.

## Licence

MIT. See `crates/zswap-tune/LICENSE`, `LICENSE-MIT`.
