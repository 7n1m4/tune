# Measuring a 50-vs-25 zswap verdict

How to collect a `PASS`/`FAIL` verdict on the ceiling comparison, and every trap that
stops a `--report` from producing one. Written for an agent or human with root.

**Tl;dr:** the tool judges `ceiling 50` against `ceiling 25`, but **only counts
intervals where the pool grew**. On an idle machine the pool drains, so most
intervals are discarded and the group never forms. You must accumulate positive
stored-page growth under *both* ceilings before a verdict can exist.

---

## 1. What the verdict actually requires

`verdict()` needs a group for **each** of `VERDICT_HIGH` (50) and `VERDICT_LOW` (25),
where a group is "judgeable" only when it holds **at least 200 MiB of net positive
stored-page growth**. If either side is missing you get `INCONCLUSIVE` — that is a
correct result, never a bug to fix.

Three drop rules silently shrink a group (see `analyse()` in `src/main.rs`):

| Rule | What it drops |
|---|---|
| `stored_delta < 0 \|\| written_delta < 0` | Any interval where the pool shrank — **the common one** |
| `after.ts - before.ts > RECORD_GAP_MAX` (300 s) | Intervals straddling a daemon restart |
| `after.limit != before.limit` | Intervals straddling a ceiling change |

The first rule is why an idle box yields `insufficient data` instead of a number.
A draining pool is pages being *returned* from swap; nothing about that measures
what the ceiling costs, so the interval is discarded rather than clamped to zero.

---

## 2. Mid-flight progress check

Run this at any time to see how far you are, without waiting for the whole run:

```console
$ python3 - <<'EOF'
import json, collections
rows = [json.loads(l) for l in open('/var/log/zswap-tune/stats.jsonl') if l.strip()]
PAGE = 4096
groups = collections.defaultdict(lambda: [0, 0])
prev = None
for r in rows:
    if prev and r['ts'] - prev['ts'] <= 300 and r['limit'] == prev['limit']:
        d = r['stored_pages'] - prev['stored_pages']
        if d >= 0:
            g = groups[r['limit']]
            g[0] += 1
            g[1] += d * PAGE
    prev = r
for limit in sorted(groups):
    n, bytes_ = groups[limit]
    print(f"ceiling {limit}%: {n} usable intervals, {bytes_/1048576:.1f} MiB growth "
          f"({'JUDGEABLE' if bytes_/1048576 >= 200 else 'short of the 200 MiB bar'})")
EOF
```

A ceiling is judgeable at **≥ 200 MiB**. Anything less will be reported as
`insufficient data`.

---

## 3. Collecting the measurement

### Step 1 — hold the low ceiling

```console
$ sudo sh -c 'echo 25 > /run/zswap-tune.pin'
```

The pin is honoured verbatim, never clamped, and must be an integer in `[25, 50]`.
Confirm it took effect (both are safe, non-mutating):

```console
$ zswap-tune --once --dry-run | head -2
current max_pool_percent : 50%
limit source             : pinned to 25% (/run/zswap-tune.pin)
```

The line must read `pinned to 25% (...)`, not `auto (decide)`. The daemon's journal
also flips from an `[auto]` to a `[pinned]` tag on each decision:

```
zswap-tune: max_pool_percent=25% MemAvailable=41.0% ratio=2.9 [pinned] -> ...
```

`--dry-run` reports the decision but never writes sysfs, so it is always safe.

### Step 2 — generate real workload at 25 %

**Do not use `stress-ng`.** Per `AGENTS.md`, synthesised pressure does not represent
the real workload and would produce an artifact-free but meaningless verdict. Use the
machine normally: compile, open applications, build/rebuild, edit video, run tests.

Target: **≥ 200 MiB of net positive growth** (check with the script in §2). At 15 GiB
RAM that is roughly 4 GiB of pages before compression, so expect a working session,
not a minute.

### Step 3 — let 50 % run alongside

You do not have to pin 50. Remove the pin and let `decide()` walk the ceiling up:

```console
$ sudo rm /run/zswap-tune.pin
```

With `MemAvailable >= 25 %` and ratio `>= 2.2` it raises 10 pp per decision
(`25 → 35 → 45 → 50`), so a healthy machine reaches 50 on its own within a few polls.
Then keep working — 50 % needs ≥ 200 MiB of growth too, under the same rules.

### Step 4 — report

```console
$ zswap-tune --report
```

---

## 4. Reading the result

```
verdict: PASS/FAIL: ceiling 50 <does|does not> earn its RAM — eviction ratio at
ceiling 50 is X against Y at ceiling 25, a Z% difference (bar: at least 25% lower)
```

The bar is **`REQUIRED_ADVANTAGE` = 0.25**: 50 % survives only if its eviction ratio
is ≥ 25 % lower than 25 %'s. A lower ceiling accepts more eviction by design (it hits
`pool_limit_hit` sooner and pushes more pages out), so 50 % wins on RAM only if that
buys back meaningful headroom.

---

## 5. Observed failure modes (2026-10-12)

Real log, 3 h 58 m span, 109 records:

```
records per ceiling: {20: 8, 25: 10, 35: 4, 45: 1, 50: 86}
```

| Symptom | Cause | Fix |
|---|---|---|
| Report lists **1 ceiling value** despite 10 records at 25 | All nine 25 % intervals had **negative** `stored_pages` (pool was draining), so every one was dropped | Accumulate growth while pinned at 25 |
| 71 of 85 intervals at 50 % dropped | Same cause: an idle machine drains its pool between loads | Only 14 usable intervals survived — enough to clear 200 MiB, unlike 25 % |
| `INCONCLUSIVE: the 50-vs-25 comparison is not available` | At least one group never formed | Not a bug. See §1 — do not manufacture the missing side |
| `ceiling NNN has no recorded samples` | No *usable* interval at that ceiling | Pin at that ceiling and generate workload |

The 25 % group had **0 of 9** usable intervals. The 50 % group had **14**. The
verdict was withheld because the comparison genuinely cannot be made from a drain.

---

## 6. Housekeeping

* Records are written every **60 s**; `ZSWAP_TUNE_RECORD_INTERVAL=<seconds>` shortens
  the cadence for testing.
* Log: `/var/log/zswap-tune/stats.jsonl`, rotated daily, 14 copies
  (`/etc/logrotate.d/zswap-tune`).
* The service is enabled and runs; it contends for the sysfs path, so **never run a
  second copy** of the binary beside it. Use `--once --dry-run` for safe inspection.
* Do not `swapoff`/`swapon` or touch kernel parameters during a run — it invalidates
  the counters by resetting `stored_pages`.
* Removing the pin restores `decide()`; the change is immediate (no reload, no reboot).
