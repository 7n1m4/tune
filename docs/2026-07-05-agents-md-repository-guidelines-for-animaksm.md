## AGENTS.md — Repository Guidelines for animaksm

**Agent Readiness:** This file contains two kinds of guidance:
- **Universal rules** — project structure, branching, architecture, and security patterns that apply regardless of what tooling you have.
- **Workflow recommendations** — tool-specific tips that are helpful when the relevant tools are available, but not required to complete tasks. Use whatever tools you have access to.

**Tool-Precedence Pledge (binding):** Whenever jcodemunch or other specialized tools are available, the agent MUST use them for every symbol/intent/impact operation. Native tools (`Read`, `Grep`, `Glob`, `Edit`, `Create`, `LS`) are reserved for side-effects, raw-text editing, and OS-level operations (git, cargo, systemctl, kernel files). A native tool marked "forbidden" in §3.5 may only run after the specialized tool returned an error or empty result AND the fallback reason is recorded in the active TodoWrite entry.

## 1. What is this repo?
`animaksm` is a Rust-based userspace daemon that drives Linux's Kernel Samepage Merging (KSM) subsystem with a PSI-aware governor, deduplicates compressed swap pages, and exports Prometheus metrics. It reduces memory pressure in cloud, container, and embedded workloads.

## 2. How is it structured?
```
animaksm/
├── Cargo.toml [workspace]
├── crates/
│   ├── common/      # Shared: config, procfs, PSI, KSM, error
│   └── daemon/      # animaksm main binary
├── config/
│   └── animaksm.toml  # Runtime configuration
├── systemd/            # Service units
├── Makefile            # check, test, coverage targets
```

## 3. How do I build/test/run?
```bash
# Mandatory commands
cargo build --workspace
make check          # cargo check + fmt + clippy
make test           # cargo test --workspace
make coverage       # HTML report in target/llvm-cov/html/
make coverage-ci    # LCOV → target/llvm-cov/lcov.info

# Exercise daemon locally
cargo run -p animaksm-daemon -- run --config config/animaksm.toml --dry-run
```

## 3.5 Tool-Precedence Matrix

The order in which the agent attempts tools is **binding**. "Forbidden" native tools may only run when the specialized tool returned an error/empty result AND the fallback reason is recorded in the active TodoWrite entry.

| Intent | First tool | Fallback (only if first errors/empty) | Forbidden native |
|---|---|---|---|
| Locate a symbol (fn/struct/enum/trait) by name or signature | jcodemunch `search_symbols` | native `Grep` (literal or regex) | `Grep` on source when index is warm |
| Show a symbol's body, params, docs | jcodemunch `get_symbol_source` | native `Read` (targeted to symbol location) | `Read` of the whole file |
| Find callers / references of a symbol | jcodemunch `get_blast_radius` | native `Grep` (literal or regex) | `Grep` for the name when index is warm |
| Rename / move / extract / edit a symbol with line anchor | jcodemunch `plan_refactoring` for diff hints | native `Edit` with exact line anchor | Bulk `Edit` without verification |
| Full-text / comment / config / string-literal search (non-symbol) | jcodemunch `search_text` | native `Grep` (literal or regex) | native `Grep` when index is warm |
| Repo topology / top-N hot paths / dead-code triage | jcodemunch `get_repo_map` / `find_hot_paths` / `get_dead_code_v2` | jcodemunch `assemble_task_context` | nested `LS`/`Read` traversal |
| Cross-file context bundle for N symbols | jcodemunch `get_context_bundle` | `get_symbol_source` | Serial `Read` per file |
| Create a brand-new file | native `Create` | — | — |
| Delete / trash a file or directory | native tool (careful!) | — | — |
| Run cargo / make / systemctl / edit kernel pseudo-files | native `Execute` | — | — |
| Interact with a TUI / browser / desktop app | `droid-control` / `agent-browser` skill tools | native `Execute` only as last resort | — |
| Test assertions in existing tests, non-symbolic Cargo.toml/config/unit edits | native `Edit` (allowed: no symbol anchor needed) | — | — |

> **Service-level rule:** "If you can name a symbol, the indexed tools own it. Native tools only for side effects, raw-text editing, and OS-level commands."

## 4. jcodemunch — Symbol Intelligence

Repo: `animaksm` (indexed). Symbol ID: `{file_path}::{qualified_name}#{kind}`

### 4.1 Core lookup
- `resolve_repo(path=".")` — confirm repo is indexed. If not: `index_folder(path=".")`
- `assemble_task_context(repo="animaksm", task="...")` — opening move; auto-classifies intent (explore/debug/refactor/extend/audit/review), surfaces symbols + ranked context
- `get_file_outline` → `get_symbol_source` / `get_context_bundle(symbol_ids=[...])` — targeted retrieval, never full files
- `search_symbols(repo="animaksm", query="...")` — find by name, signature, summary
  - `mode="context"` — query-less ranked context assembly
  - `mode="winnow"` — multi-axis constraint filter (kind, language, complexity, churn, etc.)
  - `semantic=true` — embedding-based search (requires embed provider)
  - `detail_level="compact"` — 15 tokens/row (id/name/kind/file/line only), ideal for broad discovery
- `search_text(repo="animaksm", query="...")` — full-text search across file contents (string literals, comments, configs)
- `search_ast(repo="animaksm", pattern="..." | category="...")` — structural anti-pattern scan (empty_catch, god_function, hardcoded_secret, etc.)

### 4.2 Impact & safety
- `get_blast_radius(symbol="...", include_source=true)` — check impact before changes
  - `call_depth=N` — also find symbols that *call* this symbol (call-level analysis, max 3)
  - `include_decisions=true` — surface git commit intent (revert/perf/refactor/bugfix) from history
  - `source_budget=N` — max tokens for source snippets across all files (default 8000)
- `find_references(identifier="...", cross_repo=false)` — trace who uses a symbol
  - `mode="importers"` — find files importing a given file (former `find_importers`)
  - `mode="related"` — find symbols related to a given symbol (former `get_related_symbols`)
  - `quick=true` — lightweight `is_referenced` boolean check for fast dead-code detection
- `get_call_hierarchy(symbol_id="...")` — incoming callers / outgoing callees
  - `chains=true` — also discover signal chains (HTTP routes, CLI commands, events)
  - `kind="http"|"cli"|"event"|"task"|"main"|"test"` — filter chain gateways
  - `max_depth=N` — BFS depth limit per chain (1–8, default 5)
- `check_safe(repo="animaksm", symbol="...", mode="edit"|"delete")` — composite preflight: can this symbol be safely edited/deleted?
- `plan_refactoring(repo="animaksm", symbol="...", refactor_type="rename"|"move"|"extract"|"signature")` — generate multi-file edit plan before refactoring
- `get_changed_symbols(repo="animaksm")` — map git diff to affected symbols
- `get_pr_risk_profile(repo="animaksm")` — unified risk assessment for a PR/branch

### 4.3 Repository intelligence
- `get_repo_health(repo="animaksm")` — one-call triage (dead code %, complexity, hotspots, cycle count)
- `get_repo_map(repo="animaksm")` — signature-level overview ranked by PageRank (cold-start orientation)
- `get_tectonic_map(repo="animaksm")` — logical module topology (hidden boundaries, misplaced files, drifters)
- `find_hot_paths(repo="animaksm")` — top-N symbols by runtime hit count (requires ingested traces)
- `get_dead_code_v2(repo="animaksm", min_confidence=0.67)` — multi-signal dead code detection
- `find_similar_symbols(repo="animaksm")` — cluster similar functions/methods (consolidation candidates)
- `get_symbol_provenance(repo="animaksm", symbol="...")` — git authorship lineage & evolution narrative
- `get_symbol_complexity(repo="animaksm", symbol_id="...")` — cyclomatic complexity, nesting, params
- `get_class_hierarchy(repo="animaksm", class_name="...")` — inheritance ancestors + descendants
- `find_implementations(repo="animaksm", symbol="...")` — find concrete impls of an interface/abstract
- `get_project_intel(repo="animaksm")` — auto-discover Dockerfiles, CI configs, deps, APIs
- `list_workspaces(repo="animaksm")` — enumerate monorepo workspace members
- `search_columns(repo="animaksm", query="...")` — search column metadata across indexed models

### 4.4 Runtime & indexing
- `import_runtime_signal(repo="animaksm", path="...", source="otel"|"sql_log"|"stack_log")` — ingest runtime traces
- `embed_repo(repo="animaksm")` — precompute symbol embeddings for semantic search
  - `force=true` — recompute all embeddings even if they already exist
  - `batch_size=N` — symbols per embedding batch (default 50)
- `summarize_repo(repo="animaksm", force=true)` — re-run AI summarization pipeline
- `index_file(path="...")` — surgical single-file reindex after edits
- `index_folder(path="...")` / `index_repo(url="...")` — full index/reindex
- `register_edit(repo="animaksm", file_paths=[...], reindex=true)` — invalidate caches after file edits
- `get_repo_map(repo="animaksm", mode="outline")` — lightweight directory/language/symbol count overview

### 4.5 Code Exploration Policy

**Always use the specialized toolbox (jcodemunch) for code navigation. Never fall back to native tools for exploration unless the matrix in §3.5 explicitly permits it.**

- Use jcodemunch `search_symbols`, `get_context_bundle`, `get_symbol_source` for indexed symbol retrieval.
- Use jcodemunch `assemble_task_context` as your opening move — it auto-classifies intent and returns ranked context.
- Use jcodemunch `search_text` only for non-symbol content (string literals, comments, config values).

**Native-tool decision (always route through §3.5):**
- `Edit`/`Create` allowed ONLY for non-symbolic bulk fixes (tests, Cargo.toml, systemd units, kernel pseudo-files) OR as a fallback documented in TodoWrite.
- `Grep`/`Glob`/`Read`/`LS` allowed ONLY as fallbacks when the specialized tool returned an error/empty result AND the fallback reason is recorded in the active TodoWrite entry.

Rationale: native tools scan full files with no structural context. The index understands signatures, imports, types, and call graphs — flat text search wastes tokens and produces poor decisions.

### 4.6 Session-Aware Routing — Confidence & Negative Evidence

After every jCodemunch tool call, check the response envelope before deciding what to do next:

| `_meta.confidence` | Action |
|---|---|
| **high** (≥ 0.7) | Act directly on the result. Max 2 supplementary `read_file` calls for edit verification. |
| **medium** (0.4–0.69) | Explore the recommended files. Max 5 `read_file` calls; then commit or report. |
| **low** (< 0.4) | **Do not keep searching.** Report the gap, suggest re-indexing, and ask the user for direction. |

**Negative evidence — stop, don't re-search:**
- If a search returns `verdict: "no_implementation_found"`, **stop.** Do not re-search with different terms, different capitalization, or broader patterns. An absent implementation is a valid finding — report it.
- If `resolve_repo` or `list_repos` shows the repo is not indexed, **index first** (`index_folder`), then retry. Do not work around a missing index with `grep`.
- If `_meta.freshness` indicates stale data or `repo_is_stale=true`, suggest `index_folder` before trusting the results.

### 4.7 After Editing Files

**VERBATIM RULE — run after EVERY edit:**

1. jcodemunch `register_edit` invalidates the BM25 cache + search result cache so subsequent `search_symbols` / `search_text` calls see the new content.
2. Re-issue targeted reads if you need to verify the edited content — never trust pre-edit cached data.

```
register_edit(repo="animaksm", file_paths=["crates/common/src/foo.rs"], reindex=true)
```

For surgical reindex of a single file (lighter than full `register_edit`):
```
index_file(path="/absolute/path/to/crates/common/src/foo.rs")
```

### 4.9 Tool-Precedence Compliance

A task step is **incomplete** until:
1. The fallback chain in the §3.5 matrix is exhausted in order.
2. Every fallback reason is recorded in the active TodoWrite entry.
3. `register_edit` (§4.7) has been run if a file was modified.

Failure to follow the matrix without documenting the reason is a compliance violation in code review.

### 4.10 Interpreting Search Results

jCodemunch responses include metadata fields that inform decision-making:

| Field | Meaning | Action |
|---|---|---|
| `_meta.confidence` | Result quality score (0.0–1.0) | See §4.6 routing table |
| `_meta.freshness` | Index staleness indicator | If stale, suggest `index_folder` |
| `_meta.tokens_used` / `_meta.tokens_remaining` | Token budget consumption | Adjust budget on next call if exhausted |
| `verdict: "no_implementation_found"` | No matching implementation exists | **Stop searching** — report the gap |
| `repo_is_stale` | Index was built from an older commit | Re-index before trusting blast radius / reference data |
| `source_truncated: true` | Symbol body was truncated (bounded mode) | Use `get_symbol_source` without bounds if you need the full body |

### 4.11 Power User Guide

#### Golden Rules
1. **Always start with `assemble_task_context`** — it auto-classifies intent and returns ranked symbols + context in one call. Never manually hunt for entry points.
2. **Batch everything** — use `symbol_ids[]` in `get_context_bundle`, `get_symbol_source`, `search_symbols` instead of serial calls. Token budget is your friend.
3. **Verify with `verify=true` / `verify_against="git_sha"`** — catches index drift vs. working tree.
4. **Use `mode` switches** on `search_symbols`: `context` for query-less ranked context, `winnow` for multi-axis filters, `semantic=true` for embedding search.
5. **Prefer `get_context_bundle` over raw file reads** — deduplicates imports, respects token budget, returns ready-to-use context.

#### Common Workflows

##### Cold-start orientation (new repo / unfamiliar area)
```
get_repo_map(repo="animaksm", group_by="flat", top_n=30)     # Top symbols by PageRank
get_tectonic_map(repo="animaksm")                               # Logical module boundaries
get_repo_health(repo="animaksm", detailed=true)                 # Dead code %, complexity, cycles
```

##### Feature exploration — "How does X work?"
```
assemble_task_context(repo="animaksm", task="How does X work?")
# → returns ranked symbols + context
get_context_bundle(symbol_ids=[...], budget_strategy="core_first")
```

##### Refactoring safety (rename/move/extract)
```
check_safe(repo="animaksm", symbol="SymbolName", mode="edit")
plan_refactoring(repo="animaksm", symbol="SymbolName", refactor_type="rename", new_name="newName")
get_blast_radius(symbol="SymbolName", depth=2, include_source=true)
```

##### Dead code cleanup
```
get_dead_code_v2(repo="animaksm", min_confidence=0.67, file_pattern="crates/**")
find_similar_symbols(repo="animaksm", threshold=0.85, include_kinds=["function", "method"])
```

##### Performance hotspot triage
```
find_hot_paths(repo="animaksm", top_n=20)
get_repo_health(repo="animaksm", detailed=true, top_n=30)
get_symbol_complexity(repo="animaksm", symbol_id="...")
```

##### PR / change risk assessment
```
get_changed_symbols(repo="animaksm", include_blast_radius=true, max_blast_depth=3)
get_pr_risk_profile(repo="animaksm", base_ref="main", head_ref="HEAD")
```

##### Understanding unfamiliar code before modifying
```
get_symbol_provenance(repo="animaksm", symbol="SymbolName", max_commits=30)
get_call_hierarchy(symbol_id="...", direction="both", depth=3, include_impact=true)
find_implementations(repo="animaksm", symbol="InterfaceName", include_subclasses=true)
```

##### Finding config / string literals / comments (not symbols)
```
search_text(repo="animaksm", query="MAX_RETRIES", context_lines=3)
search_ast(repo="animaksm", category="security")              # hardcoded_secret, eval_exec
search_ast(repo="animaksm", pattern="string:/password/i")      # custom pattern
```

#### Parameter Cheatsheet

Same as original, but remove Serena-specific tool references

#### Anti-patterns to Avoid
- ❌ Reading full files with native tools — use jcodemunch `get_context_bundle` / `get_symbol_source`
- ❌ Grep-first lookup of symbols — jcodemunch `search_symbols` owns it; native `Grep` is forbidden until index both errors/empty
- ❌ Serial `Read` per file — batch with `symbol_ids[]` in `get_context_bundle`
- ❌ Skipping `check_safe` before edits/deletes — prevents hours of revert
- ❌ Not verifying with `verify=true` — index can drift from working tree
- ❌ Manual blast radius tracing — `get_blast_radius(depth=2, include_source=true)` is instant
- ❌ Ignoring `_meta.confidence` < 0.4 — low confidence means widen the search or report a gap, not proceed as-is
- ❌ Editing without verification — you must have confirmation before any edit to a symbol
- ❌ Forgetting `register_edit` after any file change — invalidates BM25 + search caches

#### Token Budget Discipline
- `assemble_task_context(token_budget=4000)` for focused tasks
- `get_context_bundle(token_budget=6000, budget_strategy="core_first")` for multi-symbol context
- `search_symbols(token_budget=3000)` with `detail_level="compact"` for broad discovery (15 tokens/row)

## 5. Standard Operating Procedure — Local Helper Scripts

The following scripts are installed at `~/.agents/skills/`. Use them when the situation calls for it. Soft guidance — apply judgment, not dogma.

### auto-execute (plan runner)

`~/.agents/skills/auto-execute/auto-execute.sh`

Use when the user has an implementation plan (Markdown with `### Task N:` headers) and wants it executed task-by-task in isolated sessions.

CLI binaries: any `claude`-prefixed command name. Pass 1-5 for failover redundancy.

```
auto-execute.sh [--max-turns 80] [--task-timeout 600] [--context-limit 100000]
                [--start-task N] [--log-dir logs/auto-execute]
                <claude-binary> [claude-binary-2..5] <plan-input>
```

Plan input: path to plan file, partial match against `docs/plans/`, or `latest` for most recent.

Behavior: runs each task as `claude -p "/auto-execute task-N.md"`, monitors for timeout/context-limit, verifies exit+commit+tree-clean after each step, retries with next binary on failure. Ctrl+C is trapped cleanly.

Do not use for single-shot tasks, exploratory work, or when the user wants to review each step manually.

### commit (git committer)

`~/.agents/skills/commit/SKILL.md` — Claude Code skill, triggered via `/commit`

Use when the user says "commit" or "save this" or asks for a commit message. Generates `type: description` format, runs `git diff --staged`, prompts for staging if nothing staged.

Alternative without skill invocation:

```
git diff --staged → git add . → git commit -m "type: description"
```

### humanizer (writer)

`~/.agents/skills/humanizer/SKILL.md` — Claude Code skill, triggered via `/humanizer`

Use when the user asks to "clean up" writing, "make this sound natural", "de-AI this", or similar. Applies 25 pattern replacements (significance inflation, copula avoidance, chatbot artifacts, em dash overuse, etc.) with personality-injection pass. Repo-agnostic — works on any prose.

### When to invoke automatically

| User says | Invoke |
|-----------|--------|
| "run the plan" / "execute tasks from <file>" | auto-execute |
| "commit this" / "commit changes" | commit skill or manual |
| "fix this text" / "make it sound human" / "de-AI" | humanizer skill |

Platform check: these scripts assume Linux/macOS. On Windows, use PowerShell equivalents (not yet ported).

───