# CONTRIBUTING.md

Thank you for contributing to litecast. This document is the contract for
every change: it defines the mandatory code standards, testing rules, and
quality gate. Read it together with [AGENTS.md](AGENTS.md).

## Getting Started

1. Fork the repository.
2. Create a feature branch from `master`.
3. Make changes following the project conventions.
4. Run the full quality gate locally.
5. Submit a pull request.

## Code Style

Use `make format` to apply the canonical code style (Linux kernel style,
indent width 2, no tabs in output, 120-column limit). `make format` only
touches files whose content actually changed, so unchanged files keep their
timestamps.

## Code Standards

### Design Principles

1. **Fatal errors must cascade by return** — errors propagate up the call
   chain until reaching `main()`, where all allocated resources are released
   before exit. Calling `exit()` / `_exit()` anywhere in the program is not
   permitted. The sole exception is the async-signal-safe signal handler,
   which must follow this sequence: the first signal communicates the
   termination event to the main thread (set a `volatile sig_atomic_t` flag)
   and returns — the main loop detects the flag, runs cleanup, and returns
   from `main()`. If a second signal arrives before cleanup finishes, the
   handler calls `_exit(128 + sig)` as the nuclear option — no other use of
   `_exit` is permitted. No `atexit` is used.

2. **No global or static shared variables** — all shared data must be passed
   explicitly through function arguments/parameters. A context struct may be
   used to group related state and threaded through the call chain.
   File-scope `static` variables (module-internal state) are also prohibited
   — any state that lives beyond a single function call must be held in a
   caller-provided buffer or context. The sole exception is `__thread` (TLS)
   variables in the async-signal-safe signal handler, where a context
   pointer cannot be passed. **Exception — immutable compile-time
   constants**: `static const` tables and scalars at file scope are permitted
   when they hold read-only constant data (lookup tables, string tables and
   similar) and use UPPER_CASE names.

3. **Avoid magic numbers** — use `sizeof` for buffer sizes and stdlib
   constants (`STDOUT_FILENO`, `EXIT_FAILURE`, `SIG_DFL`, etc.) when
   available, even if it increases token count.

4. **Deduplicate every operation — no repeated syscalls, libc calls, or
   computation** — every syscall (open, read, stat, access, poll, socket,
   ioctl, ...), libc function on identical inputs (strlen, memcmp, sscanf,
   snprintf, ...), and derived computation must execute at most once per
   program cycle. Results must be cached and passed by pointer to all
   consumers. Avoid O(n²) or O(n×m) loops over the same dataset; prefer a
   single O(n) pass with accumulated state. When a probe returns a negative
   result (file absent, device missing), cache that knowledge to avoid
   re-probing — the sole exception is data that can change at runtime
   (hot-pluggable devices, dynamic state).

5. **Buffer strategy audit** — see DOMAIN.md §Buffer Strategy Audit for the
   complete read-strategy table and wrapper-layer rules. Preference order:
   batch scan over dynamic slurp when the format allows chunked processing;
   stack buffer over heap when the size is known and bounded; dynamic
   allocation over a guessed stack buffer when the size is not guaranteed by
   an API contract. Never guess a fixed stack buffer for files without a
   documented size bound.

6. **Signal handler must be async-signal-safe** — see principle #1 for the
   complete rules. The handler sets only a `volatile sig_atomic_t` flag and
   returns; cleanup runs in `main()` after the loop detects the flag.

7. **Avoid duplication** — when the same logic appears in more than one
   place, extract it into a shared function or module. Prefer a single
   authoritative implementation — small duplications drift apart and become
   bugs.

8. **Eliminate dead production code** — production code (function, variable,
   branch) only executed by tests must be removed or moved to `tests/` as a
   shared utility. Weak-symbol definitions always overridden by strong test
   definitions are the only exception.

9. **Remove dead unit tests** — unit tests that do not execute any
   production code path and exercise only mocks, stubs, or test
   infrastructure provide no coverage value and must be removed.

### Code Organization

Apply SOLID principles — especially Single Responsibility and Dependency
Inversion. To make unit tests easy, keep code decoupled and
context-agnostic: write independent functions that receive arguments,
process, and return, without relying on global, static, or shared variables.
Source files live in `src/`, with `src/main.c` as the only top-level file
and the rest grouped in meaningful subdirectories (e.g. `src/cast/`,
`src/net/`, `src/buf/`). No file exceeds 300 lines; every function stays
under 40 lines with a cyclomatic complexity of at most 6.

### Safety Checklists

Before committing, consult the applicable checklists in [QA.md](QA.md):
- [Memory Safety Checklist](QA.md#memory-safety-checklist) — required when
  modifying dynamic or shared memory.
- [Pre-Merge Safety Checklist](QA.md#pre-merge-safety-checklist) — required
  for every change.
- [Domain-Specific Pitfalls](QA.md#domain-specific-pitfalls) — review the
  project-specific entries (cast protocol framing, mDNS parsing, buffer
  growth, dangling-fd spool handling).

## Testing

Unit tests are built with our own mini-framework — no third-party testing
library. Each test file `#include`s the production `.c` file directly, which
gives the test access to `static` functions without any mocking
infrastructure or weak symbols:

```c
#include "src/buf/buffer.c"   /* production source directly */

static char mock_data[64];
static ssize_t mock_read(int fd, void *buf, size_t len)
{
    memcpy(buf, mock_data, len < sizeof(mock_data) ? len : sizeof(mock_data));
    return len;
}
```

`main()` must stay thin and separate from program logic — this makes any
testing strategy easier.

Never rely on operations that require root access or are machine-state
dependent:
- For filesystem operations, use `memfd_create` (from `<sys/mman.h>`) when an
  open fd suffices; otherwise use `mkdtemp` to create a random temporary
  directory before each test and clean it up on exit regardless of success
  or failure.
- For socket operations, always bind to port 0 (random port).
- For operations that require root or are not suitable for temporary files
  or random socket binds, use stubs/mocks/spies on the stdlib or syscall
  layer — do not rely on real kernel resources.
- Reading from `/proc`, `/dev`, or `/sys` is machine-state dependent and
  must be avoided or mocked.

Use dummies, stubs, fakes, mocks, and spies where appropriate. Tests that
depend on external system tools or services are integration tests; they are
optional and must never block unit tests or the quality gate.

Never add `#ifdef`/`#ifndef`/`#else` blocks to production code to alter its
behavior under test. Use dependency injection, weak symbols, or link-time
substitution instead — test concerns must not leak into production sources.

### Coverage exclusions

No piece of production code shall be excluded from coverage. Avoid using
`#ifdef`/`#ifndef`/`#else` preprocessor blocks that remove code from
coverage — they create untested code paths that silently rot. Weak wrappers
that are always overridden by strong test definitions are an exception: they
are dead code in the test binary and shall be excluded from coverage
calculations. Cppcheck must not be suppressed globally — see
§Cppcheck suppression discipline.

## Quality Gate

No commit may bypass any quality gate item. All thresholds are mandatory.

### Running checks

- `make lint` — chains `format`, `cppcheck` (`--enable=all
  --check-level=exhaustive`, error exit on any finding over `src/`),
  `lizard` (max CCN 6, max length 40, max arguments 5, max tokens 150), and
  `loc-check` (max 300 LOC per file). Run it first — it catches formatting
  and lint issues without needing a build.
- `make coverage` — runs the tests and enforces the 80% line coverage gate in
  one step (`coverage` depends on `test`, so a separate `make test` is
  redundant). `make cov-list` lists files below 80%, sorted ascending.
- `make [-j4]` — confirms the production binary builds cleanly with no
  warnings.

### Fixing violations

Do not circumvent build warnings, lint violations, or quality gate failures
with workarounds, suppressions, or half-baked fixes. Every violation must be
resolved at the root cause by refactoring the code. Do not cheat the metrics
with ternary operators instead of `if`/`else`, or by merging statements onto
one line — `make format` will undo cosmetic attempts anyway.

| Issue | Required action |
|---|---|
| **File > 300 LOC** | Split into multiple files based on responsibility |
| **Function > 40 LOC** | Split into multiple smaller functions |
| **Cyclomatic complexity > 6** | Split into multiple functions (extract conditions, reduce nesting) |
| **Tokens per function > 150** | Split into multiple functions |
| **Nested control depth > 3** | Extract inner blocks into helper functions |
| **Parameters > 5** | Split, or pack parameters into a struct and pass the struct |
| **Unused parameter** | Remove it from the signature and update callers. Never suppress with `(void)param;` — the only exception is mock functions bound to a fixed weak-symbol interface |
| **Unused function** | Remove it entirely |
| **Unused local variable** | Remove the variable or its dead assignment |
| **Coverage < 80%** | Add missing test cases. Use `make cov-list`, lowest first |

### Cppcheck suppression discipline

Global suppression (e.g. `--suppress=*` in the Makefile) is not allowed —
refactor to fix the root cause first. In-source suppression comments
(`// cppcheck-suppress <rule-id>`) may be used only as a last resort when the
check is genuinely unfixable (e.g. a cppcheck false positive it cannot see
across files), and must include a comment explaining why.

## Definition of Done

All items below are mandatory. A change is not complete until every item
passes:

1. **Design Principles and Safety Checklists applied** — the change follows
   §Design Principles and the applicable QA.md checklists were consulted.
2. **Code style applied and lint passes** — `make lint` must succeed.
3. **All tests pass and coverage threshold met** — `make coverage` must
   succeed (≥ 80% line coverage).
4. **Code builds with no warnings** — `make [-j4]` must succeed.
5. **Regression test for every bug** — every fixed bug must have a test that
   failed before the fix and passes after (see QA.md §Bug Prevention).
6. **TODO.md pruned** — completed sections deleted from the file per
   §TODO.md Pruning rules.
7. **Documents consistent with code** — DOMAIN.md is the source of truth and
   the code must match the spec; CLI changes must be reflected in README.md
   and DOMAIN.md.

Items 2 and 3 may be replaced by a single `make report` invocation, which
runs lint and coverage in sequence and prints a summary per step. If it
fails, run `make lint` and `make coverage` individually to see full detail.

A commit that contains only documentation changes (`.md` files) may skip the
lint, coverage, and build steps — every other commit must pass the full gate.

## TODO.md Pruning

Apply these steps in order:

1. Read the current TODO.md.
2. For each section (`## ...`), check every bullet:
   - If **all** bullets are ticked (`[x]`), delete the entire section
     (header + all its bullets) from TODO.md.
   - If **any** bullet remains unticked (`[ ]`), keep the section.
3. Write the pruned file — do not leave empty headings.

## Domain Knowledge

Refer to DOMAIN.md for business rules, the CLI, entities, flow/lifecycle,
retry landscape, memory management strategies, threading architecture, and
glossary. A compact reference is also in AGENTS.md §Domain at a glance.

## Task Lifecycle

A task is considered completed only when it fulfils all conditions in the
Definition of Done.

## Pull Request Process

1. Ensure the complete Definition of Done is met (see §Definition of Done).
2. Ensure all quality gate checks pass.
3. Update DOMAIN.md if architecture, CLI, or business rules change.
4. Update TODO.md following the TODO.md Pruning rules.
5. Follow the bug prevention process — see QA.md §Bug Prevention.