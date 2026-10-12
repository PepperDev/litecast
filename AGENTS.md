# AGENTS.md

## Your role

Keep the project minimalistic, compact, and secure. Write readable source
code that a single human can maintain.

Make the project correct, performant, and lightweight. When multiple
solutions are possible, choose the one that performs better under heavy
workload and extreme usage scenarios.

Worship lightweight resource usage. Prefer stack memory; use dynamic
allocation only when static limits would constrain performance or
throughput. Reuse buffers and objects.

Measure first. Before optimising, require a microbenchmark or latency
profile.

No external dependency libraries. The project is written in C99 and built
with a plain Makefile — no cmake, no meson. Everything must be implemented
with the C standard library and Linux system calls.

## Domain at a glance

The full design specification lives in `DOMAIN.md`; this section is a
compact reference so AGENTS.md is self-sufficient.

### What litecast does

Streams media to a Chromecast on the same network, purely as a source:

1. **Discover** — mDNS/DNS-SD browse of `_googlecast._tcp.local`, parse TXT
   records (friendly name, UUID, model, running app).
2. **Connect** — TCP port 8009, Cast V2 framing (big-endian 4-byte length +
   protobuf `CastMessage`), TLS on modern firmware, plaintext on legacy.
3. **Handshake** — `CONNECT` on the connection namespace, `PING`/`PONG`
   heartbeats. If the control socket stays healthy but an **established** DMR
   session (one that reached `BUFFERING`/`PLAYING` since its `LOAD`) ends
   abnormally (a `type=ERROR` frame, `IDLE` with `idleReason != FINISHED`, or a
   premature `IDLE idleReason=FINISHED`) while a source is still live, the
   session is **auto-restarted** — the retired session is terminated on the
   device first (best-effort receiver `STOP` on the still-live socket; giving
   up the socket zeroes the session handle, so an exit during the restart
   backoff must find the device already idle, trace.23) — then a fresh
   connect → `CONNECT` → `GET_STATUS` → `LAUNCH` → `LOAD` cycle on a dedicated
   backoff (1→2→4→8 s, held) that never spends the transport retry budget; the
   `IDLE` that immediately acks litecast's own `LOAD` (the replaced playback
   torn down, `idleReason=INTERRUPTED`, before the resumed session plays) is
   the load taking effect, not a session death, and never triggers a restart
   (trace.20); a `FINISHED` with all producers EOF is the only quiet
   exit (trace.22: a live source that the device "finished" mid-stream is an
   abandonment, and a producer stays under the ordinary consumer rules while the
   restart is pending, so nothing drains an unwatched window).
4. **Serve** — minimal embedded HTTP server on the local interface; ask the
   default media receiver for a session (`GET_STATUS`), then `LOAD` the
   local stream URL as `contentId`.
5. **Stream** — the device does the pulling; each HTTP request is a consumer.
   The model is **conditional on the source mode** (§Producers and
   consumers): file → each consumer reads the file directly; `--command
   --cache-to-fs` → exactly ONE producer writes the file **regardless of
   consumers** and every consumer reads the file directly (`Content-Length`
   only once the command completes); `--command` (no spool) → zero or more
   producers spawned on demand, several consumers may share one producer. A
   no-spool command's output is a producer that fills its own retention
   window and pauses when the window is full or no consumer is attached (pipe
   backpressure), and is terminated after an idle guard with no consumer.
   HTTP connections are never closed for idleness, so a paused-but-attached
   device keeps its consumer and thus its producer alive (an attached consumer
   — even a non-reading one — never triggers the guard). All producer-window
   and consumer-position state is resolved, attached and mutated in the single
   event-loop sequence (no threads, DOMAIN.md §Design Invariants), so an
   attach/compaction decision is atomic against any window move. A
   request's start (`0` for a plain request) is resolved against the
   producers — a **live plain request is answered as a startable whole
resource**: it attaches at retained byte 0 (the drained device re-inits its
    media parse on the resumed connection; a mid-stream continuation, cold
    frontier or delivered-end run-in, is the shape it aborts on — trace.8/9,
    `type=ERROR` + `IDLE idleReason=ERROR` ~40 ms after the resumed bytes) and
    replays the retained span at socket rate, then slips onto the live edge; if
    byte 0 has been compacted away it **spawns a fresh producer** (a
    whole-resource replay needs a window starting at 0, so a mid-stream join
    is never served); a **closed** `Range` (known `total`, or a `bytes=N-E`
    end already produced) keeps the retained/behind/spawn ladder — else attach
    to a window that retains
    it, wait for the nearest producer behind it, or spawn a fresh producer;
    an **open-ended** `Range` on an unknown-total stream is closed by the server
    at the frontier — end = `received` when the start is already produced, end
    = `N+1` (one byte, head stowed until it exists) when a running producer has
    not reached `N` — answered `206` + `Content-Range: bytes N-E/*` +
    `Content-Length`, RFC 9110 §14.4, and served in place so the device resumes
    mid-stream where it stopped instead of rewinding (trace.22); a cold start
    (nothing produced), a start below the retained prefix, and
    `--no-arbitrary-range` instead give `200` from **byte 0**; and the window
    advances at the slowest connected consumer's pace. A
    whole-resource restart is the device's only active playback: it **retires
    the device's abandoned earlier pulls** on that producer, so the replay
    consumer becomes the single pacing governor (a stale slow/paused/ghost
    consumer position must never throttle the window below the replay's live
    edge, and the abandoned producer is freed to the idle guard instead of
    running on a discarded window); a consumer index is owned by exactly one
    connection and re-attach always releases the old claim first (no ghost
    entries). The live
    join cannot outrun its own producer: a restart re-pull that lands mid-stall
    parks on an empty socket until the next fragment.
   litecast announces `Content-Length`
   only when the total is known and the stream is retained: file mode up
   front, a spooled command at its completion, and a **no-spool command when
   the first producer terminates** (its `total` is stored; any further request
   can then answer with `Content-Length`).

Only the minimum required for casting is implemented. No tray icon, no
screen recording, no audio-device handling, no codec validation.

### CLI

```
litecast [-b SIZE|--cache SIZE] [-s|--cache-to-fs] [-d NAME|--device NAME]
         [-n|--no-arbitrary-range]
         (-f|--file | -c|--command) [--] <FILES...>|<command-and-args...>
```

- `--file`/`-f` and `--command`/`-c` are mutually exclusive; file mode is
  the default. `-b`/`--cache`, `-s`/`--cache-to-fs` are the short forms of
  the buffer options.
- `--no-arbitrary-range`/`-n` is a compatibility escape hatch: never close an
  open-ended `Range: bytes=N-` on a stream of unknown length by choosing the
  end — such a request is answered `200` from **byte 0** (the pre-trace.22
  matrix) instead of an arbitrary-end `206`. A no-op in file mode, where the
  total is known up front.
- `--device`/`-d NAME` filters the cast target by friendly name: case-insensitive
  glob with `*` as the only wildcard; substring fallback (`*NAME*`); if the
  name is not found within the discovery window the first discovered device
  is used. No `--device` → first device (DOMAIN.md §Device selection).
- `--` ends option parsing; operands follow.
- Multiple files stream one after another, `cat`-style.

### Buffer and cache rules (`--cache`)

- Suffixes `K`/`M`/`G` (case-insensitive) or `%`; default `64M`; minimum one
  page; a percentage can never exceed `100%`.
- **File mode, plain size**: fixed-capacity in-memory buffer of that size.
- **File mode, `%`**: buffer target is that fraction of the file's size;
  size obtained via `stat(2)` when trustworthy (regular file), otherwise
  fallback to dynamic allocation. Pipes/special devices are never
  trustworthy.
- **Command mode**: output arrives on a pipe of unknown size, so the buffer
  is always dynamic — starts at one page and grows as data arrives. Plain
  size grows toward the size; `%` recomputes the target from a running
  counter of bytes received so far; `100%` grows with every byte.
- The exact growth/shrink algorithm, dynamic-array policy and retry
  landscape are specified in `DOMAIN.md`; keep that document in sync.

### `--cache-to-fs`

Only meaningful in `--command` mode (ignored in file mode). Create a temp
file, open it, unlink it immediately (dangling fd), write 100% of the pipe
output into it as it arrives. Memory still follows `--cache`. There is
**exactly one producer**, which writes the file **regardless of whether any
consumer is attached** (never gated on consumers, never idle-terminated);
every consumer (live or `Range`) reads the spool **directly** via `pread`
— the memory window is a non-gating cache, never a serving source — and
`Content-Length` becomes known only once the command reaches EOF (DOMAIN.md
§Producers and consumers, §HTTP response selection).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) is an extension of this document — read
it together with this section whenever you read AGENTS.md. The rules in
CONTRIBUTING.md apply to agents as they apply to human contributors, with
the exceptions noted below.

Agents work directly on the repository and commit without pull requests, so
the Getting Started (forking) and Pull Request Process sections do not
apply. All other sections — Definition of Done, TODO.md Pruning, Code
Standards, Bug Prevention, Quality Gate, Testing — are mandatory.

All items of the Definition of Done are mandatory before every commit, with
one exception: a commit that contains only documentation changes (`.md`
files) may skip the lint, coverage, and build steps. Every other commit must
pass lint, coverage (test + coverage ≥ 80%), and build, plus TODO.md pruning
and all other checks listed in CONTRIBUTING.md. Do not commit partial work —
a commit that fails any quality gate item is not permitted.

## Constraints

An agent must never start a task or bugfix that is not written to TODO.md
(for this scope, a "task" is any change that modifies code). When the user
asks to do a task not yet in TODO.md, the agent must write it down in
TODO.md before starting.

Run as an unprivileged user without sudo. When a required system tool is
missing, ask the user to install it — do not attempt privilege escalation or
circumvent this directive.

No external dependencies: no third-party libraries, no third-party tooling,
no network access for the build. Everything must build with the C99 toolchain
and `make` alone.

## Code Quality

See [CONTRIBUTING.md §Quality Gate](CONTRIBUTING.md#quality-gate) for
mandatory code quality rules and thresholds.

## Design Mode (Approval Workflow)

When the user says "we are in design mode" or asks to investigate, fix, or
implement something, follow this strict workflow:

1. **Update specification/planning docs as needed** — `DOMAIN.md`,
   `AGENTS.md`, and other spec/planning files are the expected outputs of
   design mode. Do NOT write `DOMAIN.md` or other spec updates to
   `TODO.md` — updating them during planning is the norm, not a separate
   task. Only add `TODO.md` entries when the user asks for code changes
   (bugfixes, features, refactors). Per CONTRIBUTING.md, doc-only changes
   skip the quality gate — no `make report` needed during planning.
   `DOMAIN.md` must reflect the **intended/designed behavior** (the spec),
   not what the current code happens to do — the code will be changed later
   to match.
2. **Present the plan** — show it and wait for the user to speak. While
   waiting, you are in *design mode* — only planning docs may be touched. Do
   NOT commit `TODO.md`, start coding, or modify any source/header files
   until the user explicitly approves. End your presentation with **"Ready
   for review?"** — do not commit, do not proceed.
   - After editing planning docs, show `git diff --stat` so the user sees
     what changed.
   - Do not `git add` or `git commit` until the user says "commit",
     "approve", or equivalent.
3. **Wait for approval, then commit** — after the user approves, commit
   `TODO.md` (the plan) first.
4. **Proceed to code** — user specifies either: "tackle task 1" (single
   task), or "enter loop mode" (tackle multiple tasks sequentially).

Violations: committing code without approval, coding before the user says
to, or skipping the TODO-first step are prohibited.

> **⚠️ Agent must not act on its own analysis**
> During design mode the agent may be asked to investigate or audit. The
> agent must **never** edit `TODO.md` or any other file based on findings
> from that investigation unless the user explicitly instructs it to do so.
> Present the findings, wait for instructions — do not pre-emptively add
> tasks, update plans, or fix things the user hasn't asked for.

> **⚠️ System Plan/Build mode vs AGENTS.md Design Mode**
> In system Plan mode the agent's tools are read-only — no file of any kind
> can be written. The user must switch to system Build mode to enable the
> agent to edit spec/planning files on their behalf. System build mode does
> **NOT** constitute user approval for coding or committing — the agent must
> remain in AGENTS.md design mode (no code, only planning docs) until the
> user explicitly says "tackle", "proceed", "enter loop mode", or otherwise
> signals approval. Even doc-only commits require the user's go-ahead.

> **⚠️ Incremental edits**
> When editing a document, check if there are already uncommitted changes
> before adding more. When the user asks for additional changes and the
> agent makes a mistake and wants to revert, NEVER run `git checkout` — it
> will lose the previous uncommitted state. Compare the current state with
> what was there before and try to solve the problem; as a last resource,
> restore only the affected lines, not the entire document.

## Loop Mode

Agents enter loop mode on user request only.

During context compaction, keep in the context whether the agent is
currently on loop mode or not.

When entering loop mode follow the steps:

- Check for work-in-progress changes in the worktree and try to match the
  task they belong to; resume it.
- If none, tackle the next task that makes sense.
- File and function names need not strictly match those in `TODO.md` —
  agents are free to reorganize them.
- Add multi-level source directories (only main at `src/`, remaining grouped
  in meaningful subdirectories, e.g. `src/cast/code.c`), moving files to
  group related responsibilities (SOLID).
- Apply the Definition of Done, including `TODO.md` pruning.
- Commit once per task (one task, one commit). Squash related changes into a
  single logical commit.
- Loop back until the user interrupts. For relevant missing critical
  technical details or blockers (e.g. a required system tool or permission),
  query the user. Do not query the user to decide the next task — pick the
  most relevant one and proceed.