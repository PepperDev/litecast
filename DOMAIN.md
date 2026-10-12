# DOMAIN.md

This document is the specification for litecast. It describes the
**intended/designed behavior** of the project — the code shall be written to
match this specification, not the other way around. Keep it in sync with the
code; whenever architecture, CLI, or business rules change, update this
document and the code together.

Companion documents: [AGENTS.md](AGENTS.md) (agent rules and a compact
domain reference), [CONTRIBUTING.md](CONTRIBUTING.md) (code standards and
quality gate), [QA.md](QA.md) (bug prevention and safety checklists).

## Documentation Conventions

### Flow diagrams

When documenting flows and lifecycles, use these consistent conventions:

- Quotes (`"..."`) for user input or command-line arguments.
- Backticks (`` `...` ``) for function names, syscalls, file paths, and
  variable names.
- `→` for sequencing (e.g. `parse_input → validate → execute`).
- `⟳` for retry loops; `⏎` for return values cascading through the call
  chain.
- Distinguish syscalls (`open`, `read`) from libc calls (`qsort`, `strlen`).
- Align multi-line diagrams with consistent indentation (width 4).

### Pseudocode

Prefer pseudocode over real C when describing algorithms, business rules,
and flow logic. Pseudocode keeps the spec concise and language-agnostic.
Use these conventions:

- `→` for sequencing and data flow.
- `if` / `else if` / `else` for conditionals.
- `for each` / `while` for iteration.
- `//` for inline commentary.
- Reference named sections (e.g. "per §Retry rules") for sub-logic detailed
  elsewhere.
- Keep it language-agnostic — no C-isms like `++`, `->`, or type
  declarations.

## Design Invariants

Cross-cutting non-functional requirements that apply to the whole codebase:

- **Single-threaded event loop.** litecast runs exactly one thread. All I/O
  — the Cast control socket, the mDNS socket, the HTTP server sockets, the
  source pipe, timer fds — is multiplexed with `epoll_wait` in one loop.
  The one exception is a trusted regular-file source, which is never
  registered with epoll (epoll cannot watch a regular file) and is instead
  pumped inline, synchronously, inside the pump iteration. No `pthread`, no
  mutexes, no shared-memory concurrency. This is the single most important
  guarantee: it makes the program deterministic, deadlock-free, and trivially
  testable.
- **Atomic producer/consumer state — no TOCTOU.** All producer-window and
  consumer-position state, and the attach/resolve bookkeeping, is read and
  mutated **only inside one sequential pass of the single loop thread**: a
  request is resolved (iterate the producers, pick the qualifying window),
  attached, and then served against the same live state in that one pass, so
  a decision can never be invalidated between the read and the apply. Race-
  freedom is this single-sequence guarantee, not locks: never introduce a
  second thread, a mutex, or a deferred (callback/timer-side) mutator of
  producer/consumer state — any of those is the only way this invariant can
  break.
- **Blocking-free.** No blocking syscall is issued in the loop. Sockets are
  non-blocking; reads/writes that would block are deferred until `EPOLLOUT` /
  `EPOLLIN` fires again. `epoll_wait` is the only place the program sleeps.
  This extends to producer drains: a command source's pipe read end is
  non-blocking and every wake drains a bounded amount, so a busy pipe (spool
  ingesting at full speed) or a momentarily-empty pipe can neither block the
  loop inside `read` nor starve the cast session / HTTP conns for more than a
  few milliseconds at a time (§Producers and consumers).
- **Never busy-retry a would-block write.** A socket flush that returns
  `EAGAIN`/`EWOULDBLOCK` stops the current drain and is only retried after the
  next `EPOLLOUT` on that socket. The run never spins on `write` because a
  peer stopped reading (a live cast hoards the send buffer and the DMR drains
  it at its leisure).
- **Zero-leak principle.** Every resource acquired (fd, allocation) must be
  released before the owning function returns. Cleanup must be reachable
  from every return path — no early return that skips a `close` or `free`.
- **Cleanup convergence.** Normal completion and error/failure paths
  converge to the same cleanup logic — a single `goto cleanup` pattern per
  function. See QA.md §Resource teardown on error paths.
- **Computation scoping.** No code path outside the active feature set may
  execute. If a mode or feature is inactive, none of its data sources are
  opened, read, or parsed.
- **Fatal errors cascade by return.** Errors propagate to `main()`, which
  releases all resources before exit. See CONTRIBUTING.md §Design
  Principles #1 (the sole `_exit()` exception is the nuclear-option signal
  path). litecast blocks `SIGINT`/`SIGTERM` with `sigprocmask` and consumes
  them through `signalfd` inside the epoll set, so the mandatory
  `volatile sig_atomic_t` + `_exit(128+sig)` machinery is reserved as the
  safety net should `signalfd` be unavailable.
- **Buffer discipline.** The in-memory buffer never exceeds what the
  `--cache` rules permit, and percent targets are recomputed from the
  running received-byte counter. Compaction never discards bytes a live
  consumer still needs.

## Non-goals

Deliberately out of scope — none of these will be implemented:

- Tray icon, GUI, audio-device handling, screen/input capture.
- Device selection, volume, pause/play/seeking commands from the CLI.
- Multi-device or group casting.
- Media validation, codec probing, or transcode hints.
- Encryption of the media path (see §Transport).

## CLI Arguments

```
litecast [-b SIZE|--cache SIZE] [-s|--cache-to-fs] [-d NAME|--device NAME]
         [-n|--no-arbitrary-range]
         (-f|--file | -c|--command) [--] <FILES...>|<command-and-args...>
```

| Argument | Type | Meaning |
|---|---|---|
| `--cache SIZE` / `-b SIZE` | option | Buffer size; `K`/`M`/`G` suffix (case-insensitive) or trailing `%`. Default `64M`. Minimum one page. A percentage is capped at `100%` (error above). See §Buffer model. |
| `--cache-to-fs` / `-s` | flag | Only meaningful with `--command`; ignored in file mode. Spool the casted data to a dangling temp file (always 100% of the output). See §Buffer model. |
| `--device NAME` / `-d NAME` | option | Cast target by friendly name; case-insensitive, `*` is the only wildcard. See §Device selection. |
| `--no-arbitrary-range` / `-n` | flag | **Compatibility escape hatch.** Never invent the end of an open-ended `Range` (`bytes=N-`) on a stream whose total is unknown: such a request is answered `200` from **byte 0** (the whole-resource replay, §HTTP response selection rule 3 — the pre-trace.22 matrix) instead of an arbitrary-end `206`. Only meaningful in command mode while the total is unknown; a no-op in file mode, where the total is known up front and the request is already closed. See §HTTP response selection "Arbitrary `Content-Range` end". |
| `--file` / `-f` | mode | Cast files; the default mode. Operand list = paths. |
| `--command` / `-c` | mode | Cast the stdout of a command. Operand list = command + args. Mutually exclusive with `--file`; last one wins. |
| `--` | flag | End of options; all following tokens are operands, even if prefixed with `-`. |
| `-h`, `--help` | flag | Print usage to stdout, exit 0. |
| `-V`, `--version` | flag | Print version to stdout, exit 0. |

Operands after option parsing (or after `--`) are either the file list (file
mode) or the command and its arguments (command mode). In command mode the
command is executed directly with `fork`/`execvp` — never through a shell.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean exit (stream finished, `--help`, `--version`). |
| 1 | Any failure (bad arguments, discovery found nothing, connect failed, stream error). |

## Business Rules

1. `--file` / `--command` are mutually exclusive, the default is file mode;
   specifying both keeps the last one parsed.
2. `--cache` accepts `K`/`M`/`G`/`k`/`m`/`g`/`%`. A bare number without a
   suffix is an error. `%` values above `100%` are an error. Computed byte
   sizes below one page are clamped up to one page.
3. **File mode, plain size** → the in-memory buffer is a fixed-capacity
   buffer of that size holding the bytes of the file being served (a sliding
   window when the file is larger).
4. **File mode, `%`** → the buffer target is that fraction of the file's
   size, obtained with `stat(2)`. A size is *trustworthy* only for regular
   files; for pipes, socket files, special devices, and stat failures there
   is no trustworthy size → the buffer falls back to the dynamic policy
   (rule 6) without re-probing per cycle.
5. **Command mode, any `--cache`** → output arrives on a pipe of unknown
   final size, so the buffer is always dynamic, starting at one page.
6. **Dynamic policy**: the buffer grows as data arrives. Plain size = grow
   toward that many bytes; `%` = recompute the target as `received × pct /
   100` on arrival, growing when the target exceeds capacity; `100%` =
   simply grow with every byte received (no compaction — the whole stream is
   retained, which makes it seekable in memory). Growth follows §Dynamic
   Arrays.
7. **`--cache-to-fs`**: create a temp file with `mkstemp`, hold it as a
   dangling fd (unlink immediately), and write 100% of the command output to
   it as it arrives, independent of `--cache`. In file mode it is ignored
   entirely (not even parsed for effect).
8. **`cat` semantics**: multiple files are streamed sequentially as one
   concatenated stream, one after another.
9. **No media validation.** The bytes are served verbatim; litecast never
   inspects container, codec, or SPS/PPS.
10. **Device selection** follows §Device selection — `--device NAME` filters
    by friendly name with `*`-wildcard, case-insensitive matching, and a
    timed fallback to the first discovered device.
11. **Source of truth ordering**: `contentId = http://<local-ip>:<port>/stream`
    with `streamType=LIVE` in every mode. The LOAD `contentType` is the plain
    MIME (never `video/mp4; codecs=…`) — no media inspection (§Business Rule
9). The HTTP server advertises `Content-Length` and honors `Range` per
     §HTTP response selection. `206` + a closed `Content-Range` is emitted
     only for a **closed** range — `total` known (a finite, retained stream,
     or a completed command), or a `bytes=N-E` whose end the produced bytes
     already cover. An **open-ended** `Range` on an unknown-length live pipe
     has no legal `Content-Range` (an open range is unrepresentable, RFC 9110
     §14.4), so it is answered `200` from **byte 0** (the requested offset is
     ignored; the whole resource is served, §HTTP response selection rule 3).
     Request IDs are monotonically increasing
    integers; each control message must carry a fresh id.
    > **History.** A fully seekable `BUFFERED` file cast once put the DMR
    > into its MediaSource byte-range-reconcile path, which errored
    > `detailedErrorCode 104` even with `codecs` present (`trace-lc`,
    > `trace-mk` proves the same 6.2MB fMP4 plays with plain
    > `video/mp4` + `LIVE` + a chunked feed). Re-advertising
    > `Content-Length`/`Accept-Ranges` is an explicit, user-directed decision
    > ("the client decides"); verify on the live device and drop the
    > advertising again if the receiver re-enters the 104 path.
12. On control-connection loss after a successful load, litecast attempts
    to reconnect with the reconnection policy in §Retry Landscape; the HTTP
    server stays up so playback can resume where the buffer/spool allows.
13. **Only command streams without `--cache-to-fs` follow the multi-producer
    multi-consumer model** (§Producers and consumers). The command is a
*producer*: it fills its own retention window and freezes when the window
     is full (OS pipe backpressure); with no consumer attached it is terminated
     after a bounded idle guard, freeing the command and its window
     (**an attached consumer — even a paused one — never triggers it**; HTTP
     connections are never closed for idleness, §Producer behavior "Idle
     termination"). An HTTP
request is a *consumer*: it attaches to the producer whose window can serve
     its start position `s` (**the stream beginning for a plain request on a
     file or a completed command, but the producer's **current frontier** for a
     live no-spool command — a plain request joins the live stream wherever it
     is and is never rewound to a retained head**, §Consumer attach by start
     position), else to the nearest producer behind `s` (waiting until the
     stream reaches `s`), else it spawns a fresh producer. Several consumers may
     attach to one producer; the window advances only as far as its **slowest**
     consumer.
    **File mode and command+spool are not part of this model**: they never
    spawn extra producers, file-backed serving is direct, and a spooled
    command is a single producer that writes its file *regardless of whether
    any consumer is attached* (§Producers and consumers "File mode and
    command+spool").

## Entities

| Entity | Fields | Notes |
|---|---|---|
| `device` | `name`, `uuid`, `model`, `running_app`, `ip`, `port`, `transport` | Device discovered via mDNS. `port` is always `8009` in **host byte order** (`sockaddr_for` applies `htons()` when filling `sin_port`); `ip` holds the wire bytes of the `A` record, assigned as-is to `sin_addr.s_addr`. `transport` ∈ {`tls`, `plaintext`} resolved at connect time (§Transport). |
| `source` | `mode`, `fd`, `path`/`argv`, `size`, `size_trusted`, `index` | `mode` ∈ {`file`, `command`}. In file mode `size_trusted` is true only for regular files that `stat` succeeded on; `index` tracks the current file when multiple are given. |
| `producer` | `argv`, `pid`, `position`, `buf`, `frozen`, `consumers[]`, `spawned_ms` | One per live command process **without** a spool (the no-spool model, §Producers and consumers); owns a per-producer retention window (`buf`). `position` is the stream byte count produced so far. A producer is frozen when no consumer is attached. |
| `buffer` | `data`, `cap`, `len`, `read_off`, `target`, `received`, `pct`, `spool_fd` | Retention window (§Buffer model). One per producer in the no-spool model; in file mode and command+spool a single shared buffer suffices, and in command+spool it is a **non-gating** cache (serving comes from the file, §Producers and consumers). |
| `cast_session` | `sock`, `source_id`, `request_id`, `session_id`, `transport_id`, `pending[]` | Control channel state. `pending[]` correlates `requestId` → expected response. After `LAUNCH` of the Default Media Receiver, `session_id` and `transport_id` come from `RECEIVER_STATUS`; `transport_id` is the destination for the second `CONNECT` and `LOAD`. |
| `http_srv` | `listen_fd`, `local_ip`, `port`, `conns[]` | Embedded server. `conns[]` are accepted client sockets: in the no-spool model each attaches to a producer, in file and command+spool modes each serves directly from the retained source (spool file / file); the server also holds the stream `total` (0 = unknown), the `complete` flag, the spool fd and the shared buffer pointer used by §HTTP response selection. |

## Device selection

The cast target is chosen from the discovered device list per business rule
10. Without `--device` the first device in arrival order is always the
target — there is no interactive picking.

With `--device NAME`:

- Matching is over the device's **friendly name** (the `fn` TXT record) and
  is **case-insensitive**.
- The pattern accepts **`*` as the only wildcard**; it matches any sequence
  of characters (including the empty one). Any other character in `NAME`
  matches literally. A pattern with no `*` is an exact-but-case-insensitive
  match.
- Selection is evaluated continuously during the discovery window (§Retry
  Landscape row 1): the first device that matches selects. Match order:
  1. Device matching `NAME` as a glob (case-insensitive).
  2. If at window close none matched, device whose name **contains** the
     literal `NAME`, i.e. `*NAME*` as a glob — again first arrival wins.
  3. If still none, fall back to the **first discovered device** (when at
     least one device exists).
- If no device was discovered at all, the program reports an error
  (EXIT 1) after the window.

## Flow / Lifecycle

```
main
  → parse_args            // §CLI Arguments; fill config struct
  → init_signal_handling  // sigprocmask + signalfd (SIGINT, SIGTERM, SIGCHLD)
  → resolve_buffer_policy // from --cache/--cache-to-fs; file stat when applicable
  → open_source           // fopen? no — open(2); fork+exec for --command
  → discover              // mDNS browse window, collect devices (⟳ within window)
  → pick device           // §Device selection (--device filter, else first)
  → resolve_host          // mDNS target → ip
  → connect_transport     // TCP:8009, TLS or plaintext detection (§Transport)
  → handshake             // CONNECT on connection namespace
  → bind_http             // listen on local iface, ephemeral port
  → receiver_status       // GET_STATUS (⟳ retry); identify the media session
  → launch                // LAUNCH the Default Media Receiver (CC1AD845) when the
                          // receiver_status shows no media session → session_id + transport_id
  → connect_media         // CONNECT again, destination = media transport_id (§Media routing)
  → load                  // LOAD media.namespace → destination = media transport_id,
                          // {contentId, streamType, contentType}
  ─┴─ event loop ─────────
     for each epoll event:
         mDNS socket   → (not active after discovery; fd closed)
         control sock  → read frames; reply PONG; parse RECEIVER_STATUS/MEDIA_STATUS
                         re: request ids; on loss → ⟳ reconnect (§Retry)
source fd     → (pipe only; a trusted regular-file source is not in
                           the set — it is read inline each pump instead,
                           bounded by the buffer's free room, because epoll
                           cannot watch regular files) read into that
                           producer's window while a consumer is attached or
                           the run is finishing (§Producers and consumers) —
                           **except command+spool, whose single producer is
                           drained into the file regardless of consumers**;
                           apply growth; spool write (if any); EOF(file) →
                           advance to next file or finish; EOF(pipe) →
                           finish when drained
         HTTP listen   → accept → new consumer conn
HTTP conns    → parse request — including an optional Range — then
                           resolve the request start `s` (§Producers and
                           consumers): for command mode without a spool, a new
                           or existing producer is attached at `s`; in file and
                           command+spool modes, `s` is served directly from
                           the retained source (spool file / file), then
                           respond (§HTTP response selection).
         signalfd      → set stop flag
         timerfd(s)    → heartbeat PING deadline; the RUN_FINISH_MAX_MS end
                            guard and the consumer-less producer reap
     when the device reports playback finished −
         (the DMR is the authority on consuming the stream: it stream all the
          HTTP bodies it wants, then reports completion as a MEDIA_STATUS
          frame with playerState:"IDLE" and idleReason:"FINISHED". Neither
          "source EOF", nor "every HTTP conn drained", nor "the whole file
          was pulled" proves the video actually PLAYED — the receiver may
buffer or re-request arbitrarily (mkchromecast holds the session
    until the user stops it). So the natural end waits for the device's
    own FINISHED signal; the HTTP/cast session is kept alive meanwhile
    (any new body conn or MEDIA_STATUS still resets the idle guard). An
    attached consumer — even a paused, non-reading one — counts as
    active: connections are never closed for idleness, so a paused-but-
    connected device keeps every producer and the session alive
    indefinitely (§Producer behavior "Idle termination"), and playback
resumes on the conn's next EPOLLOUT wake.
A terminal verdict that is NOT a natural finish — a media-namespace
            {"type":"ERROR"} frame, or playerState:"IDLE" with an idleReason
            other than FINISHED, or a premature playerState:"IDLE"
            idleReason:"FINISHED" — **observed for an established session**
            (`BUFFERING`/`PLAYING` seen since the last LOAD) while any producer
            source is still live means
            the DMR session died under load (a consumer-faster-than-producer
            drain starving the element; trace.12) and is **auto-restarted**
            (§Session supervision): the control socket is closed and a fresh
            reconnect → CONNECT → GET_STATUS → LAUNCH → LOAD cycle begins after
            the dedicated session-restart backoff (1→2→4→8 s, held), so the DMR
            re-pulls `/stream` and playback resumes. The restart never consumes
            the transport-loss retry budget and never exits on its own; the
            socket-level loss path (§Retry) is unchanged. Only an abandonment
            with every source drained (the stream itself is over) or a natural
            FINISHED (every producer at EOF) ends the run. A LIVE feed that dies
            repeatedly therefore
            recasts indefinitely, at bounded rate, until the user stops it
            (SIGINT/SIGTERM; §Exit).
A bounded idle guard (RUN_FINISH_MAX_MS) ends the run when no HTTP
            consumer has been attached for that long and the receiver has not
            reported FINISHED and no session restart is pending (a failed
            start or abandoned cast): a frozen
           producer (§Producers and consumers) may legitimately never reach
           EOF on its own — and an abandoned producer would otherwise be
           terminated by its own shorter idle guard — so the run's guard ends
           on consumer absence rather than on an unevidenced EOF, and the CLI
           always exits on its own. Ending tears down — a still-running
           command is terminated with the bounded reap. This never tears down
           while the device is still playing or mid-pull, and never triggers
           ⟳ [retry].)
  → teardown             // single cleanup block; sends a receiver STOP to end
                         // the DMR app (mkchromecast parity) if a session was
                         // latched, then closes, unlinks-nothing, frees
  → return 0
```

### Exit: STOP the DMR app (mkchromecast parity)

When litecast exits — after natural playback finish **or** a `SIGINT`/`SIGTERM`
(delivered via `signalfd` into the same teardown path) — it terminates the
Cast application running on the device, so the screen returns to idle/Backdrop
and no session lingers. It sends a receiver-namespace `STOP`:

```json
{"type":"STOP","requestId":N,"sessionId":"<media session id>"}
```

dest = `receiver-0` (platform receiver). A receiver `STOP` terminates the whole
Default Media Receiver app, which "stops the streaming, the playback and
terminates the application" in a single frame — the mkchromecast `stop_app`
equivalent. A separate media-namespace `STOP` (playback only) would need the
`mediaSessionId`, which litecast deliberately does not track, and is redundant
when the receiver STOP tears down the entire app. The STOP is **best-effort and
non-fatal**: it fires only when a session is latched (`CTRL_READY` +
non-empty `sessionId`); after the loop has stopped, so a failed STOP (device
gone, connection already closed) is ignored and cannot affect the exit code. It
is sent **before** the bounded child reap (§Command child reaping is bounded),
so the device stops on the signal rather than up to ~1 s behind it.

### A latched session is terminated when its socket is given up

The exit STOP alone is not enough: `cast_ctrl_close()` zeroes the ctrl (`state`,
`sessionId`), so **every** path that closes the control socket while a session
is live destroys the only handle litecast holds on that session — a later exit
has nothing left to stop. Both socket-giving-up paths therefore send the same
receiver `STOP` **before** the close (one `conn_drop()` helper, best-effort,
ignored on any failure):

- **Session restart** (§Session supervision): the retired session is terminated
  on the wire, then the socket is closed and the restart backoff runs.
- **Transport loss** (EOF, hard error, handshake or heartbeat timeout, retry
  budget exhaustion): the STOP lands on the heartbeat-timeout and
  budget-exhausted shapes, where the socket is still writable, and is silently
  dropped on the shapes where the socket died with the session.

Consequences (trace.23): a `SIGINT` that lands in a restart backoff finds the
device already idle, and a retry-budget abort leaves no DMR app streaming a
dead pull. The STOP is **session-scoped** — it carries the retiring
`sessionId` — so the `GET_STATUS`/`LAUNCH`/`LOAD` of a restart, which gets a
**new** sessionId, cannot be killed by a late STOP; the cost is that a restart
always relaunches the DMR instead of re-using the app the retire tore down (the
relaunch rides behind the ≥ 1 s restart gap). Inherent limit: when the socket
dies **with** the session, nothing can be sent — litecast never reconnects at
exit (teardown must not block) — so the device's own teardown of the dead pull
is then the last signal.

### Command child reaping is bounded

Before the pipes/child are torn down, litecast reaps a live `--command` child.
This must never block the exit: a child that catches `SIGINT`/`SIGTERM` and
ignores `SIGPIPE` (e.g. ffmpeg) can survive a plain `SIGTERM` while the cast
already ended (playback failed to start, or the idle cap fired) and the child
is not writing to the dead pipe. The reap sequence is therefore: `SIGTERM`,
gracefully poll `waitpid(WNOHANG)` for a bounded grace window, `SIGKILL`, one
final `WNOHANG` reap — then proceed regardless (an unreaped orphan is
re-parented to `init`, which reaps it). Teardown stays bounded so the exiting
process never goes deaf to signals.

## Buffer model

### Roles

The buffer is a *retention window* between a producer (file/pipe reader, or
command process) and the consumers (the device's HTTP requests) — **in the
no-spool command model only**. Bytes the producer pushed stay available for
the window's consumers until compaction. Each attached consumer records its
own `read_off` — even a consumer *waiting for a position* (§Producers and
consumers) holds its target `s` as the lowest needed offset and thereby pins
the window for itself. In the no-spool model each producer owns its own
window. In file mode and command+spool the window is a shared, non-gating
cache: file/spool serving never depends on it (§Producers and consumers
"File mode and command+spool").

### Capacity resolution (on startup)

```
policy := {type: PLAIN|PCT, bytes: N | pct: R}
if source mode == file:
    if policy == PLAIN:
        cap := max(N, page_size)
    else // PCT
        st := stat(source)         // issued once, cached
        if st.trustworthy:         // S_ISREG(st.mode) and st.st_size 0..SIZE_MAX
            cap := max(st.size * R / 100, page_size)
        else:
            cap := page_size   + dynamic policy grows from here (rule 6)
else // command mode
    cap := page_size; "target" := (PLAIN → N) | (PCT → recompute per §recompute)
```

The `stat(2)` for a file is issued exactly once (Design Invariant:
deduplicate syscalls) and the `trustworthy` verdict is cached; a pipe or
special device is never re-probed.

### Recompute (command mode, PCT)

```
on receive(n bytes):
    received += n
    target := max(received * pct / 100, page_size)
    if target > cap:
        grow_to(target)            // §Dynamic Arrays growth
```

For `pct = 100` the target always equals `received`, so the buffer retains
the whole stream. For `pct < 100` the buffer is a window of that fraction of
received data; bytes older than `received - target` are compaction
candidates.

### Compaction

Compaction happens when `read_off_lowest` (the minimum consumer offset) is
non-zero and the producer needs space. The producer needs space both when an
append would overflow AND when the source read path finds the buffer exactly
full (`len == cap`), and the decision is **grow-first**: while the window
still has `--cache` headroom (`target − cap`) the read takes that headroom
instead, so the consumed prefix stays retained and the window start never
moves; compaction runs only once the window is **at its `--cache` target**
(growth headroom exhausted) and the producer needs room, so the stream can
never stall at a full buffer (regression: command casts froze exactly there,
`trace-lc`):

```
if read_off_lowest > 0:
    if buffer target/cap allows higher retention and the buffer is not full:
        skip compaction (let growth policy decide)
    else if read_off_lowest > 0:
        free = min(read_off_lowest, room the next package needs)
        memmove(data, data + free, len - free)
        len -= free
        for each consumer: read_off -= free   (≥ 0)
        read_off_lowest := min of the shifted read_offs   (0 when free covers the lowest)
```
The window start thus advances **no further than the least-behind attached
consumer and no more than the room the next package needs** (§Multiple
consumers): the smaller move, when less room suffices, preserves more
retained history for later-start consumers and whole-resource replays. When
`free == 0` because the least-behind consumer has not advanced past the
window start, no room can be reclaimed and the producer holds (§Multiple
consumers).

Compaction never discards data any live consumer still needs. If the buffer
is full, compaction has run, and a consumer's `read_off` equals `len` (it
lags behind), that consumer can no longer catch up in memory — it is served
from the spool when present (§Spool), otherwise the media player re-requests
from the new window start, resolved against the producers (§Producers and
consumers).

### Spool (`--cache-to-fs`)

```
on source append(n bytes) and spool_fd present:
    write_all(spool_fd, bytes_received_tail)   // always 100% of output
```

The spool keeps a full copy of the stream **and is the serving source for
command+spool**: consumers read it directly via `pread` at their start `s`,
regardless of what the memory window currently retains (§Producers and
consumers "File mode and command+spool"). A consumer whose cursor reaches the
file's current end waits until the producer writes more (or the run completes
and `Content-Length` is announced). Spool writes are sequential appends; the
fd is non-blocking only in the sense that the loop never blocks on it —
appends to a regular file never return `EAGAIN`, so writes are issued inline
with the read handling. Memory usage still follows the `--cache` policy, but
the memory buffer is a non-gating cache in this mode: a full window never
back-pressures the spooled producer (its drain target is the file).

### Producers and consumers

A command (`--command`) stream **without `--cache-to-fs`** is not attached to
one connection — its output is a **producer**, and each HTTP request is a
**consumer** that attaches to a producer. These are two independent
mechanisms: producers generate bytes; consumers drain them. **The
multi-producer / multi-consumer model governs ONLY command mode without
`--cache-to-fs` (a no-spool command).** File mode and command+spool are not
part of it (see "File mode and command+spool" below: a spooled command is a
single producer that just writes its file regardless of consumers, and
consumers read that file directly).

**The model is conditional on the source mode** — exactly one of these three
applies to any run:

| Source mode | Producers | Consumers | `Content-Length` |
|---|---|---|---|
| **File** | none | each reads **directly from the file** at its `s` (§HTTP response selection) | known up front; sent when the whole body is retained |
| **Command + `--cache-to-fs`** | **one** single producer; writes the file **regardless of whether any consumer is attached**; never gated on consumers, never idle-terminated | zero or many, each reads **directly from the file** at its `s` (a **closed** `Range`'s span; an open-ended live `Range` is answered from byte 0; a caught-up mid-body pull waits at the file's end — §HTTP response selection) | **only when the command completes** (EOF → `total` known); never before |
| **Command, no spool** | **zero or more**, spawned **on demand** when a consumer needs one (attach/wait/spawn below); idle-terminated when abandoned | zero or many; several may **share one producer** (slowest consumer paces it) | unknown while every producer still runs; **the first producer to terminate stores its `total`**, and any further request can then answer with `Content-Length` (file-mode rule, subject to the retained-start condition) |

The run holds its producers in a fixed `PRODUCER_MAX`-slot list (equal to
the connection cap; §Run context). Each producer owns its command's `source`
(argv, pid, pipe) and its own retention window (`buffer`); a producer slot
freed by idle termination is reused by a later spawn. A producer may serve
several consumers, but **a consumer reads from exactly one producer's
window**; every producer and every consumer carries a position — the
producer its produced `position` (bytes produced so far), the consumer its
start `s` and advancing `read_off`.

```
producers (command processes, no spool)
  ├─ producer A   position=N1   window▶[───)  consumers: [con1, con2]
  └─ producer B   position=N2   window▶[──)   consumers: [con3]   frozen?
consumers (HTTP requests)
  each conn: start s, read_off, attached producer, waits-for-position?
```

#### Producer behavior (no-spool producers only)

- A producer runs one command process and owns one retention window
  (`buffer`), its own current stream `position` (= bytes produced so far) and
  its set of attached consumers.
- The producer fills its window by reading the command pipe. The window
  **grows toward the `--cache` target as data arrives** (rule 6) before it
  ever freezes: a full window first accepts reads into its growth headroom
  (`target − cap`, so an append's growth policy is always reachable). The
  window start **never moves while the window length is below the `--cache`
  ceiling** — compaction (reclaiming the consumed prefix) is reserved for a
  window that has reached its target and still needs room for the next
  package (§Compaction, §Multiple consumers). Only at the target, with
  nothing reclaimable, does the producer **freeze** and let the OS pipe
  backpressure the command (it blocks on `write`). Freezing is expressed as a
  **wait, never a zero-length `read`**: `read(..., 0)` returns 0 without
  consuming anything, which the source layer must never mistake for EOF — a
  0-length read must leave the fd open and `eof` unset (regression:
  `trace-lc.8` false-EOF'd the live source, closed the pipe and
  SIGPIPE-killed the still-running ffmpeg after `ftyp+moov+moof`, so the
  no-spool stream "ended" after ~5.5 KB while `--cache-to-fs` — whose drain
  always reads a full stage — kept working). While frozen the source is **not
  EPOLLIN-registered** (the pipe remains readable, so a level-triggered watch
  would spin the loop); the producer resumes purely because an attached
  consumer advances: compaction reclaims its consumed bytes and open room lets
  the read continue.
- The producer reads **only while at least one consumer is attached**, or the run
  is finishing on a **final** verdict — the DMR reported playback ended and no
  restart is pending, so the producer drains to EOF and the run can settle and
  `total` — hence `Content-Length` — becomes known. A verdict that only books a
  session restart (§Session supervision) is **not** final: the device is coming
  back on the restart backoff, so the producer keeps the ordinary rules
  (consumer-gated, idle-guard armed) and the retained prefix the device will
  resume from survives the gap. It never reads past what its own window can
  retain.
- **Idle termination.** A producer with **no consumer attached** is not read.
  Once the producer-idle guard elapses with still no consumer
  (`PRODUCER_IDLE_MS` = 60 s), the producer is terminated with a bounded reap
  and its process + window freed — a verdict pending a restart is no exemption
  (§Session supervision). An abandoned producer must not live forever
  — a paused `ffmpeg` transcoding into a full pipe would otherwise spin a CPU
  core until shut down. **An attached consumer — even a paused, non-reading
  one — protects the producer unconditionally**: it is never idle-terminated
  and never gated, so a backpressured device that merely stopped pulling
  (buffer full, producer frozen on the OS pipe) keeps its consumer attached
  and playback resumes on the conn's next `EPOLLOUT` wake, whatever the pause
  length. HTTP connections are **never closed for idleness** (there is no
  connection idle timeout); a consumer detaches only on device EOF/RST, a
  connection error, or run teardown (§Flow / Lifecycle).
- **First-termination `total`.** When a producer reaches EOF (`position` stops
  growing), its position **is the stream `total`**. The **first** producer that
  terminates stores it; from then on the server may answer any further request
  with `Content-Length` — the same file-mode rule, still subject to the
  retained-start condition of §HTTP response selection. A producer that is
  idle-terminated (no consumer) or killed by teardown has no EOF and stores
  nothing.

#### Consumer attach by start position `s` (no-spool producers only)

A request's effective start `s` is **`0` for a plain request — a request
without a `Range` asks to join the stream here**: for a live no-spool command
that is the whole resource from **byte 0** (rule 0 below), for a file or a
completed command the beginning of the stream (rule 1). With a `Range`, `s`
is its start **only for a closed range — `total` known, a `bytes=N-E` whose end
the produced bytes already cover, or an open-ended `bytes=N-` the server closes
itself** (RFC 9110 §14.4 forbids an open-ended `Content-Range`, but the server
may choose the end, so such a request is served in place at `N`
— §HTTP response selection rule 2, "Arbitrary `Content-Range` end"). A range
that cannot be closed — nothing produced yet, a start below the retained
prefix, the end of a bounded request not yet produced, or
`--no-arbitrary-range` — selects **no position and is served from byte 0**
(rule 0, §HTTP response selection rule 3). The server resolves the effective
`s` against the live producers:

The rule in one sentence — on each new request the resolver iterates the live
producers and attaches the consumer to **a producer whose window start is at
or behind the requested `s`** (rule 2 prefers the nearest such window): the
feed starts at `s` immediately when the window already holds it (rule 1), and
the consumer is held with **no bytes sent — not even the response head** (§HTTP
response selection rule 1) until the producer's window produces and retains
`s`. Only when **no** producer's window start is `≤ s` is a fresh producer
launched (same argv, position 0 — its window start is 0, which qualifies by
construction) and the consumer attached to it with the same hold-until-reached
rule (rule 3). Rules 0–3 below are this rule specialized: rule 0 is `s = 0`
on a live no-spool command — the whole-resource replay from byte 0 while a
window retains it, else a fresh spawn (a mid-stream join for `s = 0` is never
served); rule 1 is the window that already holds `s` (feed now); rule 2 is the
nearest-behind window (hold-until-reached); rule 3 is the otherwise-
unservable `s` (fresh spawn).

0. **Live plain restart.** A plain request (`s = 0`, no `Range`) against a
   **live** no-spool command (`total` still unknown) with at least one active
   producer is answered as a **startable whole resource** — consumers of a
   live stream never see a mid-file position as a body start. An
   **open-ended `Range`** (or one whose end is not produced) on the same live
   stream is answered identically: no closed range is replyable, so the
   request is treated as a plain `s = 0` restart below (§HTTP response
   selection rule 3). The DMR
   re-pulls plainly exactly when its playback buffer hit zero, and on the
   resumed connection it re-inits its media parse from the **response start**
   (instrumented CDD trace.9 on the 2024-shaped device: the DMR resumed the
   same session — no STOP, no re-LOAD, no GET_STATUS, no `Range` — yet still
   sent `type=ERROR` twice ~40 ms after the resumed bytes, then
   `MEDIA_STATUS {playerState:"IDLE", idleReason:"ERROR"}` and closed the
   connection; that held whether the served continuation was the cold
   frontier (trace.8) or a byte-exact delivered-end run-in (trace.9's
   hole-close served only the 32,512-byte produced-but-never-flushed span,
   fragment-contiguous, socket rate: the first bytes still landed mid-`mdat`,
   the shape the re-init cannot decode). Earlier 2-4 s production lulls in
   the same run only toggled BUFFERING/PLAYING, ruling out the stall itself.
The resolver therefore attaches the re-pull at **byte 0** when **any**
    producer's window still retains it (`buffer_offset == 0`), preferring the
    farthest producer that does — the replay then serves
    the retained span at socket rate — the device's own session-open GET, a
    response starting at byte 0, is accepted by this device (trace.0) — then
    slips onto the live edge once caught up. A whole-resource replay can never
    be displaced by a duplicate spawn: whenever a window retains byte 0 it
    serves (with or without farther producers alive), and only when **no**
    window retains it does the resolver **spawn a fresh producer** (same
    argv, position 0): a whole-resource replay is only possible from a window
    whose offset is 0, so a mid-stream join is never served. An empty window
    (`received == 0`, still at the live frontier — the cold start or a pull
    landed mid-stall, trace.5) also serves the byte-0 request in place: the
    request attaches to the existing producer and waits for its frontier. The
    live restart
does not displace a **closed-`Range`** recovery: a replyable `Range` resume
    (rule 1) keeps serving in place.
    **The re-pull is the device's only active playback.** A whole-resource
    restart therefore **retires the device's abandoned earlier pulls** on that
    producer: every other open connection still attached to the producer's
    window is the same device's stale pull — finalized, its consumer claim
    released, its socket closed — the moment the byte-0 replay (or the fresh
    whole-resource spawn) takes over. The replay consumer then becomes the
    producer's single pacing governor: the window advances at the replay's
    position, never at a stale slow/paused/ghost consumer's (§Multiple
    consumers), so the replay reaches the retained end and slips onto the live
    edge produced at its own pace. On the spawn branch the retirement does the
    same for the abandoned producer: with no live consumer left it is gated and
    hits the idle guard, and its duplicate command is released instead of
    running against a discarded window forever (a "producer that kept running"
    while a re-pull played a detached copy, then froze where the copy met the
    live edge — the consumer-faster-than-producer replay that must not race).
    Consumer-index hygiene is part of the same rule: a consumer index is
    **owned by exactly one connection** — re-attaching a conn (a keep-alive
    second request, a mid-body re-route, or the restart itself) first releases
    its previous claim (detach + index relocation) so no ghost entry pins
    `buffer_lowest` or keeps a producer alive unwatched.

    > *Reference:* the drained byte-0 replay holding a DMR storm-free was
    > already observed (trace.11 conn2: two 103.6 MB / 270 s pulls). The
    > freeze-at-X + runaway-producer report is that replay raced against a
    > stale earlier pull (a ghost/paused consumer on the same producer, or a
    > competing spawn): the stale pull either throttled the window below the
    > replay's live edge (the re-frozen X) or kept its command streaming into a
    > window no connection reads (the "non-stopping" producer).

1. **Retained.** A producer whose window still retains `s` → attach the
   consumer at `s` and feed immediately. "Still retains `s`" means the
   window **physically holds the byte**: `buffer_offset ≤ s ≤ received`
   (the window head `buffer_offset` is the serveability floor, not the
   least-behind consumer position — memory below that consumer is
   `consumed` but still present and remains serveable, §rule 3, §Retention
   limitation). A **closed-`Range`** resume (`total` known, or a `bytes=N-E`
   end already produced) that falls behind the active pull's position
   therefore attaches in place at its requested start (trace.13); it is never
   allowed to slide into a duplicate producer spawn. An **open-ended** live
   `Range` (the trace.5 conn3 / trace.12 conn3 resume shape) is no longer an
   attach-at-`s` request: it cannot carry a legal `Content-Range`, so it is
   answered from byte 0 as a plain whole-resource restart (rule 0).
   Retained also includes a **caught-up** consumer at the producer's
   frontier (`s` == the producer's produced `position` — nothing is
   buffered beyond it): the consumer attaches in place and reads the empty
   window as a **pause**, waiting for the producer to produce more — it is
   never mistaken for the stream's end while the producer is alive
   (command+spool behaves the same: a consumer at the file's current end
   waits for the producer to append, §File mode and command+spool).
2. **Behind.** Else the **nearest producer whose position is behind `s`**
   (position < `s`) → attach and **wait for position**: the consumer is not
   fed until the producer has produced *and still retains* `s`. If that
   producer was frozen (no consumer), attaching it unfreezes it; if it already
   had a consumer it keeps being drained. Either way the new consumer merely
   waits until the stream reaches `s`, then the feed starts.
3. **Spawn.** Else **first verify no producer could already feed the
   requested buffer**: because a window is never freed on consumption
   (not when one consumer consumed it, not even when **all** consumers
   consumed it — §Multiple consumers on one producer below, §Retention
   limitation), a producer keeps its old buffer until the moment room is
   required, so a **new consumer can attach at a later position where the
   buffer's initial position could match the request** — resolver attaches
   it in place and the consumer **pauses** until the producer fills
   (§Consumer behavior "caught up"). "Could feed" is the same physical
   test: a producer whose window holds `s` (head ≤ `s` ≤ received) can
   feed it even when every attached consumer has already read past `s` —
   the consumed prefix is retained memory, not a spawn trigger. Only when
   **no live producer could feed the requested buffer** does the resolver
   **spawn a fresh producer** (same argv, position 0) and attach with the
   same wait-for-position rule.
A plain `s=0` request is **not** such a case: on a live stream it is
    answered by rule 0's whole-resource restart — byte 0 when a window still
    retains it, else a **fresh producer spawn** (a mid-stream continuation is
    never served). A spawn for `s = 0` therefore happens for the very first
    request (no producer — its frontier is byte 0), for a live restart whose
    byte 0 was compacted away, and for `s > 0` only when no live producer
    could feed the start; once `total` is known (first producer EOF) rule 1
    serves the whole retained body.
   For `s > 0` the command is re-run from byte 0 until it reaches `s`
   (§Retention limitation below). And the fresh producer occupies the
   **first free slot**; the resolver returns **that exact slot** (never
   `count-1`), so the consumer attaches to the window that actually got the
   spawn.

A consumer may close at any time: it is detached from its producer, the
producer recomputes its lowest consumer offset, and the window can reclaim
everything the detached consumer released.

#### Multiple consumers on one producer

- Several consumers may attach to one producer, each with its own `read_off`.
  A window is **never freed because a consumer consumed it** — not when a
  single consumer consumed it, and to be safe **neither when all consumers**
  consumed it. Room is freed **only when the producer needs room** to store
  its next package and has no growth headroom left (it is at its `--cache`
  target; §Compaction): the producer then verifies **every** attached
  consumer has advanced enough to open the room it needs, and advances the
  window start **no further than the least-behind attached consumer** (never
  past it) and **no more than the room the next package needs** — a smaller
  move, when less room suffices, preserves more retained history for
  later-start consumers and whole-resource replays. If there is **no room**
  (no attached consumer has advanced past the window start, so nothing can
  be reclaimed), the producer **pauses** until a consumer advances and opens
  room — it waits for the slowest-pacing consumer to open it, then fills and
  moves on. The producer's read therefore moves at the pace room allows at
  the moment room is required, i.e. that of its **slowest** consumer — but it
  blocks the whole producer only for as long as
  room is missing. This risk is accepted by design (the stream never outruns
  any live consumer, so no live consumer ever stalls a second time). For a
  waiting consumer, every byte from `s` upward is needed, so the window
  cannot reclaim below it.
- **A consumer index is owned by exactly one connection.** Attaching a
  consumer to a window that the same connection already reads is a
  re-attach: the connection's previous claim is released **first**
  (detach + index relocation to the displaced last owner), then the new
  consumer is added. No other code path may leave a consumer entry with no
  owning connection: a ghost entry never advances its `read_off`; behind the
  live consumers it pins `buffer_lowest` so the producer can never open the
  room it needs (the replay freezes at the retained end); ahead of them it
  keeps the window floor and the producer unwatched-thrashing. Re-attach
  happens on a keep-alive second request on the same socket, a mid-body
  re-route, and the byte-0 whole-resource restart (which additionally
  **retires** the other open pulls on that producer, rule 0).
- A consumer that dies frees only its own claim; the producer continues for
  its remaining consumers, and if none remain it freezes and eventually hits
  the idle guard (§Producer behavior).

#### Retention limitation

A window is bounded by the `--cache` policy. A consumer waiting at a deep `s`
can only be served if the window still retains `s` when the producer reaches
it. If the producer outruns retention (the window slid past `s` before `s`
was read), that producer can no longer serve `s`; resolution falls back to
nearest-behind/spawn with the same bound. Adequate caching (`--cache` sized
to the seek distance) is the operator's tool; litecast guarantees only that it
serves whatever its windows retain. If **no** producer can ever retain `s`
(no behind producer, and a fresh spawn would also outrun it before arrival),
the request is answered as the live `200 + Connection: close` tail from the
producer's current retained head — the client decides from there. That tail
is the **last resort for a start no fresh producer could reach**; a live
`s=0` request is answered by rule 0's whole-resource restart — byte 0 if a
window still retains it, else a fresh producer spawn — and a retained head is
only served to a consumer that explicitly `Range`s into it with a **closed**
range (known `total`, or a request-bounded end already produced — an
open-ended live `Range` is answered from byte 0, rule 0, §HTTP response
selection rule 3) and, once
`total` is known, to any plain request, rule 1/5).

#### File mode and command+spool (outside the multi-producer model)

- **File mode.** No producers. Sources are regular files (or stat-trusted);
  every consumer answers its start `s` directly from the file (`pread` at its
  own position); the shared window is just optional caching. Any retained `s`
  is servable (§HTTP response selection).
- **Command + `--cache-to-fs`.** Exactly **one** producer, and the /
  multi-consumer machinery does not apply:
  - The producer **writes its file regardless of whether any consumer is
    attached** — it is never idle-terminated and never gated on consumer
    presence. It drains the command pipe into the spool file until the
    command completes (EOF → `total` known → `Content-Length`). A full memory
    window never back-pressures it: the drain target is the file, and the
    window is a non-gating cache.
  - Consumers **read directly from the file** (`pread` at their own `s`),
    never from the memory window. A **closed** `Range` (known `total`, or a
    `bytes=N-E` end already produced) serves its finite `206` span from the
    file (§HTTP response selection rule 2); an open-ended or not-yet-produced
    live `Range` is answered `200` from **byte 0** (rule 3). A consumer
    **caught up** at the file's current end waits (empty `pread` = wait, never
    the stream's end) until the producer appends, or until the command
    completes and `Content-Length` is announced — never answered with a
    premature `206`/`Content-Length`.

## Buffer Strategy Audit

Route all reads through a wrapper layer for testability (no `fopen`/`fread`
in production code; raw `open`/`read`/`write` plus our buffer only).

| Strategy | Use case | Buffer | Notes |
|---|---|---|---|
| **Streaming window** | File or pipe casts | `buffer` (§Buffer model) | Dynamic when size unknown initially; fixed-capacity window when file size is trustworthy and plain `--cache` given. Reads land directly at the window tail; no intermediate copies. |
| **DNS packet** | One mDNS/UDP datagram | 4096B stack (single read) | mDNS max 9000B in practice; 4096 covers unicast replies; validate `n` before parse; retry/timeout per §Retry. |
| **Cast frame** | One `CastMessage` | dynamic, from 4B length prefix | Read the 4-byte BE length, validate (1..`MAX_CAST_FRAME`), allocate exactly that, read until full (§Cast framing). |
| **HTTP request line + headers** | Strictly bounded | 1024B reuse buffer | Bounded read; header block ends at `\r\n\r\n`. Longer → 400. |

> **Never guess a fixed stack buffer for files whose size is not guaranteed
> by an API contract.** mDNS datagram and TLS record sizes are bounded by
> protocol maxima documented here; the media source size is *never*
> pre-guessed — it flows through the `--cache` window or `stat` result.

## Retry Landscape

| # | Operation | Max trials | Interval | Backoff | Notes |
|---|---|---|---|---|---|
| 1 | mDNS discovery window | continuous receive, window 5s | — | — | No retry of the window itself; the socket listens until a device is found or the window lapses. Re-run only if the control-socket reconnect needs re-resolution. |
| 2 | TCP connect to device | 3 | 1s, 2s | exponential | On failure try the next discovered device; if exhausted → error. |
| 3 | Device host (re)resolution | 3 | 1s | fixed | mDNS resolution of the target (`_googlecast._tcp.local` A/AAAA lookup for reconnects). |
| 4 | Control handshake / GET_STATUS | 3 | 1s, 2s | exponential | Timeout per attempt 10s (`TIMEOUT_TIME` analog). Fail → error. |
| 5 | Heartbeat PING | continuous every 10s | — | — | PONG expected within 10s (`PONG_TIME`). Two consecutive missed PONGs mark the connection lost → trigger reconnect (row 2) with re-handshake + re-LOAD; HTTP server keeps serving. |
| 6 | HTTP accept / serve | — | — | — | No retry in litecast; the device re-requests as needed. |

The backoff gaps for the three attempts are 1s, 2s, 2s — the tabulated
interval list (1s, 2s) is capped at its last value once the budget is
nearly spent. Reconnects happen with the HTTP server still running; only
the control session is rebuilt (connect → handshake → re-LOAD).

`epoll_wait` and all reads/writes retry on `EINTR` (loop). Non-blocking
reads/writes returning `EAGAIN` are not errors — they defer to the next
epoll event.

### Session supervision (DMR session restart)

The retry rows above repair the **transport**. Separately, the DMR session
(the Default Media Receiver app instance carrying the media namespace) can
die while the control socket stays perfectly healthy — a delivery-hole/freeze
terminal event under a consumer-faster-than-producer drain (trace.12: the
element errors out with `{"type":"ERROR"}` ×2 then reports `playerState:"IDLE"`
+ `idleReason:"ERROR"`, and the transport keeps PING/PONGing). The run layer
classifies a terminal verdict (a `type:ERROR` frame or an `IDLE` with any
`idleReason`) as **FINISHED** (idleReason `FINISHED` — a natural play-to-end)
or **ABORT** (idleReason other than `FINISHED`, or an ERROR frame), but a
verdict only counts once the session is **established** — a `MEDIA_STATUS`
with `playerState` `BUFFERING`/`PLAYING` seen for the current `LOAD` (the mark
clears when a LOAD is sent). An abort-shaped verdict observed **before**
establishment is the healthy LOAD acknowledgment — the DMR tearing down the
playback the new `LOAD` replaces, `idleReason=INTERRUPTED` — and is ignored
for classification, never scheduling a restart (trace.20: a device-side
control-socket drop while the media pull was healthy, then a clean reconnect +
re-LOAD whose `IDLE INTERRUPTED` ack was classed ABORT and re-restarted the
session forever, recasting only the first few seconds in an unbounded
1→2→4→8 s loop while the source lived). The run layer applies the
FINISHED/ABORT split only to an established session's verdict, and:

- **Natural end (unchanged):** `FINISHED` once every producer is EOF → the
  finite source is consumed; the run exits rc 0 after the receiver STOP.
- **Abandonment with live sources:** an **established** session whose verdict is
  an `ABORT` **or** a premature `FINISHED` — the DMR dropping a pull it never
  played to the end while the run can still feed a fresh one — is an
  **abandonment**, and the cast session is **auto-restarted** exactly as the
  abort arm below does. The `FINISHED` frame alone no longer ends a run whose
  sources are still producing; only `FINISHED` with every producer at EOF is
  the natural end (§Flow). `FINISHED` before establishment stays the `LOAD`
  acknowledgment class and is never an abandonment. trace.22: a live no-spool
  command played for ≈24 s, the DMR re-pulled itself twice (its resume `Range`s
  were answered rule-0 `200`-from-byte-0, resetting its own clock each time)
  and then reported `IDLE FINISHED` with the command still encoding — the run
  idled into the quiet guard and never retried, so the cast "stopped without
  trying again". A verdict that books a restart is not **final**: the producers
  return to the ordinary consumer rules while the device is away
  (§Producer behavior), so nothing drains an unwatched window.
- **Abort with live sources:** the cast session is **auto-restarted** — the
  retired session is terminated on the device first (the same receiver `STOP`
  the exit sends, on the still-live control socket — §A latched session is
  terminated when its socket is given up), the control socket is closed like a
  transport loss, the session restart backoff
  runs (1000, 2000, 4000, 8000 ms, then held at 8000 ms — **independent of,
  and never consuming, the transport retry budget cylinder**, row 2/4), and
  the identical connect → CONNECT → GET_STATUS → LAUNCH → LOAD cycle runs,
  after which the DMR re-pulls `/stream` and playback resumes. The restart
  counter clears once an attached session survives past `RESTART_RESET_MS`
  (60 s): a long-lived session that dies later re-arms the 1 s minimum, a
  crash-loop escalates 1→2→4→8 s. A live feed that aborts repeatedly
  therefore recasts indefinitely at a bounded rate — resilience, not a crash —
  and is ended only by the user (SIGINT/SIGTERM) or by the stream's own end
  (an ABORT with every source drained is itself the end).
- **Aborted/never-started (guard):** the quiet idle guard (`RUN_FINISH_MAX_MS`)
  still ends an abandoned cast — no consumer attached, no FINISHED, no restart
  pending.

The restart is waved as a single shot per verdict (closing the ctrl resets the
end classification), so a genuine crash-loop cannot double-schedule; the 8 s
backoff ceiling caps the retry rate.

## Dynamic Arrays (Grow / Shrink)

The media buffer and its `consumers[]` list are dynamic arrays (each producer
owns its own, §Producers and consumers). Defaults below apply to the
`consumers[]` list; the media buffer follows the same growth but is governed
by the `--cache` targets (it never grows past the cap, and it shrinks by
compaction, not by realloc).

### Growth algorithm

```
new_cap := cap + max(min(max(cap, 64), 65536), len + need - cap)
new_cap := (new_cap + 63) & ~63
```

Growth step is at least 64 and at most 65536; the result is rounded up to a
64-aligned boundary. A per-array ceiling (the `--cache` cap, for the media
buffer) can cap maximum capacity.

### Shrink trigger

```
if len <= cap / 4 then new_cap := min(cap / 2, floor_or_initial_value)
```

Shrink is opportunistic — if realloc fails, the old capacity is kept. The
floor prevents grow/shrink oscillation. For the media buffer the floor is
one page; for `consumers[]` the floor is the initial inline array.

### Per-array table

| # | Array | Init cap | Max cap | Growth | Shrink | Tracking |
|---|---|---|---|---|---|---|
| 1 | media buffer | `page_size` or `--cache` cap | `--cache` cap or unbounded (PCT=100) | `max(min(cap,64),65536)` + 64-align | compaction `memmove`, never realloc-down | `data/len/read_off` + per-consumer `read_off`, cap+len |
| 2 | `consumers[]` (per producer) | 4 inline | unbounded | default (§Growth) | halve, floor 4 | cap+len, swap-last compaction on close |

Device list (discovery) is a small fixed array sized at discovery time (max
16) — no hash map is needed for a local network's devices; a linear scan is
cheap and deterministic. If a map is ever needed, FNV-1a 32-bit with open
addressing and linear probing is the approved design (see the reference
template).

## Transport

### Cast V2 framing

Every frame on the control channel (and, after TLS handshake, inside TLS
application records) is:

```
[4-byte big-endian length N][CastMessage protobuf of N bytes]
```

Length bounds: `1 ≤ N ≤ MAX_CAST_FRAME = 131072`; out-of-range → drop
connection (QA.md §Cast protocol pitfalls). `CastMessage` is encoded as its
protobuf wire format (protobuf *encoding* only — no protobuf library). The
5 fields of interest:

| Protobuf field | # | Wire type | Value |
|---|---|---|---|
| `protocol_version` | 1 | varint enum | `CASTV2_1_0 = 0`. **Required proto2 field — always emitted** (`0x08 0x00`); see note below |
| `source_id` | 2 | string | e.g. `sender-0` for the control channel; we use `LOCAL-<pid>` convention kept stable per session |
| `destination_id` | 3 | string | `receiver-0` for the platform receiver channel, or the media receiver's `transportId` (from `RECEIVER_STATUS`, = the `sessionId`-derived channel) for `LOAD`/`MEDIA_STATUS` after launch |
| `namespace` | 4 | string | see namespaces below |
| `payload_type` | 5 | varint enum | `STRING = 0`. **Required proto2 field — always emitted** (`0x28 0x00`); the payload is always JSON in this project |
| `payload_utf8` | 6 | string | the JSON payload |

> **Required fields are never elided.** `protocol_version` and `payload_type`
> are `required` in the proto2 `CastMessage` definition, so they must be
> present on the wire even when 0. Verified empirically against a
> `cast_build_revision 1.56.467165` device: a CONNECT frame that omitted them
> got the connection closed immediately; with `0x08 0x00` + `0x28 0x00`
> present, the device answered PONG. "Default elision" does not apply here.

### Namespaces

| Namespace | Direction | Messages |
|---|---|---|
| `urn:x-cast:com.google.cast.tp.connection` | both | `CONNECT`, `CLOSE` |
| `urn:x-cast:com.google.cast.tp.heartbeat` | both | `PING`, `PONG` |
| `urn:x-cast:com.google.cast.receiver` | both | `GET_STATUS`, `RECEIVER_STATUS`, `LAUNCH`, `STOP` |
| `urn:x-cast:com.google.cast.media` | both | `LOAD`, `LOAD_FAILED`, `MEDIA_STATUS`, `GET_STATUS` |

### Encrypted vs plaintext

**TLS is mandatory on modern firmware.** Verified empirically against a live
device (`cast_build_revision 1.56.467165`, "Living Room TV"): port 8009
accepts *only* TLS. Sending a plaintext Cast frame draws a fatal TLS alert
record (`0x15 0x03 0x01 0x00 0x02 0x02 0x46` = alert `protocol_version`) — the
receiver interprets every byte on 8009 as a TLS handshake. A plaintext
fallback is kept only as a defensive one-shot for hypothetical legacy
firmware, and only on the first byte decision:

- A modern device answers the `ClientHello` with a TLS `ServerHello` →
  continue the TLS handshake (§Minimal TLS client), then carry the Cast
  frames inside TLS application records. The socket becomes `transport=tls`.
- A peer that never produces a valid `ServerHello` within the handshake
  timeout (legacy) → drop TLS framing, speak plaintext Cast V2 directly.
- Never reinterpret after interpretation: bytes received during the probe
  (e.g. a TLS alert) already fixed the decision; a byte `0x15` is a TLS alert,
  *not* a legacy plaintext reply (QA.md §TLS).

Certificate handling mirrors the reference implementation: the device's
certificate is accepted without chain verification (`CERT_NONE` semantics —
matching `pychromecast`'s `ssl.SSLContext()` / `get_ssl_context()`). No
dialog with `AuthChallenge`/`AuthResponse` is required for TLS transport;
those protobufs are documented in the reference but are **not** part of the
minimum control flow. (Reviewers: verify against the reference `socket_client.py`
connection routine before finalizing.)

### Minimal TLS client

Implemented in the project (no external crypto *library*). The cryptographic
primitives are **vendored into the tree, pinned at the canonical upstream
releases**: **libtomcrypt v1.18.2** and **libtommath v1.3.0** (both MIT /
public-domain licensed; the tree vendors reference clones of both). Dropbear
(commit `1442f00`) remains the
reference for the **ChaCha20-Poly1305 AEAD** (its own `src/chachapoly.c` —
the same cipher it uses for its SSH transport) and for the **pruned build
set**: which minimal set of libtomcrypt/libtommath files to compile,
mirroring how Dropbear's own Makefile already prunes these libraries. The
TLS *protocol* (handshake, record layer, PRF) is still implemented from
scratch per RFC 5246 / 4492 / 7905; only the primitives are lifted.
libtomcrypt v1.18.2 predates libtommath v1.3.0 (it was released against the
1.2.x series) — a build smoke test during the TLS task confirms the pair
(1.3.0 keeps API/ABI compatibility with 1.x).

Cipher negotiation is verified against the live device (`1.56.467165`):

| TLS 1.2 suite | Device | Verdict |
|---|---|---|
| `ECDHE-RSA-CHACHA20-POLY1305` (0xCCA8) | works | **primary** — matches Dropbear's own builtin AEAD |
| `ECDHE-RSA-AES128-GCM-SHA256` (0xC02F) | works | alternate — needs GCM mode (libtomcrypt `encauth/gcm`) |
| `ECDHE-RSA-AES128-SHA` / `AES128-SHA` (CBC) | works | rejected design: MAC-then-encrypt CBC is strictly harder to do safely |
| `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-SHA256`, `AES128-SHA256`, TLS 1.1 | refused | do not offer |
| TLS 1.3 (CHACHA20, HKDF, X25519) | works | out of scope; wider surface |

`ClientHello` advertises TLS 1.2 + `0xCCA8` first (and `0xC02F` second). If a
peer insists on anything else the handshake aborts — no silent downgrade.

The extension wire format is live-verified: `signature_algorithms` must carry
the inner 2-byte list length (`00 0d 00 04 00 02 04 01`) and
`ec_point_formats` must offer `03 00 01 02`; a divergent layout draws a
fatal `handshake_failure` alert from the device. A full handshake against
the live device was captured byte-for-byte and is replayed in the test
suite (`tests/tls_capture.h`): under the `LITECAST_TEST` deterministic PRNG
the replay reproduces the identical ephemeral ECDHE key, Finished records,
and security latch.

- PRF: `P_hash(SHA-256)` as per RFC 5246 §5.
- Record layer: TLS 1.2, ChaCha20-Poly1305 (RFC 7905). The AEAD nonce is
  the 12-byte implicit `client_write_IV` from the key block XORed with the
  8-byte record sequence number padded on the left with four zero bytes
  (RFC 7905 §2 — the same construction TLS 1.3 uses; there is no per-record
  explicit nonce, `record_iv_length = 0`). The `additional_data` is the
  full 13-byte TLS 1.2 value (RFC 5246 §6.2.3.3):
  `seq_num(8) || type(1) || version(2) || plaintext_length(2)`. Key block:
  `client_write_key = server_write_key = 32B`, `client_write_IV =
  server_write_IV = 12B`; no MAC keys (AEAD).
- Key exchange: ECDHE — generate an ephemeral P-256 key (curve
  `secp256r1`), parse the server's `ServerKeyExchange` curve + `base_point`
  + `signature` (RSA-PKCS1 v1.5 over SHA-256), compute the shared point,
  and use the **32-byte x-coordinate of that point** as the
  `pre_master_secret` (RFC 8422 §5.10 — never the 65-byte uncompressed
  point; leading zero bytes of the x-coordinate are preserved). Drop
  the ephemeral private key after use (`explicit_bzero` style).
- Certificate: parse the server's raw X.509 leaf (DER) only to extract the
  RSA public key; no chain path building, no dates/hostname validation
  (CERT_NONE semantics).
- Handshake messages handled: `ClientHello` (out), `ServerHello`,
  `Certificate`, `ServerKeyExchange`, `ServerHelloDone` (in),
  `ClientKeyExchange`, `ChangeCipherSpec` (out), `Finished` (out → in
  verify). Unknown/abbreviated handshake → fall back to plaintext per the
  detection above.
- Record size: fragments reassembled to at most `MAX_CAST_FRAME`; padding
  and length fields strictly validated (QA.md §TLS pitfalls).

## HTTP server

Binds `0.0.0.0:0` on the local interface that also carries the mDNS
membership (the address the device can reach back), requests come only from
the device.

| Behavior | Rule |
|---|---|
| Endpoint | `GET /stream` only; any other path → 404. |
| Response | Selected per request from the known stream size and the retained data (§HTTP response selection). The LOAD `streamType` stays `LIVE` and loading never uses MediaSource reconciliation (§Business Rule 11). |
| `Content-Length` | Sent **only when the total size is known and the whole body is servable from the retained start**: file mode (sizes known up front) and a command that reached EOF (total = bytes received) — with or without `--cache-to-fs`. For a **no-spool** command the total is stored when the **first producer terminates**; any further request can then answer with `Content-Length` (file-mode rule, subject to the retained-start condition below). A response that must start at a dropped (unretained) head gets no `Content-Length`. While no total is known a running command never sends it. |
| `Accept-Ranges` | `bytes`, sent only on a `Content-Length` 200 response. Passive: a `Range` is honored only when the client asks. Never on live/unknown or tail feeds. |
| `Range` | A `206` + `Content-Range` is emitted **only for a closed range**: `total` known (file, or a command that reached EOF → satisfiable `206` / `416` + `Content-Range: bytes */total`), the **request itself pins the end** and the produced bytes already cover it (`bytes=N-E` on a live pipe, `E` produced and retained → `206` + `Content-Range: bytes N-(E-1)/*` + `Content-Length: E−N`, finite, then close — the `*` complete-length is legal because the request pinned the end), or the server itself closes an **open-ended** `bytes=N-` on an unknown total with an **arbitrary end** (default): at the produced frontier when the start is already produced (`Content-Range: bytes N-(received-1)/*` + `Content-Length: received−N`), or at `N+1` when a running producer has not reached `N` yet (`Content-Range: bytes N-N/*` + `Content-Length: 1`, head stowed until that byte exists, then exactly one byte and close). Both are finite and the `*` complete-length is legal because the range is closed by the server (RFC 9110 §14.4). `--no-arbitrary-range` forbids the server closing it: an open-ended `bytes=N-` on an unknown total is then answered `200` from **byte 0** (rule 3). Any other `Range` on a still-producing stream — a `bytes=N-` before anything is produced or below the retained prefix, or a bounded one whose end is not yet produced — cannot be closed, so it is answered `200` and treated **from byte 0**: the whole resource is served with the offset ignored (`Connection: close` while live; a no-spool live request is rule 0's whole-resource restart), never a 200 whose body starts at the requested position. A finite response never sends more than the `Content-Length` it promised — a continuation is the client's next request. |
| Multiple connections | Each connection is an independent consumer with its own start `s` and `read_off`. In command-no-spool mode consumers attach to a producer (§Producers and consumers); file mode and command+spool answer `s` directly from the file — in command+spool mode the memory window is never a serving source, the spool file is. |
| MIME `contentType` | `video/mp2t` for command mode (typical transcoded output); file mode inferred from the file extension (`.mp4` → `video/mp4`, `.mkv` → `video/x-matroska`, …) with a fallback to `application/octet-stream`. No magic sniffing and no container/codec inspection (§Business Rule 9) — the LOAD `contentType` is the plain MIME, never `video/mp4; codecs=...`. |
| Idle timeout | **None.** A connection is never closed for idleness: a paused-but-attached device keeps its conn open and its consumer attached, so its producer lives on and playback resumes on the next `EPOLLOUT` wake (§Producer behavior "Idle termination"). A slot closes only on device EOF/RST, a connection error, or run teardown (§Flow / Lifecycle). |
| Frame rate | Never blocks; sends what the buffer offers, byte-granular, back-pressure via `EPOLLOUT`. |
| Write path | Per-connection tx window over a bounded reusable `stage` slice (`8192B`): bodies drain the memory-window consumer at the connection's offset (file/no-spool), a command+spool body reads its span via `pread` on the spool file, and finite ranges stage through the same slice. Partial writes re-arm `EPOLLOUT`; the window never exceeds one slice. A flush that returns `EAGAIN` halts that connection's drain until the next `EPOLLOUT` — never retried in a busy loop (Design Invariant). |

### HTTP response selection

State at request time: `received` (bytes produced), `complete` (EOF seen),
`total` (0 = unknown; file total from startup, else `received` once a command
completes — for a no-spool command the total is **stored at the first
producer's termination**, §Producers and consumers "First-termination
`total`"), `avail` (lowest retained stream offset for the **response
matrix**: **0 in file and command+spool modes** — the whole stream is in the
file — else the minimum attached-consumer offset of the no-spool producer;
the **resolution** floor is tighter than `avail` — a window physically serves
any `s ≥ buffer_offset` (its head), including bytes below the least-behind
consumer, §Consumer attach rule 1 — while `avail` only drives the
completed-stream response boundaries (`Range` below it → `416`, or the
no-spool live fallback from the retained head, rule 4)), `spool` (command
`--cache-to-fs` armed). One consumer is per connection; `s` is the requested
start — **`0` for a plain request (`Range` absent) and for a live-stream
`Range` that cannot be closed: a `bytes=N-` whose start the produced bytes do not
cover yet (or that was dropped), or a bounded one whose end they do not cover
yet** — such a request has no legal `Content-Range`, so it is
answered `200` from **byte 0** (on a live no-spool command by rule 0 of
§Consumer attach — the byte-0 whole-resource replay while a window retains
it, else a fresh spawn; never a mid-stream join — on a file/completed command
the stream start)** — else, for a **closed** range (rule 2), the `Range`
start (an open-ended `bytes=N-` that the produced bytes do cover is closed by the
server at the frontier, so `N` is the start). **Every
request resolves its effective `s` first** (§Producers and consumers): a no-spool command
attaches the consumer to a producer (live plain join → retained window →
nearest producer behind → fresh spawn); file mode and command+spool answer
`s` directly from the file, and a spooled start ahead of the running producer
waits until the producer reaches it. Then:

1. **Command mode, no spool** → the resolved producer feeds the consumer. A
   **closed** `Range` (rule 2) is served as a finite response — including an
   open-ended `bytes=N-` whose start is retained and produced, which the server
   closes at the frontier (trace.22: the DMR re-pulls itself mid-stream with
   `bytes=N-` after a buffering stall; served in place at `N` it resumes *where
   it left off* instead of rewinding to byte 0, which reset its clock on every
   re-pull until it ended reporting `FINISHED` on a still-live source). A
   `Range` whose start is not yet produced, or was dropped, is answered exactly
   like a plain request — `200 + Connection: close` from **byte 0** (rule 0's
   whole-resource restart; §HTTP server `Range` — the range cannot be closed).
   A consumer whose start the producer has not yet
   produced (a plain byte-0 load at a cold/spawned frontier) is sent **nothing
   at all — not even the response head** — until the window produces and
   retains it; a `200` head with an empty body is never flushed to a
   still-waiting start (the trace.13 82 s head-with-no-body class). The same
   stow covers a promised byte that does not exist yet: a `206` whose
   `Content-Range` promises one byte waits for it before the head goes out,
   never a `Content-Length`-bearing head with an empty body.
2. **`Range` present, satisfiable**:
   - **`total` known** (`avail ≤ s < received`): `206` + `Content-Range:
     bytes s-E/<total>` (E = min(requested end, received)) +
     `Content-Length: E−s`, fed finitely — via `pread` on the spool file in
     command+spool mode, from the window in file mode — then the connection
     closes.
   - **`total` unknown, span pinned by the request and already produced**
     (`bytes=N-E`, `end ≤ received`, start retained): `206` + `Content-Range:
     bytes N-(E-1)/*` + `Content-Length: E−N`, fed finitely from the spool
     file / the retained window, then the connection closes — the `*`
     complete-length is legal because the request itself pinned the end.
   - **`total` unknown, span pinned by the server** (open-ended `bytes=N-`,
     the **arbitrary end**, on unless `--no-arbitrary-range`): the same `206`
     with the end chosen by the server, fed finitely from the spool file /
     the retained window, then the connection closes; the device re-pulls the
     next span itself. Two arms, both with complete-length `*` (legal because
     the server closed the range, RFC 9110 §14.4):
     - **start already produced and at or above the retained prefix**: the end
       is the current frontier — `Content-Range: bytes N-(received-1)/*` +
       `Content-Length: received−N`, served at once.
     - **start not yet produced, but a producer is running** (`received > 0`,
       so this is a mid-stream resume, never a cold start): the end is `N+1` —
       `Content-Range: bytes N-N/*` + `Content-Length: 1`; the head stays
       **stowed** (rule 1) until byte `N` exists, then exactly that one byte
       is written and the connection closes. `received == 0` or a start below
       the retained prefix is **not** a server close: rule 3.
3. **`Range` present, unclosable** (unknown `total`): a bounded end not yet
   produced; or an open-ended `bytes=N-` that the server may not close —
   `--no-arbitrary-range` given, **nothing produced yet** (`received == 0`,
   the cold start: there is no frontier to promise and the device's first
   pull is the whole-resource shape that worked), or `N` below the retained
   prefix (`avail`) — **not replyable**: answered `200` from **byte 0**
   (a whole resource, rule 0 / rule 5; `Connection: close` while live; never a
   zero-length silent close, never a `206` head that cannot be fulfilled).
   The requested offset is honored *only* inside the closed spans of rule 2.
4. **`Range` present and otherwise unsatisfiable** (`s < avail` — the offset
   was already compacted away): `416` + `Content-Length: 0` (+ `Content-Range:
   bytes */total` when known, `bytes */*` otherwise). Reachable for a known
   `total` stream and for a bounded request whose start retention no longer
   spans; an open-ended live request never 416s — it is the `200`-from-byte-0
   of rule 3/5.
5. **No `Range`**:
   - total known and whole body retained (`avail == 0`): `200` +
     `Content-Length: total` + `Accept-Ranges: bytes`, consumer at 0,
     finishes exactly at `total` (a file is answered this way from the first
     byte even while it is still being read);
   - total known but head dropped (`avail > 0`): `200` +
     `Transfer-Encoding: chunked`, consumer from `avail`, finishes at
     `received` (the retained tail — the client decides what to do next);
   - total unknown (live command): `200` + `Connection: close`, consumer
     from `s` (`0` for a plain request) via rule 0's whole-resource restart
     (byte 0 while retained, else a fresh spawn, never a mid-stream
     continuation) — an open-ended or not-yet-produced `Range` that rule 2 does
     not close joins this branch with `s = 0` (rule 3), live until EOF.

### Arbitrary `Content-Range` end

An open-ended `Range: bytes=N-` cannot be answered `206` as asked — RFC 9110
§14.4 has no syntax for an open `Content-Range` — yet a mid-stream re-pull is
exactly that request (trace.22: the DMR re-pulled `bytes=8486912-` and
`bytes=12156928-`; the rule-0 `200`-from-0 answer re-inited its media parse,
reset its clock, and manufactured the abandonment this section helps avoid).
The server therefore **chooses the end itself**, on by default:

| State at request time | Answer |
|---|---|
| `avail ≤ N < received` | `206`, end = `received` — the whole retained tail in one response |
| `N ≥ received`, `received > 0` | `206`, end = `N+1` — one byte, head stowed until it exists |
| `received == 0` (cold start) | `200` from byte 0 — nothing to promise a frontier from |
| `N < avail` | `200` from byte 0 — the bytes are gone; rule 0 owns that shape |
| any of the above with `--no-arbitrary-range` | `200` from byte 0 (rule 3) |

The promise is exact: a finite response writes exactly its `Content-Length`
and closes — the continuation is the **client's** next request. The frontier arm
normally needs none (one response carries everything produced so far); the
1-byte arm is the wait-for-position shape in miniature, and a device slower to
re-request than the producer is producing simply gets a longer span next time.

Costs and bounds — why the flag exists:

- A device that reads a short `206` as end-of-stream would stop early;
  `--no-arbitrary-range` restores the whole-resource answer for it.
- The device's pull loop can degenerate to one byte per request when the
  producer is slower than the request rate. Memory stays bounded by the
  `--cache` window; throughput does not.
- A producer reaching EOF before the promised byte exists closes the response
  short of `Content-Length` (the standard truncation signal); the device's next
  request then sees the now-known total and gets rule 2's known-total answer
  (or `416`).

Non-goals: the server never invents an end for a **bounded** request (`bytes=N-E`
is the client's own promise to close), and never for a start it cannot retain.

## Heartbeats and liveness

- PING sent every 10s on the heartbeat namespace; PONG replied immediately
  on receipt.
- If no PONG is seen for 20s the connection is considered lost (§Retry
  Landscape row 5).

## Glossary

| Term | Meaning |
|---|---|
| **Cast V2** | The Google Cast protocol: length-prefixed protobuf messages over one control socket. |
| `receiver-0` | Platform receiver id: the destination for `CONNECT`, heartbeats, and `GET_STATUS`/`RECEIVER_STATUS`/`LAUNCH`. |
| `source_id` | Identifies this sender to the device; we use a per-session `sender-0`/`sender-1` style id. |
| `requestId` | Integer correlating an outgoing control message to its response. Starts at 1 and increments per message. |
| `sessionId` | Opaque string returned in `RECEIVER_STATUS` (from `LAUNCH`) identifying the active Default Media Receiver session; carried in `LOAD`. |
| `transportId` | Opaque string in `RECEIVER_STATUS` naming the media receiver's per-session virtual channel. A second `CONNECT` targets it, and `LOAD`/`MEDIA_STATUS` are routed to it rather than to `receiver-0`. |
| `contentId` | The URL the device will pull: `http://<local-ip>:<port>/stream`. |
| **dangling fd** | A file opened and immediately unlinked; only the descriptor keeps it alive. Used by `--cache-to-fs`. |
| **producer** | A command process (no-spool mode only) whose output fills its own retention window; owns `position`, its window, and its attached consumers (§Producers and consumers). Freezes (pipe backpressure) when the window is full or no consumer is attached; an attached consumer — even paused — never idle-terminates it; reaped after a consumer-less idle guard (`PRODUCER_IDLE_MS`). Not part of file or command+spool mode — those serve from the file. |
| **consumer** | An HTTP request served at start `s`: attached to a producer in no-spool command mode, or reading the file directly in file/command+spool mode. Advances its own `read_off` and pins the window up to `s` (wait-for-position). |
| **wait-for-position** | A consumer attached to a producer (no-spool) or piping the spool file that has not yet reached its start `s`: the feed begins only once the stream retains `s`. |
| **retained prefix** | The lowest stream offset still servable: `avail = 0` in file and command+spool modes (the whole stream is in the file), else the minimum `read_off` of the producer's attached consumers. Bytes below it have been compacted away. |
| **window** | The buffered-but-not-yet-consumed slice of the stream between `read_off_lowest` and `len`. |

## Performance

- `epoll` (level-triggered) over `poll`: one loop, no wakeup storms.
- Byte-granular zero-copy serves: the HTTP response writes come straight
  from the buffer via `writev`-style batches — avoid a copy into a response
  staging area whenever a single contiguous run suffices.
- Blooming hash maps avoided; the device list (≤ 16) is a linear array.
- Grow/shrink amortized per §Dynamic Arrays; compaction is a bounded
  `memmove`.
- Inline small hot functions; keep branching minimal on the byte-turn
  paths. Profile before micro-optimizing (AGENTS.md §Your role).
- mDNS parse is single-pass with bounds-checked cursors.
- The parser accepts `CACHE_FLUSH`-set records (class `0x8001`) that live
  devices use for fresh announcements; the class is the low 15 bits. A
  record's port is trusted only when it is `8009` — the cast endpoint always
  listens there, and a vendored device may advertise an HTML5 app on another
  port, which must not win (DOMAIN.md §Entities `device`).