# QA.md

Quality gates (cppcheck, gcov, lizard thresholds) are defined in
CONTRIBUTING.md §Quality Gate; the design spec lives in DOMAIN.md. This
document is the bug-prevention contract for every change.

litecast is **single-threaded** (DOMAIN.md §Design Invariants), so the
concurrency hazards that normally guard multi-threaded allocations apply
only to what a single signal-safety path still touches
(`signalfd`/`volatile sig_atomic_t`), not to shared mutable state.

## Bug Prevention

Every bug found must have a regression test — a unit test or integration
test that reproduces the bug, fails before the fix, and passes after.
Writing tests is harder, but it is mandatory to prevent the same bug from
recurring.

When a bug is genuinely impossible to test (e.g. hardware-dependent race
condition, external service behavior), add a prevention entry to
§Domain-Specific Pitfalls with bug description, root cause, and prevention
plan as a last resort.

Also consult the Memory Safety Checklist and Domain-Specific Pitfalls below
as part of the done criteria for every new task — review applicable items
before committing.

## Memory Safety Checklist

When modifying any dynamic memory allocation (malloc/calloc/realloc/free,
slab pools, or any code that manipulates allocated memory), audit for ALL of
the following hazards:

| Hazard | What to look for |
|--------|-----------------|
| **Use-after-free** | Pointer read/written after free; double-free; missing NULL after free |
| **Out-of-bounds** | Array index from untrusted input (TXT values, HTTP ranges, length prefixes); fd-indexed arrays with unbounded fd values |
| **Dangling pointer** | realloc/malloc result assigned to a struct field without failure check freeing old data first; pointer to a realloc'd array element after growth |
| **Memory corruption** | memcpy without bounds check; missing NULL check after malloc before write |
| **Write-after-read** | Compaction `memmove` after a consumer offset was invalidated |
| **Realloc ordering** | Multiple realloc calls in one success-check — if the earlier succeeds and the later fails, the earlier block is already freed |
| **Integer overflow** | `size * pct / 100`, `cap + step`, `len + need` on untrusted sizes — prefer clamped arithmetic |
| **Stale buffer data** | Static/reused scratch buffers not cleared between calls (mDNS TXT parse, HTTP header staging) |
| **Init-ordering dependency** | Guard conditions on zero-initialized buffers evaluating `0 > 0` → false, skipping required init (grow, allocation). Variants: (a) validate a precondition that isn't set yet and silently return; (b) guard uses only zero fields; (c) sentinel `0` is also a valid value — use negative sentinels (`-1`, `-2`) |

## Domain-Specific Pitfalls

This section consolidates a pre-merge safety checklist of generic C
pitfalls (consult before every commit), generic bug patterns with code
examples, and project-specific entries.

### Pre-Merge Safety Checklist

- **Integer overflow**: check all arithmetic on untrusted input for overflow
  (buffer sizes, `--cache` expansion, percentage computation, Range
  offsets).
- **Buffer bounds**: ensure every `memcpy`/`snprintf`/`strncpy` uses the
  destination buffer size; no `strcpy`, `sprintf`, `gets`.
- **Endianness**: network byte-order conversions with `htonl`/`htons`/
  `ntohl`/`ntohs` for the 4-byte Cast length prefix and DNS fields; avoid
  double-conversion (`s_addr` from `recvfrom` is already NBO).
- **File descriptor leaks**: pair every `open`/`socket`/`accept`/`mkstemp`/
  `pipe` with a `close` on all error paths — including the spool fd at
  teardown.
- **Signal safety**: `SIGINT`/`SIGTERM`/`SIGCHLD` are consumed via
  `signalfd` in the epoll set; keep a `volatile sig_atomic_t` stop flag and
  the `_exit(128+sig)` nuclear option as the documented fallback.
- **EINTR**: wrap all blocking syscalls (`epoll_wait`, `accept`, `connect`,
  `poll` in tests) in a retry loop.
- **Non-blocking discipline**: sockets are non-blocking; `EAGAIN` defers to
  the next epoll event, never spins; permanent errors (`ENOTCONN`,
  `ECONNRESET`, `EPIPE`) terminate the affected connection.
- **Child reaping**: `--command` children are reaped via the `SIGCHLD`
  entry in the event loop; no `waitpid` is called from signal handlers.
- **Hash table probe budget**: not used (≤ 16 devices, linear array), but a
  bounded probe budget is mandatory if a map is ever introduced.
- **Dynamic array stale pointers**: store an index instead of a pointer
  across a potential realloc of `buffer.data`.
- **Grow-forgot-cap**: set `cap = new_cap` immediately after grow, before
  any mask/budget computation.
- **Configuration struct defaults**: after `calloc`/`memset(0)`, all fields
  are zero — use negative sentinels (`-1`) for "unset" where `0` is valid
  (e.g. `request_id = 0` means no pending request).

### Project-specific entries

#### Cast protocol framing

The control channel is a byte stream that begins with a 4-byte big-endian
length prefix. A malicious or broken device can claim any length.

Common mistakes:
- Allocating `N` bytes from the prefix without validating `N`.
- Believing a full frame was received when only part of it has arrived.
- Treating a frame > `MAX_CAST_FRAME` as a fetch problem instead of a
  protocol violation.

When modifying `src/cast/framing.c`, check:
- Is `1 ≤ N ≤ MAX_CAST_FRAME (131072)` validated before allocation?
- Is the frame accumulated across reads until exactly `N` bytes arrive
  (streaming parser), then dispatched?
- Are protobuf varints/tags validated for overlong encodings and bounds?

Correct pattern:
```
on frame_bytes_available():
    if prefix not complete → wait 4 bytes
    n := be32(data[0..4)); reject if n < 1 or n > MAX_CAST_FRAME
    if frame not complete → wait until len == n
    parse protobuf with bounded cursor; on any overrun → drop connection
```

#### mDNS packet parsing

Discovery parses untrusted UDP datagrams from the local link. DNS packet
structure (header, question, answer records, name compression) is easy to
parse out of bounds.

Common mistakes:
- Following a name-compression pointer (`0xC0`-prefix) loop or without a
  bound.
- Reading TXT record length fields past the datagram.
- Assuming answer records are aligned or that the query name equals "ours".

When modifying `src/net/mdns.c`, check:
- Every parse step advances a cursor bounded by the datagram length;
  pointers into compression targets re-validate bounds at each hop.
- TXT key/value strings are length-delimited and null-terminated into a
  caller buffer with room.
- The parser tolerates answers for `_googlecast._tcp.local` interleaved
  with unrelated records (skip unmarshal, not fatal).

#### TLS record handling

Self-implemented TLS 1.2 is unforgiving: record lengths, padding, and
handshake boundaries are untrusted input.

Common mistakes:
- Reassembling a handshake message larger than the allowed max without
  check.
- Confusing the 4-byte Cast length prefix with TLS record headers.
- Letting the plaintext-detection fallback accept garbage after a partial
  TLS handshake.
- Reading a TLS alert (`0x15`...) as a legacy plaintext reply. Modern
  devices are TLS-only: a plaintext frame draws a fatal `protocol_version`
  alert. `0x15` first byte ⇒ TLS, never fall back.
- Truncating the AEAD `additional_data` to 5 bytes. TLS 1.2 requires all
  13: `seq_num(8) || type(1) || version(2) || plaintext_length(2)`
  (RFC 5246 §6.2.3.3). A short AAD passes a self-consistent round-trip
  test but is rejected by the peer with `bad_record_mac`.
- Feeding the 65-byte uncompressed point as the ECDHE premaster. The
  `pre_master_secret` must be the raw 32-byte x-coordinate (RFC 8422
  §5.10), leading zeros preserved.

When modifying `src/cast/tls.c`, check:
- TLS record lengths are bounded per `MAX_CAST_FRAME`; plaintext decryption
  starts only after `Finished_verify` succeeds.
- The fallback to plaintext happens only at the very first byte decision,
  before any interpreted frame.
- Ephemeral ECDHE private keys are scrubbed after use
  (`explicit_bzero(3)` equivalent) once the session keys are derived.
- A handshake header that is oversized (`> MAX_CAST_FRAME`) is rejected as
  soon as its 4-byte length field completes, even when that header is split
  across two records; a record length of 0 or an encrypted record shorter
  than the 16-byte tag (+ 1 plaintext byte) is likewise invalid.

#### Buffer growth and percentage arithmetic

`--cache 57%` and dynamic growth are integer-math-heavy.

Common mistakes:
- `received * pct` overflowing `size_t`/`off_t`.
- Growing past the `--cache` cap (plain size) or shrinking below one page.
- The buffer compacts (shrinks) while a consumer still references the
  discarded span.

When modifying `src/buf/buffer.c`, check:
- Percentage targets are computed with overflow-safe division order
  (`received / 100 * pct` plus remainder correction when precision
  matters).
- Growth respects the cap when one exists; the floor is one page.
- Compaction checks `read_off_lowest` across all consumers before
  `memmove`, and re-anchors every consumer offset after the move.

#### Spool (dangling fd) handling

`--cache-to-fs` holds a temp file that exists only as an fd.

Common mistakes:
- Writing past the file as it fills the disk (`ENOSPC`) without noticing.
- Seeking on the spool while the in-memory window offsets get out of sync.
- Closing the spool fd in one error path and using it in another (double
  close / use-after-close).

When modifying `src/source/spool.c`, check:
- `write` failures (including `ENOSPC`) are treated as fatal and reach the
  teardown path.
- Spool content is the source of truth for `Range`, and in-memory offsets
  never assume spool truncation.
- The spool fd is owned exactly once; teardown closes it exactly once.

#### HTTP request parsing

The embedded server receives only the device's requests, but they are still
untrusted input.

Common mistakes:
- `Range` parsing reading beyond the `\r\n\r\n` terminator.
- Integer overflow in `bytes=` offsets, or `end < start`.
- Serving a header block larger than the bounded buffer as an error instead
  of a graceful 400.

When modifying `src/net/http.c`, check:
- The request-line + header read is bounded (1024B reuse buffer per
  §Buffer Strategy Audit) and the cursor never reads past the terminator.
- `Range` integers parse with overflow checks; invalid specs produce `416`
  with a correct `Content-Range`, not a crash.
- Offsets served are clamped against `len`/spool size before any read.

### Generic bug patterns

#### Event-loop fairness

Every epoll event handler that drains an fd in a `for(;;)` loop must yield
back to the loop after a bounded number of iterations. Without a budget, a
flood of bytes on one fd (the source pipe) can starve the control socket and
heartbeat timers.

```
// WRONG — unbounded drain
handle_source_readable():
    for (;;) { n := read(source_fd, ...); if n ≤ 0 return; append(buf, n); }

// RIGHT — bounded iteration budget
handle_source_readable():
    budget := 64
    for (;;) {
        n := read(source_fd, ...); if n ≤ 0 return
        append(buf, n)
        if --budget == 0 return   // yield to main loop
    }
```

Check every `for(;;)` that reads from a ready fd; budget 32–128.

#### Non-blocking recv infinite loop on socket error

When `recv` on a non-blocking socket returns -1 with an errno other than
`EAGAIN` (e.g. `ENOTCONN`, `ECONNRESET`), `EPOLLIN`/`EPOLLERR` stays on, and
a loop that only breaks on `EAGAIN` spins forever.

```
// WRONG — infinite loop when recv returns a permanent error
for (;;) {
    r := recv(fd, ...)
    if r > 0 { continue }
    if r == 0 { break }
    // EAGAIN handled; permanent error missed
}

// RIGHT — bail on non-retryable errors
for (;;) {
    r := recv(fd, ...)
    if r > 0 { continue }
    if r == 0 { break }
    if errno != EAGAIN break   // non-retryable error
    if epoll_wait times out break
}
```

#### Resource teardown on error paths

In manual-cleanup code, every early `return` after a successful
acquisition is a potential leak. Free/close in reverse acquisition order and
NULL the pointer after free.

```
conn := alloc_conn()
if failure(conn) return error
job := alloc_job()
if failure(job) { free_conn(conn); return error }
if failure(register(conn, job)) {
    free_job(job)
    free_conn(conn)
    return error
}
```

#### Init-ordering gotchas

Zero-initialized dynamic arrays are vulnerable to guard conditions that
silently skip init:

```
// WRONG — (len+need) > cap on a fresh zeroed buffer → 0 > 0 → false,
//         grow never called; NULL deref later
if buffer.data == NULL || len + need > cap then grow()

// RIGHT — always guard NULL/reserved-first first
```

Also avoid sentinel value `0` when `0` is a valid index (use `-1`/`-2`).

#### Mock bypass: existing tests silently become mock tests

When a function gains a mock bypass, any existing test calling that function
now receives the mock default instead of exercising the real code path.

Common mistakes:
- Adding a `_mock_*_ret` bypass without auditing existing callers.
- Using `0` as the "disable mock" sentinel when `0` is a valid success
  return — use `-1`.
- Forgetting `mock_sys_reset()` at the start of each test.

Correct pattern:
```
mock_sys_reset()            // resets controls to bypass-default
_mock_stat_ret = -1         // disable bypass, exercise real code
result := function_under_test(...)   // real path
_mock_stat_ret = 0          // restore default for subsequent tests
```

## Past Incidents

- **Trusted-file source never drained (epoll EPERM)** — during T26 the
  file-mode loop hung: `epoll_ctl(ADD)` on a regular file returns `EPERM`,
  so a trusted (regular-file) source registered in the fd set is a source
  that never becomes readable. Root cause: `epoll_wait` cannot watch regular
  files. Prevention: a trusted source is driven *synchronously* from the
  pump, reads are bounded by the buffer's free room (backpressure), and its
  fd is never registered with epoll (also means an oversize read cannot outrun
  `ensure_space`). Regression test: `t_loop_file` / `t_loop_cmd` in
  `tests/main_test.c`.
- **Termination heuristic ≠ playback (video keeps loading, never plays)** —
  found by strace + a slow (gdb) run against the live "Living Room TV". The
  first premature-exit fix made `cast_done` end on "full delivery + a settle
  window": it survived the progressive range pulls (`bytes=0-`, `2719744-`,
  ...) but could not guarantee the video played. The DMR buffers and
  re-requests arbitrarily; under gdb (slowed scheduling) the video played,
  at full speed it kept re-loading and the app eventually tore down anyway.
  Root cause: **"the file was pulled" is not "the video played"** — only the
  receiver knows that. Prevention: base the natural end on the DMR's own
  feedback — it emits a `MEDIA_STATUS` frame with `playerState:"IDLE"` +
  `idleReason:"FINISHED"` when media plays to completion (mkchromecast holds
  the session until the user stops it precisely for this reason). `cast_ctrl`
  latches a `playback_finished` flag from inbound `MEDIA_STATUS` (`ctrl_media`),
  and `cast_done` becomes "source consumed AND `playback_finished`", plus a
  bounded idle guard (`RUN_FINISH_MAX_MS`) so live/unknown streams and a
  receiver that never reports still exit on their own. The `served_bytes`/
  `RUN_SETTLE_MS` heuristics are dropped. This never tears down mid-play or
  mid-pull and still never triggers a retry (reconnect-storm guarantee holds).
  Regression test: ctrl/loop tests that a simulated `MEDIA_STATUS` FINISHED
  ends the run and a `PLAYING`/`BUFFERING` status does not.
- **Premature exit between progressive range pulls (kills playback)** —
  found by strace against the live device ("Living Room TV", `trace-hdr2`).
  `cast_done` (`src/run/pump.c`) concluded "natural end" from `source_eof() +
  conns_idle() + served>0`. But the DMR pulls a finite stream as a sequence of
  progressive byte ranges (`GET /stream` → `Range: bytes=0-`, `2719744-`,
  `2949120-`, ... one at a time, ~50ms apart). With the whole file retained in
  the in-memory buffer, each range is served to completion and the connection
  closes instantly; in the gap before the device's next range request,
  `source_eof` + `conns_idle` + `served>0` are all true, so the loop tore down
  the media session and exited (~430ms after the first pull, but before the
  device played anything; here it had pulled up to byte 5,963,776 of a
  6,246,002-byte file). Root cause: "source EOF + transient conn idle" is not
  the end for a progressive-pulling receiver. The definitive fix is the
  device-confirmed termination above; an earlier mitigation (full-delivery +
  `RUN_SETTLE_MS` settle window) stopped the premature exit but could not
  guarantee playback. (The reconnect-storm guarantee below is preserved:
  end-of-stream never consults device-connection state, so it never triggers
  a retry.)
- **Natural end racing the reconnect storm** — when the device finishes
  pulling the stream and drops the cast socket, the old path treated it as
  session loss and scheduled a doomed reconnect loop that outran the
  "end-of-stream" check. Root cause: completion required a live device
  connection. Prevention: `cast_done` must not consult the device connection
  state; end-of-stream is source EOF + idle connections + no session fd +
  at least one served response. Regression test: the t_loop tests.
- **`rlim_max` lowered to 0 silently voids all coverage** — a coverage test
  used `setrlimit(RLIMIT_NOFILE, {0,0})` to force `signalfd` failure and then
  "restored" the old rlimit; raising a lowered *hard* limit needs
  `CAP_SYS_RESOURCE`, so the restore failed (invisibly) and the process
  stayed at 0 fds — the gcov atexit flush then failed with `EMFILE` and the
  binary wrote *no* `.gcda`, reporting `0.0%`. Prevention when faking fd
  exhaustion in a test: lower only `rlim_cur`, keep `rlim_max`, and restore
  `rlim_cur` back to `rlim_max`. Regression test: `t_run_init_fail`.