#include "run/run_internal.h"

#include "cast/verb.h"
#include "source/spool.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

static int producers_eof(struct run_ctx *ctx);

/* A producer source not yet at EOF: the run could still feed a fresh pull. */
static int producers_can_feed(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++)
    if (ctx->pros[i].active && !source_eof(&ctx->pros[i].src))
      return 1;
  return 0;
}

/* A live consumer is a connection currently serving a body. */
static int any_body(const struct run_ctx *ctx)
{
  for (size_t i = 0; i < HTTP_CONN_MAX; i++)
    if (ctx->srv.conns[i].fd >= 0 && ctx->srv.conns[i].phase == HTTP_PH_BODY)
      return 1;
  return 0;
}

/* Abandoned-cast net: no body in flight and no verdict → end on the guard. */
static int stall_guard(struct run_ctx *ctx, uint64_t now_ms)
{
  if (any_body(ctx)) {
    ctx->finish_at = 0;
    return 0;
  }
  if (ctx->finish_at == 0)
    ctx->finish_at = now_ms + RUN_FINISH_MAX_MS;
  return now_ms >= ctx->finish_at;
}

/* Natural end: the DMR played the media out (FINISHED) AND all sources drain; a
 * stalled stream idles out via stall_guard. An established session that gave up
 * while a source is still live — ABORT, or a premature FINISHED (trace.22: the
 * device abandoned the pull without playing the whole stream) — is
 * auto-restarted (§Session supervision); drained, it is the end. */
int cast_done(struct run_ctx *ctx, uint64_t now_ms)
{
  int end = cast_ctrl_end(&ctx->cn.ctrl);

  if (cast_ctrl_abandoned(&ctx->cn.ctrl) && producers_can_feed(ctx)) {
    (void)cast_conn_restart(&ctx->cn, now_ms);
    return 0;
  }
  if (producers_eof(ctx) && end != CTRL_END_NONE)
    return 1;
  return stall_guard(ctx, now_ms);
}

/* A read that made no progress — EOF or would-block — is not an error. */
static int source_waiting(int r)
{
  return r == 0 || errno == EAGAIN || errno == EWOULDBLOCK;
}

static size_t min_size(size_t a, size_t b)
{
  return a < b ? a : b;
}

/* Free bytes a live window accepts for a stage read: its room after reclaiming
 * the consumed prefix when full. A window exactly full first reads into its
 * growth headroom toward the `--cache` target (rule 6), so byte 0 stays
 * retained and a re-pull can attach in place; only at the target with nothing
 * reclaimable does the producer get read-backpressured (0). */
static size_t live_room(struct producer *p, size_t want)
{
  size_t room = p->buf.cap - p->buf.len;

  if (room == 0 && p->buf.cap < p->buf.target)
    room = p->buf.target - p->buf.cap;
  if (room == 0 && buffer_lowest(&p->buf) != 0) {
    buffer_compact(&p->buf, want);
    room = p->buf.cap - p->buf.len;
  }
  return min_size(room, want);
}

/* Read up to *n bytes of one producer's source into stage: a live (no-spool)
 * window never reads past what it can retain (full → backpressure, return 0,
 * never a 0-length read — .tmp/.trace-lc.8). A spooled producer never gates
 * on the window; the file is the drain target. 1=data, 0=wait, -1=error; *n
 * holds the read count. */
static int producer_read_chunk(struct producer *p, unsigned char *stage, size_t *n, int spooled)
{
  size_t room = spooled ? *n : live_room(p, *n);
  int r;

  if (room == 0) {
    p->backed = 1;
    *n = 0;
    return 0;
  }
  r = source_read(&p->src, stage, room);
  if (r <= 0) {
    *n = 0;
    return source_waiting(r) ? 0 : -1;
  }
  *n = (size_t)r;
  return 1;
}

static int producer_store(const struct run_ctx *ctx, struct producer *p, const unsigned char *stage, size_t n)
{
  if (ctx->spool_fd >= 0 && spool_append(ctx->spool_fd, stage, n) != 0)
    return -1;
  if (buffer_append(&p->buf, stage, n) != 0) {
    if (ctx->spool_fd >= 0)
      p->buf.received += n;     /* window full: count, never gate the spool */
    else
      return -1;
  }
  return 0;
}

/* Drain one producer's source into its window (and the spool, when armed). */
static int producer_drive_one(const struct run_ctx *ctx, struct producer *p)
{
  unsigned char stage[32768];
  int budget = RUN_SOURCE_BUDGET;

  while (budget-- > 0) {
    size_t cap = sizeof stage;
    int r = producer_read_chunk(p, stage, &cap, ctx->spool_fd >= 0);

    if (r <= 0)
      return r;
    if (producer_store(ctx, p, stage, cap) != 0)
      return -1;
  }
  return 0;
}

/* Drive every live producer's source into its own window (frozen gated
 * producers are skipped — they never reach EOF on their own). */
int producer_drive_all(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++) {
    int r;

    if (!ctx->pros[i].active || producer_gated(ctx, i))
      continue;
    if ((r = producer_drive_one(ctx, &ctx->pros[i])) != 0)
      return r;
  }
  return 0;
}

/* Non-zero once every live producer's source is fully consumed. */
static int producers_eof(struct run_ctx *ctx)
{
  size_t i;
  int live = 0;

  for (i = 0; i < PRODUCER_MAX; i++) {
    if (!ctx->pros[i].active)
      continue;
    live++;
    if (!source_eof(&ctx->pros[i].src))
      return 0;
  }
  return live > 0;
}

int accept_drive(struct run_ctx *ctx)
{
  int budget = RUN_ACCEPT_BUDGET;

  do {
    int r = http_accept(&ctx->srv);

    if (r <= 0)
      return r;
  } while (--budget > 0);
  return 0;
}

/* Drive the cast session up to RUN_CTRL_BUDGET frames (handshake sequence,
 * inbound frames, heartbeats). -1 means the session is beyond recovery. */
int ctrl_drive(struct run_ctx *ctx, uint64_t now_ms)
{
  int i;

  for (i = 0; i < RUN_CTRL_BUDGET; i++) {
    int r = cast_conn_poll(&ctx->cn, now_ms);

    if (r != 1)
      return r;
  }
  return 0;
}

/* Forward input then pump the response; returns 1 when the slot must close
 * (input error, no body phase, or the response reached a terminal verdict). */
static int conn_input_then_pump(struct run_ctx *ctx, size_t slot, uint32_t evs)
{
  if (evs & EPOLLIN) {
    if (http_conn_input(&ctx->srv, slot) < 0)
      return 1;
  }
  if (ctx->srv.conns[slot].phase != HTTP_PH_BODY)
    return 0;
  return http_conn_pump(&ctx->srv, slot) != 0;
}

/* One connection slot: forward input, pump the response, close on any
 * terminal verdict (EOF, error, response done). */
void conn_drive(struct run_ctx *ctx, size_t slot, uint32_t evs)
{
  if (ctx->srv.conns[slot].fd < 0)
    return;
  if (evs & (EPOLLERR | EPOLLHUP)) {
    http_conn_close(&ctx->srv, slot);
    return;
  }
  if (conn_input_then_pump(ctx, slot, evs))
    http_conn_close(&ctx->srv, slot);
}

/* Serve any body that new data made available on every open slot. A slot
 * whose last flush would-block (c->blocked) is skipped: the conn is pinned on
 * a full TCP send buffer, so retrying it here would busily hammer EAGAIN
 * (DOMAIN.md Design Invariant never busy-retry a would-block write); it
 * resumes on the next EPOLLOUT wake (conn_drive). */
static void pump_all(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < HTTP_CONN_MAX; i++) {
    if (ctx->srv.conns[i].fd < 0 || ctx->srv.conns[i].phase != HTTP_PH_BODY)
      continue;
    if (ctx->srv.conns[i].blocked)
      continue;
    if (http_conn_pump(&ctx->srv, i) != 0)
      http_conn_close(&ctx->srv, i);
  }
}

/* Un-freeze a backed producer once a consumer advance makes its window
 * reclaimable (room, or a consumed prefix compaction could reclaim); run_sync
 * re-registers its source EPOLLIN and the drain resumes. */
static void producers_resume(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++) {
    struct producer *p = &ctx->pros[i];

    if (!p->active || !p->backed)
      continue;
    if (p->buf.cap - p->buf.len != 0 || buffer_lowest(&p->buf) != 0)
      p->backed = 0;
  }
}

static void serve_available(struct run_ctx *ctx)
{
  ctx->srv.complete = producers_eof(ctx);
  /* First-termination total: the first producer to reach EOF stores its
   * received bytes as the stream total (idle/kill must not store). */
  if (ctx->srv.total == 0) {
    for (size_t i = 0; i < PRODUCER_MAX; i++)
      if (ctx->pros[i].active && source_eof(&ctx->pros[i].src)) {
        ctx->srv.total = (unsigned long long)buffer_received(&ctx->pros[i].buf);
        break;
      }
  }
  pump_all(ctx);
  producers_resume(ctx);
}

/* The synchronous side of the loop run for the current iteration. */
int run_pump(struct run_ctx *ctx, uint64_t now_ms)
{
  serve_available(ctx);
  /* Trusted (regular-file) sources can't be epoll-watched (EPERM): drain them
   * synchronously, the read bounded by the buffer room. */
  if (ctx->npro > 0 && source_size_trusted(&ctx->pros[0].src) && !source_eof(&ctx->pros[0].src))
    if (producer_drive_all(ctx) != 0)
      return -1;
  producer_idle_reap(ctx, now_ms);
  run_sync(ctx);
  return 0;
}
