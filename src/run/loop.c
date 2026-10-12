#include "run/run_internal.h"

#include <errno.h>
#include <sys/epoll.h>

/* === event loop core (DOMAIN.md §Flow / Lifecycle) ===
 *
 * One epoll_wait loop, level-triggered, over the control socket, the source
 * fd, the HTTP listener and its slots, a 1s timerfd (deadlines: handshake
 * budgets, heartbeat PINGs, idle timeouts) and a signalfd (SIGINT, SIGTERM,
 * SIGCHLD — blocked in the process mask). Every drain is bounded (QA.md
 * §Event-loop fairness; the drains live in pump.c, the fd reconciliation in
 * init.c); errors cascade to the loop exit code; the caller releases
 * everything after run_close (QA.md §Resource teardown). */

/* Deadline plumbing: heartbeat PINGs, handshake budgets, connection
 * retries, idle timeouts, the connect budget. */
static int run_timers(struct run_ctx *ctx, uint64_t now_ms)
{
  if (ctx->cfd < 0) {
    if (cast_conn_poll(&ctx->cn, now_ms) < 0) {
      ctx->code = 1;
      ctx->stop = 1;
      return 1;
    }
  }
  if (run_conn_begin(ctx, now_ms) != 0) {
    ctx->code = 1;
    ctx->stop = 1;
    return 1;
  }
  return 0;
}

/* Natural end: every producer must have settled — a cleanly-reaped child (or
 * none)   → 0, a failed child → non-zero, a still-running child → keep going. */
static int producers_reap(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++) {
    int r;

    if (!ctx->pros[i].active)
      continue;
    r = source_reap(&ctx->pros[i].src);
    if (r == -1)
      return -1;
    if (r == 0)
      ctx->code = 1;
  }
  return 1;
}

static int finish_natural(struct run_ctx *ctx)
{
  if (producers_reap(ctx) != -1) {
    if (ctx->code < 0)
      ctx->code = 0;
    return 1;
  }
  return 0;
}

/* Terminal conditions: stop signal, failed session, or natural end. */
static int run_finale(struct run_ctx *ctx, uint64_t now_ms)
{
  if (ctx->stop) {
    if (ctx->code < 0)
      ctx->code = ctx->nuke != 0 ? 128 + ctx->nuke : 0;
    return 1;
  }
  if (cast_done(ctx, now_ms))
    return finish_natural(ctx);
  return 0;
}

static int run_step(struct run_ctx *ctx, uint64_t now_ms)
{
  int r = run_pump(ctx, now_ms);

  if (r != 0)
    return r;
  r = run_timers(ctx, now_ms);
  if (r != 0)
    return r;
  return run_finale(ctx, now_ms);
}

enum { EV_SIG, EV_TICK, EV_SESS, EV_SRC, EV_ACCEPT, EV_NONE };

/* Match any live producer's registered source fd (multiple producers may be
 * live in the no-spool model). */
static int src_fd_match(const struct run_ctx *ctx, int fd)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++)
    if (ctx->pros[i].active && ctx->reg_src[i].fd == fd)
      return EV_SRC;
  return EV_NONE;
}

/* The pending connect and the control socket never coexist (run_sync keeps
 * them mutually exclusive), so both share one dispatch kind. */
static int ev_kind(const struct run_ctx *ctx, int fd)
{
  const int want[] = { ctx->sigfd, ctx->tfd, ctx->cfd, ctx->reg_ctrl.fd,
    ctx->srv.listen_fd, -1
  };
  const int kind[] = { EV_SIG, EV_TICK, EV_SESS, EV_SESS,
    EV_ACCEPT, EV_NONE
  };
  size_t i;

  for (i = 0; i < sizeof want / sizeof want[0]; i++)
    if (want[i] == fd)
      return kind[i];
  return src_fd_match(ctx, fd);
}

static void kill_source(struct run_ctx *ctx)
{
  if (producer_drive_all(ctx) != 0) {
    ctx->code = 1;
    ctx->stop = 1;
  }
}

static void session_event(struct run_ctx *ctx, const struct epoll_event *ev, uint64_t now_ms)
{
  if (ev->data.fd == ctx->cfd)
    (void)run_conn_step(ctx, now_ms);
  else
    (void)ctrl_drive(ctx, now_ms);
}

static void socket_event(struct run_ctx *ctx, const struct epoll_event *ev, uint64_t now_ms)
{
  switch (ev_kind(ctx, ev->data.fd)) {
  case EV_SIG:
    run_sigs(ctx);
    break;
  case EV_TICK:
    tick_drain(ev->data.fd);
    break;
  case EV_SESS:
    session_event(ctx, ev, now_ms);
    break;
  case EV_SRC:
    kill_source(ctx);
    break;
  case EV_ACCEPT:
    (void)accept_drive(ctx);
    break;
  }
}

/* The fd is an HTTP connection slot (or unknown): find the slot by fd. */
static void conn_event(struct run_ctx *ctx, const struct epoll_event *ev)
{
  size_t i;

  for (i = 0; i < HTTP_CONN_MAX; i++)
    if (ctx->srv.conns[i].fd == ev->data.fd) {
      conn_drive(ctx, i, ev->events);
      break;
    }
}

static void run_dispatch(struct run_ctx *ctx, const struct epoll_event *ev, uint64_t now_ms)
{
  int k = ev_kind(ctx, ev->data.fd);

  if (k != EV_NONE)
    socket_event(ctx, ev, now_ms);
  else
    conn_event(ctx, ev);
}

int run_loop(struct run_ctx *ctx)
{
  struct epoll_event evs[RUN_EV_MAX];

  while (ctx->code < 0) {
    uint64_t now_ms;
    int n = epoll_wait(ctx->epfd, evs, RUN_EV_MAX, -1);
    int i;

    if (n < 0) {
      if (errno == EINTR)
        continue;
      ctx->code = 1;
      break;
    }
    now_ms = cast_ctrl_now_ms();
    for (i = 0; i < n; i++)
      run_dispatch(ctx, &evs[i], now_ms);
    if (run_step(ctx, now_ms) != 0)
      break;
  }
  return ctx->code;
}
