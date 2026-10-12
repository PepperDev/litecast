#include "run/run_internal.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

/* === init / teardown (DOMAIN.md §Flow / Lifecycle) ===
 * Blocked signals (SIGINT/SIGTERM/SIGCHLD) reach the loop only through the
 * signalfd; the nuclear fallback (CONTRIBUTING §Design Principles #1) is
 * bound to the cleanup window after the mask is restored. */

static __thread volatile sig_atomic_t litecast_stopping;

static void litecast_signal(int sig)
{
  if (litecast_stopping)
    _exit(128 + sig);
  litecast_stopping = 1;
}

static const struct reg_slot REG_NONE = { -1, 0 };

static void seed_reg(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < HTTP_CONN_MAX; i++)
    ctx->reg_conn[i] = REG_NONE;
  for (i = 0; i < PRODUCER_MAX; i++)
    ctx->reg_src[i] = REG_NONE;
  ctx->reg_listen = REG_NONE;
  ctx->reg_ctrl = REG_NONE;
  ctx->reg_cfd = REG_NONE;
  ctx->cfd = -1;
  ctx->connect_tries = 0;
  ctx->connect_deadline = 0;
  ctx->stop = 0;
  ctx->nuke = 0;
  ctx->code = -1;
}

/* Undo partial run_init state and report the failure. */
static int disengage(struct run_ctx *ctx, int sigfd, int epfd, int tfd)
{
  if (sigfd >= 0)
    close(sigfd);
  if (epfd >= 0)
    close(epfd);
  if (tfd >= 0)
    close(tfd);
  (void)sigprocmask(SIG_SETMASK, &ctx->oldmask, NULL);
  return -1;
}

/* === epoll registration sync ===
 *
 * A registration is tracked (fd + mask) and re-applied on change; a terminal
 * slot is surrendered. Closing a fd drops its kernel entry, so surrendering a
 * closed fd only clears bookkeeping — never DEL a re-used number (live-CDD
 * .4). A mask change on a live fd must MOD, not ADD: ADD fails EEXIST and the
 * old mask keeps ruling the kernel (live-CDD .6/.7: cast-EPOLLOUT spin, no
 * blocked-conn EPOLLOUT resume). */
static void reg_apply(int epfd, int fd, uint32_t evs, int kept)
{
  struct epoll_event ev;

  ev.events = evs;
  ev.data.fd = fd;
  if (kept) {                   /* live mask change */
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) != 0 && errno == ENOENT)
      (void)epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
  } else if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0 && errno == EEXIST) {
    (void)epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);      /* role takeover */
  }
}

static void epoll_set(int epfd, struct reg_slot *r, int tgt, uint32_t evs_new, int still_open)
{
  if (tgt < 0) {
    if (still_open && r->fd >= 0)
      (void)epoll_ctl(epfd, EPOLL_CTL_DEL, r->fd, NULL);
    r->fd = -1;
    r->evs = 0;
    return;
  }
  if (r->fd == tgt && r->evs == evs_new)
    return;
  reg_apply(epfd, tgt, evs_new, r->fd == tgt);
  r->fd = tgt;
  r->evs = evs_new;
}

/* The control socket can only be watched while no pending connect sits on
 * EPOLLOUT; the two are never registered at once. */
static int ctrl_reg_fd(const struct run_ctx *ctx)
{
  return ctx->cfd >= 0 ? -1 : cast_conn_fd(&ctx->cn);
}

/* Trusted sources, gated producers and backed producers are never registered:
 * a backed full pipe must not spin a level-triggered EPOLLIN watch. */
static int source_reg_fd(const struct run_ctx *ctx, size_t i)
{
  if (i >= (size_t)PRODUCER_MAX || !ctx->pros[i].active)
    return -1;
  if (source_size_trusted(&ctx->pros[i].src))
    return -1;
  if (producer_gated(ctx, i))
    return -1;
  if (ctx->pros[i].backed)
    return -1;
  return source_fd(&ctx->pros[i].src);
}

static void sync_sources(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++) {
    int cur = ctx->reg_src[i].fd;
    int want = source_reg_fd(ctx, i);

    /* Surrender only a live producer fd: an EOF/idle-closed fd was auto-dropped from epoll and its number may be re-used. */
    epoll_set(ctx->epfd, &ctx->reg_src[i], want, EPOLLIN, cur > 0 && want < 0 && cur == source_fd(&ctx->pros[i].src));
  }
}

static void sync_sockets(struct run_ctx *ctx)
{
  epoll_set(ctx->epfd, &ctx->reg_listen, ctx->srv.listen_fd, EPOLLIN, 0);
  epoll_set(ctx->epfd, &ctx->reg_cfd, ctx->cfd, EPOLLOUT, 0);
  epoll_set(ctx->epfd, &ctx->reg_ctrl, ctrl_reg_fd(ctx), EPOLLIN, 0);
  sync_sources(ctx);
}

/* A conn is watched for input, plus output only while a flush is blocked. */
static uint32_t conn_evs(const struct run_ctx *ctx, size_t i)
{
  return (uint32_t) (ctx->srv.conns[i].fd < 0 ? 0 : ctx->srv.conns[i].blocked ? EPOLLIN | EPOLLOUT : EPOLLIN);
}

void run_sync(struct run_ctx *ctx)
{
  size_t i;

  sync_sockets(ctx);
  for (i = 0; i < HTTP_CONN_MAX; i++)
    epoll_set(ctx->epfd, &ctx->reg_conn[i], ctx->srv.conns[i].fd, conn_evs(ctx, i), 0);
}

/* conn_close hook: deregister first so a stale registration never survives
 * onto an fd re-used by a later accept. */
static void conn_close_del(void *user, int fd)
{
  struct run_ctx *ctx = user;
  size_t i;

  for (i = 0; i < HTTP_CONN_MAX; i++)
    if (ctx->reg_conn[i].fd == fd) {
      (void)epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, fd, NULL);
      ctx->reg_conn[i] = REG_NONE;
      return;
    }
}

static int block_signals(struct run_ctx *ctx, sigset_t *blocked)
{
  sigset_t set;

  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &set, &ctx->oldmask) != 0)
    return -1;
  *blocked = set;
  return 0;
}

static int make_sigfd(struct run_ctx *ctx, int *fd)
{
  sigset_t blocked;

  if (block_signals(ctx, &blocked) != 0)
    return -1;
  *fd = signalfd(-1, &blocked, SFD_NONBLOCK | SFD_CLOEXEC);
  if (*fd < 0) {
    (void)sigprocmask(SIG_SETMASK, &ctx->oldmask, NULL);
    return -1;
  }
  return 0;
}

static void install_handlers(void)
{
  struct sigaction sa;

  memset(&sa, 0, sizeof sa);
  sa.sa_handler = litecast_signal;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGINT, &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
  (void)signal(SIGPIPE, SIG_IGN);
}

static int add_epoll(int epfd, int fd)
{
  struct epoll_event ev;

  ev.events = EPOLLIN;
  ev.data.fd = fd;
  return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static int arm_timer(int tfd, unsigned period_ms)
{
  struct itimerspec its;

  memset(&its, 0, sizeof its);
  its.it_interval.tv_sec = period_ms / 1000;
  its.it_value.tv_sec = period_ms / 1000;
  return timerfd_settime(tfd, 0, &its, NULL);
}

/* The 1s tick fd: created, armed, and registered in one step. */
static int make_tfd(int epfd, int *fd)
{
  *fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (*fd < 0)
    return -1;
  if (arm_timer(*fd, RUN_TICK_MS) != 0)
    return -1;
  return add_epoll(epfd, *fd);
}

/* epoll fd, its timer, and the signalfd registration on top of the sigfd. */
static int open_remaining(struct run_ctx *ctx, int sigfd, int *epfd, int *tfd)
{
  *epfd = epoll_create1(EPOLL_CLOEXEC);
  if (*epfd < 0)
    return -1;
  if (make_tfd(*epfd, tfd) != 0)
    return disengage(ctx, sigfd, *epfd, -1);
  if (add_epoll(*epfd, sigfd) != 0)
    return disengage(ctx, sigfd, *epfd, *tfd);
  return 0;
}

static void commit_fds(struct run_ctx *ctx, int sigfd, int epfd, int tfd)
{
  ctx->sigfd = sigfd;
  ctx->epfd = epfd;
  ctx->tfd = tfd;
}

int run_init(struct run_ctx *ctx)
{
  int sigfd;
  int epfd;
  int tfd;

  if (ctx == NULL)
    return -1;
  seed_reg(ctx);
  ctx->srv.conn_close = conn_close_del;
  ctx->srv.conn_close_user = ctx;
  if (make_sigfd(ctx, &sigfd) != 0)
    return -1;
  install_handlers();
  if (open_remaining(ctx, sigfd, &epfd, &tfd) != 0)
    return -1;
  commit_fds(ctx, sigfd, epfd, tfd);
  return 0;
}

void run_close(struct run_ctx *ctx)
{
  if (ctx == NULL)
    return;
  if (ctx->tfd >= 0) {
    close(ctx->tfd);
    ctx->tfd = -1;
  }
  if (ctx->epfd >= 0) {
    close(ctx->epfd);
    ctx->epfd = -1;
  }
  if (ctx->sigfd >= 0) {
    close(ctx->sigfd);
    ctx->sigfd = -1;
  }
  (void)sigprocmask(SIG_SETMASK, &ctx->oldmask, NULL);
  (void)signal(SIGINT, SIG_DFL);
  (void)signal(SIGTERM, SIG_DFL);
  (void)signal(SIGPIPE, SIG_DFL);
}
