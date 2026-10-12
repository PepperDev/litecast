#include "run/run_internal.h"

#include <stdint.h>
#include <sys/signalfd.h>
#include <unistd.h>

/* === signal handling (DOMAIN.md §Flow / Lifecycle) ===
 *
 * SIGCHLD and the stop signals are blocked in the process mask and reach the
 * loop only through the signalfd: a lost command child aborts (exit 1); the
 * first stop signal requests a graceful leave, a second one goes nuclear.
 * (The nuclear fallback handler in init.c de-escalates during teardown.) */

void tick_drain(int fd)
{
  uint64_t n;
  (void)read(fd, &n, sizeof n);
}

static void lost_child(struct run_ctx *ctx)
{
  size_t i;

  for (i = 0; i < PRODUCER_MAX; i++)
    if (ctx->pros[i].active && source_reap(&ctx->pros[i].src) == 0) {
      ctx->code = 1;
      ctx->stop = 1;
    }
}

static void stop_signal(struct run_ctx *ctx, int sig)
{
  if (ctx->stop)
    ctx->nuke = sig;
  else
    ctx->stop = 1;
}

/* Read the signalfd queue. A lost command child aborts (exit 1); the first
 * stop signal requests a graceful leave, a second one goes nuclear. */
void run_sigs(struct run_ctx *ctx)
{
  struct signalfd_siginfo si;

  for (;;) {
    ssize_t r = read(ctx->sigfd, &si, sizeof si);

    if (r != (ssize_t) sizeof si)
      return;
    switch (si.ssi_signo) {
    case SIGCHLD:
      lost_child(ctx);
      break;
    case SIGINT:
    case SIGTERM:
      stop_signal(ctx, (int)si.ssi_signo);
      break;
    default:
      break;
    }
  }
}
