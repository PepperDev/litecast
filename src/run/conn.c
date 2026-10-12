#include "run/run.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* === TCP connect management (DOMAIN.md §Retry Landscape row 2) ===
 *
 * Drives the non-blocking connect to the selected device. The cast session
 * schedules reconnects (cast_conn_retry()); this file turns each booking
 * into a socket() + connect() attempt. A failed connect counts against a
 * small budget and books its own backoff pause; an exhausted budget aborts
 * the run. A successful connect hands the fd to cast_conn_attach() and a
 * fresh session rebuild begins. */

static const uint32_t CONN_BACKOFF[] = { 1000, 2000, 2000 };

static uint32_t backoff_gap(unsigned tries)
{
  size_t i = tries < 3U ? tries : 2U;

  return CONN_BACKOFF[i];
}

static int sockaddr_for(struct run_ctx *ctx, struct sockaddr_in *a)
{
  memset(a, 0, sizeof *a);
  a->sin_family = AF_INET;
  a->sin_addr.s_addr = ctx->devs[ctx->dev_idx].ip;
  a->sin_port = htons(ctx->devs[ctx->dev_idx].port);
  return 0;
}

/* A connect attempt failed: drop the fd, count it, and schedule the next
 * try after the row's backoff gap — against the next discovered device, if
 * any (§Retry Landscape row 2). */
static void run_conn_fail(struct run_ctx *ctx, uint64_t now_ms, int fd)
{
  if (fd >= 0)
    close(fd);
  ctx->connect_deadline = now_ms + backoff_gap(ctx->connect_tries);
  ctx->connect_tries++;
  if (ctx->ndev > 1)
    ctx->dev_idx = (ctx->dev_idx + 1) % ctx->ndev;
}

/* Have the connected fd: start the handshake on it. Resets the connect
 * budget so a later session loss can reconnect afresh. */
static void run_conn_ok(struct run_ctx *ctx, int fd, uint64_t now_ms)
{
  if (cast_conn_attach(&ctx->cn, fd, now_ms) != 0)
    run_conn_fail(ctx, now_ms, fd);
  else
    ctx->connect_tries = 0;
}

/* Attempt one non-blocking TCP connect to the selected device. Hands the fd
 * to the session on success, parks it in ctx->cfd while EINPROGRESS, or
 * records a defeat otherwise. Returns 0, or -1 on a socket() failure. */
static int try_connect(struct run_ctx *ctx, uint64_t now_ms)
{
  struct sockaddr_in a;
  int fd;
  int r;

  fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  (void)sockaddr_for(ctx, &a);
  do
    r = connect(fd, (struct sockaddr *)&a, sizeof a);
  while (r < 0 && errno == EINTR);
  if (r == 0) {
    run_conn_ok(ctx, fd, now_ms);
    return 0;
  }
  if (errno == EINPROGRESS) {
    ctx->cfd = fd;
    return 0;
  }
  run_conn_fail(ctx, now_ms, fd);
  return 0;
}

/* Start a connect when one is due. Returns 0 idle or in flight, -1 once the
 * budget is spent (the loop must abort). */
int run_conn_begin(struct run_ctx *ctx, uint64_t now_ms)
{
  if (ctx->cfd >= 0)
    return 0;
  if (!cast_conn_retry(&ctx->cn, now_ms))
    return 0;
  if (now_ms < ctx->connect_deadline)
    return 0;
  if (ctx->connect_tries >= RUN_CONNECT_MAX)
    return -1;
  return try_connect(ctx, now_ms);
}

/* The pending connect fd became writable (or errored): settle SO_ERROR and
 * either attach or schedule a retry. Returns 0, or -1 on a socket API
 * failure (counted as a lost attempt). */
int run_conn_step(struct run_ctx *ctx, uint64_t now_ms)
{
  int err = 0;
  socklen_t elen = sizeof err;
  int fd;

  fd = ctx->cfd;
  if (fd < 0)
    return 0;
  ctx->cfd = -1;
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) != 0)
    err = errno;
  if (err == 0)
    run_conn_ok(ctx, fd, now_ms);
  else
    run_conn_fail(ctx, now_ms, fd);
  return 0;
}
