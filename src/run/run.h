#ifndef LITECAST_RUN_H
#define LITECAST_RUN_H

#include "buf/buffer.h"
#include "cast/cast.h"
#include "cli/cache.h"
#include "cli/cli.h"
#include "net/http.h"
#include "net/mdns.h"
#include "source/source.h"

#include <signal.h>
#include <stdint.h>

/* Single-threaded epoll run (DOMAIN.md §Flow / Lifecycle): owns every live
 * fd — control socket, producer source fds, HTTP listen + connection slots,
 * the pending connect, the signalfd and a 1s timerfd — and pumps them with
 * bounded per-fd budgets. The caller prepares the producers (source +
 * window each)/spool/srv/cn, runs run_init/run_loop/run_close, then tears
 * everything down in reverse. */

enum {
  RUN_SOURCE_BUDGET = 32,       /* source reads per wake (QA §fairness) */
  RUN_ACCEPT_BUDGET = 16,
  RUN_CTRL_BUDGET = 16,         /* control frames per wake */
  RUN_EV_MAX = 64,              /* epoll_wait batch */
  RUN_CONNECT_MAX = 4,          /* TCP connects before the device fails */
  RUN_TICK_MS = 1000,           /* timerfd period; drives deadlines */
  RUN_FINISH_MAX_MS = 600000,   /* max quiet run before force-end safety net */
  PRODUCER_MAX = HTTP_CONN_MAX, /* producers (one per distinct requested start) */
  PRODUCER_IDLE_MS = 60000,     /* consumer-less idle guard: 60 s before reap (HTTP connections are never idle-closed; an attached consumer — even paused — protects the producer) */
};

/* A producer runs one command process and owns its own retention window
 * (DOMAIN.md §Producers and consumers). In file mode and command+spool the
 * run keeps exactly one producer; a no-spool command can spawn one per
 * distinct requested start, up to PRODUCER_MAX. */
struct producer {
  struct source src;
  struct buffer buf;
  struct http_prod prod;        /* server view: window + eof probe */
  int active;                   /* slot in use (spawned, not yet idle-reaped) */
  int backed;                   /* window full at target, nothing reclaimable: source is not EPOLLIN-registered until room reappears */
  uint64_t idle_since_ms;       /* monotonic: last consumer detach (0 = has cons or not idle) */
};

/* Spawn parameters for on-demand producer creation (no-spool command). */
struct producer_spec {
  int argc;
  const char **argv;
  size_t page;
  struct cache_cfg cache;
};

/* The whole run context. srv/pros/spool/cn are prepared by the caller and
 * torn down by the caller in reverse order after run_close. */
struct reg_slot {
  int fd;                       /* epoll-registered fd, -1 when none */
  uint32_t evs;                 /* registered event mask, 0 = none */
};

struct run_ctx {
  struct cast_conn cn;
  struct http_srv srv;
  struct producer pros[PRODUCER_MAX];
  struct producer_spec spec;    /* command+args+cache to spawn producers (no-spool) */
  int npro;                     /* producers currently live */
  struct mdns_device devs[MDNS_MAX_DEVICES];
  int ndev;
  int dev_idx;                  /* current connect target into devs[] */
  char cid[64];                 /* contentId URL served by this run */
  int spool_fd;
  int serve_fd;                 /* file-mode pread fd, -1 none */
  int epfd;
  int sigfd;
  int tfd;
  int cfd;                      /* pending non-blocking connect, -1 none */
  uint64_t connect_deadline;    /* next connect allowed (backoff) */
  unsigned connect_tries;       /* TCP connects so far (success resets) */
  struct reg_slot reg_ctrl;     /* the loop's epoll registrations */
  struct reg_slot reg_cfd;
  struct reg_slot reg_src[PRODUCER_MAX];        /* per-producer registrations */
  struct reg_slot reg_listen;
  struct reg_slot reg_conn[HTTP_CONN_MAX];      /* per-slot conn registrations */
  sigset_t oldmask;             /* signal mask to restore on close */
  int stop;                     /* graceful stop requested (signalfd) */
  int nuke;                     /* second stop signal: 128+sig exit */
  int code;                     /* exit code decided by the loop */
  uint64_t finish_at;           /* monotonic ms: RUN_FINISH_MAX_MS safety net */
};

/* Set up signal handling (blocked masks, signalfd, the nuclear-fallback
 * handler, SIGPIPE ignore) and the epoll + timerfds. Returns 0 or -1. */
int run_init(struct run_ctx *ctx);

/* Run the loop to a terminal condition. Returns 0 on clean end-of-stream,
 * a positive exit code (128+sig on nuclear stop) on failure. */
int run_loop(struct run_ctx *ctx);

/* Tear down the loop-owned fds and restore the signal disposition. */
void run_close(struct run_ctx *ctx);

/* conn.c — TCP connect management (DOMAIN §Retry Landscape row 2). */
int run_conn_begin(struct run_ctx *ctx, uint64_t now_ms);
int run_conn_step(struct run_ctx *ctx, uint64_t now_ms);

/* prod.c — producer opening (one entry per source mode) and the no-spool
 * producer-resolve hook into the HTTP server (called from main). */
int run_open_source(struct run_ctx *ctx, const struct cli_options *opts, size_t *page);
int run_open_spool(struct run_ctx *ctx, const struct cli_options *opts);
void run_enable_resolve(struct run_ctx *ctx);

#endif
