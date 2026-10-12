#include "cli/cli.h"
#include "run/run_internal.h"

#include "source/spool.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Producer lifecycle (DOMAIN.md). Request-start resolution lives in
 * resolve.c; this file stays a self-contained producer/gating unit. */

/* HTTP probe: non-zero when the source is fully read and its child reaped. */
static int producer_probe(void *user)
{
  return source_eof(&((struct producer *)user)->src);
}

/* Bind the server-side anchor to a producer window. */
static void producer_bind(struct producer *p)
{
  p->prod.buf = &p->buf;
  p->prod.eof = producer_probe;
  p->prod.user = p;
}

/* Open a producer's source + window; roll back the source on failure. */
static int producer_start(struct producer *p, const struct run_ctx *ctx)
{
  if (source_open(&p->src, SOURCE_MODE_COMMAND, ctx->spec.argc, ctx->spec.argv) != 0)
    return -1;
  if (buffer_open(&p->buf, ctx->spec.page, &ctx->spec.cache, &(struct buf_source) { BUFFER_MODE_COMMAND, 0, 0 }) != 0) {
    source_close(&p->src);
    return -1;
  }
  producer_bind(p);
  p->active = 1;
  p->idle_since_ms = 0;
  return 0;
}

/* Spawn a no-spool producer in the first free slot (index, or -1 full/fail).
 * Exported for resolve.c, which creates producers on demand. */
int producer_spawn(struct run_ctx *ctx)
{
  struct producer *p;
  size_t i;

  if (ctx->npro >= PRODUCER_MAX)
    return -1;
  for (i = 0; i < PRODUCER_MAX; i++)
    if (!ctx->pros[i].active)
      break;
  p = &ctx->pros[i];
  memset(p, 0, sizeof *p);
  p->src.fd = SOURCE_FD_NONE;
  if (producer_start(p, ctx) != 0)
    return -1;
  ctx->npro++;
  return (int)i;
}

/* No-spool: store the spawn parameters for on-demand producer creation. */
static int open_nospool(struct run_ctx *ctx, const struct cli_options *opts, size_t ps, size_t *page)
{
  ctx->spec.argc = opts->operands_count;
  ctx->spec.argv = opts->operands;
  ctx->spec.page = ps;
  ctx->spec.cache = opts->cache;
  *page = ps;
  return 0;
}

/* Resolve the buffer policy from an opened source and allocate its window. */
static int open_buffer(struct producer *p, const struct cli_options *opts, size_t ps)
{
  struct buf_source bsrc;

  bsrc.mode = opts->command_mode;
  bsrc.size_trustworthy = source_size_trusted(&p->src);
  bsrc.size = (size_t)source_size(&p->src);
  return buffer_open(&p->buf, ps, &opts->cache, &bsrc);
}

/* Open the producer for its mode; a no-spool command stores only the spawn
 * params (producers[0] stays closed until a request resolves). */
int run_open_source(struct run_ctx *ctx, const struct cli_options *opts, size_t *page)
{
  struct producer *p = &ctx->pros[0];
  size_t ps = (size_t)sysconf(_SC_PAGESIZE);

  if (opts->command_mode && !opts->cache_to_fs)
    return open_nospool(ctx, opts, ps, page);
  if (source_open(&p->src, opts->command_mode, opts->operands_count, opts->operands) != 0)
    return -1;
  ctx->npro = 1;
  p->active = 1;                /* ctx is memset before open, so idle_since_ms = 0 */
  *page = ps;
  return open_buffer(p, opts, ps);
}

/* Spool: only meaningful for a cache-to-fs command run. */
int run_open_spool(struct run_ctx *ctx, const struct cli_options *opts)
{
  char spool_tmpl[32] = "/tmp/litecast-XXXXXX";

  if (!opts->command_mode || !opts->cache_to_fs)
    return 0;
  ctx->spool_fd = spool_open(spool_tmpl);
  return ctx->spool_fd < 0 ? -1 : 0;
}

/* A verdict that ends the run for good: the source still gets drained to EOF so
 * its total is stored and the run can exit. A verdict whose session restart is
 * already booked does not qualify — the device is coming back for the window, so
 * the producer returns to the ordinary consumer rules and keeps its retention
 * (nothing attached, nothing advances the consumed front) instead of encoding
 * into a window nobody reads (trace.22). */
static int verdict_final(const struct run_ctx *ctx)
{
  return cast_ctrl_finished(&ctx->cn.ctrl) && !cast_conn_restarting(&ctx->cn);
}

/* A no-spool producer is gated when it has no consumer and the run is not
 * draining it to EOF. */
int producer_gated(const struct run_ctx *ctx, size_t i)
{
  const struct producer *p = &ctx->pros[i];

  if (!p->active)
    return 0;
  if (p->src.mode != SOURCE_MODE_COMMAND)
    return 0;
  if (ctx->spool_fd >= 0)
    return 0;
  if (p->buf.cons.len > 0)
    return 0;
  return !verdict_final(ctx);
}

/* Returns 0 (not idle) for EOF, active, or a final verdict; otherwise arm
 * timestamp. */
static uint64_t idle_state(const struct producer *p, int draining, uint64_t now_ms)
{
  if (p->src.eof_seen || p->buf.cons.len > 0 || draining)
    return 0;
  if (p->idle_since_ms == 0)
    return now_ms;
  return p->idle_since_ms;
}

/* File and spooled producers are exempt from idle termination. */
static int reapable(const struct producer *p, int spooled)
{
  return p->active && p->src.mode == SOURCE_MODE_COMMAND && !p->src.eof_seen && !spooled;
}

void producer_idle_reap(struct run_ctx *ctx, uint64_t now_ms)
{
  for (size_t i = 0; i < PRODUCER_MAX; i++) {
    struct producer *p = &ctx->pros[i];

    if (!reapable(p, ctx->spool_fd >= 0))
      continue;
    p->idle_since_ms = idle_state(p, verdict_final(ctx), now_ms);
    if (p->idle_since_ms != 0 && now_ms - p->idle_since_ms >= PRODUCER_IDLE_MS) {
      source_teardown(&p->src);
      source_close(&p->src);
      buffer_close(&p->buf);
      memset(p, 0, sizeof *p);
      ctx->npro--;
    }
  }
}
