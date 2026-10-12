#include "run/run_internal.h"

/* Request-start resolution against the no-spool producers (DOMAIN.md): a
 * live plain s=0 re-pull is answered as a startable whole resource — attached
 * at retained byte 0 or, once byte 0 is compacted away, a fresh producer
 * spawn — never a mid-stream continuation (the drained DMR re-inits its
 * parse from the response start and aborts on a mid-moof/mdat first byte:
 * trace.7 then trace.9, type=ERROR + IDLE idleReason=ERROR). A replay is
 * never displaced by a duplicate spawn: whenever a window can serve byte 0 it
 * attaches in place, and only a window-unservable restart spawns (trace.16).
 * Range requests keep the retained → behind → spawn ladder plus the
 * live-tail fallback. */

/* Lowest retained offset of producer buf (live-tail head). */
static unsigned long long producer_head(const struct buffer *buf)
{
  return (unsigned long long)buffer_offset(buf) + (unsigned long long)buffer_lowest(buf);
}

/* Find the producer whose window physically holds stream byte s: the head
 * (buffer_offset) is the serveability floor, not the least-behind consumer —
 * memory below that consumer is consumed but still present and remains
 * serveable (DOMAIN.md rule 1/3; a Range resume behind the active pull must
 * not spawn a duplicate producer, trace.13). */
static int find_retained(const struct run_ctx *ctx, unsigned long long s)
{
  for (int i = 0; i < PRODUCER_MAX; i++) {
    const struct buffer *b;
    unsigned long long base, recv;

    if (!ctx->pros[i].active)
      continue;
    b = &ctx->pros[i].buf;
    base = (unsigned long long)buffer_offset(b);
    recv = (unsigned long long)buffer_received(b);

    if (s >= base && s <= recv)
      return i;
  }
  return -1;
}

/* Nearest producer whose received end is before s (backend attach). */
static int find_behind(const struct run_ctx *ctx, unsigned long long s)
{
  int best = -1;
  unsigned long long bestpos = 0;

  for (int i = 0; i < PRODUCER_MAX; i++) {
    unsigned long long recv;

    if (!ctx->pros[i].active)
      continue;
    recv = (unsigned long long)buffer_received(&ctx->pros[i].buf);

    if (recv < s && (best < 0 || recv > bestpos)) {
      best = i;
      bestpos = recv;
    }
  }
  return best;
}

/* Farthest producer — the live frontier owner. */
static int find_farthest(const struct run_ctx *ctx)
{
  int best = -1;
  unsigned long long bestpos = 0;

  for (int i = 0; i < PRODUCER_MAX; i++) {
    unsigned long long recv;

    if (!ctx->pros[i].active)
      continue;
    recv = (unsigned long long)buffer_received(&ctx->pros[i].buf);

    if (recv > bestpos) {
      bestpos = recv;
      best = i;
    }
  }
  return best;
}

/* Farthest producer whose window can serve byte 0 (buffer_offset == 0) — the
 * whole-resource replay sink (rule 0): a replay is only possible from a
 * window whose offset is 0, so a mid-stream join is never served. An empty
 * window (received == 0, still at the live frontier — the cold start or a
 * pull landed mid-stall, trace.5) serves the byte-0 request in place too; it
 * attaches and waits for its frontier. */
static int find_replay(const struct run_ctx *ctx)
{
  int best = -1;
  unsigned long long bestpos = 0;

  for (int i = 0; i < PRODUCER_MAX; i++) {
    unsigned long long recv;

    if (!ctx->pros[i].active || buffer_offset(&ctx->pros[i].buf) != 0)
      continue;
    recv = (unsigned long long)buffer_received(&ctx->pros[i].buf);
    if (best < 0 || recv > bestpos) {
      bestpos = recv;
      best = i;
    }
  }
  return best;
}

/* Live plain s=0 restart: attach the re-pull at byte 0 of the farthest
 * producer whose window can still serve it, so the whole resource replays at
 * socket rate (an empty frontier window parks until it produces) and the DMR
 * re-inits cleanly. A whole-resource replay is never displaced by a
 * duplicate spawn: whenever ANY window can serve byte 0 it serves (with or
 * without farther producers alive), and only when no window can does the
 * resolver spawn a fresh producer for the same whole-resource replay.
 * -1 on failure (fatal: no producer can serve a restart). */
static int restart_hit(struct run_ctx *ctx, unsigned long long *pos)
{
  int idx = find_replay(ctx);

  if (idx < 0)
    idx = producer_spawn(ctx);
  if (idx < 0)
    return -1;
  *pos = 0;
  return idx;
}

/* Retained → behind → spawn + live-tail fallback (Range and known-total paths). */
static int resolve_hit(struct run_ctx *ctx, unsigned long long s, unsigned long long *pos, int *tail)
{
  int idx;

  idx = find_retained(ctx, s);
  if (idx < 0) {
    idx = find_behind(ctx, s);
    if (idx < 0)
      idx = producer_spawn(ctx);
  }
  if (idx >= 0) {
    *pos = s;
    return idx;
  }
  if (ctx->npro > 0) {
    idx = find_farthest(ctx);
    *pos = producer_head(&ctx->pros[idx].buf);
    *tail = 1;
    return idx;
  }
  return -1;
}

/* HTTP resolve callback: picks/creates a producer for stream offset s. A
 * live plain s=0 is a drained-conn restart (trace.9) — resolved by
 * restart_hit, never the retained/behind/spawn ladder, so a re-pull can
 * never be answered with a mid-stream continuation. */
static int run_resolve(void *user, unsigned long long s, struct http_prod **prod, unsigned long long *at, int *tail)
{
  struct run_ctx *ctx = user;
  unsigned long long pos;
  int idx;

  *tail = 0;
  if (s == 0 && ctx->srv.total == 0 && ctx->npro > 0)
    idx = restart_hit(ctx, &pos);
  else
    idx = resolve_hit(ctx, s, &pos, tail);
  if (idx < 0)
    return -1;
  *prod = &ctx->pros[idx].prod;
  *at = pos;
  return 0;
}

/* Wire the no-spool producer-resolve hook into the HTTP server. */
void run_enable_resolve(struct run_ctx *ctx)
{
  ctx->srv.resolve = run_resolve;
  ctx->srv.res_user = ctx;
}
