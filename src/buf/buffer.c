#include "buf/buffer.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static size_t buf_max(size_t a, size_t b)
{
  return a > b ? a : b;
}

static size_t buf_min(size_t a, size_t b)
{
  return a < b ? a : b;
}

static size_t pct_mul(size_t v, size_t p)
{
  return v / 100 * p + (v % 100) * p / 100;
}

struct cap_policy {
  size_t cap, limit;
  unsigned int percent_dyn;
};

static void file_cap(const struct cache_cfg *cfg, const struct buf_source *src, size_t page, struct cap_policy *pol)
{
  if (cfg->kind != CACHE_PCT) {
    pol->cap = buf_max(cfg->bytes, page);
    pol->limit = pol->cap;
    pol->percent_dyn = 0;
    return;
  }
  if (!src->size_trustworthy) {
    pol->cap = page;
    pol->limit = 0;
    pol->percent_dyn = 1;
    return;
  }
  pol->cap = buf_max(pct_mul(src->size, cfg->pct), page);
  pol->limit = pol->cap;
  pol->percent_dyn = 0;
}

static void cmd_cap(const struct cache_cfg *cfg, size_t page, struct cap_policy *pol)
{
  if (cfg->kind == CACHE_PCT) {
    pol->cap = page;
    pol->limit = 0;
    pol->percent_dyn = 1;
    return;
  }
  pol->cap = page;
  pol->limit = cfg->bytes;
  pol->percent_dyn = 0;
}

static void resolve_cap(const struct cache_cfg *cfg, const struct buf_source *src, size_t page, struct cap_policy *pol)
{
  if (src->mode == BUFFER_MODE_FILE)
    file_cap(cfg, src, page, pol);
  else
    cmd_cap(cfg, page, pol);
}

static size_t recompute_target(const struct buffer *b)
{
  size_t t = pct_mul(b->received, b->pct);

  return t < b->page_size ? b->page_size : t;
}

static size_t growth_size(size_t cap, size_t need)
{
  size_t step, base;

  step = buf_max(buf_min(buf_max(cap, 64), 65536), need - cap);
  if (step > SIZE_MAX - cap)
    return 0;
  base = cap + step;
  return (base + 63) & ~63UL;
}

static int grow_to(struct buffer *b, size_t need)
{
  size_t ncap;
  unsigned char *nd;

  if (need <= b->cap)
    return 0;
  ncap = growth_size(b->cap, need);
  if (b->cap_limit != 0 && ncap > b->cap_limit)
    ncap = b->cap_limit;
  if (ncap < need)
    return -1;
  nd = realloc(b->data, ncap);
  if (nd == NULL)
    return -1;
  b->data = nd;
  b->cap = ncap;
  return 0;
}

/* Grow-first (DOMAIN.md §Compaction): grow while under target, then compact. */
static int grow_first(struct buffer *b, size_t n)
{
  return b->cap < b->target && b->len <= SIZE_MAX - n && grow_to(b, b->len + n) == 0;
}

static int ensure_space(struct buffer *b, size_t n)
{
  size_t room = b->cap - b->len;

  if (room >= n)
    return 0;
  if (grow_first(b, n))
    return 0;
  if (buffer_lowest(b) > 0)
    buffer_compact(b, n);
  room = b->cap - b->len;
  if (room >= n)
    return 0;
  if (b->len > SIZE_MAX - n)
    return -1;
  return grow_to(b, b->len + n);
}

static void advance_dyn(struct buffer *b)
{
  if (b->cap < (b->target = recompute_target(b)))
    (void)grow_to(b, b->target);
}

static void open_fields(struct buffer *b, const struct cache_cfg *cfg, const struct cap_policy *pol, size_t page_size)
{
  b->cap = pol->cap;
  b->cap_limit = pol->limit;
  b->percent_dyn = pol->percent_dyn;
  b->target = pol->percent_dyn ? page_size : pol->limit;
  if (cfg->kind == CACHE_PCT)
    b->pct = cfg->pct;
}

static int open_ready(size_t page_size, const struct cache_cfg *cfg, const struct buf_source *src)
{
  return cfg != NULL && src != NULL && page_size != 0;
}

int buffer_open(struct buffer *b, size_t page_size, const struct cache_cfg *cfg, const struct buf_source *src)
{
  struct cap_policy pol = { 0 };

  if (b == NULL || !open_ready(page_size, cfg, src))
    return -1;
  memset(b, 0, sizeof(*b));
  b->page_size = page_size;
  resolve_cap(cfg, src, page_size, &pol);
  open_fields(b, cfg, &pol, page_size);
  if (cvec_init(&b->cons) != 0)
    return -1;
  b->data = malloc(pol.cap);
  if (b->data == NULL) {
    cvec_clear(&b->cons);
    return -1;
  }
  return 0;
}

void buffer_close(struct buffer *b)
{
  if (b == NULL)
    return;
  free(b->data);
  cvec_clear(&b->cons);
  memset(b, 0, sizeof(*b));
}

int buffer_append(struct buffer *b, const unsigned char *p, size_t n)
{
  if (b->data == NULL)
    return -1;
  if (n == 0)
    return 0;
  if (ensure_space(b, n) != 0)
    return -1;
  memcpy(b->data + b->len, p, n);
  b->len += n;
  b->received = b->received <= SIZE_MAX - n ? b->received + n : SIZE_MAX;
  if (b->percent_dyn)
    advance_dyn(b);
  return 0;
}

/* Minimum-room move (DOMAIN.md §Compaction): the window start advances by
 * min(read_off_lowest, room the next package needs; callers pass ≥ 1), never
 * past the least-behind consumer — preserves history for later starts and
 * whole-resource replays (rule 0: a window still holding byte 0). */
void buffer_compact(struct buffer *b, size_t need)
{
  size_t low, free, i;

  if (b->data == NULL)
    return;
  low = buffer_lowest(b);
  if (low > b->len)
    low = b->len;
  free = need < low ? need : low;
  if (free == 0)
    return;
  memmove(b->data, b->data + free, b->len - free);
  b->len -= free;
  for (i = 0; i < b->cons.len; i++)
    b->cons.el[i].read_off -= free;
}

size_t buffer_len(const struct buffer *b)
{
  return b->len;
}

size_t buffer_cap(const struct buffer *b)
{
  return b->cap;
}

size_t buffer_target(const struct buffer *b)
{
  return b->target;
}

size_t buffer_received(const struct buffer *b)
{
  return b->received;
}

size_t buffer_lowest(const struct buffer *b)
{
  size_t i, m = 0;

  if (b->cons.len == 0)
    return 0;
  m = b->cons.el[0].read_off;
  for (i = 1; i < b->cons.len; i++)
    if (b->cons.el[i].read_off < m)
      m = b->cons.el[i].read_off;
  return m;
}

size_t buffer_offset(const struct buffer *b)
{
  return b->len <= b->received ? b->received - b->len : 0;
}

const unsigned char *buffer_data(const struct buffer *b)
{
  return b->data;
}

int buffer_read_at(const struct buffer *b, size_t off, void *dst, size_t n)
{
  if (off > b->len || n > b->len - off)
    return -1;
  if (n != 0)
    memcpy(dst, b->data + off, n);
  return 0;
}

int buffer_add_consumer(struct buffer *b, size_t start, size_t *idx)
{
  struct buf_consumer c;

  if (idx == NULL)
    return -1;
  c.read_off = start;
  return cvec_push(&b->cons, c, idx);
}

void buffer_remove_consumer(struct buffer *b, size_t idx)
{
  cvec_pop(&b->cons, idx);
}

int buffer_consumer_read(struct buffer *b, size_t idx, void *dst, size_t n, size_t *got)
{
  struct buf_consumer *c;
  size_t take;

  if (idx >= b->cons.len)
    return -1;
  c = &b->cons.el[idx];
  take = c->read_off > b->len ? 0 : n < b->len - c->read_off ? n : b->len - c->read_off;
  if (take != 0)
    memcpy(dst, b->data + c->read_off, take);
  c->read_off += take;
  if (got != NULL)
    *got = take;
  return 0;
}
