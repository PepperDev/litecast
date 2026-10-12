#include "cast/tls.h"
#include "cast/tls/record.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* === Input queue ===
 * The reassembly buffer the record layer drains from. Growing is geometric
 * (min 64B steps, capped at 64KB) to amortise reallocs while the tls_hs_pump
 * loop re-feeds the queue. */

size_t rec_avail(const struct tls_hs *s)
{
  return s->inq_n - s->inq_off;
}

void rec_drop(struct tls_hs *s, size_t n)
{
  s->inq_off += n;
  if (s->inq_off == s->inq_n) {
    s->inq_off = 0;
    s->inq_n = 0;
  }
}

/* Copy up to want-have bytes from the queue into buf; returns bytes moved. */
size_t rec_take(struct tls_hs *s, unsigned char *buf, size_t have, size_t want)
{
  size_t n = want - have;
  size_t a = rec_avail(s);

  if (n > a)
    n = a;
  if (n) {
    memcpy(buf + have, s->inq + s->inq_off, n);
    rec_drop(s, n);
  }
  return n;
}

static void inq_compact(struct tls_hs *s)
{
  if (s->inq_off > 0) {
    memmove(s->inq, s->inq + s->inq_off, s->inq_n - s->inq_off);
    s->inq_n -= s->inq_off;
    s->inq_off = 0;
  }
}

static int inq_grow(struct tls_hs *s, size_t need)
{
  size_t step;
  size_t cap;
  unsigned char *nb;

  if (need <= s->inq_cap)
    return 0;
  step = s->inq_cap > 64 ? s->inq_cap : 64;
  if (step > 65536)
    step = 65536;
  if (need - s->inq_cap > step)
    step = need - s->inq_cap;
  cap = ((s->inq_cap + step) + 63) & ~(size_t)63;
  nb = realloc(s->inq, cap);
  if (nb == NULL)
    return -1;
  s->inq = nb;
  s->inq_cap = cap;
  return 0;
}

int tls_hs_feed(struct tls_hs *s, const unsigned char *p, size_t n)
{
  if (s == NULL)
    return -1;
  if (p == NULL && n > 0)
    return -1;
  if (n == 0)
    return 0;
  inq_compact(s);
  if (inq_grow(s, s->inq_n + n) != 0)
    return -1;
  memcpy(s->inq + s->inq_n, p, n);
  s->inq_n += n;
  return 0;
}
