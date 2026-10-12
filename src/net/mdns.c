#include "net/mdns.h"
#include "net/mdns_name.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char u8;

struct dlist {
  struct mdns_device *dev;
  int max;
  int len;
};

struct rd_rec {
  char owner[MDNS_NAME_CAP];
  struct mdns_name_acc acc;
  const u8 *r;
  size_t rdlen;
  uint16_t type;
  uint16_t rclass;
};

static unsigned int rd16(const u8 *p, size_t o)
{
  return (unsigned int)(p[o] << 8 | p[o + 1]);
}

static int ci_char(int c)
{
  return tolower(c);
}

static int ci_lit(const u8 *k, size_t kl, const char *lit)
{
  size_t i;

  if (strlen(lit) != kl)
    return 0;
  for (i = 0; i < kl; i++) {
    if (ci_char(k[i]) != ci_char((unsigned char)lit[i]))
      return 0;
  }
  return 1;
}

static int ci_str(const char *a, const char *b)
{
  for (;;) {
    int x = ci_char((unsigned char)*a);
    int y = ci_char((unsigned char)*b);

    if (x != y)
      return 0;
    if (*a == '\0')
      return 1;
    a++;
    b++;
  }
}

static void set_str(char *dst, size_t cap, const u8 *src, size_t len)
{
  size_t k;

  if (cap == 0)
    return;
  for (k = 0; k < len && k < cap - 1; k++)
    dst[k] = (char)src[k];
  dst[k] = '\0';
}

static struct mdns_device *find_host(struct dlist *l, const char *host)
{
  int i;

  for (i = 0; i < l->len; i++) {
    if (ci_str(l->dev[i].host, host))
      return &l->dev[i];
  }
  return NULL;
}

/* Extra records are owned by the service instance name (`host`) or, for the
 * A record, by the SRV target hostname — a real Chromecast attaches the A to
 * `<uuid>.local.` while the instance is `Chromecast-<uuid>._googlecast._tcp
 * .local.`. Match against either. */
static struct mdns_device *find_device(struct dlist *l, const char *owner)
{
  int i;

  for (i = 0; i < l->len; i++) {
    if (ci_str(l->dev[i].host, owner) || ci_str(l->dev[i].srv_host, owner))
      return &l->dev[i];
  }
  return NULL;
}

static void add_device(struct dlist *l, const char *host)
{
  struct mdns_device *p;

  if (find_host(l, host) != NULL)
    return;
  if (l->len >= l->max)
    return;
  p = &l->dev[l->len];
  memset(p, 0, sizeof(*p));
  set_str(p->host, sizeof p->host, (const u8 *)host, strlen(host));
  p->port = 8009;
  l->len++;
}

/* TXT key to device field: 1/name (fn), 2/uuid (id), 3/model (md),
 * 4/app (rs), 0 when the key is not one of those. */
static unsigned int txt_field(const u8 *k, size_t kl)
{
  if (ci_lit(k, kl, "fn"))
    return 1;
  if (ci_lit(k, kl, "id"))
    return 2;
  if (ci_lit(k, kl, "md"))
    return 3;
  if (ci_lit(k, kl, "rs"))
    return 4;
  return 0;
}

static void txt_apply(struct mdns_device *d, const u8 *k, size_t kl, const u8 *v, size_t vl)
{
  switch (txt_field(k, kl)) {
  case 1:
    set_str(d->name, sizeof d->name, v, vl);
    break;
  case 2:
    set_str(d->uuid, sizeof d->uuid, v, vl);
    break;
  case 3:
    set_str(d->model, sizeof d->model, v, vl);
    break;
  case 4:
    set_str(d->app, sizeof d->app, v, vl);
    break;
  }
}

static void txt_parse(const u8 *r, size_t rdlen, struct mdns_device *d)
{
  size_t o = 0;

  while (o < rdlen) {
    size_t l = r[o];
    const u8 *eq;

    o++;
    if (l == 0 || o + l > rdlen)
      break;
    eq = memchr(r + o, '=', l);
    if (eq != NULL)
      (void)txt_apply(d, r + o, (size_t)(eq - (r + o)), eq + 1, (size_t)(r + o + l - (eq + 1)));
    o += l;
  }
}

static void ptr_target(const u8 *pkt, size_t n, const u8 *r, struct dlist *l)
{
  char target[MDNS_NAME_CAP];
  struct mdns_name_acc acc = { target, sizeof target, 0 };
  size_t next;

  if (mdns_name(pkt, n, (size_t)(r - pkt), &acc, &next) == 0)
    add_device(l, target);
}

/* The cast endpoint always listens on 8009; a vendored device may publish
 * an HTML5 app on another port, which must not win. An SRV port is trusted
 * only for the cast endpoint. */
static uint16_t srv_port(const struct rd_rec *rr)
{
  if (rr->rdlen < 6)
    return 0;
  if ((rr->r[4] << 8 | rr->r[5]) != 8009)
    return 0;
  return (uint16_t) (rr->r[4] << 8 | rr->r[5]);
}

/* SRV rdata is [priority(2) weight(2) port(2) target(name)]. Record the
 * target hostname so the A record — which a real Chromecast owners with the
 * SRV *target*, not the service instance — can be associated later. */
static void srv_target(const u8 *pkt, size_t n, const struct rd_rec *rr, struct mdns_device *d)
{
  struct mdns_name_acc acc = { d->srv_host, sizeof d->srv_host, 0 };
  size_t next;

  if (rr->rdlen >= 6)
    (void)mdns_name(pkt, n, (size_t)(rr->r - pkt + 6), &acc, &next);
}

static void record_extra(const u8 *pkt, size_t n, const struct rd_rec *rr, struct mdns_device *d)
{
  if (rr->type == 33) {
    uint16_t p = srv_port(rr);

    if (p != 0)
      d->port = p;
    srv_target(pkt, n, rr, d);
  } else if (rr->type == 16)
    txt_parse(rr->r, rr->rdlen, d);
  else if (rr->type == 1 && rr->rdlen == 4)
    memcpy(&d->ip, rr->r, 4);
}

static void record_apply(const u8 *pkt, size_t n, const struct rd_rec *rr, struct dlist *l)
{
  struct mdns_device *d;

  if (rr->type == 12) {
    if (ci_str(rr->owner, MDNS_SERVICE))
      ptr_target(pkt, n, rr->r, l);
    return;
  }
  d = find_device(l, rr->owner);
  if (d == NULL)
    return;
  record_extra(pkt, n, rr, d);
}

static size_t rec_next(const u8 *pkt, size_t n, size_t o, struct rd_rec *rr)
{
  size_t o2;

  if (mdns_name(pkt, n, o, &rr->acc, &o2) != 0)
    return n + 1;
  o = o2;
  if (o + 10 > n)
    return n + 1;
  rr->type = rd16(pkt, o);
  rr->rclass = rd16(pkt, o + 2);
  rr->rdlen = rd16(pkt, o + 8);
  rr->r = pkt + o + 10;
  o += 10;
  if (o + rr->rdlen > n)
    return n + 1;
  return o + rr->rdlen;
}

static void skip_questions(const u8 *pkt, size_t n, size_t qd, size_t *o)
{
  unsigned int i;

  for (i = 0; i < qd; i++) {
    char stub[1];
    struct mdns_name_acc acc = { stub, sizeof stub, 0 };
    size_t o2;

    if (mdns_name(pkt, n, *o, &acc, &o2) != 0)
      break;
    *o = o2;
    if (*o + 4 > n)
      break;
    *o += 4;
  }
}

static int parse_records(const u8 *pkt, size_t n, size_t o, unsigned int total, struct dlist *l)
{
  unsigned int r;

  for (r = 0; r < total; r++) {
    struct rd_rec rr;

    rr.acc.buf = rr.owner;
    rr.acc.cap = sizeof rr.owner;
    rr.acc.len = 0;
    o = rec_next(pkt, n, o, &rr);
    if (o > n)
      return 0;
    /* Accept the CACHE_FLUSH variant (class 0x8001) that live devices use
     * for fresh announcements in the additional section; the low 15 bits
     * hold the record class, the high bit marks the cache flush. */
    if ((rr.rclass & 0x7FFF) == 1)
      record_apply(pkt, n, &rr, l);
  }
  return 0;
}

int mdns_parse(const u8 *pkt, size_t n, struct mdns_device *devices, int maxdev, int *count)
{
  struct dlist l = { devices, maxdev, 0 };
  size_t o;

  if (pkt == NULL || n < 12 || count == NULL || maxdev <= 0)
    return -1;
  o = 12;
  skip_questions(pkt, n, rd16(pkt, 4), &o);
  (void)parse_records(pkt, n, o, rd16(pkt, 6) + rd16(pkt, 8) + rd16(pkt, 10), &l);
  *count = l.len;
  return 0;
}
