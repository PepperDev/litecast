#include "net/mdns_name.h"

#include <stdint.h>

struct nm_elem {
  size_t next;
  size_t start;
  unsigned int len;
};

static void acc_push(struct mdns_name_acc *a, const unsigned char *pkt, size_t off, unsigned int l)
{
  size_t i;

  if (a->cap == 0 || a->len > a->cap || a->cap - a->len < (size_t)l + 1)
    return;
  for (i = 0; i < l; i++)
    a->buf[a->len++] = (char)pkt[off + i];
  a->buf[a->len++] = '.';
}

/* Decode one DNS name element at off; a pointer element lands in start.
 * Returns 1 for a compression pointer, 0 for a label, -1 on out-of-bounds. */
static int dns_elem(const unsigned char *pkt, size_t n, size_t off, struct nm_elem *e)
{
  unsigned int l;
  size_t s = off;

  if (s >= n)
    return -1;
  l = pkt[s];
  s++;
  if ((l & 0xC0) == 0xC0) {
    if (s >= n)
      return -1;
    e->len = 0;
    e->start = ((l & 0x3F) << 8) | pkt[s];
    e->next = s + 1;
    return 1;
  }
  if (l > 63 || s + l > n)
    return -1;
  e->len = l;
  e->start = s;
  e->next = s + l;
  return 0;
}

/* Apply the compression pointer in e: strictly backward, bounded hop count.
 * On violation returns a poisoned offset that the next element read rejects. */
static size_t nm_jump(const struct nm_elem *e, size_t o, int *jumps)
{
  if (e->start >= o)
    return SIZE_MAX;
  if (++*jumps > 20)
    return SIZE_MAX;
  return e->start;
}

int mdns_name(const unsigned char *pkt, size_t n, size_t off, struct mdns_name_acc *acc, size_t *next)
{
  size_t o = off;
  int jumps = 0;

  while (1) {
    struct nm_elem e;
    int r = dns_elem(pkt, n, o, &e);

    if (r < 0)
      return -1;
    if (jumps == 0)
      *next = e.next;
    if (r == 1)
      o = nm_jump(&e, o, &jumps);
    else {
      o = e.next;
      if (e.len == 0)
        break;
      acc_push(acc, pkt, e.start, e.len);
    }
  }
  acc->buf[acc->len] = '\0';
  return 0;
}
