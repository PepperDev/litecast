#include "cast/cast.h"

#include <stdint.h>
#include <string.h>

/* === Protobuf wire encode === */

struct pb_buf {
  unsigned char *d;
  size_t cap;
  size_t n;
  int err;
};

static int msg_ok(const struct cast_msg *m)
{
  return m != NULL && m->ns != NULL && m->source != NULL && m->dest != NULL && m->json != NULL;
}

static size_t pb_varint_len(uint64_t v)
{
  size_t n = 1;

  while (v >= 0x80) {
    n++;
    v >>= 7;
  }
  return n;
}

static size_t pb_varint_write(unsigned char *o, uint64_t v)
{
  size_t n = 0;

  do {
    unsigned char c = (unsigned char)(v & 0x7f);

    v >>= 7;
    if (v)
      c |= 0x80;
    o[n++] = c;
  } while (v);
  return n;
}

static void pb_uint(struct pb_buf *b, uint64_t v)
{
  size_t n = pb_varint_len(v);

  if (b->n + n > b->cap) {
    b->err = 1;
  } else {
    b->n += pb_varint_write(b->d + b->n, v);
  }
}

static void pb_str(struct pb_buf *b, unsigned char tag, const char *s)
{
  size_t l = strlen(s);

  if (b->n + 1 + pb_varint_len(l) + l > b->cap) {
    b->err = 1;
    return;
  }
  b->d[b->n++] = tag;
  b->n += pb_varint_write(b->d + b->n, l);
  memcpy(b->d + b->n, s, l);
  b->n += l;
}

static void pb_enum(struct pb_buf *b, unsigned int f)
{
  pb_uint(b, (uint64_t) f << 3);
  pb_uint(b, 0);
}

int cast_encode(const struct cast_msg *m, unsigned char *buf, size_t cap)
{
  struct pb_buf b = { buf, cap, 0, 0 };

  if (!msg_ok(m))
    return -1;
  pb_enum(&b, 1);
  pb_str(&b, 0x12, m->source);
  pb_str(&b, 0x1a, m->dest);
  pb_str(&b, 0x22, m->ns);
  pb_enum(&b, 5);
  pb_str(&b, 0x32, m->json);
  return b.err ? -1 : (int)b.n;
}

/* === Protobuf wire decode === */

/* Read one varint with a bounded cursor; >10 bytes (or >64 bits) fail. */
static int pb_read_varint(const unsigned char *p, size_t n, size_t *off, uint64_t *out)
{
  uint64_t v = 0;
  unsigned int shift = 0;
  size_t i = *off;

  while (i < n && shift < 64) {
    unsigned char b = p[i];

    i++;
    v |= (uint64_t) (b & 0x7f) << shift;
    if ((b & 0x80) == 0) {
      *off = i;
      *out = v;
      return 0;
    }
    shift += 7;
  }
  return -1;
}

static int pb_fixed(size_t n, size_t *off, size_t want)
{
  if (n - *off < want)
    return -1;
  *off += want;
  return 0;
}

/* Length-delimited field: read its length, bounds-check, capture if needed. */
static int pb_capture(const unsigned char *p, size_t *off, size_t len, unsigned int field, struct cast_decoded *d)
{
  char *dst;
  size_t cap;

  if (field == 4) {
    dst = d->ns;
    cap = sizeof d->ns;
  } else if (field == 6) {
    dst = d->payload;
    cap = sizeof d->payload;
  } else {
    *off += len;
    return 0;
  }
  if (len >= cap)
    return -1;
  memcpy(dst, p + *off, len);
  dst[len] = '\0';
  *off += len;
  return 0;
}

static int pb_len(const unsigned char *p, size_t n, size_t *off, unsigned int field, struct cast_decoded *d)
{
  uint64_t v;

  if (pb_read_varint(p, n, off, &v) != 0)
    return -1;
  if (v > n - *off)
    return -1;
  return pb_capture(p, off, (size_t)v, field, d);
}

/* Consume one field; unknown fields and foreign wire types are handled. */
static int pb_field(const unsigned char *p, size_t n, size_t *off, uint64_t tag, struct cast_decoded *d)
{
  uint64_t v;

  switch (tag & 7) {
  case 0:
    return pb_read_varint(p, n, off, &v);
  case 1:
    return pb_fixed(n, off, 8);
  case 2:
    return pb_len(p, n, off, (unsigned int)(tag >> 3), d);
  case 5:
    return pb_fixed(n, off, 4);
  default:
    return -1;
  }
}

static int pb_decode_args(const unsigned char *pb, size_t n, struct cast_decoded *d)
{
  if (pb == NULL || d == NULL || n == 0)
    return -1;
  d->ns[0] = '\0';
  d->payload[0] = '\0';
  return 0;
}

int cast_decode(const unsigned char *pb, size_t n, struct cast_decoded *d)
{
  size_t off = 0;
  uint64_t tag;

  if (pb_decode_args(pb, n, d) != 0)
    return -1;
  while (off < n) {
    if (pb_read_varint(pb, n, &off, &tag) != 0)
      return -1;
    if (tag == 0)
      return -1;
    if (pb_field(pb, n, &off, tag, d) != 0)
      return -1;
  }
  return 0;
}
