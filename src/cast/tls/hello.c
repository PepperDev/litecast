#include "cast/tls.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>

enum {
  TLS_NUM_SUITES = 2            /* suites offered on the wire */
};

#ifdef LITECAST_TEST
/* Deterministic xorshift64* PRNG so a recorded exchange can be replayed
 * byte-for-byte: the ephemeral ECDHE key must match the live capture
 * (LITECAST_TEST hook precedent: spool.c). Never compiled into bin/. */
static uint64_t prng_state = 0x243f6a8885a308d3ULL;

static uint64_t prng_next(void)
{
  prng_state ^= prng_state >> 12;
  prng_state ^= prng_state << 25;
  prng_state ^= prng_state >> 27;
  return prng_state * 0x2545f4914f6cdd1dULL;
}

/* Restore the initial PRNG state so the test replay of a recorded exchange
 * reproduces the same ephemeral ECDHE key (and hence the same Finished
 * bytes) as the live capture. Test-only; never compiled into bin/. */
void tls_test_prng_reset(void)
{
  prng_state = 0x243f6a8885a308d3ULL;
}
#endif

/* Fill out[] with portably random bytes via the kernel entropy pool. */
#ifdef LITECAST_TEST
int tls_random(unsigned char out[32])
{
  size_t i;

  for (i = 0; i < 32; i++)
    out[i] = (unsigned char)(prng_next() >> 56);
  return 0;
}
#else
int tls_random(unsigned char out[32])
{
  size_t off = 0;

  while (off < 32) {
    ssize_t r = getrandom(out + off, 32 - off, 0);

    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return 0;
}
#endif

static size_t be16(unsigned char *p, unsigned int v)
{
  p[0] = (unsigned char)(v >> 8);
  p[1] = (unsigned char)(v & 0xff);
  return 2;
}

/* The ClientHello extensions, in wire order (RFC 5246 §7.4.1.2). */
struct ch_ext {
  unsigned int id;
  unsigned char payload;
  unsigned char data[4];
};

static const struct ch_ext CH_EXTS[] = {
  {TLS_EXT_CURVES, 4, {0x00, 0x02, 0x00, TLS_CURVE_P256}},
  /* ec_point_formats: the whole list, length-prefixed (RFC 8422 §5.1.2).
   * A list of only uncompressed is valid RFC but the cast receiver aborts
   * with illegal_parameter — offer the three standard formats (verified
   * live, DOMAIN.md §Minimal TLS client). */
  {TLS_EXT_POINTS, 4, {0x03, 0x00, 0x01, 0x02}},
  /* signature_algorithms: 2-byte vector length + sha256/rsa (RFC 5246
   * §7.4.1.4.1). The inner length is mandatory; omitting it makes the
   * cast receiver abort the handshake (verified live). */
  {TLS_EXT_SIGALGS, 4, {0x00, 0x02, TLS_HASH_SHA256, TLS_SIG_RSA}},
  {TLS_EXT_RENEG, 1, {0x00}}
};

/* Append one length-prefixed extension entry; returns bytes written. */
static size_t ch_append(unsigned char *o, const struct ch_ext *e)
{
  o[0] = (unsigned char)(e->id >> 8);
  o[1] = (unsigned char)(e->id & 0xff);
  o[2] = 0;
  o[3] = e->payload;
  memcpy(o + 4, e->data, e->payload);
  return 4 + e->payload;
}

/* Append the length-prefixed extension block; returns bytes written (0 if
 * the caller's cap cannot hold it — never the case with TLS_HELLO_CAP). */
static size_t ch_ext(unsigned char *o, size_t cap)
{
  size_t p = 2;
  size_t i;

  for (i = 0; i < sizeof CH_EXTS / sizeof CH_EXTS[0]; i++) {
    if (p + 4 + CH_EXTS[i].payload > cap)
      return 0;
    p += ch_append(o + p, &CH_EXTS[i]);
  }
  be16(o, (unsigned int)(p - 2));
  return p;
}

/* The ClientHello handshake body (after the 4-byte handshake header). */
static size_t ch_body(unsigned char *o, const unsigned char random[32])
{
  size_t p = 0;

  p += be16(o + p, TLS_VERSION_1_2);
  memcpy(o + p, random, 32);
  p += 32;
  o[p++] = 0x00;                /* empty session id */
  p += be16(o + p, (unsigned int)(TLS_NUM_SUITES * 2));
  p += be16(o + p, TLS_SUITE_CHACHA);
  p += be16(o + p, TLS_SUITE_AES_GCM);
  o[p++] = 0x01;                /* one compression method */
  o[p++] = 0x00;                /* null */
  p += ch_ext(o + p, TLS_HELLO_CAP - p);
  return p;
}

/* Fill the record + handshake length fields; returns the total length. */
static size_t ch_lengths(unsigned char *o, size_t p)
{
  o[3] = (unsigned char)((p - 5) >> 8);
  o[4] = (unsigned char)(p - 5);
  o[6] = (unsigned char)((p - 9) >> 16);
  o[7] = (unsigned char)((p - 9) >> 8);
  o[8] = (unsigned char)(p - 9);
  return p;
}

/* Build the complete ClientHello TLS record (RFC 5246 §7.4.1.2): TLS 1.2,
 * handshake content, two ECDHE-RSA suites only. Never offered: CBC or any
 * suite the device must not pick (DOMAIN.md §Minimal TLS client). */
int tls_client_hello(unsigned char out[TLS_HELLO_CAP], const unsigned char random[32])
{
  out[0] = TLS_REC_HANDSHAKE;
  out[1] = 0x03;
  out[2] = 0x03;
  out[5] = TLS_HS_CLIENT_HELLO;
  return (int)ch_lengths(out, 9 + ch_body(out + 9, random));
}
