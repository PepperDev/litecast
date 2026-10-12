#include "p256.h"

#include <string.h>

/* ECDHE session seam on the p256/ecdh primitives: the ephemeral private key,
 * its public point, and the shared pre-master secret. The premaster secret is
 * the x-coordinate of the ECDH shared point (RFC 8422 §5.10, a 32-byte field
 * element with leading zeros preserved); the private key is wiped as soon as
 * it has been derived. */

struct ecx {
  struct ec c;
  mp_int k;
  struct ec_pt r;
};

static int ecx_init(struct ecx *z)
{
  if (ec_init(&z->c) != 0)
    return -1;
  if (mp_init(&z->k) != MP_OKAY)
    goto c;
  if (mp_init_multi(&z->r.x, &z->r.y, NULL) != MP_OKAY)
    goto k;
  return 0;
 k:
  mp_clear(&z->k);
 c:
  ec_free(&z->c);
  return -1;
}

static void ecx_free(struct ecx *z)
{
  mp_clear_multi(&z->k, &z->r.x, &z->r.y, NULL);
  ec_free(&z->c);
}

static int ec_put32(const mp_int *m, unsigned char *d)
{
  size_t w;

  if (mp_to_ubin(m, d, 32, &w) != MP_OKAY)
    return -1;
  if (w < 32) {                 /* mp_to_ubin does not left-pad */
    memmove(d + 32 - w, d, w);
    memset(d, 0, 32 - w);
  }
  return 0;
}

static int ec_put(const struct ec_pt *m, unsigned char out[TLS_P256_POINT_LEN])
{
  out[0] = TLS_POINT_UNCOMPRESSED;
  if (ec_put32(&m->x, out + 1) != 0 || ec_put32(&m->y, out + 33) != 0)
    return -1;
  return 0;
}

static int ec_point_out(const struct ec *c, const mp_int *k, const struct ec_pt *p,
                        struct ec_pt *r, unsigned char out[TLS_P256_POINT_LEN])
{
  int ri;

  if (ec_mul(c, p, k, r, &ri) != 0)
    return -1;
  if (ri)
    return -1;
  if (out != NULL)
    return ec_put(r, out);
  return 0;
}

/* Parse one 32-byte big-endian coordinate and require it below the prime. */
static int ec_from32(const struct ec *c, mp_int *m, const unsigned char *b)
{
  if (mp_from_ubin(m, b, 32) != MP_OKAY)
    return -1;
  return mp_cmp(m, &c->p) == MP_LT ? 0 : -1;
}

static int ec_peer(const struct ec *c, struct ec_pt *p, const unsigned char peer[TLS_P256_POINT_LEN])
{
  if (peer[0] != TLS_POINT_UNCOMPRESSED)
    return -1;
  if (ec_from32(c, &p->x, peer + 1) != 0 || ec_from32(c, &p->y, peer + 33) != 0)
    return -1;
  if (!ec_on_curve(c, p))
    return -1;
  return 0;
}

int tls_ecdhe_pub(const unsigned char sk[32], unsigned char out[TLS_P256_POINT_LEN])
{
  struct ecx z;
  int e;

  if (ecx_init(&z) != 0)
    return -1;
  e = mp_from_ubin(&z.k, sk, 32);
  if (e != MP_OKAY || !ec_scalar_ok(&z.c, &z.k)) {
    ecx_free(&z);
    return -1;
  }
  e = ec_point_out(&z.c, &z.k, &z.c.g, &z.r, out);
  ecx_free(&z);
  return e;
}

/* Init the ECDH context and validate the ephemeral scalar and peer point. */
static int ec_peer_ok(struct ecx *z, const unsigned char sk[32], const unsigned char peer[TLS_P256_POINT_LEN])
{
  int e;

  if (ecx_init(z) != 0)
    return -1;
  e = mp_from_ubin(&z->k, sk, 32);
  if (e != MP_OKAY || !ec_scalar_ok(&z->c, &z->k)) {
    ecx_free(z);
    return -1;
  }
  if (ec_peer(&z->c, &z->r, peer) != 0) {
    ecx_free(z);
    return -1;
  }
  return 0;
}

int tls_ecdhe_shared(const unsigned char sk[32], const unsigned char peer[TLS_P256_POINT_LEN], unsigned char out[32])
{
  struct ecx z;
  int e;

  if (ec_peer_ok(&z, sk, peer) != 0)
    return -1;
  e = ec_point_out(&z.c, &z.k, &z.r, &z.r, 0);  /* discard the point form */
  if (e != 0) {
    ecx_free(&z);
    return -1;
  }
  e = ec_put32(&z.r.x, out);    /* premaster = x-coordinate (RFC 8422 §5.10) */
  ecx_free(&z);
  return e;
}

int tls_ecdhe_keygen(struct tls_hs *s)
{
  int i;

  if (s == NULL)
    return -1;
  for (i = 0; i < TLS_ECDHE_RETRIES; i++) {
    if (tls_random(s->ecdhe.priv) != 0)
      return -1;
    if (tls_ecdhe_pub(s->ecdhe.priv, s->ecdhe.pub) == 0) {
      s->ecdhe.keyed = 1;
      return 0;
    }
  }
  return -1;
}

int tls_ecdhe_derive(struct tls_hs *s)
{
  int e;

  if (s == NULL || s->ecdhe.keyed == 0 || s->ske.point_n != TLS_P256_POINT_LEN)
    return -1;
  if (s->ecdhe.done)
    return 0;
  e = tls_ecdhe_shared(s->ecdhe.priv, s->ske.point, s->ecdhe.premaster);
  if (e != 0)
    return -1;
  explicit_bzero(s->ecdhe.priv, sizeof(s->ecdhe.priv));
  s->ecdhe.done = 1;
  return 0;
}
