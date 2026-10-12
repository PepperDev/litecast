#include "p256.h"

#include <string.h>

/* secp256r1 domain constants, cross-checked with an independent Python
 * reference (p prime, G on-curve, n*G = O). The field arithmetic is
 * litecast's own on libtommath bignums; the vendored library supplies the
 * primitive only. Errors cascade as -1, never a silent partial state. */

static const char P256_P2[] = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
static const char P256_B2[] = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
static const char P256_GX[] = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
static const char P256_GY[] = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
static const char P256_N2[] = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

static int ec_read(mp_int *mp, const char *s)
{
  return mp_read_radix(mp, s, 16) == MP_OKAY ? 0 : -1;
}

static int ec_reads(struct ec *c)
{
  static const char *const s5[5] = { P256_P2, P256_B2, P256_GX, P256_GY, P256_N2 };
  mp_int *d[5] = { &c->p, &c->b, &c->g.x, &c->g.y, &c->n };
  int i;

  for (i = 0; i < 5; i++)
    if (ec_read(d[i], s5[i]) != 0)
      return -1;
  return 0;
}

int ec_init(struct ec *c)
{
  if (mp_init_multi(&c->p, &c->b, &c->n, &c->three, &c->g.x, &c->g.y, NULL) != MP_OKAY)
    return -1;
  if (ec_reads(c) != 0) {
    ec_free(c);
    return -1;
  }
  mp_set(&c->three, 3);
  return 0;
}

void ec_free(struct ec *c)
{
  mp_clear_multi(&c->p, &c->b, &c->n, &c->three, &c->g.x, &c->g.y, NULL);
}

int ec_scalar_ok(const struct ec *c, const mp_int *k)
{
  return mp_iszero(k) == MP_NO && mp_cmp(k, &c->n) == MP_LT;
}

/* s := x^2, t := x^3 (mod p). */
static int ec_x3(const struct ec *c, const mp_int *x, mp_int *s, mp_int *t)
{
  int e = MP_OKAY;

  EC_STEP(e, mp_sqrmod(x, &c->p, s));
  EC_STEP(e, mp_mulmod(s, x, &c->p, t));
  return e == MP_OKAY ? 0 : -1;
}

/* t := x^3 - 3x + b (mod p). */
static int ec_cube_x(const struct ec *c, const mp_int *x, mp_int *t)
{
  mp_int s, w;
  int e;

  if (mp_init_multi(&s, &w, NULL) != MP_OKAY)
    return -1;
  e = ec_x3(c, x, &s, t);
  if (e == 0)
    e = mp_mulmod(x, &c->three, &c->p, &w);
  EC_STEP(e, mp_submod(t, &w, &c->p, t));
  EC_STEP(e, mp_addmod(t, &c->b, &c->p, t));
  mp_clear_multi(&s, &w, NULL);
  return e == 0 ? 0 : -1;
}

/* 1 when (x,y) is on the curve: y^2 == x^3 - 3x + b. */
int ec_on_curve(const struct ec *c, const struct ec_pt *a)
{
  mp_int s, t;
  int e;

  if (mp_init_multi(&s, &t, NULL) != MP_OKAY)
    return 0;
  e = ec_cube_x(c, &a->x, &t);
  if (e == 0)
    e = mp_sqrmod(&a->y, &c->p, &s);
  if (e != MP_OKAY) {
    mp_clear_multi(&s, &t, NULL);
    return 0;
  }
  e = mp_cmp(&t, &s) == MP_EQ;
  mp_clear_multi(&s, &t, NULL);
  return e;
}
