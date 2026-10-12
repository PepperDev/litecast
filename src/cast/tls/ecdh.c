#include "p256.h"

/* Affine Weierstrass point arithmetic on secp256r1 (a = -3 folded into the
 * `three` field). All functions return 0 or -1; `ec` contexts come from
 * tls/p256.c. The scalar multiplication (LSB-first double-and-add) is the
 * shared workhorse of both the public and shared-vector seams in tls/e.c
 * — these helpers are static because nothing outside this file needs them. */

static int ec_delta(const struct ec *c, const struct ec_pt *a, const struct ec_pt *b, mp_int *dx, mp_int *dy)
{
  int e = MP_OKAY;

  EC_STEP(e, mp_submod(&b->y, &a->y, &c->p, dy));
  EC_STEP(e, mp_submod(&b->x, &a->x, &c->p, dx));
  return e == MP_OKAY ? 0 : -1;
}

static int ec_lambda_x(const struct ec *c, mp_int *m, const struct ec_pt *a, const struct ec_pt *b)
{
  mp_int dx, dy;
  int e = MP_OKAY;

  if (mp_init_multi(&dx, &dy, NULL) != MP_OKAY)
    return -1;
  EC_STEP(e, ec_delta(c, a, b, &dx, &dy));
  EC_STEP(e, mp_invmod(&dx, &c->p, &dx));
  EC_STEP(e, mp_mulmod(&dy, &dx, &c->p, m));
  mp_clear_multi(&dx, &dy, NULL);
  return e == MP_OKAY ? 0 : -1;
}

/* Slope m for a doubling: (3(x^2 - 1))/(2y). */
static int ec_num(const struct ec *c, const struct ec_pt *a, mp_int *n)
{
  mp_int t;
  int e;

  if (mp_init(&t) != MP_OKAY)
    return -1;
  e = mp_sqrmod(&a->x, &c->p, &t);
  EC_STEP(e, mp_sub_d(&t, 1, &t));
  EC_STEP(e, mp_mulmod(&t, &c->three, &c->p, n));       /* 3(x^2 - 1) */
  mp_clear(&t);
  return e == MP_OKAY ? 0 : -1;
}

static int ec_den(const struct ec *c, const struct ec_pt *a, mp_int *t)
{
  return mp_addmod(&a->y, &a->y, &c->p, t) == MP_OKAY ? 0 : -1;
}

static int ec_lambda_d(const struct ec *c, mp_int *m, const struct ec_pt *a)
{
  mp_int n, t;
  int e = MP_OKAY;

  if (mp_init_multi(&n, &t, NULL) != MP_OKAY)
    return -1;
  EC_STEP(e, ec_num(c, a, &n));
  EC_STEP(e, ec_den(c, a, &t));
  EC_STEP(e, mp_invmod(&t, &c->p, &t));
  EC_STEP(e, mp_mulmod(&n, &t, &c->p, m));
  if (e != MP_OKAY)
    e = -1;
  mp_clear_multi(&n, &t, NULL);
  return e;
}

static int ec_line_x(const struct ec *c, struct ec_pt *r, const mp_int *m, const struct ec_pt *a, const struct ec_pt *b)
{
  int e = MP_OKAY;

  EC_STEP(e, mp_sqrmod(m, &c->p, &r->x));
  EC_STEP(e, mp_submod(&r->x, &a->x, &c->p, &r->x));
  EC_STEP(e, mp_submod(&r->x, &b->x, &c->p, &r->x));
  return e == MP_OKAY ? 0 : -1;
}

static int ec_line_y(const struct ec *c, struct ec_pt *r, const mp_int *m, const struct ec_pt *a)
{
  mp_int t;
  int e;

  if (mp_init(&t) != MP_OKAY)
    return -1;
  e = mp_submod(&a->x, &r->x, &c->p, &t);
  EC_STEP(e, mp_mulmod(m, &t, &c->p, &t));
  EC_STEP(e, mp_submod(&t, &a->y, &c->p, &r->y));
  mp_clear(&t);
  return e == MP_OKAY ? 0 : -1;
}

static int ec_copy_pt(struct ec_pt *to, const struct ec_pt *from)
{
  if (mp_copy(&from->x, &to->x) != MP_OKAY)
    return -1;
  if (mp_copy(&from->y, &to->y) != MP_OKAY)
    return -1;
  return 0;
}

static int ec_line(const struct ec *c, struct ec_pt *r, const mp_int *m, const struct ec_pt *a, const struct ec_pt *b)
{
  struct ec_pt q;
  int e = MP_OKAY;

  if (mp_init_multi(&q.x, &q.y, NULL) != MP_OKAY)
    return -1;
  EC_STEP(e, ec_line_x(c, &q, m, a, b));
  EC_STEP(e, ec_line_y(c, &q, m, a));
  EC_STEP(e, ec_copy_pt(r, &q));
  mp_clear_multi(&q.x, &q.y, NULL);
  return e == MP_OKAY ? 0 : -1;
}

/* 1 when y1 == -y2 (mod p), i.e. set-add of opposites → infinity. */
static int ec_cancel(const struct ec *c, const struct ec_pt *r, const struct ec_pt *p, mp_int *w)
{
  if (mp_addmod(&r->y, &p->y, &c->p, w) != MP_OKAY)
    return -1;
  return mp_iszero(w) ? 1 : 0;
}

static int ec_double(const struct ec *c, struct ec_pt *r, mp_int *m)
{
  int e = MP_OKAY;

  EC_STEP(e, ec_lambda_d(c, m, r));
  EC_STEP(e, ec_line(c, r, m, r, r));
  return e == MP_OKAY ? 0 : -1;
}

/* r = 2r, or set ri = 1 when y1 == -y2. */
static int ec_add_same(const struct ec *c, int *ri, struct ec_pt *r, const struct ec_pt *p)
{
  mp_int m, w;
  int e;

  if (mp_init_multi(&m, &w, NULL) != MP_OKAY)
    return -1;
  e = ec_cancel(c, r, p, &w);
  if (e == 1) {
    mp_clear_multi(&m, &w, NULL);
    *ri = 1;
    return 0;
  }
  if (e == 0)
    e = ec_double(c, r, &m);
  mp_clear_multi(&m, &w, NULL);
  return e;
}

static int ec_add_distinct(const struct ec *c, struct ec_pt *r, const struct ec_pt *p)
{
  mp_int m;
  int e = MP_OKAY;

  if (mp_init(&m) != MP_OKAY)
    return -1;
  EC_STEP(e, ec_lambda_x(c, &m, r, p));
  EC_STEP(e, ec_line(c, r, &m, r, p));
  mp_clear(&m);
  return e == MP_OKAY ? 0 : -1;
}

/* r += p; *ri flags the accumulator at infinity, pi the addend. */
static int ec_add(const struct ec *c, int *ri, struct ec_pt *r, int pi, const struct ec_pt *p)
{
  if (pi)
    return 0;
  if (*ri == 0) {
    if (mp_cmp(&r->x, &p->x) == MP_EQ)
      return ec_add_same(c, ri, r, p);
    return ec_add_distinct(c, r, p);
  }
  if (mp_copy(&p->x, &r->x) != MP_OKAY)
    return -1;
  if (mp_copy(&p->y, &r->y) != MP_OKAY)
    return -1;
  *ri = 0;
  return 0;
}

/* LSB-first double-and-add; kk and w are the working scalar and point. */
static int ec_mul_bits(const struct ec *c, int *ri, struct ec_pt *r, mp_int *kk, struct ec_pt *w)
{
  int pi = 0;

  while (mp_iszero(kk) == MP_NO) {
    if (mp_isodd(kk) == MP_YES && ec_add(c, ri, r, 0, w) != 0)
      return -1;
    if (ec_add(c, &pi, w, 0, w) != 0)
      return -1;
    if (mp_div_2(kk, kk) != MP_OKAY)
      return -1;
  }
  return 0;
}

static int ec_setup(const mp_int *k, const struct ec_pt *p, mp_int *kk, struct ec_pt *w)
{
  mp_err e;

  e = mp_init_copy(kk, k);
  if (e != MP_OKAY)
    return -1;
  e = mp_init_copy(&w->x, &p->x);
  if (e != MP_OKAY) {
    mp_clear(kk);
    return -1;
  }
  e = mp_init_copy(&w->y, &p->y);
  if (e != MP_OKAY) {
    mp_clear_multi(kk, &w->x, NULL);
    return -1;
  }
  return 0;
}

/* (ri, r) = k * p; *ri = 1 only for k == 0. */
int ec_mul(const struct ec *c, const struct ec_pt *p, const mp_int *k, struct ec_pt *r, int *ri)
{
  mp_int kk;
  struct ec_pt w;
  int e;

  if (ec_setup(k, p, &kk, &w) != 0)
    return -1;
  *ri = 1;
  e = ec_mul_bits(c, ri, r, &kk, &w);
  mp_clear_multi(&kk, &w.x, &w.y, NULL);
  return e;
}
