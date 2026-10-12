#ifndef LITECAST_TLS_P256_H
#define LITECAST_TLS_P256_H

#include "cast/tls.h"

#include "crypto/ltm/tommath.h"

/* secp256r1 domain + field arithmetic (tls/p256.c) and point arithmetic
 * (tls/ecdh.c), the primitive layers of the ECDHE seam in tls/ecdhe.c.
 * Callers ec_init()/ec_free() each context; all functions return -1 on
 * error (except the boolean predicates). */

/* EC_STEP: run op only while err is still MP_OKAY; keeps the op chains
 * within lizard's CCN without swallowing the failure checks. */
#define EC_STEP(err, op) \
  do { \
    if ((err) == MP_OKAY) \
      (err) = (op); \
  } while (0)

struct ec_pt {
  mp_int x, y;
};

struct ec {
  mp_int p, b, n, three;        /* a = -3 folds into `three` */
  struct ec_pt g;               /* generator */
};

int ec_init(struct ec *c);
void ec_free(struct ec *c);
int ec_scalar_ok(const struct ec *c, const mp_int * k);
int ec_on_curve(const struct ec *c, const struct ec_pt *a);

/* tls/ecdh.c: (ri, r) = k * p; *ri = 1 only when k == 0 (point at infinity). */
int ec_mul(const struct ec *c, const struct ec_pt *p, const mp_int * k, struct ec_pt *r, int *ri);

#endif
