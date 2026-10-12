#ifndef LITECAST_TLS_RSA_H
#define LITECAST_TLS_RSA_H

#include "cast/tls.h"

#include "crypto/ltm/tommath.h"

/* RSA public-key ops for the TLS handshake (tls/rsa.c), implemented on
 * libtommath alone — libtomcrypt's pk/ layer is kept disabled. CERT_NONE
 * semantics: the X.509 leaf is parsed only to extract the RSA public key
 * (RFC 5280 SubjectPublicKeyInfo), never chain-validated. The SKE RSA
 * signature is checked with PKCS#1 v1.5 (RFC 8017 §8.2) over SHA-256. */

struct tls_rsa_pub {
  mp_int n, e;                  /* modulus, public exponent */
};

/* Extract n and e from a DER X.509 leaf. Returns 0, or -1. */
int tls_rsa_leaf_pub(struct tls_rsa_pub *k, const unsigned char *leaf, size_t leaf_n);

/* PKCS#1 v1.5 verify of `sig` (len == sizeof n) against the 32-byte SHA-256
 * digest. Returns 0 on valid, -1 on failure. */
int tls_rsa_verify(const struct tls_rsa_pub *k, const unsigned char digest[32], const unsigned char *sig, size_t sig_n);

#endif
