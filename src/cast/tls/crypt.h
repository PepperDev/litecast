#ifndef LITECAST_TLS_CRYPT_H
#define LITECAST_TLS_CRYPT_H

#include <stddef.h>
#include <stdint.h>

/* TLS 1.2 PRF and ChaCha20-Poly1305 record cipher, implemented on the
 * vendored libtomcrypt primitives (SHA-256, ChaCha20, Poly1305). The PRF
 * is RFC 5246 §5 P_hash(SHA-256); the AEAD nonce is the RFC 7905 §2
 * construction (12-byte implicit IV XOR padded record sequence number) —
 * there is no per-record explicit nonce. Context structs keep every
 * public function at five parameters or fewer. */

/* PRF input: label || seed (RFC 5246 §5). */
struct tls_seed {
  const char *label;
  const unsigned char *seed;
  size_t seed_n;
};

/* Raw SHA-256 digest of msg (RFC 6234); always writes 32 bytes. */
int tls_sha256(unsigned char out[32], const unsigned char *msg, size_t n);

/* AEAD per-record context: 32-byte key, 12-byte implicit IV, record
 * sequence number, and the additional data (the 13-byte record header). */
struct tls_cc {
  const unsigned char *key;
  const unsigned char *iv;
  uint64_t seq;
  const unsigned char *aad;
  size_t aad_n;
};

/* RFC 5246 §6.2.3.3 additional-data: seq(8) || type || version || length. */
void tls_record_aad(unsigned char aad[13], uint64_t seq, int type, size_t pt);

/* RFC 5246 PRF: outlen bytes of P_hash(SHA-256)(secret, label || seed). */
int tls_prf_sha256(unsigned char *out, size_t outlen,
                   const unsigned char *secret, size_t secret_n, const struct tls_seed *seed);

/* RFC 5246 §8.1 master secret = PRF(premaster, "master secret", CR || SR). */
void tls_master_secret(unsigned char out[48], const unsigned char *premaster, size_t premaster_n,
                       const unsigned char client_random[32], const unsigned char server_random[32]);

/* RFC 5246 §6.3 key block = PRF(master, "key expansion", SR || CR). */
void tls_key_block(unsigned char *out, size_t out_n, const unsigned char master[48],
                   const unsigned char client_random[32], const unsigned char server_random[32]);

/* Seal one TLS application-data record (RFC 7905 / RFC 5246 §6.2.3.3):
 * out = ciphertext || tag. Returns 0, or -1. */
int tls_chacha_seal(const struct tls_cc *c, unsigned char *out, size_t *out_n, const unsigned char *in, size_t in_n);

/* Open one record, authenticating the additional data; returns 0 (plaintext
 * in out) or -1 on tag failure. */
int tls_chacha_open(const struct tls_cc *c, unsigned char *out, const unsigned char *in, size_t in_n);

#endif
