#include "cast/tls/crypt.h"

#include <string.h>

#include <tomcrypt.h>

/* ChaCha20-Poly1305 AEAD tag length (RFC 7539). */
#define TLS_AEAD_TAG 16

/* PRF engine state: the secret and the label || seed input. */
struct prf {
  int idx;
  const unsigned char *secret;
  size_t secret_n;
  const unsigned char *seed;
  size_t seed_n;
};

/* Register the SHA-256 hash descriptor once so find_hash("sha256") works. */
static int sha_idx(void)
{
  int idx = find_hash("sha256");

  if (idx < 0) {
    if (register_hash(&sha256_desc) != CRYPT_OK)
      return -1;
    idx = find_hash("sha256");
  }
  return idx;
}

/* HMAC-SHA256(key, a || seed); a may be empty (the A(1) step). */
static int p_mac(const struct prf *p, const unsigned char *a, size_t a_n, unsigned char out[32])
{
  hmac_state st;
  unsigned long n = 32;

  if (hmac_init(&st, p->idx, p->secret, (unsigned long)p->secret_n) != CRYPT_OK)
    return -1;
  if (a_n)
    hmac_process(&st, a, (unsigned long)a_n);
  hmac_process(&st, p->seed, (unsigned long)p->seed_n);
  hmac_done(&st, out, &n);
  return 0;
}

/* A(i+1) = HMAC-SHA256(secret, A(i)); the P_hash chaining step. */
static int a_next(const struct prf *p, unsigned char a[32])
{
  hmac_state st;
  unsigned long n = 32;

  if (hmac_init(&st, p->idx, p->secret, (unsigned long)p->secret_n) != CRYPT_OK)
    return -1;
  hmac_process(&st, a, 32);
  hmac_done(&st, a, &n);
  return 0;
}

/* Emit outlen bytes of P_hash(SHA-256) for the engine state. */
static int prf_emit(const struct prf *p, unsigned char *out, size_t outlen)
{
  unsigned char blk[32];
  unsigned char a[32];
  size_t off;

  /* A(1) = HMAC(secret, seed) */
  if (p_mac(p, NULL, 0, a) != 0)
    return -1;
  for (off = 0; off < outlen; off += 32) {
    size_t k = outlen - off < 32 ? outlen - off : 32;

    if (p_mac(p, a, 32, blk) != 0)
      return -1;
    memcpy(out + off, blk, k);
    if (a_next(p, a) != 0)      /* A(i+1) = HMAC(secret, A(i)) */
      return -1;
  }
  return 0;
}

/* RFC 5246 §5 P_hash(SHA-256): the TLS 1.2 PRF. */
int tls_prf_sha256(unsigned char *out, size_t outlen,
                   const unsigned char *secret, size_t secret_n, const struct tls_seed *s)
{
  unsigned char seedbuf[256];
  struct prf p;
  size_t sl;

  if ((p.idx = sha_idx()) < 0)
    return -1;
  sl = strlen(s->label);
  if (sl + s->seed_n > sizeof seedbuf)
    return -1;
  memcpy(seedbuf, s->label, sl);
  memcpy(seedbuf + sl, s->seed, s->seed_n);
  p.secret = secret;
  p.secret_n = secret_n;
  p.seed = seedbuf;
  p.seed_n = sl + s->seed_n;
  return prf_emit(&p, out, outlen);
}

/* Raw SHA-256 digest via the registered LTC descriptor. */
int tls_sha256(unsigned char out[32], const unsigned char *msg, size_t n)
{
  unsigned long o = 32;
  int idx = sha_idx();

  if (idx < 0)
    return -1;
  if (hash_memory(idx, msg, (unsigned long)n, out, &o) != CRYPT_OK)
    return -1;
  return 0;
}

/* RFC 5246 §8.1 master secret. */
void tls_master_secret(unsigned char out[48], const unsigned char *premaster, size_t premaster_n,
                       const unsigned char client_random[32], const unsigned char server_random[32])
{
  struct tls_seed s = { "master secret", NULL, 0 };
  unsigned char seed[64];

  memcpy(seed, client_random, 32);
  memcpy(seed + 32, server_random, 32);
  s.seed = seed;
  s.seed_n = 64;
  tls_prf_sha256(out, 48, premaster, premaster_n, &s);
  memset(seed, 0, sizeof seed);
}

/* RFC 5246 §6.3 key block. */
void tls_key_block(unsigned char *out, size_t out_n, const unsigned char master[48],
                   const unsigned char client_random[32], const unsigned char server_random[32])
{
  struct tls_seed s = { "key expansion", NULL, 0 };
  unsigned char seed[64];

  memcpy(seed, server_random, 32);
  memcpy(seed + 32, client_random, 32);
  s.seed = seed;
  s.seed_n = 64;
  tls_prf_sha256(out, out_n, master, 48, &s);
  memset(seed, 0, sizeof seed);
}

/* RFC 5246 §6.2.3.3 additional-data for one AEAD record: the 8-byte sequence
 * number followed by the 5-byte record header (type, version, length). */
void tls_record_aad(unsigned char aad[13], uint64_t seq, int type, size_t pt)
{
  int i;

  for (i = 0; i < 8; i++)
    aad[i] = (unsigned char)(seq >> (8 * (7 - i)));
  aad[8] = (unsigned char)type;
  aad[9] = 3;
  aad[10] = 3;
  aad[11] = (unsigned char)(pt >> 8);
  aad[12] = (unsigned char)pt;
}

/* Initialise and set the RFC 7905 nonce; consume the additional data.
 *
 * RFC 7905 §2: the 96-bit nonce is the 12-byte write_IV XORed with the
 * 64-bit record sequence number serialized as an 8-byte BIG-ENDIAN value,
 * padded on the left with four zero bytes (bytes 4..11 of the nonce). The
 * vendored libtomcrypt chacha20poly1305_setiv_rfc7905 folds the sequence
 * number in little-endian (STORE64L) instead, which diverges for seq >= 1;
 * recompute the nonce here in the standard byte order and hand the finished
 * 12 bytes to the plain setiv. */
static int cc_setup(chacha20poly1305_state *st, const struct tls_cc *c)
{
  unsigned char nonce[12];
  uint64_t seq = c->seq;
  int i;

  /* RFC 7905 §2: nonce = write_IV[0..3] || (write_IV[4..11] XOR seq_be).
   * The 64-bit sequence number only reaches bytes 4..11 (LSB at 11). */
  memcpy(nonce, c->iv, 12);
  for (i = 4; i < 12; i++)
    nonce[i] ^= (unsigned char)(seq >> (8 * (11 - i)));
  if (chacha20poly1305_init(st, c->key, 32) != CRYPT_OK)
    return -1;
  if (chacha20poly1305_setiv(st, nonce, 12) != CRYPT_OK)
    return -1;
  if (c->aad_n && chacha20poly1305_add_aad(st, c->aad, (unsigned long)c->aad_n) != CRYPT_OK)
    return -1;
  return 0;
}

/* Finish the 16-byte AEAD tag. */
static int cc_done(chacha20poly1305_state *st, unsigned char *tag)
{
  unsigned long taglen = TLS_AEAD_TAG;

  if (chacha20poly1305_done(st, tag, &taglen) != CRYPT_OK)
    return -1;
  return taglen == TLS_AEAD_TAG ? 0 : -1;
}

/* Seal one record: out = ciphertext || tag. */
int tls_chacha_seal(const struct tls_cc *c, unsigned char *out, size_t *out_n, const unsigned char *in, size_t in_n)
{
  chacha20poly1305_state st;

  if (cc_setup(&st, c) != 0)
    return -1;
  if (in_n && chacha20poly1305_encrypt(&st, in, (unsigned long)in_n, out) != CRYPT_OK)
    return -1;
  if (cc_done(&st, out + in_n) != 0)
    return -1;
  if (out_n)
    *out_n = in_n + TLS_AEAD_TAG;
  return 0;
}

/* Decrypt ciphertext, excluding the tagging, and finish the tag. */
static int cc_decrypt(chacha20poly1305_state *st, const unsigned char *in, size_t in_n,
                      unsigned char *out, unsigned char *tag)
{
  if (in_n && chacha20poly1305_decrypt(st, in, (unsigned long)in_n, out) != CRYPT_OK)
    return -1;
  return cc_done(st, tag);
}

/* Open one record; data = ciphertext || tag. Returns 0, or -1 on auth fail. */
int tls_chacha_open(const struct tls_cc *c, unsigned char *out, const unsigned char *in, size_t in_n)
{
  chacha20poly1305_state st;
  unsigned char tag[TLS_AEAD_TAG];

  if (in_n < TLS_AEAD_TAG)
    return -1;
  if (cc_setup(&st, c) != 0)
    return -1;
  if (cc_decrypt(&st, in, in_n - TLS_AEAD_TAG, out, tag) != 0)
    return -1;
  return mem_neq(tag, in + in_n - TLS_AEAD_TAG, TLS_AEAD_TAG) ? -1 : 0;
}
