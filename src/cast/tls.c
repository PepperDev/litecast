#include "cast/tls.h"

#include "cast/tls/crypt.h"
#include "cast/tls/rsa.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static unsigned int u24(const unsigned char *p)
{
  return ((unsigned int)p[0] << 16) | ((unsigned int)p[1] << 8) | p[2];
}

/* True unless the extension is renegotiation_info (RFC 5746), never used. */
static int ext_ok(const unsigned char *p, size_t len)
{
  if (p[0] != 0xff || p[1] != 0x01)
    return 1;
  return len == 1 && p[4] == 0x00;
}

/* Walk a ServerHello extension block bounded by its declared length. */
static int sh_exts(const unsigned char *b, size_t n)
{
  size_t o = 0;

  while (o < n) {
    size_t len;

    if (n - o < 4)
      return -1;
    len = (size_t)((b[o + 2] << 8) | b[o + 3]);
    if (len > n - o - 4)
      return -1;
    if (!ext_ok(b + o, len))
      return -1;
    o += 4 + len;
  }
  return 0;
}

/* RFC 5246 §7.4.1.3: version must be exactly TLS 1.2, the random echoed.
 * Returns the offset just past the session id, or SIZE_MAX on violation. */
static size_t sh_random(struct tls_hs *s, const unsigned char *b, size_t n)
{
  size_t slen;

  if (n < 2 + 32 + 1)
    return SIZE_MAX;
  if (b[0] != 3 || b[1] != 3)
    return SIZE_MAX;
  s->version = TLS_VERSION_1_2;
  memcpy(s->server_random, b + 2, 32);
  slen = b[34];
  if (slen > n - (2 + 32 + 1))
    return SIZE_MAX;
  return 2 + 32 + 1 + slen;
}

/* The suite must be one we offered or the handshake aborts — never a silent
 * downgrade. Also the compression method must be null. Returns the length
 * of the region, or SIZE_MAX on violation. */
static size_t sh_suite(struct tls_hs *s, const unsigned char *b, size_t n)
{
  unsigned int suite;

  if (n < 3)
    return SIZE_MAX;
  suite = (unsigned int)((b[0] << 8) | b[1]);
  if (suite != TLS_SUITE_CHACHA && suite != TLS_SUITE_AES_GCM)
    return SIZE_MAX;
  s->suite = suite;
  if (b[2] != 0x00)
    return SIZE_MAX;
  return 3;
}

static size_t sh_head(struct tls_hs *s, const unsigned char *b, size_t n)
{
  size_t o = sh_random(s, b, n);

  if (o == SIZE_MAX || sh_suite(s, b + o, n - o) == SIZE_MAX)
    return SIZE_MAX;
  return o + 3;
}

static int parse_server_hello(struct tls_hs *s, const unsigned char *b, size_t n)
{
  size_t o = sh_head(s, b, n);
  size_t len;

  if (o == SIZE_MAX)
    return -1;
  if (n - o < 2)
    return 0;                   /* no extension block */
  len = (size_t)((b[o] << 8) | b[o + 1]);
  if (len != n - o - 2)
    return -1;
  return sh_exts(b + o + 2, len);
}

/* Bounds-walk the remaining chain certificates (CERT_NONE, DOMAIN.md). */
static int cert_skip(const unsigned char *p, size_t left)
{
  while (left > 0) {
    size_t len;
    if (left < 3)
      return -1;
    len = u24(p);
    if (len > left - 3)
      return -1;
    p += 3 + len;
    left -= 3 + len;
  }
  return 0;
}

/* Copy the leaf certificate out of the already-validated list. */
static int cert_leaf(struct tls_hs *s, const unsigned char *p, size_t len)
{
  unsigned char *leaf = malloc(len);

  if (leaf == NULL)
    return -1;
  memcpy(leaf, p, len);
  free(s->leaf);
  s->leaf = leaf;
  s->leaf_n = len;
  return 0;
}

/* Take the first (leaf) entry of a validated list, then walk the chain. */
static int cert_leaf_list(struct tls_hs *s, const unsigned char *b, size_t n)
{
  size_t leaf_len;

  if (n < 3)
    return -1;
  leaf_len = u24(b);
  if (leaf_len == 0 || leaf_len > n - 3)
    return -1;
  if (cert_leaf(s, b + 3, leaf_len) != 0)
    return -1;
  return cert_skip(b + 3 + leaf_len, n - 3 - leaf_len);
}

/* RFC 5246 §7.4.2. Take the first cert (the leaf); the message size is
 * already bounded by TLS_MAX_MSG, so the leaf cannot exceed it. */
static int parse_certificate(struct tls_hs *s, const unsigned char *b, size_t n)
{
  size_t total;

  if (n < 3)
    return -1;
  total = u24(b);
  if (total != n - 3)
    return -1;                  /* the list must fill the message */
  return cert_leaf_list(s, b + 3, total);
}

/* RFC 4492 §5.4: fixed-size named-curve P-256 parameter block; sets *curve.
 * Also keep a copy of it (the signed body). Returns the signature-tail
 * length, or SIZE_MAX on violation. */
static int ske_body(const unsigned char *b, size_t n, uint16_t *curve)
{
  if (n < 4 + TLS_P256_POINT_LEN)
    return 1;
  *curve = (uint16_t) ((b[1] << 8) | b[2]);
  return b[0] != TLS_CURVE_TYPE_NAMED || *curve != TLS_CURVE_P256 ||
      b[3] != TLS_P256_POINT_LEN || b[4] != TLS_POINT_UNCOMPRESSED;
}

static size_t ske_params(struct tls_ske *k, const unsigned char *b, size_t n)
{
  size_t m;
  unsigned char *p;

  if (ske_body(b, n, &k->curve))
    return SIZE_MAX;
  m = 4 + TLS_P256_POINT_LEN;
  memcpy(k->point, b + 4, TLS_P256_POINT_LEN);
  k->point_n = TLS_P256_POINT_LEN;
  p = malloc(m);
  if (p == NULL)
    return SIZE_MAX;
  memcpy(p, b, m);
  free(k->params);
  k->params = p;
  k->params_n = m;
  return n - m;
}

/* Own the signature blob (already validated to fill the message tail). */
static int ske_store(struct tls_ske *k, const unsigned char *p, size_t n)
{
  unsigned char *sig = malloc(n);

  if (sig == NULL) {
    k->sig_n = 0;
    return -1;
  }
  memcpy(sig, p, n);
  k->sig_n = n;
  free(k->sig);
  k->sig = sig;
  return 0;
}

/* SignatureAndHashAlgorithm + signature blob. Only RSA over SHA-256 is
 * accepted (the sigalgs offered in the ClientHello); anything else aborts —
 * never a silent downgrade. Returns 0 or -1. */
static int ske_signature(struct tls_ske *k, const unsigned char *p, size_t n)
{
  unsigned int slen;

  if (n < 5 || p[1] != TLS_SIG_RSA || p[0] != TLS_HASH_SHA256)
    return -1;
  k->sigalg = (uint16_t) ((p[0] << 8) | p[1]);
  slen = (unsigned int)((p[2] << 8) | p[3]);
  if (slen != n - 4)
    return -1;                  /* signature must fill the message tail */
  return ske_store(k, p + 4, slen);
}

/* RSA signature over client||server||ServerECDHParams; 0 valid, else -1. */
static int ske_digest(const struct tls_hs *s, unsigned char digest[32])
{
  unsigned char body[133];

  memcpy(body, s->client_random, 32);
  memcpy(body + 32, s->server_random, 32);
  memcpy(body + 64, s->ske.params, s->ske.params_n);
  return tls_sha256(digest, body, 64 + s->ske.params_n);
}

static int ske_verify(const struct tls_hs *s)
{
  struct tls_rsa_pub k;
  unsigned char digest[32];
  int ret;

  if (ske_digest(s, digest) != 0)
    return -1;
  if (tls_rsa_leaf_pub(&k, s->leaf, s->leaf_n) != 0)
    return -1;
  ret = tls_rsa_verify(&k, digest, s->ske.sig, s->ske.sig_n);
  mp_clear_multi(&k.n, &k.e, NULL);
  return ret;
}

static int parse_ske(struct tls_hs *s, const unsigned char *b, size_t n)
{
  size_t tail = ske_params(&s->ske, b, n);

  if (tail == SIZE_MAX)
    return -1;
  if (ske_signature(&s->ske, b + n - tail, tail) != 0)
    return -1;
  if (ske_verify(s) != 0)       /* signature must validate before the point */
    return -1;
  return tls_ecdhe_derive(s);
}

static int parse_done(size_t n)
{
  return n == 0 ? 0 : -1;
}

/* Parse a parsed, transcript-booked server message body. */
static int parse_by_type(struct tls_hs *s, int type, const unsigned char *body, size_t n)
{
  switch (type) {
  case TLS_HS_SERVER_HELLO:
    return parse_server_hello(s, body, n);
  case TLS_HS_CERTIFICATE:
    return parse_certificate(s, body, n);
  case TLS_HS_SERVER_KEY_EXCHANGE:
    return parse_ske(s, body, n);
  case TLS_HS_SERVER_HELLO_DONE:
    return parse_done(n);
  default:
    return -1;                  /* unexpected message type */
  }
}

/* Parse the next inbound handshake message; 0 = parsed, -1 = abort. */
int tls_parse_server_msg(struct tls_hs *s)
{
  int type;
  const unsigned char *body;
  size_t n;

  if (tls_hs_message(s, &type, &body, &n) != 0)
    return -1;
  if (type == TLS_HS_FINISHED)
    return tls_fin_verify(s, body, n);
  tls_trans(s, type, body, n);
  return parse_by_type(s, type, body, n);
}
