#include "cast/tls/rsa.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libtomcrypt constant-time compare; rsa.c links it but its public header
 * pulls GNU extensions, so declare it locally instead of including it. */
int mem_neq(const void *a, const void *b, size_t len);

/* RSA public-key ops for the handshake (see rsa.h). The X.509 leaf is
 * walked with minimal DER readers to the SubjectPublicKeyInfo; the SKE
 * signature is checked with RSA PKCS#1 v1.5 (RFC 8017 §8.2) over SHA-256
 * via libtommath only (libtomcrypt's pk/ layer stays disabled). */

/* rsaEncryption OID 1.2.840.113549.1.1.1 */
static const unsigned char oid_rsa[9] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};

/* SHA-256 DigestInfo prefix (RFC 8017 §9.2): 19 bytes + 32-byte digest. */
static const unsigned char emsa_dgst[19] = {
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
  0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

/* Parse a DER length after its length octet p[0]: returns the header size
 * or 0 on error, with *len the content length. */
static size_t der_ln(const unsigned char *p, size_t n, size_t *len)
{
  size_t k;
  size_t i;
  size_t l;

  if (n < 1)
    return 0;
  k = p[0] & 0x7f;
  if ((p[0] & 0x80) == 0) {
    *len = k;
    return 1;
  }
  if (k > 4 || n < 1 + k)
    return 0;
  for (l = 0, i = 0; i < k; i++)
    l = (l << 8) | p[1 + i];
  *len = l;
  return 1 + k;
}

/* Read one DER TLV: set *tag and the content window; return the element's
 * total length (header + content), 0 on malformed input. */
static size_t der_elem(const unsigned char *p, size_t n, unsigned *tag, const unsigned char **c, size_t *cn)
{
  size_t hl;
  size_t ln;

  if (n < 2)
    return 0;
  *tag = p[0];
  hl = der_ln(p + 1, n - 1, &ln);
  if (hl == 0 || n < 1 + hl + ln)
    return 0;
  *c = p + 1 + hl;
  *cn = ln;
  return 1 + hl + ln;
}

/* Read one element at p; require it to carry the given tag; on success set
 * its content and return the element length, else 0. */
static size_t der_read(const unsigned char *p, size_t n, unsigned want, const unsigned char **c, size_t *cn)
{
  unsigned tag;
  size_t tot;

  tot = der_elem(p, n, &tag, c, cn);
  if (tot == 0 || tag != want)
    return 0;
  return tot;
}

/* True if the element at p is the rsaEncryption OID. */
static size_t der_oid(const unsigned char *p, size_t n)
{
  unsigned tag;
  const unsigned char *c;
  size_t cn;
  size_t tot;

  tot = der_elem(p, n, &tag, &c, &cn);
  if (tot == 0 || tag != 0x06 || cn != sizeof oid_rsa)
    return 0;
  return memcmp(c, oid_rsa, sizeof oid_rsa) == 0 ? tot : 0;
}

/* Read a positive INTEGER at p into m (m rejects negative values). */
static int der_int(mp_int *m, const unsigned char *p, size_t n)
{
  unsigned tag;
  const unsigned char *c;
  size_t cn;
  size_t tot;

  tot = der_elem(p, n, &tag, &c, &cn);
  if (tot == 0 || tag != 0x02 || cn == 0 || (c[0] & 0x80))
    return -1;
  return mp_from_ubin(m, c, cn) == MP_OKAY ? (int)tot : -1;
}

/* Does p open a SEQUENCE whose first element is the rsa OID? */
static int spki_pat(const unsigned char *p, size_t n)
{
  unsigned tag;
  const unsigned char *c;
  size_t cn;
  size_t tot;

  tot = der_elem(p, n, &tag, &c, &cn);
  if (tot == 0 || tag != 0x30)
    return 0;
  return der_oid(c, cn) != 0;
}

/* Walk tbsCertificate content to the SubjectPublicKeyInfo SEQUENCE. */
static size_t der_spki(const unsigned char *p, size_t n, const unsigned char **c, size_t *cn)
{
  size_t o = 0;

  while (o < n) {
    unsigned tag;
    size_t tot;

    tot = der_elem(p + o, n - o, &tag, c, cn);
    if (tot == 0)
      return 0;
    if (tag == 0x30 && spki_pat(*c, *cn) != 0)
      return tot;
    o += tot;
  }
  return 0;
}

/* Fail path: release the key ints and report failure. */
static int rsa_fail(struct tls_rsa_pub *k)
{
  mp_clear_multi(&k->n, &k->e, NULL);
  return -1;
}

/* Walk the SPKI content (already found to match spki_pat) to the
 * RSAPublicKey SEQUENCE inside its BIT STRING. */
static size_t der_alg_bits(const unsigned char *p, size_t n, const unsigned char **c, size_t *cn)
{
  size_t tot;

  tot = der_read(p, n, 0x30, c, cn);    /* algorithm SEQUENCE */
  if (tot == 0 || tot >= n)
    return 0;
  tot = der_read(p + tot, n - tot, 0x03, c, cn);        /* BIT STRING */
  if (tot == 0)
    return 0;
  return tot;
}

static int der_pub_bits(const unsigned char *p, size_t n, const unsigned char **seq, size_t *sn)
{
  const unsigned char *c;
  size_t cn;
  size_t tot;

  tot = der_alg_bits(p, n, &c, &cn);
  if (tot == 0 || cn == 0 || c[0] != 0x00)
    return -1;
  tot = der_read(c + 1, cn - 1, 0x30, seq, sn);
  if (tot == 0)
    return -1;
  return 0;
}

/* Extract n and e out of the RSAPublicKey held in the SPKI content. */
static int der_rsa_key(struct tls_rsa_pub *k, const unsigned char *p, size_t n)
{
  const unsigned char *seq;
  size_t sn;
  int step;

  if (der_pub_bits(p, n, &seq, &sn) != 0)
    return -1;
  step = der_int(&k->n, seq, sn);
  if (step <= 0 || der_int(&k->e, seq + (size_t)step, sn - (size_t)step) < 0)
    return -1;
  return 0;
}

/* Descend through the certificate and tbsCertificate headers to the tbs
 * content, then find the SPKI within it. */
static int leaf_spki(const unsigned char *leaf, size_t leaf_n, const unsigned char **c, size_t *cn)
{
  unsigned tag;
  size_t tot;

  tot = der_elem(leaf, leaf_n, &tag, c, cn);
  if (tot == 0 || tag != 0x30)
    return -1;
  tot = der_elem(*c, *cn, &tag, c, cn);
  if (tot == 0 || tag != 0x30)
    return -1;
  return der_spki(*c, *cn, c, cn) == 0 ? -1 : 0;
}

/* Parse the DER X.509 leaf into k->n / k->e. */
int tls_rsa_leaf_pub(struct tls_rsa_pub *k, const unsigned char *leaf, size_t leaf_n)
{
  const unsigned char *c;
  size_t cn;
  int r;

  if (mp_init_multi(&k->n, &k->e, NULL) != MP_OKAY)
    return -1;
  r = leaf_spki(leaf, leaf_n, &c, &cn);
  if (r == 0)
    r = der_rsa_key(k, c, cn);
  if (r != 0)
    return rsa_fail(k);
  return 0;
}

/* Left-pad an mp_int into an exactly klen-byte buffer (mp_to_ubin pads 0). */
static int rsa_fill(const mp_int *m, unsigned char *out, size_t klen)
{
  size_t w = 0;

  if (mp_to_ubin(m, out, klen, &w) != MP_OKAY)
    return -1;
  memmove(out + klen - w, out, w);
  memset(out, 0, klen - w);
  return 0;
}

/* Build the PKCS#1 v1.5 (type 1) encoded message into want (klen bytes);
 * caller guarantees klen >= 54 so the padding run is not negative. */
static void rsa_emsa(unsigned char *want, const unsigned char digest[32], size_t klen)
{
  size_t ps = klen - sizeof emsa_dgst - 32 - 3;

  want[0] = 0x00;
  want[1] = 0x01;
  memset(want + 2, 0xff, ps);
  want[2 + ps] = 0x00;
  memcpy(want + 3 + ps, emsa_dgst, sizeof emsa_dgst);
  memcpy(want + 3 + ps + sizeof emsa_dgst, digest, 32);
}

/* em = sig^e mod n (raw PKCS#1 v1.5), as exactly klen bytes. */
static int rsa_pow(const struct tls_rsa_pub *k, const unsigned char *sig, size_t sig_n, unsigned char *em, size_t klen)
{
  mp_int mp;
  mp_int me;
  int r = -1;

  if (mp_init_multi(&mp, &me, NULL) != MP_OKAY)
    return -1;
  if (mp_from_ubin(&me, sig, sig_n) == MP_OKAY &&
      mp_exptmod(&me, &k->e, &k->n, &mp) == MP_OKAY && rsa_fill(&mp, em, klen) == 0)
    r = 0;
  mp_clear_multi(&mp, &me, NULL);
  return r;
}

int tls_rsa_verify(const struct tls_rsa_pub *k, const unsigned char digest[32], const unsigned char *sig, size_t sig_n)
{
  size_t klen = (size_t)mp_ubin_size(&k->n);
  unsigned char *mem;
  int ok = 0;

  if (sig_n != klen || klen < sizeof emsa_dgst + 32 + 3)
    return -1;
  mem = malloc(klen + klen);
  if (mem == NULL)
    return -1;
  if (rsa_pow(k, sig, sig_n, mem, klen) == 0) {
    rsa_emsa(mem + klen, digest, klen);
    ok = mem_neq(mem, mem + klen, klen) == 0;
  }
  free(mem);
  return ok ? 0 : -1;
}
