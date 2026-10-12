#include "cast/tls.h"
#include "cast/tls/crypt.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FIN_VD 12

extern int mem_neq(const void *a, const void *b, size_t len);

static int trans_grow(struct tls_hs *s, size_t need)
{
  size_t cap;
  unsigned char *nb;

  if (need <= s->trans_cap)
    return 0;
  cap = s->trans_cap ? s->trans_cap * 2 : 256;
  if (cap < need)
    cap = need;
  nb = realloc(s->trans, cap);
  if (nb == NULL)
    return -1;
  s->trans = nb;
  s->trans_cap = cap;
  return 0;
}

void tls_trans(struct tls_hs *s, int type, const void *body, size_t n)
{
  size_t o = s->trans_n;

  if (trans_grow(s, o + 4 + n) != 0)
    return;
  s->trans[o] = (unsigned char)type;
  s->trans[o + 1] = (unsigned char)(n >> 16);
  s->trans[o + 2] = (unsigned char)(n >> 8);
  s->trans[o + 3] = (unsigned char)n;
  if (n)
    memcpy(s->trans + o + 4, body, n);
  s->trans_n = o + 4 + n;
}

int tls_fin_begin(struct tls_hs *s)
{
  unsigned char kb[TLS_KEY_BLOCK];

  if (s->ecdhe.done == 0)
    return -1;
  tls_master_secret(s->master, s->ecdhe.premaster, sizeof s->ecdhe.premaster, s->client_random, s->server_random);
  tls_key_block(kb, sizeof kb, s->master, s->client_random, s->server_random);
  memcpy(s->c_key, kb, 32);
  memcpy(s->s_key, kb + 32, 32);
  memcpy(s->c_iv, kb + 64, 12);
  memcpy(s->s_iv, kb + 76, 12);
  memset(kb, 0, sizeof kb);
  s->fin.stage = 1;
  return 0;
}

static int fin_vd(const struct tls_hs *s, const char *label, unsigned char out[FIN_VD])
{
  struct tls_seed seed = { label, NULL, 0 };
  unsigned char h[32];

  if (tls_sha256(h, s->trans, s->trans_n) != 0)
    return -1;
  seed.seed = h;
  seed.seed_n = sizeof h;
  return tls_prf_sha256(out, FIN_VD, s->master, 48, &seed);
}

static int fin_write(struct tls_hs *s, const unsigned char *p, size_t n)
{
  size_t off = 0;

  while (off < n) {
    ssize_t r = s->io->write(s->io, p + off, n - off);

    if (r < 0)
      return -1;
    if (r == 0)
      return 0;
    off += (size_t)r;
  }
  return 0;
}

static void fin_hdr(unsigned char hdr[5], int type, size_t n)
{
  hdr[0] = (unsigned char)type;
  hdr[1] = 3;
  hdr[2] = 3;
  hdr[3] = (unsigned char)(n >> 8);
  hdr[4] = (unsigned char)n;
}

/* Seal one outbound Finished record with c_seq (RFC 5246 §6.2.3.3 AAD). */
static int fin_seal(struct tls_hs *s, const unsigned char *p, size_t n, unsigned char ct[TLS_MAX_MSG], size_t *ct_n)
{
  unsigned char aad[13];
  uint64_t seq = s->fin.c_seq;

  tls_record_aad(aad, seq, TLS_REC_HANDSHAKE, n);
  if (tls_chacha_seal(&(struct tls_cc) { s->c_key, s->c_iv, seq, aad, 13 },
                      ct, ct_n, p, n) != 0)
    return -1;
  s->fin.c_seq++;
  return 0;
}

static int fin_enc(struct tls_hs *s, const unsigned char *p, size_t n)
{
  unsigned char hdr[5];
  unsigned char ct[TLS_MAX_MSG];
  size_t ct_n;

  fin_hdr(hdr, TLS_REC_HANDSHAKE, n);
  if (fin_seal(s, p, n, ct, &ct_n) != 0)
    return -1;
  hdr[3] = (unsigned char)(ct_n >> 8);
  hdr[4] = (unsigned char)ct_n;
  return fin_write(s, hdr, 5) || fin_write(s, ct, ct_n);
}

static int fin_send_cke(struct tls_hs *s)
{
  unsigned char hs[4 + 1 + TLS_P256_POINT_LEN];
  unsigned char hdr[5];

  hs[0] = TLS_HS_CLIENT_KEY_EXCHANGE;
  hs[1] = 0;
  hs[2] = 0;
  hs[3] = (unsigned char)(1 + TLS_P256_POINT_LEN);
  hs[4] = (unsigned char)TLS_P256_POINT_LEN;
  memcpy(hs + 5, s->ecdhe.pub, TLS_P256_POINT_LEN);
  tls_trans(s, TLS_HS_CLIENT_KEY_EXCHANGE, hs + 4, 1 + TLS_P256_POINT_LEN);
  fin_hdr(hdr, TLS_REC_HANDSHAKE, 4 + 1 + TLS_P256_POINT_LEN);
  return fin_write(s, hdr, 5) || fin_write(s, hs, sizeof hs);
}

static int fin_send_ccs(struct tls_hs *s)
{
  unsigned char hdr[5];
  static const unsigned char body[1] = { 1 };

  fin_hdr(hdr, TLS_REC_CHANGE_CIPHER_SPEC, 1);
  if (fin_write(s, hdr, 5) != 0 || fin_write(s, body, 1) != 0)
    return -1;
  s->fin.cipher_on = 1;
  return 0;
}

static int fin_send_fin(struct tls_hs *s)
{
  unsigned char vd[FIN_VD];
  unsigned char fin[4 + FIN_VD];

  if (fin_vd(s, "client finished", vd) != 0)
    return -1;
  fin[0] = TLS_HS_FINISHED;
  fin[1] = 0;
  fin[2] = 0;
  fin[3] = FIN_VD;
  memcpy(fin + 4, vd, FIN_VD);
  tls_trans(s, TLS_HS_FINISHED, fin + 4, FIN_VD);
  return fin_enc(s, fin, sizeof fin);
}

int tls_fin_send(struct tls_hs *s)
{
  if (s->fin.stage != 1)
    return -1;
  if (fin_send_cke(s) != 0)
    return -1;
  if (fin_send_ccs(s) != 0)
    return -1;
  if (fin_send_fin(s) != 0)
    return -1;
  s->fin.stage = 2;
  return 0;
}

int tls_fin_verify(struct tls_hs *s, const unsigned char *vd, size_t n)
{
  unsigned char expect[FIN_VD];

  if (s->fin.stage != 2 || n != FIN_VD)
    return -1;
  if (fin_vd(s, "server finished", expect) != 0)
    return -1;
  if (mem_neq(vd, expect, FIN_VD))
    return -1;
  s->fin.verified = 1;
  return 0;
}
