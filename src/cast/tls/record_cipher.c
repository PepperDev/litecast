#include "cast/tls.h"
#include "cast/tls/crypt.h"
#include "cast/tls/record.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TLS_AEAD_TAG 16

/* Record content type the current handshake stage allows (QA.md §TLS):
 * handshake throughout, a ChangeCipherSpec once the client Finished is
 * sent, application data only after the server Finished verified (the
 * security latch). */
int rec_kind_ok(const struct tls_hs *s, const unsigned char rh[5])
{
  if (rh[1] != 3)               /* record layer major version */
    return 0;
  switch (rh[0]) {
  case TLS_REC_HANDSHAKE:
    return 1;
  case TLS_REC_CHANGE_CIPHER_SPEC:
    return s->fin.stage >= 2;   /* only after the client Finished went out */
  case TLS_REC_APP_DATA:
    return s->fin.verified;     /* no plaintext before Finished_verify */
  default:
    return 0;
  }
}

/* ChangeCipherSpec body (RFC 5246 §6.1) is the single byte 0x01; once seen
 * every subsequent server record is encrypted. Returns 2 (consumed). */
int rec_ccs(struct tls_hs *s)
{
  if (s->rlen != 1 || s->rec[0] != 1)
    return -1;
  s->fin.peer_cipher = 1;
  s->rh_n = 0;
  return 2;
}

/* Decrypt one encrypted record in place (RFC 5246 AEAD / RFC 7905), the
 * 16-byte tag stripped. Returns 0, or -1 on authentication failure. */
int rec_decrypt(struct tls_hs *s)
{
  unsigned char aad[13];
  size_t pt = s->rlen - TLS_AEAD_TAG;

  if (pt < 1 || pt > TLS_MAX_MSG)
    return -1;
  tls_record_aad(aad, s->fin.s_seq, s->rec_type, pt);
  if (tls_chacha_open(&(struct tls_cc) { s->s_key, s->s_iv, s->fin.s_seq, aad, 13 },
                      s->rec, s->rec, s->rlen) != 0)
    return -1;
  s->fin.s_seq++;
  s->rec_dec = 1;
  s->rlen = pt;
  s->rec_n = pt;
  return 0;
}

/* Write a TLS 1.2 record header for `type` with a zero length; the caller
 * patches bytes 3-4 once the ciphertext length is known. */
static void rec_head(unsigned char out[5], int type)
{
  out[0] = (unsigned char)type;
  out[1] = 3;
  out[2] = 3;
  out[3] = 0;
  out[4] = 0;
}

/* Seal one application-data plaintext chunk into a full TLS APP_DATA record
 * (RFC 5246 §6.2.3.3 / RFC 7905), header included, advancing c_seq. The
 * caller bounds n to a TLS record payload (<= 16384) and out to the
 * ciphertext space. Returns 0, or -1 on failure. */
int tls_rec_seal(struct tls_hs *s, const unsigned char *pt, size_t n, unsigned char *out, size_t *out_n)
{
  unsigned char aad[13];
  size_t ct_n;

  rec_head(out, TLS_REC_APP_DATA);
  tls_record_aad(aad, s->fin.c_seq, TLS_REC_APP_DATA, n);
  if (tls_chacha_seal(&(struct tls_cc) { s->c_key, s->c_iv, s->fin.c_seq, aad, 13 },
                      out + 5, &ct_n, pt, n) != 0)
    return -1;
  out[3] = (unsigned char)(ct_n >> 8);
  out[4] = (unsigned char)ct_n;
  *out_n = 5 + ct_n;
  s->fin.c_seq++;
  return 0;
}
