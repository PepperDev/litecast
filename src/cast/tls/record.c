#include "cast/tls.h"
#include "cast/tls/record.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* === Record layer === */
/* Allocate the record payload for a validated header. */
static int rec_alloc(struct tls_hs *s)
{
  unsigned char *nb;
  if (s->rec_cap >= s->rlen)
    return 0;
  nb = realloc(s->rec, s->rlen);
  if (nb == NULL)
    return -1;
  s->rec = nb;
  s->rec_cap = s->rlen;
  return 0;
}

/* Collect and validate the 5-byte record header; 1 = taken, 0 = wait. */
static int rec_header(struct tls_hs *s)
{
  unsigned int len;
  s->rh_n += rec_take(s, s->rh, s->rh_n, 5);
  if (s->rh_n < 5)
    return 0;
  if (!rec_kind_ok(s, s->rh))
    return -1;
  len = ((unsigned int)s->rh[3] << 8) | s->rh[4];
  if (len < 1 || len > TLS_MAX_MSG)
    return -1;
  s->rec_type = s->rh[0];
  s->rlen = len;
  s->rec_n = 0;
  s->rec_off = 0;
  s->rec_dec = 0;
  if (rec_alloc(s) != 0)
    return -1;
  return 1;
}

/* Pull record payload bytes from the queue. Returns 1 = progress, 0 = block. */
static int rec_gather(struct tls_hs *s)
{
  size_t a = rec_avail(s);
  size_t k = s->rlen - s->rec_n;
  if (k > a)
    k = a;
  if (k == 0)
    return 0;
  memcpy(s->rec + s->rec_n, s->inq + s->inq_off, k);
  s->rec_n += k;
  rec_drop(s, k);
  return 1;
}

/* === Handshake reassembly === */

/* Commit the assembled 4-byte handshake header and size the body. */
static int hs_commit(struct tls_hs *s)
{
  unsigned char *nb;
  s->hs_hdr_done = 1;
  s->hs_type = s->hs_phdr[0];
  s->hs_len = ((uint32_t) s->hs_phdr[1] << 16) | ((uint32_t) s->hs_phdr[2] << 8) | s->hs_phdr[3];
  if (s->hs_len > TLS_MAX_MSG)
    return -1;                  /* QA.md §TLS: oversized reassembly */
  if (s->hs_cap >= s->hs_len)
    return 0;
  nb = realloc(s->hs_body, s->hs_len);
  if (nb == NULL)
    return -1;
  s->hs_body = nb;
  s->hs_cap = s->hs_len;
  return 0;
}

/* Assemble the 4-byte handshake header from the record payload; returns
 * 1 = taken, 0 = split across records, -1 = oversized or allocation. */
static int hs_hdr(struct tls_hs *s)
{
  size_t k = 4 - s->hs_phdr_n;
  size_t a = s->rec_n - s->rec_off;
  if (k > a)
    k = a;
  memcpy(s->hs_phdr + s->hs_phdr_n, s->rec + s->rec_off, k);
  s->hs_phdr_n += k;
  s->rec_off += k;
  if (s->hs_phdr_n < 4)
    return 0;
  if (hs_commit(s) != 0)
    return -1;
  return 1;
}

/* Move record bytes into the message body; returns 1 when complete. */
static int hs_fill(struct tls_hs *s)
{
  if (s->hs_n < s->hs_len) {
    size_t k = s->hs_len - s->hs_n;
    size_t a = s->rec_n - s->rec_off;

    if (k > a)
      k = a;
    memcpy(s->hs_body + s->hs_n, s->rec + s->rec_off, k);
    s->hs_n += k;
    s->rec_off += k;
  }
  return s->hs_n == s->hs_len;
}

/* Extract handshake messages from the record payload (messaging may span
 * records). 1 = a message completed, 0 = record drained. */
static int hs_drain(struct tls_hs *s)
{
  while (s->rec_off < s->rec_n) {
    if (!s->hs_hdr_done) {
      int r = hs_hdr(s);

      if (r <= 0)
        return r;
    }
    if (hs_fill(s)) {
      s->hs_ready = 1;
      s->hs_hdr_done = 0;
      s->hs_phdr_n = 0;
      s->hs_n = 0;
      return 1;
    }
    return 0;                   /* needs the next record */
  }
  return 0;
}

/* A non-handshake record. A ChangeCipherSpec or a record before the latch
 * was already rejected by rec_kind_ok; a post-latch APP_DATA record is the
 * frame-carrying plaintext: decrypt happened in rec_consume, so copy
 * s->rec[0..rlen) into the transport's app-data buffer for the reader. */
static size_t ap_grow(struct tls_hs *s, size_t need)
{
  size_t cap = s->ap_cap ? s->ap_cap : 256;
  unsigned char *nb;

  if (need <= s->ap_cap)
    return 0;
  while (cap < need)
    cap *= 2;
  nb = realloc(s->ap, cap);
  if (nb == NULL)
    return 1;
  s->ap = nb;
  s->ap_cap = cap;
  return 0;
}

static int rec_nonhs(struct tls_hs *s)
{
  size_t n = s->rlen;

  if (ap_grow(s, s->ap_n + n) != 0)
    return -1;
  memcpy(s->ap + s->ap_n, s->rec, n);
  s->ap_n += n;
  s->rh_n = 0;
  s->rec_n = 0;
  s->rec_off = 0;
  return 2;
}

/* Consume a handshake record; 1 = message ready, 2 = drained, -1 = error. */
static int rec_handshake(struct tls_hs *s)
{
  int r = hs_drain(s);
  if (s->hs_ready)
    return 1;
  if (r < 0)
    return -1;
  s->rh_n = 0;                  /* arm the next record header */
  s->rec_n = 0;
  s->rec_off = 0;
  return 2;
}

/* A full record is in s->rec: decrypt if needed, drain messages; 1 = a
 * message ready, 2 = consumed (keep pumping), -1 = error. */
static int rec_consume(struct tls_hs *s)
{
  if (s->rec_type == TLS_REC_CHANGE_CIPHER_SPEC)
    return rec_ccs(s);          /* 2 consumed, -1 bad body */
  if (s->fin.peer_cipher && !s->rec_dec && rec_decrypt(s) != 0)
    return -1;
  if (s->rec_type != TLS_REC_HANDSHAKE)
    return rec_nonhs(s);
  return rec_handshake(s);
}

/* Advance one record frame: 1 = message ready, 0 = blocked, 2 = drained. */
static int rec_progress(struct tls_hs *s)
{
  if (s->rh_n < 5) {
    int r = rec_header(s);

    if (r != 1)
      return r;
  }
  if (s->rec_n < s->rlen) {
    int r = rec_gather(s);

    if (r != 1)
      return r;
    if (s->rec_n < s->rlen)
      return 0;                 /* record not yet full: wait */
  }
  return rec_consume(s);
}

int tls_hs_pump(struct tls_hs *s)
{
  if (s == NULL)
    return -1;
  if (s->hs_ready) {            /* previous message was consumed */
    s->hs_ready = 0;
    s->hs_hdr_done = 0;
    s->hs_phdr_n = 0;
  }
  for (;;) {
    int r = rec_progress(s);

    if (r == 2)
      continue;                 /* one record fully drained */
    return r;
  }
}

int tls_hs_message(const struct tls_hs *s, int *type, const unsigned char **body, size_t *n)
{
  if (s == NULL || type == NULL || body == NULL || n == NULL)
    return -1;
  if (!s->hs_ready)
    return -1;
  *type = s->hs_type;
  *body = s->hs_body;
  *n = s->hs_len;
  return 0;
}

/* === Post-latch application-data transport === */

size_t tls_rec_available(const struct tls_hs *s)
{
  return s == NULL ? 0 : s->ap_n - s->ap_off;
}

const unsigned char *tls_rec_peek(const struct tls_hs *s, size_t *n)
{
  if (s == NULL || n == NULL)
    return NULL;
  *n = s->ap_n - s->ap_off;
  return s->ap + s->ap_off;
}

void tls_rec_consume(struct tls_hs *s, size_t n)
{
  if (s == NULL)
    return;
  s->ap_off += s->ap_n - s->ap_off > n ? n : s->ap_n - s->ap_off;
  if (s->ap_off == s->ap_n) {
    s->ap_off = 0;
    s->ap_n = 0;
  }
}
