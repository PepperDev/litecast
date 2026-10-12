#include "cast/cast.h"
#include "cast/tls.h"
#include "cast/tls/tls_ctrl.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define TLS_REC_MAX_PL 16384    /* RFC 5246 §6.2.1 max record plaintext */

/* Classify a single recv() result: positive count, EOF, would-block, error. */
static ssize_t tls_sock_in(ssize_t r)
{
  if (r > 0)
    return r;
  if (r == 0)
    return -1;                  /* EOF */
  if (errno == EAGAIN || errno == EWOULDBLOCK)
    return 0;                   /* would-block */
  return -1;
}

static ssize_t tls_raw_read(struct cast_ctrl *c, unsigned char *buf, size_t cap)
{
  ssize_t r;

  do
    r = recv(c->fd, buf, cap, 0);
  while (r < 0 && errno == EINTR);
  return tls_sock_in(r);
}

static ssize_t tls_raw_write(const struct cast_ctrl *c, const unsigned char *buf, size_t cap)
{
  ssize_t r;

  do
    r = send(c->fd, buf, cap, MSG_NOSIGNAL);
  while (r < 0 && errno == EINTR);
  if (r > 0)
    return r;
  return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
}

/* Copy up to cap bytes of decrypted application data into buf, consuming
 * them. Returns the count, or 0 when none is buffered. */
static ssize_t tls_drain(struct tls_hs *h, unsigned char *buf, size_t cap)
{
  size_t avail;
  const unsigned char *p = tls_rec_peek(h, &avail);
  size_t k;

  if (p == NULL || avail == 0)
    return 0;
  k = avail > cap ? cap : avail;
  memcpy(buf, p, k);
  tls_rec_consume(h, k);
  return (ssize_t) k;
}

/* TLS transport read: serve buffered decrypted app-data; otherwise pull raw
 * ciphertext, feed the record layer, and decrypt until plaintext appears. */
ssize_t tls_io_read(struct cast_io *io, unsigned char *buf, size_t cap)
{
  struct cast_ctrl *c = (struct cast_ctrl *)io->opaque;
  struct tls_hs *h = c->hs;

  for (;;) {
    ssize_t d = tls_drain(h, buf, cap);

    if (d > 0)
      return d;
    {
      unsigned char raw[8192];
      ssize_t r = tls_raw_read(c, raw, sizeof raw);

      if (r <= 0)
        return r;
      if (tls_hs_feed(h, raw, (size_t)r) != 0)
        return -1;
      if (tls_hs_pump(h) < 0)
        return -1;
    }
  }
}

/* Send a fully-sealed buffer; a peer that cannot absorb the (small) control
 * frame is an error — the control channel reconnects. */
static int tls_write_all(const struct cast_ctrl *c, const unsigned char *out, size_t n)
{
  size_t k;

  for (k = 0; k < n;) {
    ssize_t w = tls_raw_write(c, out + k, n - k);

    if (w <= 0)
      return -1;
    k += (size_t)w;
  }
  return 0;
}

/* Seal the whole plaintext chunk into consecutive APP_DATA records. */
static int tls_seal_all(struct tls_hs *h, const unsigned char *buf, size_t cap, unsigned char *out, size_t *out_n)
{
  size_t off = 0;

  while (off < cap) {
    size_t pl = cap - off > TLS_REC_MAX_PL ? TLS_REC_MAX_PL : cap - off;
    size_t rec_n;

    if (tls_rec_seal(h, buf + off, pl, out + *out_n, &rec_n) != 0)
      return -1;
    *out_n += rec_n;
    off += pl;
  }
  return 0;
}

/* Worst-case sealed size for the given plaintext length. */
static size_t tls_bulk(size_t cap)
{
  return 5 + (cap / TLS_REC_MAX_PL + 1) * (TLS_REC_MAX_PL + 16);
}

/* TLS transport write: seal the plaintext chunk into APP_DATA records and
 * send them. Returns bytes of plaintext taken. */
ssize_t tls_io_write(struct cast_io *io, const unsigned char *buf, size_t cap)
{
  struct cast_ctrl *c = (struct cast_ctrl *)io->opaque;
  struct tls_hs *h = c->hs;
  unsigned char *out = malloc(tls_bulk(cap));
  size_t out_n = 0;

  if (out == NULL)
    return -1;
  if (tls_seal_all(h, buf, cap, out, &out_n) != 0) {
    free(out);
    return -1;
  }
  if (tls_write_all(c, out, out_n) != 0) {
    free(out);
    return -1;
  }
  free(out);
  return (ssize_t) cap;
}

/* Flush queued handshake tx bytes; 0 = flushed, 1 = would-block, -1 = error. */
static int ctrl_tls_flush(struct tls_hs *h)
{
  while (h->tx_off < h->tx_n) {
    if (tls_hs_step(h) < 0)
      return -1;
    return h->tx_off < h->tx_n ? 1 : 0;
  }
  return 0;
}

/* Handle one transcripted handshake message; the security latch check and the
 * Finished send for SERVER_HELLO_DONE. */
static int ctrl_tls_message(struct tls_hs *h)
{
  int type;
  const unsigned char *body;
  size_t bn;

  if (tls_hs_message(h, &type, &body, &bn) != 0)
    return -1;
  if (tls_parse_server_msg(h) != 0)
    return -1;
  if (type == TLS_HS_SERVER_HELLO_DONE)
    return tls_fin_begin(h) == 0 && tls_fin_send(h) == 0 ? 0 : -1;
  return 0;
}

/* Pump the handshake messages until the security latch. Returns 1 = latch
 * set, 0 = need more bytes, -1 = handshake error. */
static int ctrl_tls_drive(struct cast_ctrl *c)
{
  struct tls_hs *h = c->hs;
  int guard;

  for (guard = 0; guard < 16; guard++) {
    int r = tls_hs_pump(h);

    if (r == 0)
      break;                    /* blocked: need more raw bytes */
    if (r < 0)
      return -1;
    if (ctrl_tls_message(h) != 0)
      return -1;
    if (h->fin.verified)
      return 1;
  }
  return 0;
}

/* In AUTO, classify the peer's first byte and latch the transport. Returns
 * 1 = latched to TLS, 0 = transport already fixed, -1 = error, -2 = a
 * plaintext legacy peer was detected. */
static int ctrl_tls_latch(struct cast_ctrl *c, const unsigned char *raw, size_t n)
{
  int d;

  if (c->transport != CAST_TP_AUTO)
    return 0;
  d = tls_hs_detect(raw, n);
  if (d < 0)
    return -1;
  if (d != TLS_DETECT_TLS)
    return -2;                  /* plaintext legacy peer (one-shot) */
  c->transport = CAST_TP_TLS;
  return 1;
}

/* Read raw bytes, classify (AUTO), and feed the record layer. Returns
 * 1 = fed, 0 = would-block, -1 = error, -2 = plaintext legacy peer. */
static int ctrl_tls_ingress(struct cast_ctrl *c, struct tls_hs *h, unsigned char *raw, size_t cap)
{
  ssize_t n = tls_raw_read(c, raw, cap);
  int latched;

  if (n < 0)
    return -1;
  if (n == 0)
    return 0;
  latched = ctrl_tls_latch(c, raw, (size_t)n);
  if (latched < 0)
    return latched;
  if (tls_hs_feed(h, raw, (size_t)n) != 0)
    return -1;
  return 1;
}

/* Build and queue the ClientHello for an AUTO transport in the SEND_HELLO
 * phase. Returns 0 = nothing to send (not applicable), -1 = error. */
static int ctrl_tls_hello(const struct cast_ctrl *c, struct tls_hs *h)
{
  unsigned char rnd[32];

  if (c->transport != CAST_TP_AUTO || h->phase != TLS_PH_SEND_HELLO)
    return 0;
  if (tls_random(rnd) != 0)
    return -1;
  return tls_hs_send_hello(h, rnd) == 0 ? 0 : -1;
}

int tls_ctrl_mode(int transport)
{
  if (transport == CAST_TP_TLS || transport == CAST_TP_AUTO)
    return 1;
  if (transport == CAST_TP_PLAIN)
    return 0;
  return -1;
}

int tls_ctrl_setup(struct cast_ctrl *c, int tls)
{
  if (!tls) {
    c->state = CTRL_CONNECT;
    return 0;
  }
  c->hs = calloc(1, sizeof *c->hs);
  if (c->hs == NULL) {
    cast_reader_close(&c->rd);
    return -1;
  }
  if (tls_hs_init(c->hs, &c->io) != 0) {
    free(c->hs);
    c->hs = NULL;
    cast_reader_close(&c->rd);
    return -1;
  }
  c->state = CTRL_TLS;
  return 0;
}

/* One step of the TLS transport setup: send the ClientHello, latch the
 * transport on the peer's first byte (AUTO), and pump the handshake through
 * to the security latch. Returns 1 = latch set, 0 = needs more I/O,
 * -1 = error, -2 = plaintext legacy peer. */
int tls_ctrl_step(struct cast_ctrl *c)
{
  struct tls_hs *h = c->hs;
  unsigned char raw[8192];
  int d;

  d = ctrl_tls_hello(c, h);
  if (d < 0)
    return -1;
  d = ctrl_tls_flush(h);
  if (d != 0)
    return d;                   /* 1 = flush pending (EPOLLOUT) */
  d = ctrl_tls_ingress(c, h, raw, sizeof raw);
  if (d != 0 && d != 1)
    return d;                   /* -1 error, -2 plaintext */
  return ctrl_tls_drive(c);
}
