#include "cast/tls.h"

#include <stdlib.h>
#include <string.h>

/* === Session plumbing === */

int tls_hs_init(struct tls_hs *s, struct cast_io *io)
{
  if (s == NULL || io == NULL)
    return -1;
  memset(s, 0, sizeof *s);
  s->io = io;
  s->phase = TLS_PH_SEND_HELLO;
  return 0;
}

void tls_hs_close(struct tls_hs *s)
{
  if (s == NULL)
    return;
  free(s->inq);
  free(s->rec);
  free(s->hs_body);
  free(s->leaf);
  free(s->ske.params);
  free(s->ske.sig);
  free(s->trans);
  free(s->ap);
  memset(s, 0, sizeof *s);
}

int tls_hs_send_hello(struct tls_hs *s, const unsigned char random[32])
{
  if (s == NULL || random == NULL)
    return -1;
  if (tls_ecdhe_keygen(s) != 0)
    return -1;
  s->tx_n = (size_t)tls_client_hello(s->tx, random);
  memcpy(s->client_random, random, 32);
  tls_trans(s, s->tx[5], s->tx + 5 + 4, (size_t)((s->tx[6] << 16) | (s->tx[7] << 8) | s->tx[8]));
  s->tx_off = 0;
  s->phase = TLS_PH_READ;
  return 0;
}

/* === Outbound === */

/* Flush the pending outbound record; returns 0 when fully sent or blocked. */
static int hstx_flush(struct tls_hs *s)
{
  while (s->tx_off < s->tx_n) {
    ssize_t r = s->io->write(s->io, s->tx + s->tx_off, s->tx_n - s->tx_off);

    if (r < 0)
      return -1;
    if (r == 0)
      return 0;
    s->tx_off += (size_t)r;
  }
  return 0;
}

/* Flush the outbound record, then surface the next inbound handshake
 * message: 1 = ready, 0 = would-block, -1 = error. */
static int hs_flush_pump(struct tls_hs *s)
{
  if (hstx_flush(s) < 0) {
    return -1;
  }
  if (s->tx_off < s->tx_n) {
    return 0;                   /* the ClientHello is still pending */
  }
  return tls_hs_pump(s);
}

int tls_hs_step(struct tls_hs *s)
{
  if (s == NULL)
    return -1;
  return hs_flush_pump(s);
}
