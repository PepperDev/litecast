#ifndef LITECAST_TLS_RECORD_H
#define LITECAST_TLS_RECORD_H

#include "cast/tls.h"

/* Record content-type and cipher helpers used by record.c (T15): they touch
 * only struct tls_hs, so they live apart from the framing state machine. */

int rec_kind_ok(const struct tls_hs *s, const unsigned char rh[5]);
int rec_ccs(struct tls_hs *s);  /* 2 consumed, -1 bad body */
int rec_decrypt(struct tls_hs *s);

/* Input-queue drains used by record.c's framing loop (record_inq.c). */
size_t rec_avail(const struct tls_hs *s);
void rec_drop(struct tls_hs *s, size_t n);
size_t rec_take(struct tls_hs *s, unsigned char *buf, size_t have, size_t want);

#endif
