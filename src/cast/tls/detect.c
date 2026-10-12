#include "cast/tls.h"

/* One-shot transport decision on the first byte the peer sends after the
 * ClientHello (DOMAIN.md §Encrypted vs plaintext, QA.md §TLS). Only a TLS
 * record content type (20-23) keeps the TLS framing; any other byte —
 * including a plaintext Cast V2 frame — means legacy: drop TLS framing and
 * speak plaintext. The decision is made exactly once, on the first byte,
 * before any frame is interpreted: a TLS alert (0x15) is TLS, never a
 * legacy plaintext reply. A plaintext frame never starts with 0x14-0x17
 * (that would imply a length >= 4 GiB >> MAX_CAST_FRAME). */
int tls_hs_detect(const unsigned char *p, size_t n)
{
  if (p == NULL)
    return -1;
  if (n == 0)
    return TLS_DETECT_WAIT;
  if (p[0] >= TLS_REC_CHANGE_CIPHER_SPEC && p[0] <= TLS_REC_APP_DATA)
    return TLS_DETECT_TLS;
  return TLS_DETECT_PLAINTEXT;
}
