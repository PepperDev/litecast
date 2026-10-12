#include "net/http.h"

#include <limits.h>
#include <string.h>

/* === Bounded request parsing (DOMAIN.md §HTTP server) ===
 *
 * Pure logic over the request bytes; no socket access. The caller hands a
 * NUL-terminated header block (it inserts the terminator at the head end),
 * so the pieces we hand back — the path — are valid C strings. Every
 * function stays well under the CCN gate by delegating to helpers. */

static int hdr_term(const unsigned char *in, size_t i)
{
  return in[i] == '\r' && in[i + 1] == '\n' && in[i + 2] == '\r' && in[i + 3] == '\n';
}

int http_req_done(const unsigned char *in, size_t n, size_t *head_end)
{
  size_t i;

  if (n < 4)
    return 0;
  for (i = 0; i + 3 < n; i++)
    if (hdr_term(in, i)) {
      *head_end = i + 4;
      return 1;
    }
  return 0;
}

static int hdr_eol(const unsigned char *in, size_t i)
{
  return in[i] == '\r' && in[i + 1] == '\n';
}

/* "GET <path> SP <version> CRLF"; fills path + header start. */
static int req_token(const unsigned char *in, size_t *i, size_t *start, size_t *len)
{
  *start = *i;
  while (in[*i] != '\0' && in[*i] != ' ' && in[*i] != '\r')
    (*i)++;
  if (*i == *start)
    return -1;
  *len = *i - *start;
  if (in[*i] != ' ')
    return -1;
  (*i)++;
  return 0;
}

static int req_line(const unsigned char *in, const char **path, size_t *len, size_t *hdrs)
{
  size_t b;
  size_t l;
  size_t i = 4;

  if (memcmp(in, "GET ", 4) != 0)
    return -1;
  if (req_token(in, &i, &b, &l) != 0)
    return -1;
  *path = (const char *)in + b;
  *len = l;
  while (in[i] != '\0' && in[i] != '\r')
    i++;
  if (!hdr_eol(in, i))
    return -1;
  *hdrs = i + 2;
  return 0;
}

int http_req_path(const unsigned char *in, const char **path, size_t *len)
{
  size_t hdrs;

  if (path == NULL || len == NULL || req_line(in, path, len, &hdrs) != 0)
    return -1;
  return 0;
}

/* === Single-byte Range parsing (DOMAIN.md §HTTP response selection) ===
 *
 * Only a single "bytes=START[-END]" range is served, with END inclusive per
 * RFC 7233; any other form — a suffix range ("-N"), a list, a non-bytes
 * unit, a missing dash — is ignored as if the header were absent, so the
 * receiver still gets a full response. The value returned in *end is one
 * past the last byte; HTTP_RANGE_OPEN marks "bytes=START-". */

static int hdr_preceded(const unsigned char *in, size_t i)
{
  return i == 0 || in[i - 1] == '\n';
}

static int hdr_name(const unsigned char *in, size_t i, const char *name, size_t len)
{
  size_t k;

  for (k = 0; k < len; k++) {
    unsigned char a = in[i + k];
    unsigned char b = (unsigned char)name[k];

    if (a != b && (a | 0x20) != (b | 0x20))
      return 0;
  }
  return in[i + len] == ':';
}

/* Value span of the first header line whose name starts the line. OWS around
 * the value is trimmed. Returns 1 on a hit, 0 when the header is absent. */
static int hdr_find(const unsigned char *in, const char *name, size_t len, size_t *vi)
{
  size_t i;

  for (i = 0; in[i] != '\0'; i++) {
    if (hdr_preceded(in, i) && hdr_name(in, i, name, len)) {
      *vi = i + len + 1;
      return 0;
    }
  }
  return -1;
}

static int hdr_ows(unsigned char b)
{
  return b == ' ' || b == '\t';
}

static void hdr_trim(const unsigned char **v, size_t *vlen)
{
  const unsigned char *s = *v;
  size_t n = *vlen;

  while (n > 0 && hdr_ows(s[0])) {
    s++;
    n--;
  }
  while (n > 0 && hdr_ows(s[n - 1]))
    n--;
  *v = s;
  *vlen = n;
}

static int hdr_value(const unsigned char *in, const char *name, size_t len, const unsigned char **val, size_t *vlen)
{
  size_t vi;
  size_t i;

  if (hdr_find(in, name, len, &vi) != 0)
    return 0;
  *val = in + vi;
  for (i = vi; in[i] != '\0' && in[i] != '\r' && in[i] != '\n'; i++) ;
  *vlen = i - vi;
  hdr_trim(val, vlen);
  return 1;
}

/* Decimal digits with saturation; *used receives the digits consumed. */
static unsigned long long rng_u(const unsigned char *s, size_t n, size_t *used)
{
  unsigned long long v = 0;
  size_t i = 0;

  while (i < n && s[i] >= '0' && s[i] <= '9') {
    if (v <= (ULLONG_MAX - 9) / 10)
      v = v * 10 + (unsigned long long)(s[i] - '0');
    else
      v = ULLONG_MAX;
    i++;
  }
  *used = i;
  return v;
}

/* End bytes after "bytes=START-": an EOF or a clamped one-past END. */
static int rng_end(const unsigned char *v, size_t vlen, size_t i, unsigned long long *end)
{
  size_t used;

  if (i >= vlen) {
    *end = HTTP_RANGE_OPEN;
    return 1;
  }
  *end = rng_u(v + i, vlen - i, &used);
  i += used;
  if (i != vlen)
    return 0;
  if (*end != ULLONG_MAX)
    (*end)++;
  return 1;
}

/* Parse a single "bytes=START[-END]" value. */
static int rng_value(const unsigned char *v, size_t vlen, unsigned long long *start, unsigned long long *end)
{
  size_t i;
  size_t used;

  *start = 0;
  *end = 0;
  if (vlen < 7 || memcmp(v, "bytes=", 6) != 0)
    return 0;
  i = 6;
  *start = rng_u(v + i, vlen - i, &used);
  i += used;
  if (used == 0)
    return 0;
  if (i >= vlen || v[i] != '-')
    return 0;
  i++;
  return rng_end(v, vlen, i, end);
}

int http_req_range(const unsigned char *in, unsigned long long *start, unsigned long long *end)
{
  const unsigned char *v;
  size_t vlen;

  if (start == NULL || end == NULL || in == NULL)
    return 0;
  if (!hdr_value(in, "range", 5, &v, &vlen))
    return 0;
  return rng_value(v, vlen, start, end);
}
