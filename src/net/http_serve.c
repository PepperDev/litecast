#include "net/http.h"

#include <stdio.h>
#include <string.h>

/* Request routing (DOMAIN.md §HTTP response selection): a retained tail
 * (chunked), a Content-Length span (200/206/416), or a live tail (close). */

static unsigned long long stream_base(const struct http_srv *s, const struct http_conn *c)
{
  return (unsigned long long)buffer_offset(conn_buf(s, c));
}

/* Lowest retained stream offset of the serving window. */
static unsigned long long stream_avail(const struct http_srv *s, const struct http_conn *c)
{
  if (s->spool_fd >= 0)
    return 0;
  return stream_base(s, c) + (unsigned long long)buffer_lowest(conn_buf(s, c));
}

/* Attach a window consumer at stream offset `off` (as a data index). */
static int attach_at(const struct http_srv *s, struct http_conn *c, unsigned long long off)
{
  return buffer_add_consumer(conn_buf(s, c), (size_t)(off - stream_base(s, c)), &c->cidx);
}

/* Attach a window consumer at the lowest retained byte (live-tail front). */
static int attach_tail(const struct http_srv *s, struct http_conn *c)
{
  return buffer_add_consumer(conn_buf(s, c), buffer_lowest(conn_buf(s, c)), &c->cidx);
}

/* Window or file for a finite span at `off`: a direct serving fd (file mode or
 * command+spool) is the source of truth, else the window must retain `off`. */
static int body_source(const struct http_srv *s, struct http_conn *c, unsigned long long off)
{
  if (s->spool_fd >= 0) {
    c->spooling = 1;
    c->spoff = off;
    return 0;
  }
  {
    const struct buffer *b = conn_buf(s, c);
    unsigned long long base = stream_base(s, c);
    long long recv = (long long)buffer_received(b);
    unsigned long long retained = base + (unsigned long long)buffer_lowest(b);

    if (off >= retained && (long long)off < recv)
      return attach_at(s, c, off);
  }
  return -1;
}

/* --- response matrix --- */

/* Known total, nothing retained: serve the whole stream. */
static int route_clear(const struct http_srv *s, struct http_conn *c)
{
  c->resp = HTTP_RESP_FINITE;
  c->start = 0;
  c->end = s->total;
  c->span = s->total;
  return c->cidx == SIZE_MAX ? body_source(s, c, 0) : 0;
}

/* Live tail from a direct-serving fd (file or spool): the file until EOF. */
static int route_spool_tail(struct http_conn *c, unsigned long long off)
{
  c->spooling = 1;
  c->spoff = off;
  c->start = off;
  c->end = HTTP_RANGE_OPEN;
  c->resp = HTTP_RESP_CLOSE;
  return 0;
}

/* Live tail from the window: CHUNKED until a known total, then CLOSE. */
static int route_win_tail(const struct http_srv *s, struct http_conn *c, unsigned long long off)
{
  if (c->cidx == SIZE_MAX && attach_tail(s, c) != 0)
    return -1;
  c->start = off;
  c->end = HTTP_RANGE_OPEN;
  c->resp = s->total != 0 ? HTTP_RESP_CHUNKED : HTTP_RESP_CLOSE;
  return 0;
}

static int route_plain(const struct http_srv *s, struct http_conn *c)
{
  unsigned long long avail = stream_avail(s, c);

  if (s->total != 0 && avail == 0)
    return route_clear(s, c);
  if (s->spool_fd >= 0)
    return route_spool_tail(c, avail);
  return route_win_tail(s, c, avail);
}

static int route_live_tail(const struct http_srv *s, struct http_conn *c)
{
  if (s->spool_fd >= 0)
    return route_spool_tail(c, c->start);
  if (c->cidx == SIZE_MAX && attach_tail(s, c) != 0)
    return -1;
  c->resp = HTTP_RESP_CLOSE;
  c->end = HTTP_RANGE_OPEN;
  return 0;
}

/* Range span: 416, live tail, or the produced frontier as the end. */
static int route_range(const struct http_srv *s, struct http_conn *c, unsigned long long recv)
{
  unsigned long long avail = stream_avail(s, c);

  if (c->start < avail) {
    c->bad = 416;
    c->resp = HTTP_RESP_FINITE;
    return 0;
  }
  if (c->start >= recv)
    return route_live_tail(s, c);
  if (c->end == HTTP_RANGE_OPEN || c->end > recv)
    c->end = recv;
  c->span = c->end - c->start;
  c->resp = HTTP_RESP_FINITE;
  return c->cidx == SIZE_MAX ? body_source(s, c, c->start) : 0;
}

/* A byte-0 live restart is the device's only active playback (DOMAIN.md rule
 * 0): every other open body pull is an abandoned earlier pull — finalized so
 * the replay paces alone and the old producer idles out. */
static void retire_stale(struct http_srv *s, const struct http_conn *self)
{
  size_t k;

  for (k = 0; k < HTTP_CONN_MAX; k++) {
    const struct http_conn *o = &s->conns[k];

    if (o == self || o->fd < 0 || o->phase != HTTP_PH_BODY)
      continue;
    http_conn_close(s, k);
  }
}

/* Fire retirement only for a live plain byte-0 restart of an unknown-total stream. */
static void retire_stale_live(struct http_srv *s, const struct http_conn *c, unsigned long long at)
{
  if (at == 0 && c->start == 0 && s->total == 0)
    retire_stale(s, c);
}

/* Live tail from the resolved producer's retained head. */
static int resolve_tail(const struct http_srv *s, struct http_conn *c)
{
  if (attach_tail(s, c) != 0)
    return -1;
  c->start = stream_avail(s, c);
  c->end = HTTP_RANGE_OPEN;
  c->resp = HTTP_RESP_CLOSE;
  return 1;
}

/* Resolve a no-spool request to a producer window: 1 live tail, 0 attach, -1 fatal. */
static int resolve_body(struct http_srv *s, struct http_conn *c)
{
  struct http_prod *prod = NULL;
  unsigned long long at = c->start;
  int tail = 0;

  /* Re-attach releases the previous claim first: the same conn re-arming a
   * request (a keep-alive second GET, a mid-body re-route) must not leave a
   * ghost consumer pacing its old producer (§Multiple consumers). */
  http_conn_detach(s, c);
  if (s->resolve(s->res_user, c->start, &prod, &at, &tail) != 0)
    return -1;
  c->prod = prod;
  if (tail)
    return resolve_tail(s, c);
  if (attach_at(s, c, at) != 0)
    return -1;
  retire_stale_live(s, c, at);
  return 0;
}

/* 1 = routed (serviceable), -1 = fatal (route functions: 0 = routed). */
static int routed(int r)
{
  return r == 0 ? 1 : -1;
}

/* No producible end left: a whole-resource 200 from byte 0, re-resolved there. */
static int reroute_from_zero(struct http_srv *s, struct http_conn *c)
{
  int rv;

  c->range = 0;
  c->start = 0;
  rv = resolve_body(s, c);
  if (rv == 0)
    rv = routed(route_plain(s, c));
  return rv;
}

/* May the server close an open-ended `Range: bytes=N-` itself? A known total or
 * `--no-arbitrary-range` forbids it; a cold stream or a start already dropped
 * from the window is rule 0's whole-resource 200 instead. */
static int pin_closable(const struct http_srv *s, const struct http_conn *c, unsigned long long recv)
{
  return s->arbitrary_end && c->end == HTTP_RANGE_OPEN && s->total == 0 && recv > 0 && c->start >= stream_avail(s, c);
}

/* The device's own live resume (trace.22): the end is the live frontier, or
 * `N+1` — one byte, head stowed until the producer reaches it — when a running
 * producer is behind the start. */
static int pin_live_span(const struct http_srv *s, struct http_conn *c, unsigned long long recv)
{
  if (!pin_closable(s, c, recv))
    return 0;
  c->end = c->start < recv ? recv : c->start + 1;
  return 1;
}

/* Plain route, a Range span (closed, or closed by pin_live_span) or rule 3. */
static int body_route(struct http_srv *s, struct http_conn *c)
{
  unsigned long long recv = (unsigned long long)buffer_received(conn_buf(s, c));

  if (!c->range)
    return routed(route_plain(s, c));
  if (pin_live_span(s, c, recv))
    recv = c->end;              /* a chosen end is final: it is the frontier */
  if (s->total != 0 || c->end <= recv)
    return routed(route_range(s, c, recv));
  if (s->resolve == NULL)
    return routed(route_plain(s, c));
  return reroute_from_zero(s, c);
}

/* Body response for a valid request: a Range is resolved against the producers
 * and served in place; the plain route needs no resolution. */
static int pick_body(struct http_srv *s, struct http_conn *c)
{
  if (s->resolve != NULL) {
    int rv = resolve_body(s, c);

    if (rv != 0)
      return rv;
  }
  return body_route(s, c);
}

/* Route a valid request: 1 body to serve, 0 error head (c->bad set), -1
 * fatal.  On success c->resp / c->start / c->end / c->span / c->cidx /
 * c->spooling / c->spoff are all set for http_head and the body pump. */
static int http_route(struct http_srv *s, struct http_conn *c)
{
  const char *path;
  size_t plen;

  if (http_req_path(c->in, &path, &plen) != 0) {
    c->bad = 400;
    return 0;
  }
  if (plen != 7 || memcmp(path, "/stream", 7) != 0) {
    c->bad = 404;
    return 0;
  }
  return pick_body(s, c);
}

/* A no-spool consumer attached at a start the producer has not reached keeps its
 * response head STOWED (DOMAIN.md §HTTP response selection rule 1): a `200` head
 * with an empty body is never flushed to a still-waiting start (trace.13). */
int http_start_produced(const struct http_srv *s, const struct http_conn *c)
{
  const struct buffer *b;

  if (s->resolve == NULL || c->spooling || c->bad != 0)
    return 1;
  b = conn_buf(s, c);
  return (unsigned long long)buffer_offset(b) + (unsigned long long)buffer_received(b) > c->start;
}

int http_prep(struct http_srv *s, struct http_conn *c)
{
  int r = http_route(s, c);

  if (r == -1)
    return -1;
  if (http_head(c, s) != 0)
    return -1;
  c->phase = HTTP_PH_BODY;
  if (!http_start_produced(s, c))
    c->hdr_pend = 1;            /* hold the head until the start is produced */
  return 1;
}

/* --- body stepping (headers in http_head.c) --- */
