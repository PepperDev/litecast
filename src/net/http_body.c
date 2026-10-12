#include "net/http.h"
#include "source/spool.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Body serving: back-pressured streaming out of the per-connection tx
 * window. Window steps drain the memory-window consumer; chunked frames are
 * assembled from the staged payload, close-mode simply forwards the bytes;
 * finite-mode stops at c->span and needs no terminal chunk.
 *
 * Write discipline (DOMAIN.md Design Invariant "never busy-retry a
 * would-block write"): a flush that would block halts that connection's
 * drain with c->blocked set and returns HTTP_STEP_STALL; the event loop
 * skips blocked slots (pump_all) until the next EPOLLOUT wakes the conn and
 * the socket has room again. Win/stall are distinct verdicts: a step that
 * yields bytes (or reaches a terminal state) returns 0/1, a would-block
 * flush or an empty window returns STALL so a single pump pass never burns
 * its 32-step budget against a stuck consumer. */

#ifdef LITECAST_TEST
/* Test-only write injector. -1 = real path (default). Any value below -1
 * forces a would-block result (errno=EAGAIN) persistently and is counted;
 * 0 forces a zero-byte write (error); a positive value caps a real write at
 * that many bytes, one-shot, so the partial-write loop is exercised against
 * a consistent offset. */
ssize_t _mock_conn_write = -1;
size_t _mock_conn_writes = 0;

void http_body_mock_reset(void)
{
  _mock_conn_write = -1;
  _mock_conn_writes = 0;
}
#endif

static ssize_t conn_write(int fd, const void *p, size_t n)
{
#ifdef LITECAST_TEST
  if (_mock_conn_write < -1) {
    _mock_conn_writes++;
    errno = EAGAIN;
    return -1;
  }
  if (_mock_conn_write == 0)
    return 0;
  if (_mock_conn_write > 0 && (size_t)_mock_conn_write < n)
    n = (size_t)_mock_conn_write;
  _mock_conn_writes++;
  _mock_conn_write = -1;
#endif
  return write(fd, p, n);
}

static ssize_t write_retry(int fd, const void *p, size_t n)
{
  ssize_t r;

  do
    r = conn_write(fd, p, n);
  while (r < 0 && errno == EINTR);
  return r;
}

enum {
  HTTP_STEP_STALL = 2           /* no progress possible: break the budget */
};

/* Source-complete test: a no-spool conn uses the per-producer anchor;
 * file / spool conns fall back to the loop-driven s->complete flag. */
static int conn_complete(const struct http_srv *s, const struct http_conn *c)
{
  return c->prod ? c->prod->eof((void *)c->prod->user) : s->complete;
}

static int http_flush(struct http_conn *c)
{
  while (c->tx_len > 0) {
    ssize_t r;

    r = write_retry(c->fd, c->tx, c->tx_len);
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      c->blocked = 1;
      return HTTP_STEP_STALL;
    }
    if (r <= 0)
      return -1;
    c->tx += r;
    c->tx_len -= (size_t)r;
  }
  c->blocked = 0;
  return 1;
}

/* Assemble one chunk frame: "<hex>\r\n" payload "\r\n". */
static void win_chunk(struct http_conn *c, size_t got)
{
  size_t n;

  n = (size_t)snprintf((char *)c->stage, 64, "%zx\r\n", got);
  memmove(c->stage + n, c->stage + 64, got);
  c->stage[n + got] = '\r';
  c->stage[n + got + 1] = '\n';
  c->tx = c->stage;
  c->tx_len = n + got + 2;
}

/* Finalize a window response: terminal chunk, or plain EOF after drain. */
static int win_last(struct http_conn *c)
{
  if (c->resp == HTTP_RESP_FINITE) {
    c->pend = 0;
    c->phase = HTTP_PH_DONE;
    return 1;
  }
  if (c->resp == HTTP_RESP_CHUNKED) {
    int r;

    c->tx = (const unsigned char *)"0\r\n\r\n";
    c->tx_len = 5;
    c->pend = 0;
    r = http_flush(c);
    if (r == 1)
      c->phase = HTTP_PH_DONE;
    return r;
  }
  c->phase = HTTP_PH_DONE;
  return 1;
}

/* Stage one window slice from the memory-window consumer. */
static int win_read(const struct http_srv *s, struct http_conn *c, size_t want, size_t *got)
{
  if (buffer_consumer_read(conn_buf(s, c), c->cidx, c->stage + 64, want, got) != 0)
    return -1;
  if (*got == 0 && conn_complete(s, c))
    c->last = 1;
  return 0;
}

/* Bytes a step may read up to, capped at the staging window and the span
 * bound. A CLOSE response (live pull) has no span; read up to the staging
 * cap. */
static size_t body_cap(const struct http_conn *c)
{
  size_t cap = sizeof c->stage - 64;

  if (c->resp == HTTP_RESP_FINITE) {
    size_t need = (size_t)(c->span - c->done);

    if (cap > need)
      cap = need;
  }
  return cap;
}

static int win_slice(const struct http_srv *s, struct http_conn *c)
{
  size_t got = 0;
  size_t want = body_cap(c);

  if (win_read(s, c, want, &got) != 0)
    return -1;
  if (got == 0)
    return conn_complete(s, c) ? win_last(c) : HTTP_STEP_STALL;
  c->pend = got;
  if (c->resp == HTTP_RESP_CHUNKED) {
    win_chunk(c, got);
  } else {
    c->tx = c->stage + 64;
    c->tx_len = got;
  }
  return 1;
}

static int spool_last(struct http_conn *c)
{
  c->last = 1;
  return win_last(c);
}

static void win_commit(struct http_conn *c)
{
  c->done += c->pend;
  c->pend = 0;
}

static int win_done(const struct http_conn *c)
{
  return c->last || (c->resp == HTTP_RESP_FINITE && c->done >= c->span);
}

static int http_step_spool(const struct http_srv *s, struct http_conn *c)
{
  size_t got = 0;
  int r;

  if (win_done(c))
    return win_last(c);
  r = spool_read(s->spool_fd, c->spoff, c->stage + 64, body_cap(c), &got);
  if (r != 0)
    return -1;
  if (got == 0)
    return conn_complete(s, c) ? spool_last(c) : HTTP_STEP_STALL;
  c->spoff += got;
  c->pend = got;
  c->tx = c->stage + 64;
  c->tx_len = got;
  r = http_flush(c);
  if (r != 1)
    return r;
  win_commit(c);
  return 1;
}

static int http_step_win(const struct http_srv *s, struct http_conn *c)
{
  int r;

  if (win_done(c))
    return win_last(c);
  r = win_slice(s, c);
  if (r != 1)
    return r;
  r = http_flush(c);
  if (r != 1)
    return r;
  c->done += c->pend;
  c->pend = 0;
  return 1;
}

static int pump_head(const struct http_srv *s, struct http_conn *c)
{
  if (c->hdr_sent)
    return 0;
  if (c->hdr_pend && !http_start_produced(s, c))
    return 0;                   /* head deferred: start s not produced yet */
  c->hdr_pend = 0;
  c->tx = (const unsigned char *)c->out;
  c->tx_len = c->out_len;
  c->hdr_sent = 1;
  return 1;
}

static int pump_step(const struct http_srv *s, struct http_conn *c)
{
  int r;

  if (c->tx_len == 0) {
    if (c->phase == HTTP_PH_DONE)
      return 1;
    if (c->spooling)
      r = http_step_spool(s, c);
    else
      r = http_step_win(s, c);
    if (r != 1)
      return r;
  } else {
    r = http_flush(c);
    if (r != 1)
      return r;
  }
  return 0;
}

static int pump_budget(const struct http_srv *s, struct http_conn *c)
{
  int i;

  for (i = 0; i < 32; i++) {
    int r = pump_step(s, c);

    if (r == 0)
      continue;
    if (r == HTTP_STEP_STALL)
      return 0;
    return r;
  }
  return 0;
}

int http_conn_pump(struct http_srv *s, size_t slot)
{
  struct http_conn *c;

  if (slot >= HTTP_CONN_MAX)
    return -1;
  c = &s->conns[slot];
  if (c->fd < 0 || c->phase != HTTP_PH_BODY)
    return 0;
  (void)pump_head(s, c);
  return pump_budget(s, c);
}
