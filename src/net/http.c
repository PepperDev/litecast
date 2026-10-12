#include "net/http.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HTTP_BACKLOG 8

/* Socket plumbing and connection lifecycle (DOMAIN.md §HTTP server).
 * Response construction and body stepping live in http_serve.c; these two
 * files together stay under the per-file LOC gate. */

static int blocked(void)
{
  return errno == EAGAIN || errno == EWOULDBLOCK;
}

static ssize_t read_retry(int fd, void *buf, size_t n)
{
  ssize_t r;

  do
    r = read(fd, buf, n);
  while (r < 0 && errno == EINTR);
  return r;
}

/* One bounded read. Returns 1 progress, 2 oversized (answered 400), 0
 * would-block, -1 EOF or fatal error. */
static int http_read1(const struct http_srv *s, struct http_conn *c, unsigned char *buf, size_t n)
{
  ssize_t r;

  r = read_retry(c->fd, buf, n);
  if (r <= 0)
    return r < 0 && blocked()? 0 : -1;
  if ((size_t)r > sizeof c->in - c->in_len) {
    c->bad = 400;
    (void)http_head(c, s);
    c->phase = HTTP_PH_BODY;
    return 2;
  }
  memcpy(c->in + c->in_len, buf, (size_t)r);
  c->in_len += (size_t)r;
  return 1;
}

static int http_drive(struct http_srv *s, struct http_conn *c)
{
  for (;;) {
    unsigned char buf[512];
    size_t he;
    int r;

    r = http_read1(s, c, buf, sizeof buf);
    if (r <= 0)
      return r;
    if (r == 2)
      return 1;
    if (http_req_done(c->in, c->in_len, &he)) {
      c->in[he] = '\0';
      c->range = http_req_range(c->in, &c->start, &c->end);
      return http_prep(s, c);
    }
  }
}

int http_conn_input(struct http_srv *s, size_t slot)
{
  struct http_conn *c;

  c = &s->conns[slot];
  if (c->fd < 0)
    return -1;
  return http_drive(s, c);
}

int http_srv_init(struct http_srv *s, const struct http_src *src)
{
  size_t i;

  if (s == NULL || src == NULL || src->buf == NULL)
    return -1;
  memset(s, 0, sizeof *s);
  s->buf = src->buf;
  s->spool_fd = src->spool_fd;
  s->total = src->total;
  s->content_type = src->content_type;
  s->arbitrary_end = src->arbitrary_end;
  s->listen_fd = -1;
  for (i = 0; i < HTTP_CONN_MAX; i++)
    s->conns[i].fd = -1;
  return 0;
}

void http_srv_close(struct http_srv *s)
{
  size_t i;

  if (s == NULL)
    return;
  for (i = 0; i < HTTP_CONN_MAX; i++)
    if (s->conns[i].fd >= 0)
      http_conn_close(s, i);
  if (s->listen_fd >= 0) {
    close(s->listen_fd);
    s->listen_fd = -1;
  }
}

static int http_bind(int fd, struct sockaddr_in *a)
{
  memset(a, 0, sizeof *a);
  a->sin_family = AF_INET;
  a->sin_addr.s_addr = htonl(INADDR_ANY);
  return bind(fd, (struct sockaddr *)a, sizeof *a) != 0 || listen(fd, HTTP_BACKLOG) != 0;
}

int http_listen(struct http_srv *s, uint16_t *port)
{
  struct sockaddr_in a;
  socklen_t alen = sizeof a;
  int fd;
  int on = 1;

  if (s == NULL)
    return -1;
  fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
  if (http_bind(fd, &a) != 0 || getsockname(fd, (struct sockaddr *)&a, &alen) != 0) {
    close(fd);
    return -1;
  }
  s->listen_fd = fd;
  if (port != NULL)
    *port = ntohs(a.sin_port);
  return 0;
}

int http_conn_set_fd(struct http_srv *s, size_t slot, int fd)
{
  struct http_conn *c;

  if (slot >= HTTP_CONN_MAX || fd < 0)
    return -1;
  c = &s->conns[slot];
  memset(c, 0, sizeof *c);
  c->fd = fd;
  c->phase = HTTP_PH_HEAD;
  c->cidx = SIZE_MAX;
  return 0;
}

static struct http_conn *free_slot(struct http_srv *s)
{
  size_t i;

  if (s->listen_fd < 0)
    return NULL;
  for (i = 0; i < HTTP_CONN_MAX; i++)
    if (s->conns[i].fd < 0)
      return &s->conns[i];
  return NULL;
}

int http_accept(struct http_srv *s)
{
  const struct http_conn *c;
  int fd;

  if (s == NULL)
    return -1;
  c = free_slot(s);
  if (c == NULL)
    return -1;
  fd = accept4(s->listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
  if (fd < 0)
    return blocked()? 0 : -1;
  if (http_conn_set_fd(s, (size_t)(c - s->conns), fd) != 0) {
    close(fd);
    return -1;
  }
  return 1;
}

/* Connections are never closed for idleness (DOMAIN.md §HTTP server): a
 * paused-but-attached device keeps its conn and its producer alive, and
 * playback resumes on the next EPOLLOUT wake. A slot closes only on device
 * EOF/RST, a connection error, or run teardown. */

/* Removing a consumer swaps the last one into the hole: move the displaced
 * consumer index back into the conn that held it. With per-connection
 * anchoring, only conns sharing the same buffer may hold valid indices. */
static void reloc_consumer(struct http_srv *s, size_t self, size_t old, size_t last)
{
  const struct buffer *b = conn_buf(s, &s->conns[self]);
  size_t k;

  for (k = 0; k < HTTP_CONN_MAX; k++)
    if (k != self && s->conns[k].cidx == last && conn_buf(s, &s->conns[k]) == b) {
      s->conns[k].cidx = old;
      return;
    }
}

/* Release a conn's consumer, relocating the displaced last index first. */
static void detach_consumer(struct http_srv *s, const struct http_conn *c)
{
  struct buffer *b = conn_buf(s, c);
  size_t last = b->cons.len - 1;

  if (c->cidx != last)
    reloc_consumer(s, (size_t)(c - s->conns), c->cidx, last);
  buffer_remove_consumer(b, c->cidx);
}

/* Re-attach hygiene (DOMAIN.md §Multiple consumers): a consumer index is
 * owned by exactly one connection, so releasing a conn's previous claim is
 * the first step of any re-attach. A stale entry never advances its
 * read_off and no path can see it is dead — behind the live consumers it
 * pins buffer_lowest (the producer never opens room, the replay freezes at
 * the retained end), ahead of them it keeps the window floor and the
 * producer unwatched-thrashing forever (cons.len > 0 blocks both gating and
 * the idle reap). */
void http_conn_detach(struct http_srv *s, const struct http_conn *c)
{
  if (c->cidx != SIZE_MAX)
    detach_consumer(s, c);
}

/* Close-time accounting: completed responses. */
static void note_close(struct http_srv *s, const struct http_conn *c)
{
  if (c->phase == HTTP_PH_DONE) {
    s->served++;
    s->served_bytes += (unsigned long long)c->done;
  }
}

void http_conn_close(struct http_srv *s, size_t slot)
{
  struct http_conn *c;

  if (slot >= HTTP_CONN_MAX)
    return;
  c = &s->conns[slot];
  if (c->fd < 0)
    return;
  note_close(s, c);
  if (c->cidx != SIZE_MAX)
    detach_consumer(s, c);
  if (s->conn_close != NULL)
    s->conn_close(s->conn_close_user, c->fd);
  close(c->fd);
  c->fd = -1;
  c->cidx = SIZE_MAX;           /* no consumer held by a closed conn */
  c->prod = NULL;               /* drop the per-conn producer anchor */
}
