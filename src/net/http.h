#ifndef LITECAST_NET_HTTP_H
#define LITECAST_NET_HTTP_H

#include "buf/buffer.h"

#include <stddef.h>
#include <stdint.h>

/* Embedded HTTP server (DOMAIN.md §HTTP server): one endpoint `GET /stream`,
 * one response per connection, back-pressured writes. Event-loop-agnostic:
 * the loop accepts, assigns an fd to a slot, and steps the slot on EPOLLIN
 * (http_conn_input) / EPOLLOUT (http_conn_pump). */

enum {
  HTTP_PATH_CAP = 128,          /* bounded request line */
  HTTP_HDR_CAP = 1024,          /* bounded header block */
  HTTP_CONN_MAX = 8,            /* concurrent device pulls */
};

enum {
  HTTP_PH_HEAD = 0,             /* still reading the request */
  HTTP_PH_BODY = 1,             /* response head sent, serving body */
  HTTP_PH_DONE = 2              /* finished; slot may close */
};

enum {
  HTTP_RESP_NONE,
  HTTP_RESP_CHUNKED,            /* retained tail: finite, windowed memory */
  HTTP_RESP_FINITE,             /* Content-Length span (200/206/416) */
  HTTP_RESP_CLOSE               /* live: read-until-EOF then close */
};

#define HTTP_RANGE_OPEN ((unsigned long long)-1)        /* "bytes=START-" */

/* Static shape of the served stream, set once by the caller. A file-mode
 * stream with a trustworthy total is answered with Content-Length (and
 * Accept-Ranges); retained bytes are served from the memory window or the
 * spool; a request past the retained prefix falls back to a live tail. When
 * no trustworthy total exists, the stream is sent read-until-EOF then the
 * connection closes. DOMAIN.md §HTTP response selection describes the
 * selection matrix. */
struct http_src {
  struct buffer *buf;
  int spool_fd;                 /* -1 or a disk copy of the stream */
  unsigned long long total;     /* trustworthy total; 0 = unknown */
  const char *content_type;     /* response Content-Type, may be NULL */
  int arbitrary_end;            /* close an open-ended live Range at the frontier */
};

/* Server-side view of a no-spool producer window handed to a per-connection
 * anchor (DOMAIN.md §Producers and consumers). buf is the producer's
 * retention window; eof() is non-zero once that producer's source is fully
 * read and the command behind it has reaped. */
struct http_prod {
  struct buffer *buf;
  int (*eof)(void *user);
  void *user;
};

/* Resolve a no-spool request start to a producer window.  Returns 0 with
 * *prod set and *at = stream offset to attach at.  *tail = 1 when the
 * requested start cannot be retained: the caller serves a live tail from
 * the producer's head.  Returns -1 on a fatal (e.g. spawn failure). */
typedef int (*http_resolve_fn)(void *user, unsigned long long s,
                               struct http_prod ** prod, unsigned long long *at, int *tail);

/* One accepted connection. Fields are driven by the server; the loop only
 * pokes fd/events and reads the error/state verdicts. */
struct http_conn {
  int fd;
  unsigned char in[HTTP_HDR_CAP];
  size_t in_len;                /* request bytes buffered so far */
  int phase;
  int resp;                     /* HTTP_RESP_* */
  int range;                    /* request carried a served single Range */
  unsigned long long start;     /* first requested byte (exclusive of end) */
  unsigned long long end;       /* one past the last byte; RANGE_OPEN if open */
  unsigned long long span;      /* bytes promised in the finite body */
  size_t done;                  /* body bytes flushed so far */
  size_t cidx;                  /* memory-window consumer, SIZE_MAX if none */
  int spooling;                 /* finite body reads from the spool */
  unsigned long long spoff;     /* next spool stream offset to read */
  int bad;                      /* error status code instead of a body */
  char out[256];                /* stowed response head */
  size_t out_len;
  int hdr_sent;                 /* response head written */
  int hdr_pend;                 /* head deferred: start s not produced yet */
  int blocked;                  /* a flush would-block: skip until EPOLLOUT */
  int last;                     /* last stream bytes / final chunk pending */
  struct http_prod *prod;       /* no-spool producer anchor (NULL if none) */
  unsigned char stage[8192];    /* chunk framing assembly */
  const unsigned char *tx;      /* in-flight write pointer */
  size_t tx_len;                /* in-flight write credits */
  size_t pend;                  /* body bytes staged in the tx window */
};

struct http_srv {
  struct buffer *buf;
  int spool_fd;
  unsigned long long total;     /* known total; 0 = unknown */
  const char *content_type;
  int arbitrary_end;            /* 0 = never invent a Range end (--no-arbitrary-range) */
  int complete;                 /* source EOF reached (loop sets) */
  http_resolve_fn resolve;      /* no-spool producer resolution (NULL = none) */
  void *res_user;               /* opaque token forwarded to resolve() */
  void (*conn_close)(void *user, int fd);       /* loop hook: deregister before close */
  void *conn_close_user;
  size_t served;                /* responses completed (device pulled) */
  unsigned long long served_bytes;      /* cumulative body bytes flushed to device */
  int listen_fd;
  struct http_conn conns[HTTP_CONN_MAX];
};

/* http_parse.c */
int http_req_done(const unsigned char *in, size_t n, size_t *head_end);
int http_req_path(const unsigned char *in, const char **path, size_t *len);
int http_req_range(const unsigned char *in, unsigned long long *start, unsigned long long *end);

/* http.c */
int http_srv_init(struct http_srv *s, const struct http_src *src);
void http_srv_close(struct http_srv *s);
int http_listen(struct http_srv *s, uint16_t * port);
int http_accept(struct http_srv *s);
int http_conn_input(struct http_srv *s, size_t slot);
int http_conn_pump(struct http_srv *s, size_t slot);
int http_conn_set_fd(struct http_srv *s, size_t slot, int fd);
void http_conn_close(struct http_srv *s, size_t slot);
void http_conn_detach(struct http_srv *s, const struct http_conn *c);

/* http_serve.c */
int http_prep(struct http_srv *s, struct http_conn *c);
int http_head(struct http_conn *c, const struct http_srv *s);
int http_start_produced(const struct http_srv *s, const struct http_conn *c);

/* Resolve the buffer that owns a connection's window. Per-connection
 * anchoring replaces the global s->buf for no-spool conns. */
static inline struct buffer *conn_buf(const struct http_srv *s, const struct http_conn *c)
{
  return c->prod ? c->prod->buf : s->buf;
}

#endif
