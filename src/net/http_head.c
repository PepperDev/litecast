#include "net/http.h"

#include <stdio.h>
#include <string.h>

/* Response-head construction (DOMAIN.md §HTTP response selection).  The
 * routing matrix in http_serve.c decides *what* to serve and stamps the
 * per-connection state; this unit turns that verdict into the HTTP head
 * bytes (200/206/416/400/404, finite/chunked/close). */

static const char err_400[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
static const char err_404[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

static const char *http_mime(const struct http_srv *s)
{
  return s->content_type != NULL ? s->content_type : "application/octet-stream";
}

static int head_err(struct http_conn *c)
{
  if (c->bad == 404) {
    memcpy(c->out, err_404, sizeof err_404 - 1);
    c->out_len = sizeof err_404 - 1;
  } else {
    memcpy(c->out, err_400, sizeof err_400 - 1);
    c->out_len = sizeof err_400 - 1;
  }
  return 0;
}

static int head_range(struct http_conn *c, const struct http_srv *s)
{
  if (s->total != 0) {
    char buf[32];

    (void)snprintf(buf, sizeof buf, "%llu", (unsigned long long)s->total);
    c->out_len =
        (size_t)snprintf(c->out, sizeof c->out,
                         "HTTP/1.1 416 Range Not Satisfiable\r\n"
                         "Content-Range: bytes */%s\r\n" "Content-Length: 0\r\n\r\n", buf);
  } else {
    c->out_len =
        (size_t)snprintf(c->out, sizeof c->out,
                         "HTTP/1.1 416 Range Not Satisfiable\r\n"
                         "Content-Range: bytes */*\r\n" "Content-Length: 0\r\n\r\n");
  }
  return c->out_len >= sizeof c->out ? -1 : 0;
}

static int head_part(struct http_conn *c, const struct http_srv *s)
{
  if (s->total != 0) {
    c->out_len =
        (size_t)snprintf(c->out, sizeof c->out,
                         "HTTP/1.1 206 Partial Content\r\n"
                         "Content-Range: bytes %llu-%llu/%llu\r\n"
                         "Content-Length: %llu\r\n"
                         "Content-Type: %s\r\n\r\n",
                         c->start, c->end - 1, (unsigned long long)s->total, (unsigned long long)c->span, http_mime(s));
  } else {
    c->out_len =
        (size_t)snprintf(c->out, sizeof c->out,
                         "HTTP/1.1 206 Partial Content\r\n"
                         "Content-Range: bytes %llu-%llu/*\r\n"
                         "Content-Length: %llu\r\n"
                         "Content-Type: %s\r\n\r\n", c->start, c->end - 1, (unsigned long long)c->span, http_mime(s));
  }
  return c->out_len >= sizeof c->out ? -1 : 0;
}

static int head_ok_full(struct http_conn *c, const struct http_srv *s)
{
  c->out_len =
      (size_t)snprintf(c->out, sizeof c->out,
                       "HTTP/1.1 200 OK\r\nContent-Length: %llu\r\n"
                       "Accept-Ranges: bytes\r\n"
                       "Content-Type: %s\r\n\r\n", (unsigned long long)c->span, http_mime(s));
  return c->out_len >= sizeof c->out ? -1 : 0;
}

static int head_finite(struct http_conn *c, const struct http_srv *s)
{
  if (!c->range)
    return head_ok_full(c, s);
  return head_part(c, s);
}

static int head_ok(struct http_conn *c, const struct http_srv *s)
{
  const char *mime = http_mime(s);

  switch (c->resp) {
  case HTTP_RESP_CHUNKED:
    c->out_len =
        (size_t)snprintf(c->out, sizeof c->out,
                         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" "Content-Type: %s\r\n\r\n", mime);
    break;
  case HTTP_RESP_CLOSE:
    c->out_len =
        (size_t)snprintf(c->out, sizeof c->out,
                         "HTTP/1.1 200 OK\r\nConnection: close\r\n" "Content-Type: %s\r\n\r\n", mime);
    break;
  case HTTP_RESP_FINITE:
    return head_finite(c, s);
  default:
    return -1;
  }
  return c->out_len >= sizeof c->out ? -1 : 0;
}

int http_head(struct http_conn *c, const struct http_srv *s)
{
  if (c->bad != 0) {
    if (c->bad == 416)
      return head_range(c, s);
    return head_err(c);
  }
  return head_ok(c, s);
}
