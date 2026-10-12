#include "test_util.h"

#include "buf/buffer.h"
#include "buf/cvec.h"
#include "source/spool.h"
#include "../src/source/spool.c"
#include "../src/net/http_parse.c"
#include "../src/net/http.c"
#include "../src/net/http_serve.c"
#include "../src/net/http_head.c"
#include "../src/net/http_body.c"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PAGE 4096UL
#define NOW 1000000UL

static const unsigned char DATA[] = "ABCDEFGHIJKLMNOP";
#define DLEN (sizeof DATA - 1)
/* 25 bytes, so DLEN + 25 produced leaves byte 40 as the filler's last byte. */
static const unsigned char FILL[] = "QRSTUVWXYZabcdefghijklmno";

static void make_cfg(struct cache_cfg *cfg, size_t bytes)
{
  memset(cfg, 0, sizeof *cfg);
  cfg->kind = CACHE_BYTES;
  cfg->bytes = bytes;
}

static int srv_full(struct http_srv *srv, struct buffer *b)
{
  struct http_src src;

  memset(&src, 0, sizeof src);
  src.buf = b;
  src.spool_fd = -1;
  src.total = DLEN;
  src.arbitrary_end = 1;        /* the default; a known total ignores it */
  return http_srv_init(srv, &src);
}

/* Receive whatever the server wrote; pump until done or until cap. */
static size_t drain(struct http_srv *s, size_t slot, int cfd, unsigned char *out, size_t cap)
{
  size_t got = 0;
  unsigned int i;

  for (i = 0; i < 200000; i++) {
    ssize_t n;
    int r;

    r = http_conn_pump(s, slot);
    do
      n = recv(cfd, out + got, cap - got, MSG_DONTWAIT);
    while (n < 0 && errno == EINTR);
    if (n > 0)
      got += (size_t)n;
    if (r == 1 || r < 0)
      break;
    if (n <= 0)
      break;
  }
  return got;
}

/* Full request/response exchange on a fresh socketpair at the slot. */
static int xact_at(struct http_srv *s, size_t slot, const char *req, unsigned char *resp, size_t cap, size_t *resp_len)
{
  int sv[2];

  http_conn_close(s, slot);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(s, slot, sv[0]) == 0);
  EXPECT(write(sv[1], req, strlen(req)) == (ssize_t) strlen(req));
  EXPECT(http_conn_input(s, slot) == 1);
  *resp_len = drain(s, slot, sv[1], resp, cap);
  http_conn_close(s, slot);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

static int xact(struct http_srv *s, const char *req, unsigned char *resp, size_t cap, size_t *resp_len)
{
  return xact_at(s, 0, req, resp, cap, resp_len);
}

/* First body byte after the response head, with its length. */
static size_t body_of(const unsigned char *buf, size_t n, size_t *off)
{
  size_t i;

  for (i = 0; i + 4 <= n; i++)
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      *off = i + 4;
      return n - (i + 4);
    }
  *off = n;
  return 0;
}

static int bytes_in(const unsigned char *buf, size_t n, const char *needle)
{
  size_t nl = strlen(needle);
  size_t i;

  if (nl > n)
    return 0;
  for (i = 0; i + nl <= n; i++)
    if (memcmp(buf + i, needle, nl) == 0)
      return 1;
  return 0;
}

static int t_parse(void)
{
  unsigned char in[128];
  const char *path;
  size_t he;
  size_t plen;
  unsigned long long s;
  unsigned long long e;

  EXPECT(http_req_done((const unsigned char *)"GET /\r\n\r\n", 10, &he) == 1);
  EXPECT(http_req_done((const unsigned char *)"GET /nope", 9, &he) == 0);
  EXPECT(http_req_done((const unsigned char *)"ab", 2, &he) == 0);

  memcpy(in, "GET /stream HTTP/1.1\r\nRange: bytes=2-5\r\nHost: x\r\n\r\n",
         sizeof "GET /stream HTTP/1.1\r\nRange: bytes=2-5\r\nHost: x\r\n\r\n");
  EXPECT(http_req_path(in, &path, &plen) == 0);
  EXPECT(plen == 7 && memcmp(path, "/stream", 7) == 0);

  memcpy(in, "GET /stream HTTP/1.1\r\n\r\n", 25);
  EXPECT(http_req_path(in, &path, &plen) == 0);
  EXPECT(plen == 7 && memcmp(path, "/stream", 7) == 0);

  memcpy(in, "POST /stream HTTP/1.1\r\n\r\n", 25);
  EXPECT(http_req_path(in, &path, &plen) != 0);

  /* Range parsing: inclusive end becomes exclusive; open-ended; suffix and
   * multi-range and non-bytes forms are ignored (treated as no Range). */
  memcpy(in, "GET /s HTTP/1.1\r\nRange: bytes=2-5\r\n\r\n", 35);
  (void)in;
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\nRange: bytes=2-5\r\n\r\n", &s, &e) == 1);
  EXPECT(s == 2 && e == 6);
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\nrange: bytes=10-\r\n\r\n", &s, &e) == 1);
  EXPECT(s == 10 && e == HTTP_RANGE_OPEN);
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\nRange: bytes=-5\r\n\r\n", &s, &e) == 0);
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\nRange: bytes=2-5,8-9\r\n\r\n", &s, &e) == 0);
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\nRange: items=2-5\r\n\r\n", &s, &e) == 0);
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\n\r\n", &s, &e) == 0);
  EXPECT(http_req_range((const unsigned char *)"GET /s HTTP/1.1\r\nX-Range: bytes=2-5\r\n\r\n", &s, &e) == 0);
  EXPECT(http_req_range(NULL, &s, &e) == 0);
  return 0;
}

static int t_listen(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct sockaddr_in a;
  uint16_t port;
  int cfd;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);
  EXPECT(srv_full(&s, &b) == 0);
  EXPECT(http_listen(&s, &port) == 0);
  EXPECT(port != 0);
  EXPECT(http_accept(&s) == 0); /* no client yet: EAGAIN */

  cfd = socket(AF_INET, SOCK_STREAM, 0);
  EXPECT(cfd >= 0);
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  EXPECT(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
  EXPECT(connect(cfd, (struct sockaddr *)&a, sizeof a) == 0);

  EXPECT(http_accept(&s) == 1);
  EXPECT((unsigned char)write(cfd, "GET /stream HTTP/1.1\r\n\r\n", 24) >= 0);
  EXPECT(http_conn_input(&s, 0) == 1);

  close(cfd);
  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

static int t_full_ok(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  unsigned char resp[4096];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);
  EXPECT(srv_full(&s, &b) == 0);
  s.complete = 1;

  /* Total known and the whole stream retained: Content-Length +
   * Accept-Ranges, served as a finite span from the window. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "HTTP/1.1 200 OK"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 16"));
  EXPECT(bytes_in(resp, rl, "Accept-Ranges: bytes"));
  EXPECT(!bytes_in(resp, rl, "Transfer-Encoding:"));
  EXPECT(!bytes_in(resp, rl, "10\r\nABCDEFGHIJKLMNOP\r\n0\r\n\r\n"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

static int t_range206(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  unsigned char resp[4096];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);
  EXPECT(srv_full(&s, &b) == 0);
  s.complete = 1;

  /* Single satisfiable range: 206, Content-Range, span body from the window. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=2-5\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "HTTP/1.1 206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 2-5/16"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 4"));
  EXPECT(bytes_in(resp, rl, "CDEF"));
  EXPECT(!bytes_in(resp, rl, "ABCD"));

  /* Open-ended range clamps at the produced bytes. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=12-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 12-15/16"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA + 12));

  /* Request past the produced bytes: live tail, no Content-Range. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=99-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "HTTP/1.1 200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Range:"));

  /* Exactly at the end (start == total): same live tail, not a silent close
   * (pre-fix body_source hit off == recv → span-0 → -1 → no response). */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=16-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "HTTP/1.1 200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Range:"));

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

/* Window with the head dropped (base > 0): plain GET becomes a chunked
 * retained tail, ranges behind the retained prefix are refused with 416. */
static int t_range_dropped(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  unsigned char resp[4096];
  size_t rl;
  size_t cidx;
  unsigned char disc[8];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);
  EXPECT(buffer_add_consumer(&b, 0, &cidx) == 0);
  EXPECT(buffer_consumer_read(&b, cidx, disc, 8, &rl) == 0);
  EXPECT(rl == 8);
  buffer_compact(&b, 8);
  EXPECT(buffer_offset(&b) == 8);
  buffer_remove_consumer(&b, cidx);
  EXPECT(srv_full(&s, &b) == 0);
  s.complete = 1;

  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Transfer-Encoding: chunked"));
  EXPECT(!bytes_in(resp, rl, "Content-Length:"));
  EXPECT(bytes_in(resp, rl, "8\r\nIJKLMNOP\r\n0\r\n\r\n"));

  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=2-5\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "416 Range Not Satisfiable"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes */16"));
  EXPECT(!bytes_in(resp, rl, "ABCD"));

  /* Range inside the retained window still 206s from memory. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=13-14\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 13-14/16"));
  EXPECT(bytes_in(resp, rl, "NO"));

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

static int t_400_oversize(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  char req[2048];
  unsigned char resp[1024];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(srv_full(&s, &b) == 0);

  memset(req, 'A', sizeof req - 5);
  memcpy(req + sizeof req - 5, "\r\n\r\n", 5);
  EXPECT(xact(&s, req, resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "400 Bad Request"));

  EXPECT(xact(&s, "GET /other HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "404 Not Found"));

  EXPECT(xact(&s, "POST /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "400 Bad Request"));

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

static int t_close(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct http_src src;
  unsigned char resp[4096];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);

  memset(&src, 0, sizeof src);
  src.buf = &b;
  src.spool_fd = -1;
  EXPECT(http_srv_init(&s, &src) == 0);
  s.complete = 0;

  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Transfer-Encoding:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));
  EXPECT(!bytes_in(resp, rl, "Content-Length:"));

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

static int t_multi(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  unsigned char r0[1024];
  unsigned char r1[1024];
  size_t l0;
  size_t l1;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);
  EXPECT(srv_full(&s, &b) == 0);
  s.complete = 1;

  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", r0, sizeof r0, &l0) == 0);
  EXPECT(xact_at(&s, 1, "GET /stream HTTP/1.1\r\n\r\n", r1, sizeof r1, &l1) == 0);
  EXPECT(bytes_in(r1, l1, "200 OK") && bytes_in(r1, l1, (const char *)DATA));

  /* both conns alive at the same time, independent */
  {
    int sv[2];
    unsigned char rb[1024];
    size_t got = 0;

    http_conn_close(&s, 0);
    http_conn_close(&s, 1);
    EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
    EXPECT(http_conn_set_fd(&s, 1, sv[1]) == 0);
    EXPECT((unsigned char)write(sv[1], "GET /stream HTTP/1.1\r\n\r\n", 24) >= 0);
    EXPECT((unsigned char)write(sv[0], "GET /stream HTTP/1.1\r\n\r\n", 24) >= 0);
    EXPECT(http_conn_input(&s, 0) == 1);
    EXPECT(http_conn_input(&s, 1) == 1);
    EXPECT(http_conn_pump(&s, 0) >= 0);
    got = drain(&s, 1, sv[0], rb, sizeof rb);
    EXPECT(bytes_in(rb, got, "200 OK"));
    memset(rb, 0, sizeof rb);
    got = drain(&s, 0, sv[1], rb, sizeof rb);
    EXPECT(bytes_in(rb, got, "200 OK") && bytes_in(rb, got, (const char *)DATA));
    close(sv[0]);
    close(sv[1]);
  }

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

static int t_spool(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct http_src src;
  unsigned char resp[4096];
  size_t rl;
  char tmpl[64] = "/tmp/lh_http_XXXXXX";
  int sp;

  make_cfg(&cfg, 16UL);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);

  sp = spool_open(tmpl);
  EXPECT(sp >= 0);
  EXPECT(spool_append(sp, DATA, DLEN) == 0);

  memset(&src, 0, sizeof src);
  src.buf = &b;
  src.spool_fd = sp;
  EXPECT(http_srv_init(&s, &src) == 0);
  s.complete = 1;

  /* Unknown total (command still producing): live read-until-EOF, served
   * from the memory window, never Content-Length. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Length:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));

  /* A finished command with the head dropped: the spool serves ranges the
   * memory window already rewound past, caught up over the disk copy. */
  s.total = DLEN;
  s.complete = 1;
  {
    struct buffer b2;
    size_t cidx;
    unsigned char disc[8];

    EXPECT(buffer_open(&b2, PAGE, &cfg, &bsrc) == 0);
    EXPECT(buffer_append(&b2, DATA, DLEN) == 0);
    EXPECT(buffer_add_consumer(&b2, 0, &cidx) == 0);
    EXPECT(buffer_consumer_read(&b2, cidx, disc, 8, &rl) == 0);
    buffer_compact(&b2, 8);
    buffer_remove_consumer(&b2, cidx);
    s.buf = &b2;

    EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=0-3\r\n\r\n", resp, sizeof resp, &rl) == 0);
    EXPECT(bytes_in(resp, rl, "206 Partial Content"));
    EXPECT(bytes_in(resp, rl, "Content-Range: bytes 0-3/16"));
    EXPECT(bytes_in(resp, rl, "ABCD"));

    buffer_close(&b2);
  }
  s.buf = &b;

  /* spool write-error and partial-write paths via the test injector */
  EXPECT(spool_open(NULL) == -1);
  spool_mock_reset();
  _mock_write_result = -2;
  EXPECT(spool_append(sp, DATA, DLEN) == -1);
  _mock_write_result = 0;
  EXPECT(spool_append(sp, DATA, DLEN) == -1);
  spool_mock_reset();
  _mock_write_result = 3;
  EXPECT(spool_append(sp, DATA, DLEN) == 0);
  spool_mock_reset();

  http_srv_close(&s);
  spool_close(sp);
  buffer_close(&b);
  return 0;
}

/* Live spool pull (`.tmp/.trace-lc.5`): a still-running `--command
 * --cache-to-fs` serves its bytes straight from the disk copy with no
 * Content-Length, stalls at the file's current end, and resumes in place
 * as the producer advances — the loop must regain the session socket
 * instead of draining the pipe until the command exhausts. */
static int t_spool_live(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct http_src src;
  unsigned char out[512];
  unsigned char resp[256];
  size_t off = 0;
  size_t rl;
  size_t boff;
  char tmpl[64] = "/tmp/lh_http_XXXXXX";
  int sp;
  int sv[2];
  int sv2[2];

  make_cfg(&cfg, 16UL);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);

  sp = spool_open(tmpl);
  EXPECT(sp >= 0);
  EXPECT(spool_append(sp, DATA, 8) == 0);

  memset(&src, 0, sizeof src);
  src.buf = &b;                 /* window mirrors produced (non-gating) count */
  src.spool_fd = sp;
  src.arbitrary_end = 1;
  EXPECT(http_srv_init(&s, &src) == 0);
  s.total = 0;                  /* command still running */
  s.complete = 0;

  EXPECT(buffer_append(&b, DATA, 8) == 0);      /* produced prefix, as the loop */

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 0) == 1);

  /* Mid-command live tail: no Content-Length, no 206, streams the spool. */
  off += drain(&s, 0, sv[1], out + off, sizeof out - off);
  EXPECT(bytes_in(out, off, "200 OK"));
  EXPECT(bytes_in(out, off, "Connection: close"));
  EXPECT(!bytes_in(out, off, "Content-Length:"));
  EXPECT(!bytes_in(out, off, "206"));
  EXPECT(bytes_in(out, off, "ABCDEFGH"));
  EXPECT(s.conns[0].phase == HTTP_PH_BODY);     /* stalled at current file end */

  /* A live Range with a pinned, already-produced end is the legal 206 too
   * (served from the spool); it does not reset the open pull above. */
  EXPECT(xact_at(&s, 1, "GET /stream HTTP/1.1\r\nRange: bytes=2-5\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 2-5/*"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 4"));
  EXPECT(bytes_in(resp, rl, "CDEF"));
  EXPECT(!bytes_in(resp, rl, "AB"));

  /* The producer advances: the caught-up pull resumes without a new head. */
  EXPECT(spool_append(sp, DATA + 8, DLEN - 8) == 0);
  EXPECT(buffer_append(&b, DATA + 8, DLEN - 8) == 0);
  off += drain(&s, 0, sv[1], out + off, sizeof out - off);
  EXPECT(bytes_in(out, off, (const char *)DATA));
  EXPECT(s.conns[0].phase == HTTP_PH_BODY);

  /* The device's live resume on a running spooled command: the open-ended
   * start takes the 1-byte arm and is served by pread once the command reaches
   * byte 40 — a 206 spanning `bytes 40-40` with an unknown complete length and
   * CL 1, never a rewind to byte 0. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
  EXPECT(http_conn_set_fd(&s, 2, sv2[0]) == 0);
  EXPECT(write(sv2[1], "GET /stream HTTP/1.1\r\nRange: bytes=40-\r\n\r\n", 42) == 42);
  EXPECT(http_conn_input(&s, 2) == 1);
  rl = drain(&s, 2, sv2[1], resp, sizeof resp);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 40-40/*"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 1"));
  EXPECT(body_of(resp, rl, &boff) == 0);        /* byte 40 not spooled yet */
  EXPECT(spool_append(sp, FILL, sizeof FILL - 1) == 0); /* reaches byte 40 */
  EXPECT(http_conn_pump(&s, 2) != -1);
  rl = drain(&s, 2, sv2[1], resp, sizeof resp);
  EXPECT(s.conns[2].phase == HTTP_PH_DONE);
  http_conn_close(&s, 2);
  close(sv2[0]);
  close(sv2[1]);

  /* The command completes: EOF is latched and the live pull finishes. */
  s.complete = 1;
  off += drain(&s, 0, sv[1], out + off, sizeof out - off);
  EXPECT(s.conns[0].phase == HTTP_PH_DONE);
  EXPECT(bytes_in(out, off, (const char *)DATA));
  EXPECT(!bytes_in(out, off, "Content-Length:"));

  http_conn_close(&s, 0);
  close(sv[0]);
  close(sv[1]);
  http_srv_close(&s);
  spool_close(sp);
  buffer_close(&b);
  return 0;
}

static int t_live_pull(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  unsigned char resp[4096];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);

  /* A still-running command (total == 0) answers a closed Range span with a
   * legal 206 and a complete-length star (RFC 9110 §14.4). An open-ended Range
   * has its end chosen by the server: the produced frontier when the bytes
   * cover the start, else the 1-byte arm. */
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, DATA, DLEN) == 0);
  EXPECT(srv_full(&s, &b) == 0);
  s.total = 0;                  /* running command: total unknown */
  s.complete = 0;

  /* Request-pinned end already produced: the one legal live 206. Pre-fix:
   * any Range on a running command was ignored and served as a live tail. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=0-3\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 0-3/*"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 4"));
  EXPECT(bytes_in(resp, rl, "ABCD"));
  EXPECT(!bytes_in(resp, rl, "EFGH"));

  /* --no-arbitrary-range: the DMR's open-ended probe keeps the pre-trace.22
   * answer — a plain whole-resource 200 from byte 0 (rule 3), which this
   * window-only fixture can serve, never a mid-stream join at 4096. (The
   * 1-byte arm needs a source that can still produce byte N: the resolver of
   * no-spool command mode (t_live_resume) or a spool fd (t_spool_live).) */
  s.arbitrary_end = 0;
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=4096-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "206"));
  EXPECT(!bytes_in(resp, rl, "Content-Length:"));
  EXPECT(!bytes_in(resp, rl, "Content-Range:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));
  EXPECT(s.conns[0].start == 0);        /* rule 0: served from byte 0 */

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

/* A would-block flush must never be busy-retried (DOMAIN.md Design
 * Invariant): one pump pass performs exactly one write per EAGAIN — the
 * conn is pinned blocked until EPOLLOUT — instead of burning all 32 budget
 * steps hammering a full TCP send buffer (the `.tmp/.trace-lc.3` spin). */
static int t_write_stall(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct http_src src;
  unsigned char payload[8192];
  unsigned char out[16384];
  size_t got;
  int sv[2];
  int fl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = sizeof payload;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  memset(payload, 'x', sizeof payload);
  EXPECT(buffer_append(&b, payload, sizeof payload) == 0);

  memset(&src, 0, sizeof src);
  src.buf = &b;
  src.spool_fd = -1;
  src.total = sizeof payload;
  EXPECT(http_srv_init(&s, &src) == 0);
  s.complete = 1;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  fl = fcntl(sv[0], F_GETFL, 0);
  EXPECT(fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) == 0);
  fl = fcntl(sv[1], F_GETFL, 0);
  EXPECT(fcntl(sv[1], F_SETFL, fl | O_NONBLOCK) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 0) == 1);

  http_body_mock_reset();

  /* A zero-byte write is a transport error, surfaced as -1. */
  _mock_conn_write = 0;
  EXPECT(http_conn_pump(&s, 0) == -1);
  EXPECT(s.conns[0].blocked == 0);
  http_body_mock_reset();

  /* Persistent EAGAIN: one write attempt per pump pass, blocked pinned. */
  _mock_conn_write = -2;
  EXPECT(http_conn_pump(&s, 0) == 0);
  EXPECT(s.conns[0].blocked == 1);
  EXPECT(s.conns[0].phase == HTTP_PH_BODY);
  EXPECT(_mock_conn_writes == 1);
  EXPECT(http_conn_pump(&s, 0) == 0);
  EXPECT(_mock_conn_writes == 2);
  EXPECT(s.conns[0].blocked == 1);

  /* A capped write exercises the partial-write loop, then real writes. The
   * head + payload fit the socket buffer, so the file response completes. */
  _mock_conn_write = 3;
  EXPECT(http_conn_pump(&s, 0) == 1);
  EXPECT(s.conns[0].blocked == 0);
  EXPECT(s.conns[0].phase == HTTP_PH_DONE);

  http_body_mock_reset();
  got = drain(&s, 0, sv[1], out, sizeof out);
  EXPECT(bytes_in(out, got, "200 OK"));
  EXPECT(got >= sizeof payload);
  EXPECT(memcmp(out + got - sizeof payload, payload, sizeof payload) == 0);
  EXPECT(s.conns[0].phase == HTTP_PH_DONE);

  http_conn_close(&s, 0);
  close(sv[0]);
  close(sv[1]);
  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

/* A connection is never closed for idleness (DOMAIN.md §HTTP server): the
 * server has no idle sweep, so a conn that has seen no traffic — e.g. a
 * paused device that stopped reading — stays open and its slot stays live. */
static int t_never_idle_closed(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  int sv[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = DLEN;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(srv_full(&s, &b) == 0);
  EXPECT(http_listen(&s, NULL) == 0);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(s.conns[0].fd >= 0);
  EXPECT(http_conn_pump(&s, 0) == 0);   /* nothing to serve, blob open */
  EXPECT(s.conns[0].fd >= 0);   /* no idle close swept it */
  close(sv[1]);

  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

/* === no-spool producer resolution === */

struct res_ctl {
  struct http_prod prod;
  unsigned long long at;        /* requested attach stream offset */
  int tail;                     /* 1 = serve a live tail from the retained head */
  int done;                     /* 1 = the producer's source reached EOF */
};

static int stub_eof(void *user)
{
  (void)user;
  return 0;                     /* producer still running */
}

static int res_ctl_eof(void *user)
{
  struct res_ctl *ctl = user;

  return ctl->done;
}

static int resolve_fake(void *user, unsigned long long s, struct http_prod **prod, unsigned long long *at, int *tail)
{
  struct res_ctl *ctl = user;

  *prod = &ctl->prod;
  *at = ctl->tail ? ctl->at : s;
  *tail = ctl->tail;
  return 0;
}

/* A fresh command-mode server whose conns resolve to a producer window. */
static int resolved_srv(struct http_srv *s, struct res_ctl *ctl, struct buffer *anchor)
{
  struct http_src src;
  struct cache_cfg cfg;
  struct buf_source bsrc;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(anchor, PAGE, &cfg, &bsrc) == 0);
  memset(&src, 0, sizeof src);
  src.buf = anchor;
  src.spool_fd = -1;
  src.total = 0;                /* running command: total unknown */
  src.arbitrary_end = 1;
  EXPECT(http_srv_init(s, &src) == 0);
  s->resolve = resolve_fake;
  s->res_user = ctl;
  return 0;
}

static int t_resolve_retained(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[1024];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  /* A request resolved to a retained producer window: the body answers from
   * the producer's buffer (never the unopened anchor). */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Length:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));
  EXPECT(s.conns[0].cidx == SIZE_MAX);  /* xact closed the conn */
  EXPECT(s.conns[0].prod == NULL);

  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* The device's own live resume (trace.22): an open-ended `Range: bytes=N-` on a
 * stream of unknown total is served in place as a legal 206 whose end the server
 * chooses (RFC 9110 §14.4) — the live frontier when the produced bytes cover
 * `N`, else `N+1` (one byte, head stowed until the producer reaches it) — so the
 * DMR continues its parse instead of re-initializing at byte 0. A cold start, a
 * start below the retained prefix, and `--no-arbitrary-range` stay rule 0's
 * whole-resource 200 from byte 0, as does a bounded unproduced end. */
static int t_live_resume(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[1024];
  size_t rl;
  size_t got;
  size_t boff;
  int sv[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);   /* 16 bytes produced */
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  /* Open-ended live resume the produced bytes cover: pinned-span 206 in place. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=12-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 12-15/*"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 4"));
  EXPECT(bytes_in(resp, rl, "MNOP"));
  EXPECT(!bytes_in(resp, rl, "ABCD"));
  EXPECT(s.conns[0].start == 12);
  EXPECT(s.conns[0].end == 16);
  EXPECT(s.conns[0].resp == HTTP_RESP_FINITE);

  /* A running producer behind `N`: the 1-byte arm, head stowed until byte 40
   * exists, then exactly one promised byte and the close. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\nRange: bytes=40-\r\n\r\n", 42) == 42);
  EXPECT(http_conn_input(&s, 0) == 1);
  EXPECT(s.conns[0].hdr_pend == 1);
  EXPECT(s.conns[0].end == 41);
  got = drain(&s, 0, sv[1], resp, sizeof resp);
  EXPECT(got == 0);             /* head held: byte 40 not produced yet */
  EXPECT(buffer_append(&w, FILL, sizeof FILL - 1) == 0);        /* received 41 */
  EXPECT(http_conn_pump(&s, 0) != -1);
  got = drain(&s, 0, sv[1], resp, sizeof resp);
  EXPECT(bytes_in(resp, got, "206 Partial Content"));
  EXPECT(bytes_in(resp, got, "Content-Range: bytes 40-40/*"));
  EXPECT(bytes_in(resp, got, "Content-Length: 1"));
  EXPECT(s.conns[0].phase == HTTP_PH_DONE);     /* promised byte delivered, no more */
  EXPECT(body_of(resp, got, &boff) == 1);
  EXPECT(resp[boff] == 'o');
  http_conn_close(&s, 0);
  close(sv[0]);
  close(sv[1]);

  /* --no-arbitrary-range: never invent an end — both shapes fall back to the
   * whole-resource 200 at byte 0. */
  s.arbitrary_end = 0;
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=12-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Range:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));
  EXPECT(s.conns[0].start == 0);
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=40-\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(!bytes_in(resp, rl, "206"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));
  s.arbitrary_end = 1;

  /* Request-pinned end already produced: a closed-range live 206. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=4-7\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 4-7/*"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 4"));
  EXPECT(bytes_in(resp, rl, "EFGH"));
  EXPECT(!bytes_in(resp, rl, "ABCD"));

  /* Bounded but not yet produced (41 bytes so far): 200 from byte 0, never a
   * partial at 4 — a request-pinned end is never invented (DOMAIN.md rule 3). */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=4-80\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Range:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));

  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* Rule 1 head stow (cold frontier): a plain request whose byte 0 the producer
 * has not produced yet holds its response head — a `200` with an empty body
 * is never flushed to a still-waiting start — until the window produces it. */
static int t_resolve_stow(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[1024];
  size_t got;
  int sv[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);      /* nothing produced yet */
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 0) == 1);
  EXPECT(s.conns[0].hdr_pend == 1);
  got = drain(&s, 0, sv[1], resp, sizeof resp);
  EXPECT(got == 0);             /* head held: byte 0 not produced yet */

  /* The producer reaches byte 0: the stowed head and body flow. */
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  EXPECT(http_conn_pump(&s, 0) == 0);
  EXPECT(s.conns[0].hdr_pend == 0);
  got = drain(&s, 0, sv[1], resp, sizeof resp);
  EXPECT(bytes_in(resp, got, "200 OK"));
  EXPECT(bytes_in(resp, got, (const char *)DATA));

  http_conn_close(&s, 0);
  close(sv[0]);
  close(sv[1]);
  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* Nothing produced yet: there is no frontier for the server to close an
 * open-ended range at, so a cold `Range: bytes=0-` is rule 0's whole-resource
 * `200` at byte 0 (head stowed until byte 0 exists), never a 1-byte 206. */
static int t_cold_range_stow(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[1024];
  size_t got;
  int sv[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);      /* nothing produced yet */
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\nRange: bytes=0-\r\n\r\n", 41) == 41);
  EXPECT(http_conn_input(&s, 0) == 1);
  EXPECT(s.conns[0].hdr_pend == 1);
  EXPECT(s.conns[0].range == 0 && s.conns[0].start == 0);       /* cold: rule 0 */
  EXPECT(drain(&s, 0, sv[1], resp, sizeof resp) == 0);

  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  EXPECT(http_conn_pump(&s, 0) != -1);
  EXPECT(s.conns[0].hdr_pend == 0);
  got = drain(&s, 0, sv[1], resp, sizeof resp);
  EXPECT(bytes_in(resp, got, "200 OK"));
  EXPECT(!bytes_in(resp, got, "206"));
  EXPECT(!bytes_in(resp, got, "Content-Range:"));
  EXPECT(bytes_in(resp, got, (const char *)DATA));

  http_conn_close(&s, 0);
  close(sv[0]);
  close(sv[1]);
  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* Re-attach hygiene (§Multiple consumers): a consumer index is owned by
 * exactly one connection. Re-running prep on a conn that already holds a
 * claim — a keep-alive second request, a mid-body re-route — must release
 * the old claim before attaching the new one. A stale entry never advances
 * its read_off and nothing can see it is dead: behind the live consumers it
 * pins buffer_lowest (the producer never opens room, the replay freezes at
 * the retained end) and cons.len > 0 blocks both producer gating and the idle
 * reap (DOMAIN.md rule 0). */
static int t_reattach_no_ghost(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  int sv[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 0) == 1);
  EXPECT(s.conns[0].cidx != SIZE_MAX);
  EXPECT(w.cons.len == 1);

  /* A second request worth of input on the same socket re-runs prep on the
   * live conn: the old claim is released first, so the window never gains a
   * ghost consumer. */
  EXPECT(write(sv[1], "GET / HTTP/1.1\r\n\r\n", 18) == 18);
  EXPECT(http_conn_input(&s, 0) == 1);
  EXPECT(s.conns[0].cidx != SIZE_MAX);
  EXPECT(w.cons.len == 1);

  http_conn_close(&s, 0);
  EXPECT(w.cons.len == 0);
  close(sv[0]);
  close(sv[1]);
  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* Byte-0 whole-resource restart (DOMAIN.md rule 0): the re-pull is the
 * device's only active playback, so any other open body pull is the stale
 * earlier pull. It is retired — closed, its claim released — so its frozen
 * position can no longer pace the window and the abandoned producer/command
 * falls to gating + the idle reap instead of running unwatched (cons.len > 0
 * blocks both). The replay consumer becomes the producer's single pacing
 * governor. */
static int t_restart_retire(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[1024];
  size_t rl;
  int sv0[2];
  int sv1[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  /* conn A (slot 0): the earlier pull — still open, still BODY, drained to
   * the frontier; its held position would throttle the producer. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv0) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv0[0]) == 0);
  EXPECT(write(sv0[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 0) == 1);
  EXPECT(s.conns[0].phase == HTTP_PH_BODY);
  rl = drain(&s, 0, sv0[1], resp, sizeof resp);
  EXPECT(bytes_in(resp, rl, (const char *)DATA));
  EXPECT(w.cons.len == 1);

  /* conn B (slot 1): the drained re-pull — a live plain s=0 request is
   * answered as a startable whole resource (attached at byte 0) and the
   * device's abandoned earlier pull is retired on the same resolve. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) == 0);
  EXPECT(http_conn_set_fd(&s, 1, sv1[0]) == 0);
  EXPECT(write(sv1[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 1) == 1);
  EXPECT(s.conns[0].fd == -1);  /* the abandoned pull is closed */
  EXPECT(s.conns[0].cidx == SIZE_MAX);  /* its claim is released */
  EXPECT(w.cons.len == 1);      /* only the replay consumer remains */

  /* The replay serves the retained whole resource from byte 0. */
  rl = drain(&s, 1, sv1[1], resp, sizeof resp);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));

  http_conn_close(&s, 1);
  EXPECT(w.cons.len == 0);
  close(sv0[1]);
  close(sv1[1]);
  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* Cannot retain the request start: the resolve hook says "live tail", and the
 * response is served from wherever the producer's retained head is. */
static int t_resolve_tail(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[1024];
  size_t rl;

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&w, DATA, 8) == 0);
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = stub_eof;
  ctl.prod.user = NULL;
  ctl.tail = 1;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(bytes_in(resp, rl, "ABCDEFGH"));       /* from the retained head */
  EXPECT(!bytes_in(resp, rl, "IJKL"));

  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* A caught-up no-spool consumer must never be mistaken for EOF: an empty
 * producer window parks the conn in HTTP_PH_BODY — the pull resumes in place
 * once the producer fills and ends only when the source reaches its real
 * EOF. */
static int t_live_park(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer w;
  struct buffer anchor;
  struct res_ctl ctl;
  struct http_srv s;
  unsigned char resp[512];
  size_t off = 0;
  int sv[2];

  make_cfg(&cfg, 1024UL * 1024);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&w, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  memset(&ctl, 0, sizeof ctl);
  ctl.prod.buf = &w;
  ctl.prod.eof = res_ctl_eof;
  ctl.prod.user = &ctl;
  EXPECT(resolved_srv(&s, &ctl, &anchor) == 0);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  EXPECT(http_conn_set_fd(&s, 0, sv[0]) == 0);
  EXPECT(write(sv[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&s, 0) == 1);

  /* The whole window drains and the consumer catches the producer's
   * frontier: the conn parks at the empty window instead of ending. */
  off += drain(&s, 0, sv[1], resp + off, sizeof resp - off);
  EXPECT(bytes_in(resp, off, "200 OK"));
  EXPECT(bytes_in(resp, off, (const char *)DATA));
  EXPECT(s.conns[0].phase == HTTP_PH_BODY);

  /* The producer fills again: the parked pull resumes from where it held
   * (an empty window was never EOF), still not done while going. */
  EXPECT(buffer_append(&w, DATA, DLEN) == 0);
  off += drain(&s, 0, sv[1], resp + off, sizeof resp - off);
  EXPECT(bytes_in(resp, off, "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"));
  EXPECT(s.conns[0].phase == HTTP_PH_BODY);

  /* Only the source's true EOF latches the end. */
  ctl.done = 1;
  off += drain(&s, 0, sv[1], resp + off, sizeof resp - off);
  EXPECT(s.conns[0].phase == HTTP_PH_DONE);

  http_conn_close(&s, 0);
  close(sv[0]);
  close(sv[1]);
  http_srv_close(&s);
  buffer_close(&w);
  buffer_close(&anchor);
  return 0;
}

/* File mode: a file larger than the cache is served via pread, so a plain
 * request answers 200 + Content-Length with the full file, and a range into
 * the retained tail also works. */
static int t_file_large(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct http_src src;
  unsigned char resp[4096];
  unsigned char payload[128];
  unsigned char big[256];
  size_t rl;
  char tmpl[] = "/tmp/lh_httpfile_XXXXXX";
  int fd;

  memset(payload, 'A', sizeof payload);
  memset(big, 'B', sizeof big);
  /* The memory window is 64 bytes — far smaller than the payload. */
  make_cfg(&cfg, 64);
  bsrc.mode = BUFFER_MODE_FILE;
  bsrc.size_trustworthy = 1;
  bsrc.size = sizeof big;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&b, big, sizeof big) == 0);

  /* Open a temp file containing the payload and hand it as the serving fd. */
  fd = mkstemp(tmpl);
  EXPECT(fd >= 0);
  EXPECT(write(fd, payload, sizeof payload) == sizeof payload);
  (void)lseek(fd, 0, SEEK_SET);

  memset(&src, 0, sizeof src);
  src.buf = &b;
  src.spool_fd = fd;
  src.total = sizeof payload;
  EXPECT(http_srv_init(&s, &src) == 0);
  s.complete = 1;

  /* Plain request: 200 + Content-Length, full payload served from the file. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "HTTP/1.1 200 OK"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 128"));
  EXPECT(bytes_in(resp, rl, "Accept-Ranges: bytes"));
  EXPECT(memmem(resp, rl, payload, sizeof payload) != NULL);

  /* Range at offset 64 — behind the window's retained prefix but fully in
   * the file: 206 with correct data. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=64-127\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "206 Partial Content"));
  EXPECT(bytes_in(resp, rl, "Content-Range: bytes 64-127/128"));
  EXPECT(bytes_in(resp, rl, "Content-Length: 64"));

  close(fd);
  (void)unlink(tmpl);
  http_srv_close(&s);
  buffer_close(&b);
  return 0;
}

/* Command+spool live pull (total unknown): the body reads the file via
 * pread, not the memory window. */
static int t_spool_live_pread(void)
{
  struct cache_cfg cfg;
  struct buf_source bsrc;
  struct buffer b;
  struct http_srv s;
  struct http_src src;
  unsigned char resp[4096];
  unsigned char wbuf[32];
  size_t rl;
  char tmpl[] = "/tmp/lh_httplive_XXXXXX";
  int sp;

  make_cfg(&cfg, 16);
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  EXPECT(buffer_open(&b, PAGE, &cfg, &bsrc) == 0);

  sp = spool_open(tmpl);
  EXPECT(sp >= 0);
  EXPECT(spool_append(sp, DATA, DLEN) == 0);

  memset(&src, 0, sizeof src);
  src.buf = &b;
  src.spool_fd = sp;
  EXPECT(http_srv_init(&s, &src) == 0);
  s.total = 0;                  /* command still producing */
  s.complete = 0;

  /* Live pull: 200 + Connection: close, body reads from the file. */
  EXPECT(xact(&s, "GET /stream HTTP/1.1\r\n\r\n", resp, sizeof resp, &rl) == 0);
  EXPECT(bytes_in(resp, rl, "HTTP/1.1 200 OK"));
  EXPECT(bytes_in(resp, rl, "Connection: close"));
  EXPECT(!bytes_in(resp, rl, "Content-Length:"));
  EXPECT(bytes_in(resp, rl, (const char *)DATA));

  /* Now simulate completion: set total and complete, verify the file is
   * the serving source (range behind the window hits the file via pread). */
  s.total = DLEN;
  s.complete = 1;
  {
    struct buffer b2;
    size_t cidx;

    EXPECT(buffer_open(&b2, PAGE, &cfg, &bsrc) == 0);
    EXPECT(buffer_append(&b2, DATA, DLEN) == 0);
    /* Drop the head of the window so offset 0 is not retained. */
    EXPECT(buffer_add_consumer(&b2, 0, &cidx) == 0);
    EXPECT(buffer_consumer_read(&b2, cidx, wbuf, 8, &rl) == 0);
    buffer_compact(&b2, 8);
    buffer_remove_consumer(&b2, cidx);
    s.buf = &b2;

    EXPECT(xact(&s, "GET /stream HTTP/1.1\r\nRange: bytes=0-3\r\n\r\n", resp, sizeof resp, &rl) == 0);
    EXPECT(bytes_in(resp, rl, "206 Partial Content"));
    EXPECT(bytes_in(resp, rl, "Content-Range: bytes 0-3/16"));
    EXPECT(bytes_in(resp, rl, "ABCD"));

    buffer_close(&b2);
  }

  http_srv_close(&s);
  spool_close(sp);
  buffer_close(&b);
  return 0;
}

int main(void)
{
  RUN(t_parse);
  RUN(t_listen);
  RUN(t_full_ok);
  RUN(t_range206);
  RUN(t_range_dropped);
  RUN(t_400_oversize);
  RUN(t_close);
  RUN(t_multi);
  RUN(t_spool);
  RUN(t_spool_live);
  RUN(t_live_pull);
  RUN(t_write_stall);
  RUN(t_never_idle_closed);
  RUN(t_resolve_retained);
  RUN(t_live_resume);
  RUN(t_resolve_stow);
  RUN(t_cold_range_stow);
  RUN(t_live_park);
  RUN(t_resolve_tail);
  RUN(t_reattach_no_ghost);
  RUN(t_restart_retire);
  RUN(t_file_large);
  RUN(t_spool_live_pread);
  TEST_SUMMARY();
}
