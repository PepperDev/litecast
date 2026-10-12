#include "test_util.h"

#include "buf/buffer.h"
#include "cast/cast.h"
#include "cli/cache.h"
#include "net/http.h"
#include "run/run.h"
#include "source/source.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* Coverage note: the loop, the connect manager, the CLI and main are
 * #included so their counters attach to this binary (they have no unit-test
 * home of their own). The buffer/cast/net/source modules are linked as
 * objects instead — their binary-attributed tests keep the merged coverage
 * honest. */
#include "cli/cache.c"
#include "cli/cli.c"
#include "run/conn.c"
#include "run/init.c"
#include "run/loop.c"
#include "run/pump.c"
#include "run/prod.c"
#include "run/resolve.c"
#include "run/sig.c"

#define main litecast_main
#include "main.c"
#undef main

enum { DEV_SERVE = 0, DEV_SIGNAL = 1 };

static int read_full(int fd, void *buf, size_t n)
{
  size_t off = 0;

  while (off < n) {
    ssize_t r = read(fd, (unsigned char *)buf + off, n - off);

    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return 0;
}

static int write_all(int fd, const void *buf, size_t n)
{
  size_t off = 0;

  while (off < n) {
    ssize_t w = write(fd, (const unsigned char *)buf + off, n - off);

    if (w < 0 && errno == EINTR)
      continue;
    if (w <= 0)
      return -1;
    off += (size_t)w;
  }
  return 0;
}

static int read_line(int fd, char *buf, size_t cap)
{
  size_t n = 0;

  for (;;) {
    char c;
    ssize_t r = read(fd, &c, 1);

    if (r == 1) {
      if (c == '\n') {
        buf[n] = '\0';
        return n > 0 ? 0 : -1;
      }
      if (n + 1 < cap)
        buf[n++] = c;
    } else if (r < 0 && errno == EINTR) {
      continue;
    } else {
      buf[n] = '\0';
      return -1;
    }
  }
}

static void write_line(int fd, const char *s)
{
  (void)write_all(fd, s, strlen(s));
  (void)write_all(fd, "\n", 1);
}

/* Bounded wait until fd is readable: a freshly spawned command producer's
 * pipe is non-blocking, so the producer may not have written yet. */
static int wait_readable(int fd)
{
  struct pollfd pfd;
  int i;

  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  for (i = 0; i < 2000; i++) {
    int r = poll(&pfd, 1, 1);

    if (r != 0)
      return r;
  }
  return 0;
}

/* === fake cast device (child process) === */

static ssize_t dev_io_write(struct cast_io *io, const unsigned char *p, size_t cap)
{
  int fd = (int)(intptr_t) io->opaque;

  return write_all(fd, p, cap) == 0 ? (ssize_t) cap : -1;
}

static int dev_send(int fd, const char *ns, const char *json)
{
  struct cast_msg m = { ns, "receiver-0", "sender-0", json };
  struct cast_io io;

  io.read = NULL;
  io.write = dev_io_write;
  io.opaque = (void *)(intptr_t) fd;
  return cast_send(&io, &m);
}

/* Decode a chunked body (RFC 7230 §4.1) from p[0..n) into f. Returns 0 on
 * success (terminal chunk seen), -1 on malformed framing. */
static int chunk_decode(FILE *f, const unsigned char *p, size_t n)
{
  size_t i = 0;

  while (i < n) {
    size_t j = i;
    long sz = 0;
    int any = 0;

    while (j < n && p[j] != '\r') {
      int c = p[j];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
        return -1;
      if (sz > 0x1fffff)
        return -1;
      sz = sz * 16 + (c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
      j++;
      any = 1;
    }
    if (!any || j + 1 >= n || p[j + 1] != '\n')
      return -1;
    i = j + 2;
    if (sz == 0)
      return 0;
    if ((size_t)sz > n - i)
      return -1;
    if (fwrite(p + i, 1, (size_t)sz, f) != (size_t)sz)
      return -1;
    i += (size_t)sz;
    if (i + 1 >= n || p[i] != '\r' || p[i + 1] != '\n')
      return -1;
    i += 2;
  }
  return -1;
}

static int dev_http_get(int http_port, const char *body_path)
{
  static const char req[] = "GET /stream HTTP/1.1\r\nHost: litecast\r\nConnection: close\r\n\r\n";
  static const char ten_key[] = "Transfer-Encoding: chunked";
  struct sockaddr_in a;
  unsigned char *all = NULL;
  size_t cap = 0;
  size_t len = 0;
  size_t i;
  size_t j;
  int fd;
  int chunked;
  FILE *f;

  fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons((uint16_t) http_port);
  if (inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) != 1 || connect(fd, (struct sockaddr *)&a, sizeof a) != 0) {
    close(fd);
    return -1;
  }
  if (write_all(fd, req, strlen(req)) != 0) {
    close(fd);
    return -1;
  }
  for (;;) {
    unsigned char buf[8192];
    ssize_t n;

    n = read(fd, buf, sizeof buf);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      break;
    if (len + (size_t)n > cap) {
      size_t ncap = cap == 0 ? 65536 : cap * 2;
      unsigned char *nd;

      if (ncap > 1 << 20)
        ncap = 1 << 20;
      if (len + (size_t)n > ncap) {
        free(all);
        close(fd);
        return -1;
      }
      nd = realloc(all, ncap);
      if (nd == NULL) {
        free(all);
        close(fd);
        return -1;
      }
      all = nd;
      cap = ncap;
    }
    memcpy(all + len, buf, (size_t)n);
    len += (size_t)n;
    if (len > (1 << 20)) {
      free(all);
      close(fd);
      return -1;
    }
  }
  close(fd);
  for (i = 0; i + 3 < len; i++)
    if (all[i] == '\r' && all[i + 1] == '\n' && all[i + 2] == '\r' && all[i + 3] == '\n') {
      i += 4;
      break;
    }
  chunked = 0;
  for (j = 0; j + sizeof ten_key - 1 <= i; j++)
    if (memcmp(all + j, ten_key, sizeof ten_key - 1) == 0) {
      chunked = 1;
      break;
    }
  f = fopen(body_path, "wb");
  if (f == NULL) {
    free(all);
    return -1;
  }
  if (chunked) {
    if (chunk_decode(f, all + i, len - i) != 0) {
      fclose(f);
      free(all);
      return -1;
    }
  } else if (i < len) {
    if (fwrite(all + i, 1, len - i, f) != len - i) {
      fclose(f);
      free(all);
      return -1;
    }
  }
  fclose(f);
  free(all);
  return 0;
}

/* Serve one control connection as the DMR; returns 1 when the run terminated
 * the session with a receiver STOP (§Exit), 0 when it never did. */
static int dev_serve(int fd, int http_port, const char *body_path)
{
  struct cast_decoded d;
  unsigned char hdr[4];
  unsigned char *pb;
  uint32_t n;
  char type[64];
  int loaded = 0;
  int stopped = 0;

  for (;;) {
    if (read_full(fd, hdr, sizeof hdr) != 0)
      break;
    n = ((uint32_t) hdr[0] << 24) | ((uint32_t) hdr[1] << 16) | ((uint32_t) hdr[2] << 8) | (uint32_t) hdr[3];
    if (n == 0 || n + 4 > CAST_MAX_FRAME)
      break;
    pb = malloc(n);
    if (pb == NULL)
      break;
    if (read_full(fd, pb, n) != 0 || cast_decode(pb, n, &d) != 0) {
      free(pb);
      break;
    }
    free(pb);
    if (strcmp(d.ns, CAST_NS_HEARTBEAT) == 0) {
      if (cast_json_get(d.payload, "type", type, sizeof type) == 0 && strcmp(type, "PING") == 0)
        (void)dev_send(fd, CAST_NS_HEARTBEAT, "{\"type\":\"PONG\"}");
      continue;
    }
    if (strcmp(d.ns, CAST_NS_RECEIVER) == 0) {
      if (cast_json_get(d.payload, "type", type, sizeof type) == 0 && strcmp(type, "STOP") == 0)
        stopped = 1;
      (void)dev_send(fd, CAST_NS_RECEIVER, "{\"type\":\"RECEIVER_STATUS\",\"sessionId\":\"s\"}");
      continue;
    }
    if (strcmp(d.ns, CAST_NS_MEDIA) == 0 && !loaded) {
      loaded = 1;
      (void)dev_http_get(http_port, body_path);
      /* The run ends only when the DMR reports playback finished: send the
       * FINISHED verdict (DOMAIN.md §Lifecycle) so the loop can terminate. */
      (void)dev_send(fd, CAST_NS_MEDIA,
                     "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"FINISHED\"}]}");
    }
  }
  return stopped;
}

/* The device child: bind an ephemeral TCP port, report it, then either reply
 * to the handshake (and pull the stream once LOAD arrives) or signal the
 * parent and leave. Never touches gcov: it _exit()s. */
static void fake_device(int c2p, int p2c)
{
  struct sockaddr_in a;
  socklen_t alen = sizeof a;
  char modebuf[16];
  char pdbuf[16];
  char bpath[192];
  int mode;
  int http_port;
  int lfd;
  int cfd;
  int r;

  /* The run closes the control socket right after its exit STOP, so the
   * STOP ack can race into EPIPE. The mock, like any socket peer, must not
   * die on that benign close (the run ignores SIGPIPE for the same reason). */
  (void)signal(SIGPIPE, SIG_IGN);
  lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (lfd < 0)
    _exit(1);
  memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 8) != 0)
    _exit(1);
  (void)getsockname(lfd, (struct sockaddr *)&a, &alen);
  r = dprintf(c2p, "%u\n", (unsigned)ntohs(a.sin_port));
  (void)r;
  close(c2p);
  if (read_line(p2c, modebuf, sizeof modebuf) != 0 ||
      read_line(p2c, pdbuf, sizeof pdbuf) != 0 || read_line(p2c, bpath, sizeof bpath) != 0)
    _exit(1);
  mode = atoi(modebuf);
  http_port = atoi(pdbuf);
  if (mode == DEV_SIGNAL) {
    (void)kill(getppid(), SIGINT);
    _exit(0);
  }
  cfd = accept(lfd, NULL, NULL);
  if (cfd < 0)
    _exit(1);
  close(lfd);
  /* Exit status carries "the run terminated the session with a receiver STOP"
   * to the parent; the other tests ignore it. */
  _exit(dev_serve(cfd, http_port, bpath) ? 0 : 1);
}

/* === run plumbing (mirrors src/main.c phases) === */

static int make_tmp(const char *tag, char path[], size_t cap, const char *data)
{
  ssize_t n;
  int fd;

  (void)snprintf(path, cap, "/tmp/litecast-%s-XXXXXX", tag);
  fd = mkstemp(path);
  if (fd < 0)
    return -1;
  n = (ssize_t) strlen(data);
  if (write_all(fd, data, (size_t)n) != 0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static int read_file(const char *path, char *out, size_t cap, size_t *n)
{
  FILE *f;
  size_t got = 0;
  int c;

  f = fopen(path, "rb");
  if (f == NULL)
    return -1;
  while (got + 1 < cap && (c = fgetc(f)) != EOF)
    out[got++] = (char)c;
  fclose(f);
  out[got] = '\0';
  if (n != NULL)
    *n = got;
  return 0;
}

static unsigned listen_port(const struct http_srv *s)
{
  struct sockaddr_in a;
  socklen_t alen = sizeof a;

  if (getsockname(s->listen_fd, (struct sockaddr *)&a, &alen) != 0)
    return 0;
  return (unsigned)ntohs(a.sin_port);
}

static void teardown(struct run_ctx *ctx)
{
  size_t i;
  int fd = ctx->cfd >= 0 ? ctx->cfd : cast_conn_fd(&ctx->cn);

  (void)cast_ctrl_stop(&ctx->cn.ctrl);  /* terminate the DMR app on the device */
  if (fd >= 0)
    close(fd);
  cast_conn_close(&ctx->cn);
  http_srv_close(&ctx->srv);
  spool_close(ctx->spool_fd);
  for (i = 0; i < (size_t)ctx->npro; i++) {
    buffer_close(&ctx->pros[i].buf);
    source_close(&ctx->pros[i].src);
  }
  run_close(ctx);
}

static int begin_run(struct run_ctx *ctx, struct cli_options *opts, const char **ops, int nops, int command)
{
  memset(ctx, 0, sizeof *ctx);
  ctx->spool_fd = -1;
  ctx->serve_fd = -1;
  memset(opts, 0, sizeof *opts);
  opts->command_mode = command;
  opts->cache.kind = CACHE_BYTES;
  opts->cache.bytes = 65536;
  opts->operands = ops;
  opts->operands_count = nops;
  if (command)
    opts->cache_to_fs = 1;
  if (run_init(ctx) != 0 || run_phase(ctx, opts) != 0)
    return -1;
  return 0;
}

static void set_fake(struct run_ctx *ctx, unsigned port)
{
  memset(&ctx->devs[0], 0, sizeof ctx->devs[0]);
  ctx->devs[0].ip = htonl(INADDR_LOOPBACK);
  ctx->devs[0].port = (uint16_t) port;  /* host-order; sockaddr_for htons()s it */
  ctx->ndev = 1;
  ctx->dev_idx = 0;
}

/* === tests === */

static int t_version_and_help(void)
{
  char *aV[] = { "litecast", "-V" };
  char *aVV[] = { "litecast", "--version" };
  char *ah[] = { "litecast", "-h" };
  char *ahh[] = { "litecast", "--help" };
  char *aBoth[] = { "litecast", "-V", "-h" };
  char *aBoth2[] = { "litecast", "--help", "--version" };

  EXPECT(litecast_main(2, aV) == 0);
  EXPECT(litecast_main(2, aVV) == 0);
  EXPECT(litecast_main(2, ah) == 0);
  EXPECT(litecast_main(2, ahh) == 0);
  EXPECT(litecast_main(3, aBoth) == 0);
  EXPECT(litecast_main(3, aBoth2) == 0);
  return 0;
}

static int t_bad_inputs(void)
{
  char *a0[] = { "litecast" };
  char *ax[] = { "litecast", "-x" };
  char *along[] = { "litecast", "--unknown" };
  char *ab[] = { "litecast", "-b" };
  char *addash[] = { "litecast", "--" };

  EXPECT(litecast_main(1, a0) != 0);
  EXPECT(litecast_main(2, ax) != 0);
  EXPECT(litecast_main(2, along) != 0);
  EXPECT(litecast_main(2, ab) != 0);
  EXPECT(litecast_main(2, addash) != 0);
  return 0;
}

static int t_missing_sources(void)
{
  char *af[] = { "litecast", "/nonexistent-litecast-file.mp4" };
  char *ab[] = { "litecast", "-b", "1M", "/nonexistent-litecast-file.mp4" };

  EXPECT(litecast_main(2, af) != 0);
  EXPECT(litecast_main(4, ab) != 0);
  return 0;
}

static int t_no_device(void)
{
  char srcpath[128];
  char *af[2];
  int rc;

  EXPECT(make_tmp("nodev", srcpath, sizeof srcpath, "hi") == 0);
  af[0] = "litecast";
  af[1] = srcpath;
  EXPECT(setenv("LITECAST_MDNS_MS", "40", 1) == 0);
  rc = litecast_main(2, af);
  EXPECT(rc != 0);
  (void)unsetenv("LITECAST_MDNS_MS");
  (void)unlink(srcpath);
  return 0;
}

/* cast_done natural-end guard (device-confirmed playback): the run ends only
 * once the source is fully drained AND the DMR reported playback finished
 * (MEDIA_STATUS playerState:IDLE / idleReason:FINISHED), with a bounded idle
 * cap so a receiver that never reports cannot hang the CLI forever. A session
 * that DIED (ABORT) while a producer source is still live is auto-restarted
 * instead of ended. The device connection state is never consulted (no
 * reconnect storm). */
static int t_cast_done(void)
{
  struct run_ctx ctx;
  size_t i;

  memset(&ctx, 0, sizeof ctx);
  ctx.cfd = -1;
  ctx.npro = 1;
  for (i = 0; i < HTTP_CONN_MAX; i++)
    ctx.srv.conns[i].fd = -1;
  ctx.pros[0].active = 1;
  ctx.pros[0].src.eof_seen = 1;
  ctx.cn.ctrl.fd = -1;          /* no transport attached in this state model */

  /* Not done: source not fully drained yet, regardless of device verdict. */
  ctx.pros[0].src.eof_seen = 0;
  ctx.cn.ctrl.end_class = CTRL_END_FINISHED;
  EXPECT(cast_done(&ctx, 1000) == 0);
  EXPECT(ctx.cn.restart == 0);  /* the session never played: no abandonment */
  ctx.pros[0].src.eof_seen = 1;

  /* Not done: source drained but the DMR has not confirmed playback. */
  ctx.cn.ctrl.end_class = CTRL_END_NONE;
  EXPECT(cast_done(&ctx, 1000) == 0);

  /* Done: source drained and the DMR reported FINISHED. */
  ctx.cn.ctrl.end_class = CTRL_END_FINISHED;
  EXPECT(cast_done(&ctx, 1000) == 1);

  /* ABORT with a live source: the session is auto-restarted, not ended — the
   * conn retires into CONN_WAIT on the dedicated restart backoff (the run
   * keeps going; the DMR will be re-cast and re-pull). */
  ctx.cn.ctrl.end_class = CTRL_END_ABORT;
  ctx.pros[0].src.eof_seen = 0;
  ctx.cn.ctrl.fd = -1;
  EXPECT(cast_done(&ctx, 1000) == 0);
  EXPECT(ctx.cn.st == 3 && ctx.cn.restart == 1 && ctx.cn.restarts == 1);
  EXPECT(ctx.cn.restart_at > 1000);
  EXPECT(cast_conn_retry(&ctx.cn, 1000 + 999) == 0);
  EXPECT(cast_conn_retry(&ctx.cn, 1000 + 1000) == 1);

  /* ABORT with every source drained is the end: a finite stream that died
   * under a DMR fault has nothing left to restart for. */
  ctx.pros[0].src.eof_seen = 1;
  ctx.cn.ctrl.end_class = CTRL_END_ABORT;
  EXPECT(cast_done(&ctx, 1000) == 1);

  /* trace.22: a premature FINISHED on an ESTABLISHED session whose source is
   * still live is the DMR abandoning the pull, not a natural play-to-end — the
   * restart lane takes it exactly like an ABORT (the user saw the stream "stop
   * without trying again"). */
  ctx.cn.st = 2;
  ctx.cn.restart = 0;
  ctx.cn.restarts = 0;
  ctx.pros[0].src.eof_seen = 0;
  ctx.cn.ctrl.media_started = 1;
  ctx.cn.ctrl.end_class = CTRL_END_FINISHED;
  EXPECT(cast_done(&ctx, 1000) == 0);
  EXPECT(ctx.cn.st == 3 && ctx.cn.restart == 1 && ctx.cn.restarts == 1);
  EXPECT(cast_conn_retry(&ctx.cn, 1000 + 999) == 0);
  EXPECT(cast_conn_retry(&ctx.cn, 1000 + 1000) == 1);

  /* The same verdict with every source drained is the natural end. */
  ctx.pros[0].src.eof_seen = 1;
  ctx.cn.restart = 0;
  EXPECT(cast_done(&ctx, 2000) == 1);
  EXPECT(ctx.cn.restart == 0);

  /* A FINISHED before the session ever played is the LOAD ack, never an
   * abandonment: no restart, the stall guard holds the run open. */
  ctx.pros[0].src.eof_seen = 0;
  ctx.cn.ctrl.media_started = 0;
  ctx.cn.restart = 0;
  ctx.cn.restarts = 0;
  ctx.cn.st = 2;
  ctx.finish_at = 0;
  EXPECT(cast_done(&ctx, 1000) == 0);
  EXPECT(ctx.cn.restart == 0 && ctx.cn.restarts == 0);

  /* A stalled guard: with no body in flight the idle cap RUN_FINISH_MAX_MS is
   * armed so the CLI exits on its own if the receiver never pulls or never
   * reports FINISHED. */
  ctx.cn.ctrl.end_class = CTRL_END_NONE;
  ctx.finish_at = 0;
  EXPECT(cast_done(&ctx, 1000) == 0);
  EXPECT(cast_done(&ctx, 1000 + RUN_FINISH_MAX_MS - 1) == 0);
  EXPECT(cast_done(&ctx, 1000 + RUN_FINISH_MAX_MS) == 1);

  /* A cap is re-armed from a later deadline: now_ms before the armed cap still
   * returns NOT done, even when the source is mid-drain. */
  ctx.pros[0].src.eof_seen = 0;
  ctx.finish_at = 0;
  EXPECT(cast_done(&ctx, 2000 + RUN_FINISH_MAX_MS) == 0);

  /* The latch is monotonic: a PLAYING/BUFFERING status never un-ends. */
  ctx.pros[0].src.eof_seen = 1;
  ctx.cn.ctrl.end_class = CTRL_END_FINISHED;
  EXPECT(cast_done(&ctx, 3000) == 1);

  return 0;
}

static int t_loop_file(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[1];
  char srcpath[128];
  char bpath[128];
  char pbuf[16];
  char mdbuf[16];
  char body[32];
  size_t blen;
  unsigned dport;
  int c2p[2];
  int p2c[2];
  int child;
  int r;
  int st;

  EXPECT(make_tmp("file", srcpath, sizeof srcpath, "hello") == 0);
  EXPECT(make_tmp("body", bpath, sizeof bpath, "") == 0);
  ops[0] = srcpath;
  EXPECT(pipe(c2p) == 0 && pipe(p2c) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    close(c2p[0]);
    close(p2c[1]);
    fake_device(c2p[1], p2c[0]);
  }
  close(c2p[1]);
  close(p2c[0]);
  EXPECT(read_line(c2p[0], pbuf, sizeof pbuf) == 0);
  close(c2p[0]);
  dport = (unsigned)atoi(pbuf);

  EXPECT(setenv("LITECAST_TP", "plain", 1) == 0);       /* mock speaks plaintext */
  EXPECT(begin_run(&ctx, &opts, ops, 1, 0) == 0);
  set_fake(&ctx, dport);
  (void)snprintf(mdbuf, sizeof mdbuf, "%u", DEV_SERVE);
  write_line(p2c[1], mdbuf);
  (void)snprintf(pbuf, sizeof pbuf, "%u", listen_port(&ctx.srv));
  write_line(p2c[1], pbuf);
  write_line(p2c[1], bpath);
  close(p2c[1]);

  alarm(20);
  r = run_loop(&ctx);
  alarm(0);
  EXPECT(r == 0);
  teardown(&ctx);
  (void)unsetenv("LITECAST_TP");
  EXPECT(waitpid(child, &st, 0) == child);
  /* The run held a live session when it ended, so the device must have been
   * told to terminate it (§Exit). */
  EXPECT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
  EXPECT(read_file(bpath, body, sizeof body, &blen) == 0);
  EXPECT(blen == 5 && memcmp(body, "hello", 5) == 0);
  (void)unlink(srcpath);
  (void)unlink(bpath);
  return 0;
}

static int t_loop_cmd(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[] = { "/bin/echo", "hello" };
  char bpath[128];
  char pbuf[16];
  char mdbuf[16];
  char body[32];
  size_t blen;
  unsigned dport;
  int c2p[2];
  int p2c[2];
  int child;
  int r;

  EXPECT(make_tmp("body", bpath, sizeof bpath, "") == 0);
  EXPECT(pipe(c2p) == 0 && pipe(p2c) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    close(c2p[0]);
    close(p2c[1]);
    fake_device(c2p[1], p2c[0]);
  }
  close(c2p[1]);
  close(p2c[0]);
  EXPECT(read_line(c2p[0], pbuf, sizeof pbuf) == 0);
  close(c2p[0]);
  dport = (unsigned)atoi(pbuf);

  EXPECT(setenv("LITECAST_TP", "plain", 1) == 0);       /* mock speaks plaintext */
  EXPECT(begin_run(&ctx, &opts, ops, 2, 1) == 0);
  set_fake(&ctx, dport);
  (void)snprintf(mdbuf, sizeof mdbuf, "%u", DEV_SERVE);
  write_line(p2c[1], mdbuf);
  (void)snprintf(pbuf, sizeof pbuf, "%u", listen_port(&ctx.srv));
  write_line(p2c[1], pbuf);
  write_line(p2c[1], bpath);
  close(p2c[1]);

  alarm(20);
  r = run_loop(&ctx);
  alarm(0);
  EXPECT(r == 0);
  teardown(&ctx);
  (void)unsetenv("LITECAST_TP");
  EXPECT(waitpid(child, NULL, 0) == child);
  EXPECT(read_file(bpath, body, sizeof body, &blen) == 0);
  EXPECT(blen == 6 && memcmp(body, "hello\n", 6) == 0);
  (void)unlink(bpath);
  return 0;
}

/* No-spool command run (DOMAIN.md §Producers and consumers): the run starts
 * with zero producers; the DMR's first HTTP pull spawns one on demand; the
 * first-termination latch stores the stream total so a later request can
 * answer with Content-Length. */
static int t_loop_cmd_nospool(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[2];
  const char *data = "0123456789abcdef0123456789abcdef";
  char srcpath[128];
  char bpath[128];
  char pbuf[16];
  char mdbuf[16];
  char body[64];
  size_t blen;
  unsigned dport;
  int c2p[2];
  int p2c[2];
  int child;
  int r;

  EXPECT(make_tmp("raw", srcpath, sizeof srcpath, data) == 0);
  EXPECT(make_tmp("body", bpath, sizeof bpath, "") == 0);
  ops[0] = "/bin/cat";
  ops[1] = srcpath;
  EXPECT(pipe(c2p) == 0 && pipe(p2c) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    close(c2p[0]);
    close(p2c[1]);
    fake_device(c2p[1], p2c[0]);
  }
  close(c2p[1]);
  close(p2c[0]);
  EXPECT(read_line(c2p[0], pbuf, sizeof pbuf) == 0);
  close(c2p[0]);
  dport = (unsigned)atoi(pbuf);

  EXPECT(setenv("LITECAST_TP", "plain", 1) == 0);
  memset(&ctx, 0, sizeof ctx);
  ctx.spool_fd = -1;
  ctx.serve_fd = -1;
  memset(&opts, 0, sizeof opts);
  opts.command_mode = 1;
  opts.cache_to_fs = 0;         /* no-spool: producers spawn on demand */
  opts.cache.kind = CACHE_BYTES;
  opts.cache.bytes = 16;
  opts.operands = ops;
  opts.operands_count = 2;
  EXPECT(run_init(&ctx) == 0 && run_phase(&ctx, &opts) == 0);
  EXPECT(ctx.npro == 0);        /* nothing started until the first pull */
  EXPECT(ctx.srv.resolve != NULL);
  set_fake(&ctx, dport);
  (void)snprintf(mdbuf, sizeof mdbuf, "%u", DEV_SERVE);
  write_line(p2c[1], mdbuf);
  (void)snprintf(pbuf, sizeof pbuf, "%u", listen_port(&ctx.srv));
  write_line(p2c[1], pbuf);
  write_line(p2c[1], bpath);
  close(p2c[1]);

  alarm(20);
  r = run_loop(&ctx);
  alarm(0);
  EXPECT(r == 0);
  EXPECT(ctx.npro == 1);        /* a producer was spawned for the pull */
  EXPECT(ctx.srv.total == strlen(data));        /* first-termination total held */
  teardown(&ctx);
  (void)unsetenv("LITECAST_TP");
  EXPECT(waitpid(child, NULL, 0) == child);
  EXPECT(read_file(bpath, body, sizeof body, &blen) == 0);
  EXPECT(blen == strlen(data) && memcmp(body, data, blen) == 0);
  (void)unlink(srcpath);
  (void)unlink(bpath);
  return 0;
}

/* Command casts froze once the buffer was exactly full with the consumer
 * caught up: source_read_chunk refused to read at len == cap and compaction
 * ran only inside buffer_append, so the consumed window was never reclaimed
 * (regression for `.tmp/.trace-lc` — the loop busy-spun on the source pipe
 * and the http conn with no read/write). A source larger than the cache
 * pulled by a fast consumer must flow through compaction to completion. */
static int t_loop_cmd_big(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[] = { "/bin/cat", NULL };
  const size_t total = 256 * 1024;
  const size_t blk = 4096;
  unsigned char pat[4096];
  char srcpath[128];
  char bpath[128];
  char pbuf[16];
  char mdbuf[16];
  size_t i;
  size_t got;
  unsigned dport;
  int c2p[2];
  int p2c[2];
  int child;
  int r;

  for (i = 0; i < blk; i++)
    pat[i] = (unsigned char)(i % 251);
  EXPECT(make_tmp("big", srcpath, sizeof srcpath, "") == 0);
  EXPECT(make_tmp("body", bpath, sizeof bpath, "") == 0);
  {
    int fd = open(srcpath, O_WRONLY | O_TRUNC);

    EXPECT(fd >= 0);
    for (i = 0; i < total / blk; i++)
      EXPECT(write_all(fd, pat, blk) == 0);
    EXPECT(close(fd) == 0);
  }
  ops[1] = srcpath;
  EXPECT(pipe(c2p) == 0 && pipe(p2c) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    close(c2p[0]);
    close(p2c[1]);
    fake_device(c2p[1], p2c[0]);
  }
  close(c2p[1]);
  close(p2c[0]);
  EXPECT(read_line(c2p[0], pbuf, sizeof pbuf) == 0);
  close(c2p[0]);
  dport = (unsigned)atoi(pbuf);

  EXPECT(setenv("LITECAST_TP", "plain", 1) == 0);       /* mock speaks plaintext */
  EXPECT(begin_run(&ctx, &opts, ops, 2, 1) == 0);
  set_fake(&ctx, dport);
  (void)snprintf(mdbuf, sizeof mdbuf, "%u", DEV_SERVE);
  write_line(p2c[1], mdbuf);
  (void)snprintf(pbuf, sizeof pbuf, "%u", listen_port(&ctx.srv));
  write_line(p2c[1], pbuf);
  write_line(p2c[1], bpath);
  close(p2c[1]);

  alarm(20);
  r = run_loop(&ctx);
  alarm(0);
  EXPECT(r == 0);
  teardown(&ctx);
  (void)unsetenv("LITECAST_TP");
  EXPECT(waitpid(child, NULL, 0) == child);
  {
    FILE *f = fopen(bpath, "rb");
    unsigned char buf[4096];

    EXPECT(f != NULL);
    got = 0;
    for (;;) {
      size_t n = fread(buf, 1, sizeof buf, f);

      if (n == 0)
        break;
      EXPECT(n == blk && memcmp(buf, pat, n) == 0);
      got += n;
    }
    EXPECT(fclose(f) == 0);
  }
  EXPECT(got == total);
  (void)unlink(srcpath);
  (void)unlink(bpath);
  return 0;
}

static int t_stop_signal(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[1];
  char srcpath[128];
  char bpath[128];
  char pbuf[16];
  char mdbuf[16];
  unsigned dport;
  int c2p[2];
  int p2c[2];
  int child;
  int r;

  EXPECT(make_tmp("file", srcpath, sizeof srcpath, "hello") == 0);
  EXPECT(make_tmp("body", bpath, sizeof bpath, "") == 0);
  ops[0] = srcpath;
  EXPECT(pipe(c2p) == 0 && pipe(p2c) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    close(c2p[0]);
    close(p2c[1]);
    fake_device(c2p[1], p2c[0]);
  }
  close(c2p[1]);
  close(p2c[0]);
  EXPECT(read_line(c2p[0], pbuf, sizeof pbuf) == 0);
  close(c2p[0]);
  dport = (unsigned)atoi(pbuf);

  EXPECT(begin_run(&ctx, &opts, ops, 1, 0) == 0);
  set_fake(&ctx, dport);
  (void)snprintf(mdbuf, sizeof mdbuf, "%u", DEV_SIGNAL);
  write_line(p2c[1], mdbuf);
  (void)snprintf(pbuf, sizeof pbuf, "%u", listen_port(&ctx.srv));
  write_line(p2c[1], pbuf);
  write_line(p2c[1], bpath);
  close(p2c[1]);

  alarm(20);
  r = run_loop(&ctx);
  alarm(0);
  EXPECT(r == 0);
  teardown(&ctx);
  EXPECT(waitpid(child, NULL, 0) == child);
  (void)unlink(srcpath);
  (void)unlink(bpath);
  return 0;
}

/* SIGINT must stop the loop in the trace.14 recast state: the cast control
 * socket is dead/closed (a session-supervision restart lane pending, session
 * supervision aborted the DMR session) and a --command child is alive. A stop
 * signal is read through the signalfd on the very next loop pass — it never
 * waits out the restart backoff or the producer, and the run exits 0. */
static int t_stop_recast(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[2];
  char bpath[128];
  char pbuf[16];
  char mdbuf[16];
  unsigned dport;
  int c2p[2];
  int p2c[2];
  int child;
  int r;

  EXPECT(make_tmp("body", bpath, sizeof bpath, "") == 0);
  ops[0] = "sleep";
  ops[1] = "30";
  EXPECT(pipe(c2p) == 0 && pipe(p2c) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    close(c2p[0]);
    close(p2c[1]);
    fake_device(c2p[1], p2c[0]);
  }
  close(c2p[1]);
  close(p2c[0]);
  EXPECT(read_line(c2p[0], pbuf, sizeof pbuf) == 0);
  close(c2p[0]);
  dport = (unsigned)atoi(pbuf);

  EXPECT(begin_run(&ctx, &opts, ops, 2, 1) == 0);
  set_fake(&ctx, dport);
  /* Session-supervision post-abort state: the DMR session died (CTRL_END_ABORT
   * verdict) while the command source was still live, so the restart lane is
   * armed with the ctrl socket closed and the loop is between reconnect
   * attempts (cast_conn_restart is exactly what cast_done waves on abort). */
  EXPECT(cast_conn_restart(&ctx.cn, 0) == 0);
  (void)snprintf(mdbuf, sizeof mdbuf, "%u", DEV_SIGNAL);
  write_line(p2c[1], mdbuf);
  (void)snprintf(pbuf, sizeof pbuf, "%u", listen_port(&ctx.srv));
  write_line(p2c[1], pbuf);
  write_line(p2c[1], bpath);
  close(p2c[1]);

  alarm(20);
  r = run_loop(&ctx);
  alarm(0);
  EXPECT(r == 0);
  teardown(&ctx);
  EXPECT(waitpid(child, NULL, 0) == child);
  (void)unlink(bpath);
  return 0;
}

/* The discovered device's port is host-order; sockaddr_for must htons() it
 * into sin_port, or a device at 8009 gets connected to 18719. Regression for
 * the end-to-end integration test finding. */
static int t_connect_addr(void)
{
  struct run_ctx ctx;
  struct sockaddr_in a;

  memset(&ctx, 0, sizeof ctx);
  memset(&ctx.cn, 0, sizeof ctx.cn);
  ctx.cn.ctrl.fd = -1;
  ctx.ndev = 1;
  ctx.dev_idx = 0;
  ctx.devs[0].ip = htonl(INADDR_LOOPBACK);
  ctx.devs[0].port = 8009;      /* host-order, as mDNS stores it */
  EXPECT(sockaddr_for(&ctx, &a) == 0);
  EXPECT(a.sin_port == htons(8009));
  EXPECT(a.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
  return 0;
}

static int t_connect_budget(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[1];
  char srcpath[128];

  EXPECT(make_tmp("file", srcpath, sizeof srcpath, "hello") == 0);
  ops[0] = srcpath;
  EXPECT(begin_run(&ctx, &opts, ops, 1, 0) == 0);
  set_fake(&ctx, 1);
  ctx.connect_tries = RUN_CONNECT_MAX - 1;
  alarm(20);
  EXPECT(run_loop(&ctx) == 1);
  alarm(0);
  teardown(&ctx);
  (void)unlink(srcpath);
  return 0;
}

static int t_failed_session(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[1];
  char srcpath[128];

  EXPECT(make_tmp("file", srcpath, sizeof srcpath, "hello") == 0);
  ops[0] = srcpath;
  EXPECT(begin_run(&ctx, &opts, ops, 1, 0) == 0);
  set_fake(&ctx, 1);
  ctx.cn.st = 4;                /* CONN_FAILED (conn.c private) */
  alarm(20);
  EXPECT(run_loop(&ctx) == 1);
  alarm(0);
  teardown(&ctx);
  (void)unlink(srcpath);
  return 0;
}

/* A REAL terminal ^C, not kill(2): the child opens a pty as its controlling
 * terminal and makes its own process group the pty's foreground group, then
 * runs the loop in the post-abort recast state (live --command child, session
 * restart lane armed). A separate write of 0x03 to the pty master lets the
 * tty driver generate SIGINT for the foreground process group (si_code =
 * SI_KERNEL) — the exact path an operator's Ctrl-C takes. The loop must stop
 * cleanly; this is the delivery mode no kill()-based test exercises. */
static int t_tty_sigint(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[3];
  char pt[64];
  char ready;
  int mfd;
  int sfd;
  int pres[2];
  int rc;
  int st;
  pid_t c;

  mfd = posix_openpt(O_RDWR | O_NOCTTY);
  EXPECT(mfd >= 0);
  EXPECT(grantpt(mfd) == 0);
  EXPECT(unlockpt(mfd) == 0);
  EXPECT(ptsname_r(mfd, pt, sizeof pt) == 0);
  sfd = open(pt, O_RDWR | O_NOCTTY);
  EXPECT(sfd >= 0);
  if (sfd < 0)
    return -1;
  EXPECT(pipe(pres) == 0);
  c = fork();
  EXPECT(c >= 0);
  if (c == 0) {
    if (setsid() < 0)
      _exit(2);
    close(sfd);
    sfd = open(pt, O_RDWR);     /* no O_NOCTTY: the new session's controlling tty */
    if (sfd < 0)
      _exit(3);
    if (dup2(sfd, STDIN_FILENO) < 0 || dup2(sfd, STDOUT_FILENO) < 0 || dup2(sfd, STDERR_FILENO) < 0)
      _exit(4);
    if (tcsetpgrp(STDIN_FILENO, getpgrp()) < 0)
      _exit(7);
    ops[0] = "sh";
    ops[1] = "-c";
    ops[2] = "trap '' INT; exec sleep 30";      /* survives the ^C burst */
    if (begin_run(&ctx, &opts, ops, 3, 1) != 0)
      _exit(5);
    set_fake(&ctx, 1);
    if (cast_conn_restart(&ctx.cn, 0) != 0)
      _exit(6);
    ready = 1;
    (void)!write_all(pres[1], &ready, 1);
    alarm(20);                  /* watchdog: a hung loop must not hang the suite */
    rc = run_loop(&ctx);
    alarm(0);
    teardown(&ctx);
    (void)!write_all(pres[1], &rc, sizeof rc);
    close(pres[1]);
    _exit(0);
  }
  close(sfd);
  close(pres[1]);
  EXPECT(read_full(pres[0], &ready, 1) == 0 && ready == 1);
  {
    struct timespec ts = { 0, 100 * 1000 * 1000L };

    (void)nanosleep(&ts, NULL); /* let the loop settle into the recast state */
  }
  EXPECT(write_all(mfd, "\x03", 1) == 0);
  EXPECT(read_full(pres[0], &rc, sizeof rc) == 0);      /* the loop returns (stops) */
  EXPECT(waitpid(c, &st, 0) == c);
  EXPECT(WIFEXITED(st) && WEXITSTATUS(st) == 0);
  EXPECT(rc == 0);              /* terminal ^C is a clean stop: rc 0 */
  close(mfd);
  close(pres[0]);
  return 0;
}

static int t_run_init_fail(void)
{
  struct rlimit rl;
  struct run_ctx ctx;

  run_close(NULL);
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
    return 0;
  rl.rlim_cur = 0;
  if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
    return 0;
  memset(&ctx, 0, sizeof ctx);
  ctx.cfd = -1;
  EXPECT(run_init(&ctx) != 0);
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0)
    return 0;
  rl.rlim_cur = rl.rlim_max;
  (void)setrlimit(RLIMIT_NOFILE, &rl);
  return 0;
}

static int t_bad_command(void)
{
  struct run_ctx ctx;
  struct cli_options opts;
  const char *ops[] = { "/nonexistent-litecast-xyz" };
  char srcpath[128];

  EXPECT(make_tmp("file", srcpath, sizeof srcpath, "") == 0);
  ops[0] = "/nonexistent-litecast-xyz";
  EXPECT(begin_run(&ctx, &opts, ops, 1, 1) == 0);
  set_fake(&ctx, 1);
  alarm(20);
  EXPECT(run_loop(&ctx) == 1);
  alarm(0);
  teardown(&ctx);
  (void)unlink(srcpath);
  return 0;
}

/* No-spool resolver branches (DOMAIN.md §HTTP server): live plain frontier
 * join (s=0, total unknown), retained window, nearest-behind wait, live-tail
 * fallback, spawn-exhausted, spawn failure, and the total-known spawn
 * ladder. The run-layer resolver is #included with run/prod.c, so the
 * calls below hit the real selection logic without a device or loop. */
static int t_resolve_branches(void)
{
  struct run_ctx ctx;
  struct run_ctx x;
  struct cache_cfg cache;
  struct buf_source bsrc;
  struct http_prod *prod;
  unsigned char data[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };
  unsigned char sink[16];
  size_t got;
  size_t idx;
  size_t i;
  unsigned long long at;
  int tail;

  memset(&ctx, 0, sizeof ctx);
  memset(&cache, 0, sizeof cache);
  cache.kind = CACHE_BYTES;
  cache.bytes = 4096;
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  ctx.spec.page = 4096;
  EXPECT(buffer_open(&ctx.pros[0].buf, ctx.spec.page, &cache, &bsrc) == 0);
  EXPECT(buffer_append(&ctx.pros[0].buf, data, sizeof data) == 0);
  ctx.pros[0].active = 1;
  ctx.npro = 1;

  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 8, &prod, &at, &tail) == 0);
  EXPECT(prod == &ctx.pros[0].prod && at == 8 && tail == 0);

  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 32, &prod, &at, &tail) == 0);
  EXPECT(prod == &ctx.pros[0].prod && at == 32 && tail == 0);

  EXPECT(buffer_add_consumer(&ctx.pros[0].buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&ctx.pros[0].buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof sink);
  for (i = 1; i < PRODUCER_MAX; i++) {  /* every window advanced: no behind */
    EXPECT(buffer_open(&ctx.pros[i].buf, ctx.spec.page, &cache, &bsrc) == 0);
    EXPECT(buffer_append(&ctx.pros[i].buf, data, sizeof data) == 0);
    ctx.pros[i].active = 1;
    EXPECT(buffer_add_consumer(&ctx.pros[i].buf, 0, &idx) == 0);
    EXPECT(buffer_consumer_read(&ctx.pros[i].buf, idx, sink, sizeof sink, &got) == 0);
  }
  ctx.npro = PRODUCER_MAX;      /* spawn exhausted below */
  prod = NULL;
  at = 0;
  tail = -1;
  /* Consumed-prefix retained (trace.13): every consumer has already read the
   * byte s=8, but each window physically holds it (offset 0, span [0,16]) —
   * rule 1 "still retains s" is physical presence, so the re-pull attaches in
   * place at 8; it must NEVER fall to the spawn/fallback ladder for a start
   * the window still holds. */
  EXPECT(run_resolve(&ctx, 8, &prod, &at, &tail) == 0);
  EXPECT(prod == &ctx.pros[0].prod && at == 8 && tail == 0);
  /* Byte 0 compacted away (offset == 16 everywhere): s=8 sinks below the
   * window head and no producer is behind it — no live producer could feed
   * it, so with spawn exhausted the retained-head live-tail fallback replies
   * from the front. */
  for (i = 0; i < PRODUCER_MAX; i++)
    buffer_compact(&ctx.pros[i].buf, sizeof data);
  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 8, &prod, &at, &tail) == 0);
  EXPECT(prod == &ctx.pros[0].prod && at == sizeof data && tail == 1);

  EXPECT(producer_spawn(&ctx) == -1);   /* already at PRODUCER_MAX */
  for (i = 0; i < PRODUCER_MAX; i++)
    buffer_close(&ctx.pros[i].buf);

  memset(&ctx, 0, sizeof ctx);  /* spawn failure: no operands */
  ctx.npro = 0;
  ctx.spec.argc = 0;
  ctx.spec.argv = NULL;
  prod = NULL;
  tail = -1;
  EXPECT(run_resolve(&ctx, 8, &prod, &at, &tail) == -1);

  /* Wrong-slot regression (fix a4629c86): a reaped producer leaves a HOLE;
   * the next spawn fills THAT hole (first free slot), and resolve_hit must
   * return the exact slot it filled - never npro-1, which would attach a
   * re-pulled conn to a foreign producer whose window does not retain the
   * stream offset (stall -> RUN_FINISH_MAX_MS force-end -> re-spawn loop). */
  memset(&ctx, 0, sizeof ctx);
  ctx.spec.page = 4096;
  ctx.spec.cache.kind = CACHE_BYTES;
  ctx.spec.cache.bytes = 4096;
  ctx.spec.argc = 2;
  ctx.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  /* Two live foreign producers (slots 1,2) with their windows COMPACTED past
   * s (heads at 16 > s = 15): the byte is gone from every live window, so
   * neither retains nor sits behind it. Slot 0 stays a hole. */
  for (i = 1; i <= 2; i++) {
    EXPECT(buffer_open(&ctx.pros[i].buf, ctx.spec.page, &cache, &bsrc) == 0);
    EXPECT(buffer_append(&ctx.pros[i].buf, data, sizeof data) == 0);
    ctx.pros[i].active = 1;
    EXPECT(buffer_add_consumer(&ctx.pros[i].buf, 0, &idx) == 0);
    EXPECT(buffer_consumer_read(&ctx.pros[i].buf, idx, sink, sizeof sink, &got) == 0);
    buffer_compact(&ctx.pros[i].buf, sizeof data);
    EXPECT(buffer_offset(&ctx.pros[i].buf) == sizeof data);
  }
  ctx.npro = 2;
  /* Spawn lands in the first free slot = the hole at 0. */
  EXPECT(producer_spawn(&ctx) == 0);
  EXPECT(ctx.pros[0].active == 1 && ctx.npro == 3);
  prod = NULL;
  at = 0;
  tail = -1;
  /* s is below every foreign window head; the fresh hole-slot producer is
   * the nearest behind it -> the resolver attaches to the exact hole (0),
   * never count-1 (=2, a foreign producer). */
  EXPECT(run_resolve(&ctx, sizeof data - 1, &prod, &at, &tail) == 0);
  EXPECT(prod == &ctx.pros[0].prod && at == sizeof data - 1 && tail == 0);
  for (i = 0; i <= 2; i++)
    buffer_close(&ctx.pros[i].buf);

  /* Live plain s=0 restart: a plain s=0 re-pull on a live stream (total
   * unknown) whose window still retains byte 0 resolves to byte 0 — the
   * drained DMR is answered as a startable whole resource (trace.9: a
   * mid-stream continuation, whether frontier or run-in, is re-init'd from
   * the response start and aborts ~40ms later). No spawn, no speculative
   * frontier join. */
  memset(&ctx, 0, sizeof ctx);
  ctx.spec.page = 4096;
  ctx.spec.cache.kind = CACHE_BYTES;
  ctx.spec.cache.bytes = 4096;
  ctx.spec.argc = 2;
  ctx.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  for (i = 0; i < 2; i++) {
    EXPECT(buffer_open(&ctx.pros[i].buf, ctx.spec.page, &cache, &bsrc) == 0);
    EXPECT(buffer_append(&ctx.pros[i].buf, data, sizeof data) == 0);
    ctx.pros[i].active = 1;
    EXPECT(buffer_add_consumer(&ctx.pros[i].buf, 0, &idx) == 0);
    EXPECT(buffer_consumer_read(&ctx.pros[i].buf, idx, sink, sizeof sink, &got) == 0);
  }
  ctx.npro = 2;
  prod = NULL;
  at = ~0ULL;
  tail = -1;
  EXPECT(run_resolve(&ctx, 0, &prod, &at, &tail) == 0);
  EXPECT(ctx.npro == 2);        /* live restart attaches, never spawns */
  EXPECT(prod == &ctx.pros[0].prod && at == 0 && tail == 0);

  /* Byte 0 compacted away (buffer_offset > 0): the restart is impossible on
   * the live window — the request spawns a fresh producer to replay the whole
   * resource from zero. */
  buffer_compact(&ctx.pros[0].buf, sizeof data);
  {
    struct run_ctx c2;

    memset(&c2, 0, sizeof c2);
    c2.spec.page = 4096;
    c2.spec.cache.kind = CACHE_BYTES;
    c2.spec.cache.bytes = 4096;
    c2.spec.argc = 2;
    c2.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
    for (i = 0; i < 2; i++) {
      EXPECT(buffer_open(&c2.pros[i].buf, 4096, &c2.spec.cache, &bsrc) == 0);
      EXPECT(buffer_append(&c2.pros[i].buf, data, sizeof data) == 0);
      EXPECT(buffer_add_consumer(&c2.pros[i].buf, 0, &idx) == 0);
      EXPECT(buffer_consumer_read(&c2.pros[i].buf, idx, sink, sizeof sink, &got) == 0);
      buffer_compact(&c2.pros[i].buf, sizeof data);
      EXPECT(buffer_offset(&c2.pros[i].buf) == sizeof data);
      c2.pros[i].active = 1;
    }
    c2.npro = 2;
    prod = NULL;
    at = ~0ULL;
    tail = -1;
    EXPECT(run_resolve(&c2, 0, &prod, &at, &tail) == 0);
    EXPECT(c2.npro == 3 && prod == &c2.pros[2].prod && at == 0 && tail == 0);
    for (i = 0; i < 3; i++)
      buffer_close(&c2.pros[i].buf);
  }

  /* Once the total is known (first producer EOF) the restart edge is OFF but
   * rule 1 still holds: producer 1's window physically retains byte 0 (its
   * consumer read it, the window never slid) — a plain s=0 re-pull attaches
   * in place at 0 and is never answered by a spawn for a start a live
   * window still holds. */
  ctx.srv.total = buffer_received(&ctx.pros[0].buf);
  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 0, &prod, &at, &tail) == 0);
  EXPECT(ctx.npro == 2 && prod == &ctx.pros[1].prod && at == 0 && tail == 0);
  /* Byte 0 gone from EVERY window (both heads compacted): no live producer
   * can feed s=0 — the spawn ladder returns and a fresh producer is spawned
   * for a whole-body restart serve. */
  buffer_compact(&ctx.pros[1].buf, sizeof data);
  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 0, &prod, &at, &tail) == 0);
  EXPECT(ctx.npro == 3 && prod == &ctx.pros[2].prod && at == 0 && tail == 0);
  for (i = 0; i < 3; i++)
    buffer_close(&ctx.pros[i].buf);

  /* Rule 0 no-duplicate-spawn guard: a FARTHEST producer that has compacted
   * past byte 0 must not trigger a fresh spawn while a slower window still
   * retains it. pros[0] drained ahead (recv 16, offset 4); pros[1] kept the
   * whole span (recv 16, offset 0). find_farthest would pick the drained
   * producer and spawn — the recast loop's duplicate-command vector — but
   * find_replay attaches the whole-resource restart to the retaining window
   * and never spawns while any window holds byte 0. */
  memset(&x, 0, sizeof x);
  x.spec.page = 4096;
  x.spec.cache.kind = CACHE_BYTES;
  x.spec.cache.bytes = 4096;
  x.spec.argc = 2;
  x.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  for (i = 0; i < 2; i++) {
    EXPECT(buffer_open(&x.pros[i].buf, x.spec.page, &cache, &bsrc) == 0);
    EXPECT(buffer_append(&x.pros[i].buf, data, sizeof data) == 0);
    x.pros[i].active = 1;
  }
  EXPECT(buffer_add_consumer(&x.pros[0].buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&x.pros[0].buf, idx, sink, 4, &got) == 0);
  buffer_compact(&x.pros[0].buf, 4);    /* offset 4: byte 0 gone from pros[0] */
  EXPECT(buffer_offset(&x.pros[0].buf) == 4);
  EXPECT(buffer_add_consumer(&x.pros[1].buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&x.pros[1].buf, idx, sink, sizeof data, &got) == 0);
  x.npro = 2;
  prod = NULL;
  at = ~0ULL;
  tail = -1;
  EXPECT(run_resolve(&x, 0, &prod, &at, &tail) == 0);
  EXPECT(x.npro == 2);          /* any-window retain: no duplicate spawn */
  EXPECT(prod == &x.pros[1].prod && at == 0 && tail == 0);
  for (i = 0; i < 2; i++)
    buffer_close(&x.pros[i].buf);

  /* Empty window at the live frontier (received == 0): byte 0 IS still that
   * producer's frontier — the plain re-pull attaches in place to the existing
   * producer and waits for its frontier (trace.5); it must NEVER spawn a
   * second producer while a cold window can serve (trace.16's duplicate
   * command vector). */
  memset(&x, 0, sizeof x);
  x.spec.page = 4096;
  x.spec.cache.kind = CACHE_BYTES;
  x.spec.cache.bytes = 4096;
  x.spec.argc = 2;
  x.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  EXPECT(buffer_open(&x.pros[0].buf, x.spec.page, &cache, &bsrc) == 0);
  x.pros[0].active = 1;
  x.npro = 1;
  prod = NULL;
  at = ~0ULL;
  tail = -1;
  EXPECT(run_resolve(&x, 0, &prod, &at, &tail) == 0);
  EXPECT(x.npro == 1);          /* cold frontier: attach, no spawn */
  EXPECT(prod == &x.pros[0].prod && at == 0 && tail == 0);
  buffer_close(&x.pros[0].buf);

  return 0;
}

/* Whole-resource restart with byte 0 compacted away (DOMAIN.md rule 0,
 * spawn branch): the drained re-pull resolves through the real resolver to a
 * FRESH producer (restart_hit never answers a mid-stream continuation), and
 * the device's abandoned earlier pull is retired on the same resolve — closed,
 * its claim released — so that stale consumer can no longer pace the window
 * (pinning the floor) nor keep its command running non-stop: a consumerless
 * producer is gated and armed for the idle reap. */
static int t_spawn_retires_stale(void)
{
  struct run_ctx ctx;
  struct cache_cfg cache;
  struct buf_source bsrc;
  struct buffer anchor;
  struct http_src src;
  unsigned char data[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };
  unsigned char sink[256];
  int sv0[2];
  int sv1[2];

  memset(&ctx, 0, sizeof ctx);
  memset(&cache, 0, sizeof cache);
  cache.kind = CACHE_BYTES;
  cache.bytes = 4096;
  bsrc.mode = BUFFER_MODE_COMMAND;
  bsrc.size_trustworthy = 0;
  bsrc.size = 0;
  ctx.spec.page = 4096;
  ctx.spec.cache = cache;
  ctx.spec.argc = 2;
  ctx.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  EXPECT(buffer_open(&ctx.pros[0].buf, ctx.spec.page, &cache, &bsrc) == 0);
  EXPECT(buffer_append(&ctx.pros[0].buf, data, sizeof data) == 0);
  producer_bind(&ctx.pros[0]);  /* prod.c: normal spawn bind */
  ctx.pros[0].active = 1;
  ctx.npro = 1;
  EXPECT(buffer_open(&anchor, ctx.spec.page, &cache, &bsrc) == 0);
  memset(&src, 0, sizeof src);
  src.buf = &anchor;
  src.spool_fd = -1;
  src.total = 0;                /* live stream: total unknown */
  EXPECT(http_srv_init(&ctx.srv, &src) == 0);
  run_enable_resolve(&ctx);

  /* conn A (slot 0): the earlier pull — resolved in place, drained to the
   * frontier so the retention floor can slide past byte 0. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv0) == 0);
  EXPECT(http_conn_set_fd(&ctx.srv, 0, sv0[0]) == 0);
  EXPECT(write(sv0[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&ctx.srv, 0) == 1);
  EXPECT(ctx.srv.conns[0].cidx != SIZE_MAX);
  EXPECT(http_conn_pump(&ctx.srv, 0) != -1);    /* window drains to the socket */
  EXPECT(recv(sv0[1], sink, sizeof sink, 0) > 0);
  EXPECT(buffer_lowest(&ctx.pros[0].buf) == sizeof data);       /* caught up */
  buffer_compact(&ctx.pros[0].buf, sizeof data);
  EXPECT(buffer_offset(&ctx.pros[0].buf) == sizeof data);       /* byte 0 gone */

  /* conn B (slot 1): the drained re-pull. Byte 0 is no longer retained, so
   * restart_hit spawns a fresh producer and resolve_body retires conn A. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) == 0);
  EXPECT(http_conn_set_fd(&ctx.srv, 1, sv1[0]) == 0);
  EXPECT(write(sv1[1], "GET /stream HTTP/1.1\r\n\r\n", 24) == 24);
  EXPECT(http_conn_input(&ctx.srv, 1) == 1);
  EXPECT(ctx.npro == 2);        /* fresh producer spawned */
  EXPECT(ctx.pros[1].active == 1);
  EXPECT(ctx.srv.conns[0].fd == -1);    /* stale pull closed */
  EXPECT(ctx.srv.conns[0].cidx == SIZE_MAX);
  EXPECT(ctx.pros[0].buf.cons.len == 0);        /* its claim released: the old
                                                 * producer is consumerless */
  EXPECT(ctx.pros[1].buf.cons.len == 1);        /* replay is the only consumer */
  EXPECT(ctx.srv.conns[1].cidx != SIZE_MAX);

  http_conn_close(&ctx.srv, 1);
  EXPECT(ctx.pros[1].buf.cons.len == 0);
  close(sv0[1]);
  close(sv1[1]);
  buffer_close(&ctx.pros[0].buf);
  buffer_close(&ctx.pros[1].buf);
  buffer_close(&anchor);
  return 0;
}

/* Producer gating + idle termination (part c). */
static int t_gating(void)
{
  struct run_ctx ctx;
  uint64_t t0;

  memset(&ctx, 0, sizeof ctx);
  ctx.spool_fd = -1;            /* no-spool model */
  ctx.serve_fd = -1;
  ctx.pros[0].active = 1;
  ctx.pros[0].src.mode = SOURCE_MODE_COMMAND;
  ctx.pros[0].src.fd = SOURCE_FD_NONE;
  ctx.npro = 1;

  /* Gated: no consumer, not finishing. */
  EXPECT(producer_gated(&ctx, 0) == 1);
  /* A live consumer un-gates. */
  ctx.pros[0].buf.cons.len = 1;
  EXPECT(producer_gated(&ctx, 0) == 0);
  ctx.pros[0].buf.cons.len = 0;
  /* Finishing (terminal verdict reported) un-gates: freeze must end. */
  ctx.cn.ctrl.end_class = CTRL_END_FINISHED;
  EXPECT(producer_gated(&ctx, 0) == 0);
  /* trace.22: a verdict whose session restart is already booked is not final —
   * the device is coming back, so the producer keeps the ordinary consumer
   * rules (gated with no consumer, idle-guard-armed) instead of draining the
   * whole command into a window nobody reads. */
  ctx.cn.restart = 1;
  EXPECT(producer_gated(&ctx, 0) == 1);
  producer_idle_reap(&ctx, 1000);
  EXPECT(ctx.pros[0].idle_since_ms == 1000 && ctx.npro == 1);
  ctx.cn.restart = 0;
  EXPECT(producer_gated(&ctx, 0) == 0); /* final: drain to EOF */
  producer_idle_reap(&ctx, 2000);
  EXPECT(ctx.pros[0].idle_since_ms == 0);       /* exempt from the guard */
  ctx.cn.ctrl.end_class = CTRL_END_NONE;
  /* Spooled producers and file sources are never gated. */
  ctx.spool_fd = 3;
  EXPECT(producer_gated(&ctx, 0) == 0);
  ctx.spool_fd = -1;
  ctx.pros[0].src.mode = SOURCE_MODE_FILE;
  EXPECT(producer_gated(&ctx, 0) == 0);
  ctx.pros[0].src.mode = SOURCE_MODE_COMMAND;
  /* Inactive slots are never gated (and never reaped). */
  ctx.pros[0].active = 0;
  EXPECT(producer_gated(&ctx, 0) == 0);
  EXPECT(producer_gated(&ctx, 1) == 0);

  /* Idle arm: first consumer-less tick records the guard start. */
  ctx.pros[0].active = 1;
  t0 = 1000;
  producer_idle_reap(&ctx, t0);
  EXPECT(ctx.pros[0].idle_since_ms == t0 && ctx.npro == 1);
  /* Before the guard expires the producer survives. */
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS - 1);
  EXPECT(ctx.pros[0].active == 1 && ctx.npro == 1);
  /* Past the guard the producer is reaped and its slot freed. */
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS);
  EXPECT(ctx.pros[0].active == 0 && ctx.npro == 0);

  /* An attached consumer — even a paused, non-reading one — protects the
   * producer unconditionally: the consumer-less idle guard never fires while
   * a consumer is attached, so an arbitrary-length device pause (conn open,
   * DMR stopped reading, buffer full, producer backed) never terminates the
   * producer. HTTP connections are never closed for idleness (DOMAIN.md
   * §HTTP server). */
  ctx.pros[0].active = 1;
  ctx.pros[0].src.mode = SOURCE_MODE_COMMAND;
  ctx.pros[0].src.fd = SOURCE_FD_NONE;
  ctx.pros[0].src.eof_seen = 0;
  ctx.pros[0].idle_since_ms = 0;
  ctx.npro = 1;
  ctx.pros[0].buf.cons.len = 1; /* a consumer is attached, though paused */
  producer_idle_reap(&ctx, t0);
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS * 4);  /* way past the guard */
  EXPECT(ctx.pros[0].active == 1 && ctx.npro == 1);

  /* The consumer detaches (device closed its conn): the guard arms fresh and
   * the producer is reaped exactly PRODUCER_IDLE_MS later. */
  ctx.pros[0].buf.cons.len = 0;
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS * 4);
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS * 5 - 1);
  EXPECT(ctx.pros[0].active == 1 && ctx.npro == 1);     /* just before the guard */
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS * 5);
  EXPECT(ctx.pros[0].active == 0 && ctx.npro == 0);

  /* An EOF'd producer is not reaped: its window serves Content-Length. */
  ctx.pros[0].active = 1;
  ctx.pros[0].src.eof_seen = 1;
  ctx.npro = 1;
  producer_idle_reap(&ctx, t0 + PRODUCER_IDLE_MS * 2);
  EXPECT(ctx.pros[0].active == 1 && ctx.npro == 1);
  return 0;
}

/* No-spool live backpressure (regression `.tmp/.trace-lc.8`): a live window
 * exactly full (len == cap == target) with a lagging consumer must wait — the
 * drain must never issue a zero-length read, which read(2) answers with 0 and
 * source_read used to take as EOF (pre-fix it closed the pipe and
 * SIGPIPE-killed the still-live command). The source fd stays open, eof is
 * never latched, a backed producer is not EPOLLIN-registered (no spin), and
 * a consumer advance resumes the drain by compaction. */
static int t_live_backpressure(void)
{
  struct run_ctx tctx;
  struct cache_cfg cfg;
  struct buf_source bsrc;
  const char *ops[2];
  unsigned char stage[32768];
  unsigned char buf[512];
  char srcpath[128];
  unsigned char pat[4096];
  struct producer *p;
  size_t got, n, idx, i;
  int fd;
  int r;

  for (i = 0; i < sizeof pat; i++)
    pat[i] = (unsigned char)(i % 251);
  EXPECT(make_tmp("bp", srcpath, sizeof srcpath, "") == 0);
  fd = open(srcpath, O_WRONLY | O_TRUNC);
  EXPECT(fd >= 0);
  for (i = 0; i < 64; i++)
    EXPECT(write_all(fd, pat, sizeof pat) == 0);
  EXPECT(close(fd) == 0);

  memset(&tctx, 0, sizeof tctx);
  tctx.spool_fd = -1;
  tctx.serve_fd = -1;
  memset(&cfg, 0, sizeof cfg);
  cfg.kind = CACHE_BYTES;
  cfg.bytes = 4096;             /* target == cap == page: no growth headroom */
  memset(&bsrc, 0, sizeof bsrc);
  bsrc.mode = BUFFER_MODE_COMMAND;
  ops[0] = "/bin/cat";
  ops[1] = srcpath;
  p = &tctx.pros[0];
  EXPECT(source_open(&p->src, SOURCE_MODE_COMMAND, 2, ops) == 0);
  EXPECT(buffer_open(&p->buf, 4096, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&p->buf, pat, sizeof pat) == 0); /* exactly full */
  EXPECT(p->buf.len == p->buf.cap);
  p->active = 1;
  p->backed = 0;

  EXPECT(buffer_add_consumer(&p->buf, 0, &idx) == 0);
  /* Full window, nothing reclaimable: backpressure wait, fd + eof untouched. */
  n = sizeof stage;
  EXPECT(producer_read_chunk(p, stage, &n, 0) == 0);
  EXPECT(n == 0);
  EXPECT(p->backed == 1);
  EXPECT(source_fd(&p->src) != SOURCE_FD_NONE); /* pre-fix: closed */
  EXPECT(source_eof(&p->src) == 0);     /* pre-fix: latched */
  EXPECT(source_reg_fd(&tctx, 0) == -1);        /* no EPOLLIN spin */
  /* A still-writable producer drive must not turn the wait into an error. */
  r = producer_drive_one(&tctx, p);
  EXPECT(r == 0 && p->backed == 1);
  /* room reappearing is the resume trigger: un-back, then read proceeds. */
  EXPECT(buffer_consumer_read(&p->buf, idx, buf, sizeof buf, &got) == 0);
  EXPECT(got == sizeof buf);
  p->backed = 0;
  EXPECT(wait_readable(source_fd(&p->src)) > 0);
  n = sizeof stage;
  EXPECT(producer_read_chunk(p, stage, &n, 0) == 1);
  EXPECT(n == sizeof buf);
  EXPECT(p->backed == 0);
  EXPECT(source_eof(&p->src) == 0);
  EXPECT(source_fd(&p->src) != SOURCE_FD_NONE);

  source_teardown(&p->src);
  buffer_close(&p->buf);
  source_close(&p->src);
  (void)unlink(srcpath);
  return 0;
}

/* No-spool window growth (rule 6, command mode): a live window full at
 * len == cap but below its `--cache` target must read into the growth
 * headroom (target - cap) instead of backpressuring — and definitely instead
 * of false-EOFing. The plain-size no-spool window was stuck at one page
 * (reads never exceeded the room, so append-growth never triggered), which
 * froze on the very first burst. */
static int t_live_grow(void)
{
  struct run_ctx tctx;
  struct cache_cfg cfg;
  struct buf_source bsrc;
  const char *ops[2];
  unsigned char stage[32768];
  char srcpath[128];
  unsigned char pat[4096];
  struct producer *p;
  size_t n, i;
  int fd;

  for (i = 0; i < sizeof pat; i++)
    pat[i] = (unsigned char)(i % 251);
  EXPECT(make_tmp("gr", srcpath, sizeof srcpath, "") == 0);
  fd = open(srcpath, O_WRONLY | O_TRUNC);
  EXPECT(fd >= 0);
  for (i = 0; i < 64; i++)
    EXPECT(write_all(fd, pat, sizeof pat) == 0);
  EXPECT(close(fd) == 0);

  memset(&tctx, 0, sizeof tctx);
  tctx.spool_fd = -1;
  tctx.serve_fd = -1;
  memset(&cfg, 0, sizeof cfg);
  cfg.kind = CACHE_BYTES;
  cfg.bytes = 8192;             /* target 8192 > cap page 4096 */
  memset(&bsrc, 0, sizeof bsrc);
  bsrc.mode = BUFFER_MODE_COMMAND;
  ops[0] = "/bin/cat";
  ops[1] = srcpath;
  p = &tctx.pros[0];
  EXPECT(source_open(&p->src, SOURCE_MODE_COMMAND, 2, ops) == 0);
  EXPECT(buffer_open(&p->buf, 4096, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&p->buf, pat, sizeof pat) == 0); /* full, cap < target */
  p->active = 1;
  p->backed = 0;

  EXPECT(wait_readable(source_fd(&p->src)) > 0);
  n = sizeof stage;
  EXPECT(producer_read_chunk(p, stage, &n, 0) == 1);    /* grow, not EOF */
  EXPECT(n > 0 && n <= 4096);   /* at most target-cap */
  EXPECT(p->backed == 0);
  EXPECT(source_eof(&p->src) == 0);     /* pre-fix: latched */
  EXPECT(source_fd(&p->src) != SOURCE_FD_NONE); /* pre-fix: closed */
  /* The append grows the window to the target; the next read freezes there. */
  EXPECT(producer_store(&tctx, p, stage, n) == 0);
  EXPECT(p->buf.cap == 8192);
  n = sizeof stage;
  EXPECT(producer_read_chunk(p, stage, &n, 0) == 0);
  EXPECT(n == 0 && p->backed == 1);

  source_teardown(&p->src);
  buffer_close(&p->buf);
  source_close(&p->src);
  (void)unlink(srcpath);
  return 0;
}

/* Byte-0 retention conformance (DOMAIN.md §Compaction decision tree): a live
 * window below its `--cache` target with a drained consumer must GROW toward
 * the target instead of compacting — the consumed prefix (byte 0) stays in
 * memory (buffer_offset 0, byte 0 readable, len == received). Only a window
 * already AT its target compacts, and then just the minimum consumed prefix
 * (the drained bytes, never below a live consumer's claim). Resolution: a
 * live plain s=0 request joins the producer FRONTIER (never rewinds to the
 * retained byte 0 — trace.5), while a Range into retained history and any
 * request once the total is known attach in place. */
static int t_retention_grow_first(void)
{
  struct run_ctx tctx;
  struct cache_cfg cfg;
  struct buf_source bsrc;
  const char *ops[2];
  unsigned char stage[32768];
  unsigned char pat[4096];
  unsigned char sink[4096];
  unsigned char out[16];
  struct producer *p;
  struct http_prod *prod;
  char srcpath[128];
  size_t n, got, idx, i;
  unsigned long long at;
  int tail;
  int fd;

  for (i = 0; i < sizeof pat; i++)
    pat[i] = (unsigned char)(i % 251);

  /* Phase 1: below-target window with a drained prefix must grow, keep byte 0. */
  EXPECT(make_tmp("rt", srcpath, sizeof srcpath, "") == 0);
  fd = open(srcpath, O_WRONLY | O_TRUNC);
  EXPECT(fd >= 0);
  for (i = 0; i < 64; i++)      /* 256KB source: plenty ahead to read */
    EXPECT(write_all(fd, pat, sizeof pat) == 0);
  EXPECT(close(fd) == 0);

  memset(&tctx, 0, sizeof tctx);
  tctx.spool_fd = -1;
  tctx.serve_fd = -1;
  memset(&cfg, 0, sizeof cfg);
  cfg.kind = CACHE_BYTES;
  cfg.bytes = 8192;             /* target 8192 > cap page 4096: growth headroom */
  memset(&bsrc, 0, sizeof bsrc);
  bsrc.mode = BUFFER_MODE_COMMAND;
  ops[0] = "/bin/cat";
  ops[1] = srcpath;
  p = &tctx.pros[0];
  EXPECT(source_open(&p->src, SOURCE_MODE_COMMAND, 2, ops) == 0);
  EXPECT(buffer_open(&p->buf, 4096, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&p->buf, pat, sizeof pat) == 0); /* len==cap 4096 < target */
  p->active = 1;
  p->backed = 0;
  EXPECT(buffer_add_consumer(&p->buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof sink);   /* consumer drained the whole window */

  EXPECT(wait_readable(source_fd(&p->src)) > 0);
  n = sizeof stage;
  EXPECT(producer_read_chunk(p, stage, &n, 0) == 1);
  /* The drained prefix was NOT compacted: the window kept byte 0 (offset 0,
   * len == received) and simply grew. Pre-fix: compaction slid offset to
   * 4096 and byte 0 was gone. */
  EXPECT(buffer_offset(&p->buf) == 0);
  EXPECT(buffer_len(&p->buf) == buffer_received(&p->buf));
  EXPECT(n > 0 && n <= 4096);   /* headroom toward the target, nothing reclaimed */
  EXPECT(producer_store(&tctx, p, stage, n) == 0);
  EXPECT(p->buf.cap > 4096);    /* it grew, it did not slide */
  EXPECT(buffer_offset(&p->buf) == 0);
  EXPECT(buffer_read_at(&p->buf, 0, out, 4) == 0);
  EXPECT(memcmp(out, pat, 4) == 0);     /* byte 0 still the original stream's */

  /* The connection closes: its consumer detaches, nothing else reclaims. */
  buffer_remove_consumer(&p->buf, idx);
  EXPECT(buffer_lowest(&p->buf) == 0);

  /* Phase 2: a plain s=0 live request replays the whole resource from byte 0
   * — the window still retains it (the drained prefix grew, never slid) — as
   * a startable whole resource (trace.9: a mid-stream continuation is re-init'd
   * and aborts). No spawn, tail 0. */
  tctx.npro = 1;
  tctx.spec.page = 4096;
  tctx.spec.argc = 0;
  tctx.spec.argv = NULL;
  prod = NULL;
  at = ~0ULL;
  tail = -1;
  EXPECT(run_resolve(&tctx, 0, &prod, &at, &tail) == 0);
  EXPECT(tctx.npro == 1);       /* no duplicate producer spawned */
  EXPECT(prod == &tctx.pros[0].prod && at == 0 && tail == 0);

  /* Phase 2b: once the total is known (first producer EOF) the frontier join
   * is off — a plain s=0 resolves to the retained byte 0 in place (the
   * whole-body serving path stays untouched). */
  tctx.srv.total = buffer_received(&p->buf);
  at = ~0ULL;
  tail = -1;
  EXPECT(run_resolve(&tctx, 0, &prod, &at, &tail) == 0);
  EXPECT(at == 0 && tail == 0);
  tctx.srv.total = 0;

  /* Phase 2c: a live Range start (s > 0, retained) keeps the in-place ladder
   * — it must NOT be diverted to the frontier. */
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&tctx, 1000, &prod, &at, &tail) == 0);
  EXPECT(at == 1000 && tail == 0);

  source_teardown(&p->src);
  buffer_close(&p->buf);
  source_close(&p->src);
  (void)unlink(srcpath);

  /* Phase 3: the same window AT its target must compact the minimum prefix —
   * exactly the drained bytes (offset 1000), below-vs-at-target degradation. */
  memset(&tctx, 0, sizeof tctx);
  tctx.spool_fd = -1;
  tctx.serve_fd = -1;
  memset(&cfg, 0, sizeof cfg);
  cfg.kind = CACHE_BYTES;
  cfg.bytes = 4096;             /* target == cap == page: no growth headroom */
  EXPECT(make_tmp("rt2", srcpath, sizeof srcpath, "") == 0);
  fd = open(srcpath, O_WRONLY | O_TRUNC);
  EXPECT(fd >= 0);
  for (i = 0; i < 64; i++)
    EXPECT(write_all(fd, pat, sizeof pat) == 0);
  EXPECT(close(fd) == 0);
  p = &tctx.pros[0];
  EXPECT(source_open(&p->src, SOURCE_MODE_COMMAND, 2, ops) == 0);
  EXPECT(buffer_open(&p->buf, 4096, &cfg, &bsrc) == 0);
  EXPECT(buffer_append(&p->buf, pat, sizeof pat) == 0); /* len == cap == target */
  p->active = 1;
  p->backed = 0;
  EXPECT(buffer_add_consumer(&p->buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, 1000, &got) == 0);
  EXPECT(got == 1000);          /* a 1000-byte consumed prefix */
  EXPECT(wait_readable(source_fd(&p->src)) > 0);
  n = sizeof stage;
  EXPECT(producer_read_chunk(p, stage, &n, 0) == 1);
  EXPECT(buffer_offset(&p->buf) == 1000);       /* minimum slide: the 1000 consumed */
  EXPECT(p->buf.cap == 4096);   /* at target: no growth, compaction only */
  EXPECT(buffer_len(&p->buf) == 4096 - 1000);
  buffer_remove_consumer(&p->buf, idx);
  source_teardown(&p->src);
  buffer_close(&p->buf);
  source_close(&p->src);
  (void)unlink(srcpath);
  return 0;
}

/* trace.9 serve shape: a plain s=0 live re-pull is answered as a startable
 * whole resource — the retained window replays from byte 0 at socket rate,
 * then slips onto the live edge and parks on an empty socket through a
 * production stall (trace.6's 2.31 s conn2), resuming on the next append
 * with exactly the fresh bytes. The mid-stream continuation (frontier or
 * delivered-end run-in) is what the drained DMR aborted on. */
static int t_resume_stall(void)
{
  struct run_ctx ctx;
  struct buf_source bsrc;
  unsigned char p1[4096], p2[4096], sink[4096];
  struct producer *p;
  struct http_prod *prod;
  size_t got, idx;
  unsigned long long at;
  int tail, i;

  memset(&ctx, 0, sizeof ctx);
  ctx.spool_fd = -1;
  ctx.serve_fd = -1;
  memset(&ctx.spec.cache, 0, sizeof ctx.spec.cache);
  ctx.spec.page = 4096;
  ctx.spec.cache.kind = CACHE_BYTES;
  ctx.spec.cache.bytes = 8192;  /* target > cap: growth headroom between fragments */
  ctx.spec.argc = 2;
  ctx.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  for (i = 0; i < (int)sizeof p1; i++) {
    p1[i] = (unsigned char)(i % 251);
    p2[i] = (unsigned char)~p1[i];      /* distinguishable: a replay would show p1 */
  }
  memset(&bsrc, 0, sizeof bsrc);
  bsrc.mode = BUFFER_MODE_COMMAND;
  p = &ctx.pros[0];
  EXPECT(buffer_open(&p->buf, 4096, &ctx.spec.cache, &bsrc) == 0);
  EXPECT(buffer_append(&p->buf, p1, sizeof p1) == 0);   /* frag ..23 lands */
  p->active = 1;
  ctx.npro = 1;

  /* conn1 catches up (drains every buffered byte) then detaches — trace.6
   * conn1: the device FIN'd 0.8 s after the last byte, its buffer drained. */
  EXPECT(buffer_add_consumer(&p->buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof p1 && memcmp(sink, p1, sizeof p1) == 0);
  buffer_remove_consumer(&p->buf, idx);

  /* conn2: the DMR re-pulls plain s=0 while the stream is live — the restart
   * rule serves byte 0 (still retained) at socket rate: no spawn, the whole
   * resource replays from its start. */
  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 0, &prod, &at, &tail) == 0);
  EXPECT(ctx.npro == 1 && prod == &ctx.pros[0].prod);
  EXPECT(at == 0 && tail == 0);

  /* The replay serves the retained window from byte 0 — the original p1
   * fragment (a frontier join would have read nothing). */
  EXPECT(buffer_add_consumer(&p->buf, (size_t)at, &idx) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof p1 && memcmp(sink, p1, sizeof p1) == 0);

  /* Caught up at the live edge: parks until the next append, and the first
   * read after the append returns exactly the fresh bytes. */
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == 0);

  /* Next append: the restart consumer reads exactly the fresh bytes,
   * byte-contiguous with the replay — and the retained head still carries
   * the original p1 fragment. */
  EXPECT(buffer_append(&p->buf, p2, sizeof p2) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof p2 && memcmp(sink, p2, sizeof p2) == 0);
  EXPECT(buffer_read_at(&p->buf, 0, sink, 4) == 0);
  EXPECT(memcmp(sink, p1, 4) == 0);

  buffer_remove_consumer(&p->buf, idx);
  buffer_close(&p->buf);
  return 0;
}

/* trace.7+trace.9 drained-conn restart: a plain s=0 re-pull after a
 * connection closed behind the producer frontier (trace.7's 154,432-byte
 * produced-but-never-flushed hole) is answered as a startable whole resource
 * — the window still retains byte 0, so the re-pull replays it from stream
 * byte 0 at socket rate (trace.9: a mid-stream continuation, whether cold
 * frontier or delivered-end run-in, is what the drained DMR re-init'd and
 * aborted on ~40ms later). The retained head IS the replay source. */
static int t_restart(void)
{
  struct run_ctx ctx;
  struct buf_source bsrc;
  unsigned char p1[4096], p2[4096], sink[4096];
  struct producer *p;
  struct http_prod *prod;
  size_t got, idx;
  unsigned long long at;
  int tail, i;

  memset(&ctx, 0, sizeof ctx);
  ctx.spool_fd = -1;
  ctx.serve_fd = -1;
  memset(&ctx.spec.cache, 0, sizeof ctx.spec.cache);
  ctx.spec.page = 4096;
  ctx.spec.cache.kind = CACHE_BYTES;
  ctx.spec.cache.bytes = 8192;
  ctx.spec.argc = 2;
  ctx.spec.argv = (const char *[]) { "/bin/echo", "x", NULL };
  for (i = 0; i < (int)sizeof p1; i++) {
    p1[i] = (unsigned char)(i % 251);
    p2[i] = (unsigned char)~p1[i];
  }
  memset(&bsrc, 0, sizeof bsrc);
  bsrc.mode = BUFFER_MODE_COMMAND;
  p = &ctx.pros[0];
  EXPECT(buffer_open(&p->buf, 4096, &ctx.spec.cache, &bsrc) == 0);
  EXPECT(buffer_append(&p->buf, p1, sizeof p1) == 0);
  p->active = 1;
  ctx.npro = 1;

  /* conn1 drains only 3000 of the 4096 buffered bytes before closing: its
   * delivered end (3000) trails the frontier (4096) — trace.7's hole; the
   * window still retains byte 0, so a re-pull must restart from it. */
  EXPECT(buffer_add_consumer(&p->buf, 0, &idx) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, 3000, &got) == 0);
  EXPECT(got == 3000 && memcmp(sink, p1, 3000) == 0);
  buffer_remove_consumer(&p->buf, idx);

  /* conn2 re-pulls plain s=0: the restart serves the whole resource from byte
   * 0 — no spawn, no delivered-end/frontier continuation. */
  prod = NULL;
  at = 0;
  tail = -1;
  EXPECT(run_resolve(&ctx, 0, &prod, &at, &tail) == 0);
  EXPECT(ctx.npro == 1 && prod == &ctx.pros[0].prod);
  EXPECT(at == 0 && tail == 0);

  /* The whole retained window replays from byte 0 at socket rate — the trace
   * that the run-in previously served as a "hole" [3000, 4096) is now served
   * as the start of the resource (p1 retained include its head). */
  EXPECT(buffer_add_consumer(&p->buf, (size_t)at, &idx) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof p1);
  EXPECT(memcmp(sink, p1, sizeof p1) == 0);

  /* Caught up: slips onto the live edge, parking until the next append. */
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == 0);

  /* The next append resumes the restarted consumer with exactly the fresh
   * bytes — byte-contiguous with the replay, no overlap. */
  EXPECT(buffer_append(&p->buf, p2, sizeof p2) == 0);
  EXPECT(buffer_consumer_read(&p->buf, idx, sink, sizeof sink, &got) == 0);
  EXPECT(got == sizeof p2 && memcmp(sink, p2, sizeof p2) == 0);
  buffer_remove_consumer(&p->buf, idx);

  buffer_close(&p->buf);
  return 0;
}

static void reg_ctx_reset(struct run_ctx *ctx)
{
  size_t i;

  memset(ctx, 0, sizeof *ctx);
  ctx->cfd = -1;
  ctx->cn.ctrl.fd = -1;
  ctx->srv.listen_fd = -1;
  for (i = 0; i < HTTP_CONN_MAX; i++)
    ctx->srv.conns[i].fd = -1;
}

/* Bugfix-1/.4 conn registration, asserted through the kernel (epoll_wait),
 * not the bookkeeping: the .4-era test only checked reg_conn.evs, so it never
 * noticed that the EPOLLOUT arm failed EEXIST — the ADD-only epoll_set left
 * the kernel on EPOLLIN, which is the .7 blocked-conn deadlock. */
static int t_reg_epoll(void)
{
  struct run_ctx ctx;
  struct epoll_event evs[8];
  int sv[2];

  reg_ctx_reset(&ctx);
  EXPECT(run_init(&ctx) == 0);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  ctx.srv.conns[0].fd = sv[0];
  ctx.srv.conns[0].blocked = 0;
  run_sync(&ctx);
  EXPECT(ctx.reg_conn[0].fd == sv[0] && ctx.reg_conn[0].evs == EPOLLIN);
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 0); /* quiet conn: no wake */

  ctx.srv.conns[0].blocked = 1;
  run_sync(&ctx);
  EXPECT(ctx.reg_conn[0].evs == (EPOLLIN | EPOLLOUT));
  /* The always-writable socketpair is now level-EPOLLOUT ready: the arm must
   * reach the kernel (pre-fix: ADD EEXIST, the conn never woke). */
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 1);
  EXPECT(evs[0].data.fd == sv[0] && (evs[0].events & EPOLLOUT));

  ctx.srv.conns[0].blocked = 0;
  run_sync(&ctx);
  EXPECT(ctx.reg_conn[0].evs == EPOLLIN);
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 0); /* wake source gone */

  conn_close_del(&ctx, sv[0]);
  EXPECT(ctx.reg_conn[0].fd == -1);
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 0);

  run_close(&ctx);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Bugfix-2/.6 handover: the pending-connect EPOLLOUT watch must become the
 * session's EPOLLIN watch on the SAME open fd. The ctrl EPOLLIN ADD used to
 * fail EEXIST, leaving the kernel on EPOLLOUT — 75 k and 352 k quick spins —
 * and the session never EPOLLIN-woken. */
static int t_reg_handover(void)
{
  struct run_ctx ctx;
  struct epoll_event evs[8];
  int sv[2];

  reg_ctx_reset(&ctx);
  EXPECT(run_init(&ctx) == 0);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  ctx.cfd = sv[0];              /* connect in flight: watched EPOLLOUT */
  run_sync(&ctx);
  EXPECT(ctx.reg_cfd.fd == sv[0] && ctx.reg_cfd.evs == EPOLLOUT);
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 1);
  EXPECT(evs[0].data.fd == sv[0] && (evs[0].events & EPOLLOUT));

  ctx.cfd = -1;                 /* connect done: same fd becomes the session */
  ctx.cn.ctrl.fd = sv[0];
  run_sync(&ctx);
  EXPECT(ctx.reg_cfd.fd == -1 && ctx.reg_ctrl.fd == sv[0]);
  EXPECT(ctx.reg_ctrl.evs == EPOLLIN);
  /* Quiet session socket must no longer spin EPOLLOUT (pre-fix: it did). */
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 0);
  /* Session input wakes the socket. */
  EXPECT(write(sv[1], "x", 1) == 1);
  EXPECT(epoll_wait(ctx.epfd, evs, 8, 0) == 1);
  EXPECT(evs[0].data.fd == sv[0] && (evs[0].events & EPOLLIN));

  run_close(&ctx);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Bugfix-1 source registration: an un-gated untrusted pipe is watched; a gated
 * or trusted source is never watched (no EPOLLIN spin); a gated live fd is
 * surrendered with a real DEL, a closed fd only loses its bookkeeping (its
 * number may be re-used — live-CDD .4 close(10)-then-DEL → EBADF). */
static int t_reg_source(void)
{
  struct run_ctx ctx;
  struct epoll_event ev;
  int sv[2];

  reg_ctx_reset(&ctx);
  EXPECT(run_init(&ctx) == 0);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  memset(&ev, 0, sizeof ev);
  ctx.pros[0].active = 1;
  ctx.pros[0].src.mode = SOURCE_MODE_COMMAND;
  ctx.pros[0].src.fd = sv[0];

  ctx.spool_fd = sv[1];         /* spool de-gates: watched */
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == sv[0]);
  EXPECT(epoll_ctl(ctx.epfd, EPOLL_CTL_MOD, sv[0], &ev) == 0);

  ctx.spool_fd = -1;            /* gated: surrendered with a live-fd DEL */
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == -1);
  errno = 0;
  EXPECT(epoll_ctl(ctx.epfd, EPOLL_CTL_MOD, sv[0], &ev) == -1 && errno == ENOENT);

  ctx.spool_fd = sv[1];         /* re-arm */
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == sv[0]);
  close(sv[0]);                 /* EOF close: kernel auto-drops */
  ctx.pros[0].src.fd = -1;
  ctx.spool_fd = -1;
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == -1);

  ctx.pros[0].src.size_trusted = 1;
  ctx.pros[0].src.fd = sv[1];
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == -1);

  /* A backpressured (backed) producer is never watched either: its pipe stays
   * readable while the window is full, so a level EPOLLIN watch would spin
   * (no-spool false-EOF fix). Room reappearing un-backs and re-arms it. */
  ctx.pros[0].src.size_trusted = 0;
  ctx.spool_fd = sv[1];
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == sv[1]);
  ctx.pros[0].backed = 1;
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == -1);
  ctx.pros[0].backed = 0;
  run_sync(&ctx);
  EXPECT(ctx.reg_src[0].fd == sv[1]);

  run_close(&ctx);
  close(sv[1]);
  return 0;
}

int main(void)
{
#define T(n) fprintf(stderr, "== %s ==\n", #n); RUN(n); fflush(stderr);
  T(t_version_and_help);
  T(t_bad_inputs);
  T(t_missing_sources);
  T(t_no_device);
  T(t_cast_done);
  T(t_loop_file);
  T(t_loop_cmd);
  T(t_loop_cmd_nospool);
  T(t_loop_cmd_big);
  T(t_resolve_branches);
  T(t_spawn_retires_stale);
  T(t_gating);
  T(t_live_backpressure);
  T(t_live_grow);
  T(t_retention_grow_first);
  T(t_resume_stall);
  T(t_restart);
  T(t_stop_signal);
  T(t_stop_recast);
  T(t_tty_sigint);
  T(t_connect_addr);
  T(t_connect_budget);
  T(t_failed_session);
  T(t_bad_command);
  T(t_run_init_fail);
  T(t_reg_epoll);
  T(t_reg_handover);
  T(t_reg_source);
  TEST_SUMMARY();
}
