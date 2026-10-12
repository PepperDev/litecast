#include "cli/cli.h"
#include "run/run.h"

#include "source/spool.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define LITECAST_VERSION "0.1.0"

static const char USAGE[] =
    "litecast [-b SIZE|--cache SIZE] [-s|--cache-to-fs] [-d NAME|--device NAME]\n"
    "         [-n|--no-arbitrary-range]\n"
    "         (-f|--file | -c|--command) [--] <FILES...>|<command-and-args...>\n";

/* The local interface address reached through the default route (DOMAIN §HTTP server). */
static int local_probe(struct sockaddr_in *got, socklen_t *glen)
{
  struct sockaddr_in dst;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  if (fd < 0)
    return -1;
  memset(&dst, 0, sizeof dst);
  dst.sin_family = AF_INET;
  dst.sin_port = htons(53);
  if (inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr) != 1)
    goto closeerr;
  if (connect(fd, (struct sockaddr *)&dst, sizeof dst) != 0)
    goto closeerr;
  if (getsockname(fd, (struct sockaddr *)got, glen) != 0)
    goto closeerr;
  close(fd);
  return 0;
 closeerr:
  close(fd);
  return -1;
}

static void local_ipv4(char out[16])
{
  struct sockaddr_in got;
  socklen_t glen = sizeof got;

  if (local_probe(&got, &glen) != 0 || inet_ntop(AF_INET, &got.sin_addr, out, 16) == NULL)
    memcpy(out, "0.0.0.0", 8);
}

static const char *content_type_of(const char *path)
{
  static const struct {
    const char *ext, *type;
  } types[] = {
    {".mp4", "video/mp4"}, {".mkv", "video/x-matroska"},
    {".webm", "video/webm"}, {".mp3", "audio/mpeg"},
    {".ogg", "audio/ogg"}, {".wav", "audio/wav"},
  };
  const char *dot = path ? strrchr(path, '.') : NULL;
  size_t i;

  for (i = 0; i < sizeof types / sizeof types[0]; i++)
    if (dot && strcmp(dot, types[i].ext) == 0)
      return types[i].type;
  return "application/octet-stream";
}

/* File mode: a second fd on the single source file for direct pread serving,
 * so the whole stream stays servable after the producer's fd closes at drain;
 * other modes pass the command spool fd / -1 through. */
static int open_serve_fd(struct run_ctx *ctx, const struct cli_options *opts)
{
  if (!opts->command_mode && source_size_trusted(&ctx->pros[0].src)
      && ctx->pros[0].src.nfiles == 1) {
    ctx->serve_fd = open(ctx->pros[0].src.files[0], O_RDONLY);
    if (ctx->serve_fd < 0)
      return -1;
  }
  return 0;
}

static const char *serve_type(const struct cli_options *opts)
{
  return opts->command_mode ? "video/mp2t" : content_type_of(opts->operands[0]);
}

/* No-spool command mode: resolve late requests to a producer window. */
static void maybe_resolve(struct run_ctx *ctx, const struct cli_options *opts)
{
  if (opts->command_mode && !opts->cache_to_fs)
    run_enable_resolve(ctx);
}

static int serve_start(struct run_ctx *ctx, const struct cli_options *opts, struct http_src *hsrc, uint16_t *port)
{
  /* pros[0] is memset-zero in no-spool mode but never opened: the pointer
   * anchor is valid, conns resolve to spawned producers' buffers. */
  hsrc->buf = &ctx->pros[0].buf;
  if (open_serve_fd(ctx, opts) != 0)
    return -1;
  hsrc->spool_fd = ctx->serve_fd < 0 ? ctx->spool_fd : ctx->serve_fd;
  hsrc->total = source_total(&ctx->pros[0].src);
  hsrc->content_type = serve_type(opts);
  if (http_srv_init(&ctx->srv, hsrc) != 0)
    return -1;
  maybe_resolve(ctx, opts);
  if (http_listen(&ctx->srv, port) != 0)
    return -1;
  return 0;
}

static int session_setup(struct run_ctx *ctx, const struct cli_options *opts,
                         const struct http_src *hsrc, uint16_t port)
{
  struct cast_load load;
  char lip[16];

  (void)opts;
  local_ipv4(lip);
  (void)snprintf(ctx->cid, sizeof ctx->cid, "http://%s:%u/stream", lip, (unsigned)port);
  memset(&load, 0, sizeof load);
  load.content_id = ctx->cid;
  load.content_type = hsrc->content_type;
  load.stream_type = "LIVE";
  if (cast_conn_init(&ctx->cn, &load, "sender-0") != 0)
    return -1;
  return 0;
}

/* Phase setup: open source, resolve buffer, bind HTTP, wire cast session. */
static int run_phase(struct run_ctx *ctx, const struct cli_options *opts)
{
  struct http_src hsrc;
  uint16_t port = 0;
  size_t page;

  if (run_open_source(ctx, opts, &page) != 0)
    return -1;
  if (run_open_spool(ctx, opts) != 0)
    return -1;
  memset(&hsrc, 0, sizeof hsrc);
  hsrc.arbitrary_end = !opts->no_arbitrary_range;
  if (serve_start(ctx, opts, &hsrc, &port) != 0)
    return -1;
  return session_setup(ctx, opts, &hsrc, port);
}

/* Parse help/version/usage exits. Returns -1 to proceed, else exit code. */
static int early_options(int argc, char **argv, struct cli_options *opts)
{
  if (cli_parse(argc, argv, opts) != 0) {
    (void)fputs(USAGE, stderr);
    return EXIT_FAILURE;
  }
  if (opts->show_help) {
    (void)fputs(USAGE, stdout);
    return EXIT_SUCCESS;
  }
  if (opts->show_version) {
    (void)printf("litecast " LITECAST_VERSION "\n");
    return EXIT_SUCCESS;
  }
  if (opts->operands_count == 0) {
    (void)fputs(USAGE, stderr);
    return EXIT_FAILURE;
  }
  return -1;
}

static void seed_ctx(struct run_ctx *ctx)
{
  size_t i;

  memset(ctx, 0, sizeof *ctx);
  ctx->cfd = -1;
  ctx->spool_fd = -1;
  ctx->serve_fd = -1;
  ctx->srv.listen_fd = -1;
  for (i = 0; i < HTTP_CONN_MAX; i++)
    ctx->srv.conns[i].fd = -1;
  ctx->cn.ctrl.fd = -1;
  for (i = 0; i < PRODUCER_MAX; i++)
    ctx->pros[i].src.fd = SOURCE_FD_NONE;
}

/* mDNS discovery window: LITECAST_MDNS_MS overrides the default (tests). */
static int mdns_window(void)
{
  const char *e = getenv("LITECAST_MDNS_MS");
  int win = MDNS_WINDOW_MS;

  if (e != NULL) {
    int w = atoi(e);
    if (w >= 0)
      win = w;
  }
  return win;
}

static size_t device_count(const struct run_ctx *ctx)
{
  size_t ndev;
  for (ndev = 0; ndev < MDNS_MAX_DEVICES; ndev++)
    if (ctx->devs[ndev].name[0] == '\0')
      break;
  return ndev;
}

/* mDNS discovery with the (test-overridable) window, applied to ctx. */
static int discover_device(struct run_ctx *ctx, const struct cli_options *opts)
{
  int sel;

  memset(ctx->devs, 0, sizeof ctx->devs);
  sel = mdns_discover_ms(NULL, opts->device, ctx->devs, MDNS_MAX_DEVICES, mdns_window());
  if (sel < 0) {
    (void)fputs("litecast: no Chromecast device found\n", stderr);
    return -1;
  }
  ctx->ndev = (int)device_count(ctx);
  ctx->dev_idx = sel;
  return 0;
}

static int prepare_run(struct run_ctx *ctx, const struct cli_options *opts)
{
  if (run_phase(ctx, opts) != 0) {
    (void)fputs("litecast: cannot prepare the stream\n", stderr);
    return -1;
  }
  return 0;
}

/* The live session socket: close the pending connect or control socket. */
static void close_session_fd(struct run_ctx *ctx)
{
  int tfd = ctx->cfd >= 0 ? ctx->cfd : cast_conn_fd(&ctx->cn);

  if (tfd >= 0)
    (void)close(tfd);
}

/* Stop the --command child with a bounded reap (see source_teardown) so the exit
 * never blocks — a SIGPIPE-ignoring ffmpeg outlasts SIGTERM with no pending write
 * to detect the dead pipe — and free every producer (QA.md §Resource teardown). */
static void close_producers(struct run_ctx *ctx)
{
  for (size_t i = 0; i < PRODUCER_MAX; i++)
    if (ctx->pros[i].active) {
      buffer_close(&ctx->pros[i].buf);
      source_close(&ctx->pros[i].src);
    }
}

static void teardown_run(struct run_ctx *ctx)
{
  int i;

  (void)cast_ctrl_stop(&ctx->cn.ctrl);  /* terminate the DMR app on the device */
  for (i = 0; i < PRODUCER_MAX; i++)
    if (ctx->pros[i].active)
      source_teardown(&ctx->pros[i].src);
  close_session_fd(ctx);
  cast_conn_close(&ctx->cn);
  http_srv_close(&ctx->srv);
  spool_close(ctx->spool_fd);
  spool_close(ctx->serve_fd);
  close_producers(ctx);
  run_close(ctx);
}

int main(int argc, char **argv)
{
  struct cli_options opts;
  struct run_ctx ctx;
  int rc;

  rc = early_options(argc, argv, &opts);
  if (rc != -1)
    return rc;
  seed_ctx(&ctx);
  if (run_init(&ctx) != 0)
    return EXIT_FAILURE;
  rc = prepare_run(&ctx, &opts);
  if (rc == 0)
    rc = discover_device(&ctx, &opts);
  if (rc == 0)
    rc = run_loop(&ctx);
  if (rc < 0)
    rc = EXIT_FAILURE;
  teardown_run(&ctx);
  return rc;
}
