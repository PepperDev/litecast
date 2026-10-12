#include "cast/cast.h"
#include "cast/tls.h"
#include "cast/tls/tls_ctrl.h"
#include "cast/verb.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* === Control channel (DOMAIN.md §Transport) ===
 * CONNECT, GET_STATUS + sessionId latch, PING/PONG; requestId monotonic from
 * 1; AUTO first-byte probe; handshake runs to the security latch first. */

#define CTRL_DEST "receiver-0"  /* platform receiver id */

int cast_ctrl_send_to(struct cast_ctrl *c, const char *ns, const char *dest, const char *json)
{
  struct cast_msg m = { ns, c->source, dest, json };

  return cast_send(&c->io, &m);
}

int cast_ctrl_send(struct cast_ctrl *c, const char *ns, const char *json)
{
  const char *dest;

  if (strcmp(ns, CAST_NS_MEDIA) == 0 && c->transport_id[0] != '\0')
    dest = c->transport_id;
  else
    dest = CTRL_DEST;
  return cast_ctrl_send_to(c, ns, dest, json);
}

static int ctrl_connect(struct cast_ctrl *c)
{
  char json[128];
  int n;

  if (c->state != CTRL_CONNECT)
    return 0;
  n = json_bcast(json, sizeof json, "CONNECT");
  if (n < 0)
    return -1;
  if (cast_ctrl_send(c, CAST_NS_CONNECTION, json) != 0)
    return -1;
  c->state = CTRL_STATUS;
  return 1;
}

static int ctrl_argcopy(struct cast_ctrl *c, const char *source)
{
  size_t n;

  if (source == NULL)
    return -1;
  n = strlen(source);
  if (n >= sizeof c->source)
    return -1;
  memcpy(c->source, source, n + 1);
  return 0;
}

static int ctrl_io_init(struct cast_ctrl *c, int fd)
{
  c->fd = fd;
  if (cast_io_fd(&c->io, &c->fd) != 0)
    return -1;
  if (cast_reader_init(&c->rd, &c->io) != 0)
    return -1;
  return 0;
}

int cast_ctrl_init(struct cast_ctrl *c, int fd, const char *source, int transport)
{
  int tls = tls_ctrl_mode(transport);
  if (c == NULL || tls < 0)
    return -1;
  memset(c, 0, sizeof *c);
  c->last_pong_ms = cast_ctrl_now_ms();
  if (ctrl_argcopy(c, source) != 0)
    return -1;
  c->transport = transport;
  if (ctrl_io_init(c, fd) != 0)
    return -1;
  return tls_ctrl_setup(c, tls);
}

void cast_ctrl_close(struct cast_ctrl *c)
{
  if (c != NULL) {
    cast_reader_close(&c->rd);
    if (c->hs != NULL) {
      tls_hs_close(c->hs);
      free(c->hs);
      c->hs = NULL;
    }
    memset(c, 0, sizeof *c);
  }
}

int cast_ctrl_now(struct cast_ctrl *c)
{
  char json[CAST_JSON_CAP];
  int n;

  if (c == NULL)
    return -1;
  n = json_get_status(json, sizeof json, ++c->rid);
  if (n < 0)
    return -1;
  if (cast_ctrl_send(c, CAST_NS_RECEIVER, json) != 0)
    return -1;
  c->state = CTRL_STATUS;
  return 1;
}

int cast_ctrl_load(struct cast_ctrl *c, const struct cast_load *l)
{
  struct cast_load m;
  char json[CAST_JSON_CAP];
  int n;

  if (c == NULL || l == NULL)
    return -1;
  if (!cast_ctrl_ready(c))
    return -1;
  m = *l;
  m.rid = ++c->rid;
  n = json_load(json, sizeof json, &m);
  if (n < 0)
    return -1;
  if (cast_ctrl_send(c, CAST_NS_MEDIA, json) != 0)
    return -1;
  c->media_started = 0;         /* verdicts before the next PLAYING are the ack */
  return 1;
}

int cast_ctrl_stop(struct cast_ctrl *c)
{
  char json[CAST_JSON_CAP];
  int n;

  if (c == NULL || c->state != CTRL_READY || c->session_id[0] == '\0')
    return 0;
  n = json_stop(json, sizeof json, ++c->rid, c->session_id);
  if (n < 0)
    return -1;
  return cast_ctrl_send(c, CAST_NS_RECEIVER, json);
}

static int ctrl_beat(struct cast_ctrl *c, const struct cast_decoded *d)
{
  char type[64];

  if (strcmp(d->ns, CAST_NS_HEARTBEAT) != 0)
    return 0;
  if (cast_json_get(d->payload, "type", type, sizeof type) != 0)
    return -1;
  c->last_pong_ms = cast_ctrl_now_ms();
  if (strcmp(type, "PING") != 0)
    return 1;
  return cast_ctrl_send(c, CAST_NS_HEARTBEAT, "{\"type\":\"PONG\"}") == 0 ? 1 : -1;
}

/* Media ns §Lifecycle (verb.c): LOAD_FAILED fatal; terminal verdicts are
 * classified (CTRL_END_*) so the run layer can tell a natural finish from a
 * dead session and exit or auto-restart it (§Session supervision). */
static int ctrl_handle(struct cast_ctrl *c, const struct cast_decoded *d)
{
  int r;
  r = ctrl_beat(c, d);
  if (r != 0)
    return r;
  r = cast_ctrl_media(c, d);
  if (r != 0)
    return r;
  return cast_ctrl_status(c, d);
}

static int ctrl_next(struct cast_ctrl *c, struct cast_decoded *d)
{
  const unsigned char *pb;
  size_t n;
  int r;

  r = cast_pump(&c->rd);
  if (r <= 0)
    return r;
  if (cast_reader_message(&c->rd, &pb, &n) != 0)
    return -1;
  if (cast_decode(pb, n, d) != 0)
    return -1;
  return 1;
}

int cast_ctrl_step(struct cast_ctrl *c)
{
  struct cast_decoded d;
  int r;

  if (c == NULL)
    return -1;
  if (c->state == CTRL_TLS) {
    r = tls_ctrl_step(c);
    if (r <= 0)
      return r;                 /* 0 = more I/O; -1 error; -2 plaintext peer */
    c->io.read = tls_io_read;   /* security latch: TLS transport + handshake */
    c->io.write = tls_io_write;
    c->io.opaque = c;
    c->state = CTRL_CONNECT;
    return 1;
  }
  if (c->state == CTRL_CONNECT)
    return ctrl_connect(c);
  r = ctrl_next(c, &d);
  if (r <= 0)
    return r;
  return ctrl_handle(c, &d);
}

uint64_t cast_ctrl_now_ms(void)
{
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

int cast_ctrl_ping(struct cast_ctrl *c)
{
  if (c == NULL)
    return -1;
  if (cast_ctrl_send(c, CAST_NS_HEARTBEAT, "{\"type\":\"PING\"}") != 0)
    return -1;
  c->last_ping_ms = cast_ctrl_now_ms();
  return 1;
}

int cast_ctrl_alive(const struct cast_ctrl *c, uint64_t now_ms)
{
  if (c == NULL)
    return 0;
  return now_ms >= c->last_pong_ms && now_ms - c->last_pong_ms <= CAST_LOST_MS;
}

int cast_ctrl_ready(const struct cast_ctrl *c)
{
  return c != NULL && c->state == CTRL_READY;
}

int cast_ctrl_finished(const struct cast_ctrl *c)
{
  return c != NULL && c->end_class != CTRL_END_NONE;
}

int cast_ctrl_end(const struct cast_ctrl *c)
{
  return c != NULL ? c->end_class : CTRL_END_NONE;
}

const char *cast_ctrl_session(const struct cast_ctrl *c)
{
  if (c == NULL)
    return NULL;
  return cast_ctrl_ready(c) ? c->session_id : NULL;
}
