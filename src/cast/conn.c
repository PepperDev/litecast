#include "cast/cast.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* === Connection lifecycle policy (DOMAIN.md §Retry Landscape rows 2-5) ===
 *
 * Orchestrates one control socket: the Cast V2 handshake (CONNECT→GET_STATUS
 * →sessionId), LOAD on the media namespace, then heartbeats. Any socket loss
 * — EOF/hard error, a 10s handshake timeout, or 20s of heartbeat silence —
 * schedules a reconnect: 1s/2s backoff against a budget of 3 attempts.
 * Exhausting it marks the session FAILED and the caller aborts; the HTTP
 * server is not owned here, so it keeps serving across reconnects.
 *
 * Event-loop-agnostic: cast_conn_poll() is driven with now_ms, and
 * cast_conn_retry() says when a fresh TCP connect is due. */

#define CONN_HANDSHAKE_MS 10000 /* per-attempt handshake budget */
#define CONN_RETRY_MAX 3        /* rows 2/4: at most three attempts */

/* Backoff gaps (s) before each re-attempt, per §Retry Landscape rows 2-4. */
static const uint32_t CONN_BACKOFF[] = { 1000, 2000, 2000 };

/* Backoff gaps for a DMR session restart (DOMAIN.md §Session supervision),
 * on a lane that never spends the transport budget: a fast-dying session
 * escalates 1s→2s→4s→8s, and one surviving past RESTART_RESET_MS re-arms. */
static const uint32_t RESTART_BACKOFF[] = { 1000, 2000, 4000, 8000 };

#define RESTART_RESET_MS 60000  /* a session surviving this long clears the escalation */

static uint32_t restart_gap(unsigned restarts)
{
  return RESTART_BACKOFF[restarts < 3U ? restarts : 3U];
}

enum {
  CONN_HANDSHAKE = 1,           /* socket open, session not ready yet */
  CONN_ACTIVE = 2,              /* session ready, LOAD sent, streaming */
  CONN_WAIT = 3,                /* backoff pause before a reconnect */
  CONN_FAILED = 4,              /* retry budget exhausted */
};

/* Give up the control socket: STOP the latched session, then close (§Exit). */
static void conn_drop(struct cast_conn *cn)
{
  int fd = cn->ctrl.fd;
  if (fd >= 0) {
    (void)cast_ctrl_stop(&cn->ctrl);
    cast_ctrl_close(&cn->ctrl); /* frees TLS session + reader */
    close(fd);                  /* the transport fd itself */
    cn->ctrl.fd = -1;           /* cast_conn_fd reports the dropped socket */
  }
}

/* A socket that died or timed out consumes an attempt and schedules the
 * next try after the row's backoff gap; the stale fd is dropped so epoll no
 * longer watches it. Returns 1 with a reconnect booked (CONN_WAIT), 0 when
 * the budget is spent (CONN_FAILED). */
static int conn_lost(struct cast_conn *cn, uint64_t now_ms)
{
  conn_drop(cn);
  if (cn->attempt >= CONN_RETRY_MAX) {
    cn->st = CONN_FAILED;
    return 0;
  }
  cn->deadline = now_ms + CONN_BACKOFF[cn->attempt];
  cn->attempt++;
  cn->st = CONN_WAIT;
  return 1;
}

/* Lost-socket verdict for poll: 0 (reconnect booked) or -1 (budget spent). */
static int conn_wound(struct cast_conn *cn, uint64_t now_ms)
{
  return conn_lost(cn, now_ms) ? 0 : -1;
}

/* Session ready: send LOAD (sessionId spliced in) and go active. */
static int conn_start(struct cast_conn *cn)
{
  struct cast_load m;
  const char *sid;
  int r;

  if (!cast_ctrl_ready(&cn->ctrl))
    return 0;
  sid = cast_ctrl_session(&cn->ctrl);
  if (sid == NULL)
    return -1;
  m = cn->load;
  m.session_id = sid;
  r = cast_ctrl_load(&cn->ctrl, &m);
  if (r != 1)
    return -1;
  cn->st = CONN_ACTIVE;
  return 1;
}

/* Drive the handshake: TLS, CONNECT/GET_STATUS, then the ctrl pump. */
static int conn_handshake(struct cast_conn *cn)
{
  int r;

  if (cn->ctrl.state == CTRL_TLS || cn->ctrl.state == CTRL_CONNECT)
    return cast_ctrl_step(&cn->ctrl);
  if (cn->status == 0) {
    r = cast_ctrl_now(&cn->ctrl);
    if (r != 1)
      return r;
    cn->status = 1;
    return 1;
  }
  r = cast_ctrl_step(&cn->ctrl);
  if (r == -1)
    return -1;
  return conn_start(cn);
}

static int conn_beat(struct cast_conn *cn, uint64_t now_ms)
{
  if (now_ms - cn->ctrl.last_ping_ms < CAST_PING_MS)
    return 0;
  return cast_ctrl_ping(&cn->ctrl) == 1 ? 1 : -1;
}

/* Full-body pump of the ACTIVE session; -1 means the session was lost. */
static int conn_active(struct cast_conn *cn, uint64_t now_ms)
{
  int r;

  if (!cast_ctrl_alive(&cn->ctrl, now_ms))
    return -1;
  r = conn_beat(cn, now_ms);
  if (r != 0)
    return r;
  r = cast_ctrl_step(&cn->ctrl);
  return r == -1 ? -1 : r;
}

/* Transport override for tests: LITECAST_TP=plain forces the legacy channel. */
static int conn_transport_default(void)
{
  const char *v = getenv("LITECAST_TP");

  if (v != NULL && strcmp(v, "plain") == 0)
    return CAST_TP_PLAIN;
  return CAST_TP_AUTO;
}

int cast_conn_init(struct cast_conn *cn, const struct cast_load *load, const char *source)
{
  size_t n;

  if (cn == NULL || load == NULL || source == NULL)
    return -1;
  n = strlen(source);
  if (n >= sizeof cn->source)
    return -1;
  memset(cn, 0, sizeof *cn);
  memcpy(cn->source, source, n + 1);
  cn->load = *load;
  cn->ctrl.fd = -1;             /* no transport yet; accessor reports -1 */
  cn->transport = conn_transport_default();
  cn->ctrl.state = CTRL_CONNECT;
  cn->st = CONN_WAIT;           /* nothing attached yet */
  return 0;
}

void cast_conn_close(struct cast_conn *cn)
{
  if (cn != NULL) {
    cast_ctrl_close(&cn->ctrl);
    memset(cn, 0, sizeof *cn);
    cn->ctrl.fd = -1;           /* accessor reports -1 after close */
  }
}

/* Take ownership of a freshly connected socket and start the handshake with
 * a fresh attempt (accounted at the loss that preceded it). */
int cast_conn_attach(struct cast_conn *cn, int fd, uint64_t now_ms)
{
  if (cn == NULL || fd < 0)
    return -1;
  if (cast_ctrl_init(&cn->ctrl, fd, cn->source, cn->transport) != 0)
    return -1;
  cn->status = 0;
  cn->st = CONN_HANDSHAKE;
  cn->deadline = now_ms + CONN_HANDSHAKE_MS;
  cn->restart = 0;              /* a healthy attach clears the restart lane */
  cn->attached_ms = now_ms;     /* survival clock for the escalation reset */
  return 0;
}

static int conn_poll_handshake(struct cast_conn *cn, uint64_t now_ms)
{
  int r;

  if (now_ms >= cn->deadline)
    return conn_wound(cn, now_ms);
  r = conn_handshake(cn);
  if (r == -1)
    return conn_wound(cn, now_ms);
  if (r == -2) {
    /* plaintext legacy peer: latch the decision and reconnect to speak it */
    cn->transport = CAST_TP_PLAIN;
    return conn_wound(cn, now_ms);
  }
  return r;
}

static int conn_poll_active(struct cast_conn *cn, uint64_t now_ms)
{
  int r;
  r = conn_active(cn, now_ms);
  if (r == -1)
    return conn_wound(cn, now_ms);
  return r;
}

static int conn_idle(struct cast_conn *cn, uint64_t now_ms)
{
  (void)cn;
  (void)now_ms;
  return 0;
}

static int conn_nope(struct cast_conn *cn, uint64_t now_ms)
{
  (void)cn;
  (void)now_ms;
  return -1;
}

static int (*const conn_poll_st[])(struct cast_conn *, uint64_t) = {
  conn_nope,                    /* 0 unused */
  conn_poll_handshake,
  conn_poll_active,
  conn_idle,                    /* CONN_WAIT: nothing until the backoff lapses */
  conn_nope,                    /* CONN_FAILED */
};

/* One non-blocking step: 1 progress, 0 idle, -1 beyond recovery. */
int cast_conn_poll(struct cast_conn *cn, uint64_t now_ms)
{
  if (cn == NULL)
    return -1;
  if (cn->st < 0 || cn->st >= (int)(sizeof conn_poll_st / sizeof *conn_poll_st))
    return -1;
  return conn_poll_st[cn->st] (cn, now_ms);
}

int cast_conn_retry(const struct cast_conn *cn, uint64_t now_ms)
{
  if (cn == NULL)
    return 0;
  if (cn->st != CONN_WAIT)
    return 0;
  if (cn->restart != 0)
    return now_ms >= cn->restart_at;
  return now_ms >= cn->deadline;
}

int cast_conn_failed(const struct cast_conn *cn)
{
  return cn != NULL && cn->st == CONN_FAILED;
}

/* Retire a DMR session that died under load (§Session supervision): close
 * the control socket like a transport loss, then book a fresh handshake →
 * LOAD on the dedicated restart backoff. cn->attempt is untouched (the
 * transport budget stays available); a session surviving past
 * RESTART_RESET_MS re-arms the 1s minimum, a fast-dying loop escalates. */
int cast_conn_restart(struct cast_conn *cn, uint64_t now_ms)
{
  if (cn == NULL)
    return -1;
  conn_drop(cn);
  if (cn->attached_ms != 0 && now_ms >= cn->attached_ms && now_ms - cn->attached_ms >= RESTART_RESET_MS)
    cn->restarts = 0;
  cn->restart_at = now_ms + restart_gap(cn->restarts);
  cn->restarts++;
  cn->restart = 1;
  cn->st = CONN_WAIT;
  return 0;
}

/* The transport fd the loop must watch, or -1 when nothing is attached. */
int cast_conn_fd(const struct cast_conn *cn)
{
  if (cn == NULL)
    return -1;
  return cn->ctrl.fd;
}

/* The session is streaming: control channel up, sessionId latched, LOAD sent. */
int cast_conn_active(const struct cast_conn *cn)
{
  return cn != NULL && cn->st == CONN_ACTIVE && cast_ctrl_ready(&cn->ctrl);
}
