#ifndef LITECAST_CAST_H
#define LITECAST_CAST_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum {
  CAST_MAX_FRAME = 131072,      /* protocol cap on the frame length prefix */
  CAST_JSON_CAP = 8192,         /* largest payload_utf8 we build or hold */
  CAST_ENC_CAP = CAST_JSON_CAP + 256,
  CAST_NS_MAX = 64              /* decoded namespace buffer (+NUL room) */
};

#define CAST_NS_CONNECTION "urn:x-cast:com.google.cast.tp.connection"
#define CAST_NS_HEARTBEAT  "urn:x-cast:com.google.cast.tp.heartbeat"
#define CAST_NS_RECEIVER   "urn:x-cast:com.google.cast.receiver"
#define CAST_NS_MEDIA      "urn:x-cast:com.google.cast.media"

#define CAST_DMR_APPID     "CC1AD845"   /* Default Media Receiver */

struct cast_conn;
struct tls_hs;

/* Control-channel transport resolution (DOMAIN.md §Encrypted vs plaintext).
 * AUTO: the first attempt probes TLS (sends a ClientHello) and latches the
 * decision from the peer's first byte via tls_hs_detect; a non-TLS reply
 * clears to PLAIN and the reconnect speaks plaintext directly. TLS: a modern
 * TLS-only device (mandatory). PLAIN: a resolved/hypothetical legacy peer. */
enum {
  CAST_TP_AUTO = 0,
  CAST_TP_TLS = 1,
  CAST_TP_PLAIN = 2
};

/* Byte-stream transport: an attached plaintext fd today, the TLS session
 * later — both offer the same framing above them. read() returns >0 progress,
 * 0 = would-block, -1 = error/EOF. write() returns >0 progress, 0 =
 * would-block, -1 = error. */
struct cast_io {
  ssize_t(*read) (struct cast_io * io, unsigned char *buf, size_t cap);
  ssize_t(*write) (struct cast_io * io, const unsigned char *buf, size_t cap);
  void *opaque;
};

/* Outbound CastMessage. */
struct cast_msg {
  const char *ns;
  const char *source;
  const char *dest;
  const char *json;
};

/* Inbound CastMessage — only the fields this project consumes. */
struct cast_decoded {
  char ns[CAST_NS_MAX];
  char payload[CAST_JSON_CAP];
};

/* Streaming frame reader over a cast_io. */
struct cast_reader {
  struct cast_io *io;
  unsigned char *buf;
  uint32_t frame_len;
  uint32_t len;
  uint32_t alloc;
  int ready;
};

/* LOAD JSON payload parameters. */
struct cast_load {
  long rid;
  const char *session_id;
  const char *content_id;
  const char *content_type;
  const char *stream_type;
};

/* Control-channel session (DOMAIN.md §Transport): CONNECT on the connection
 * namespace, GET_STATUS on the receiver namespace, sessionId from the
 * RECEIVER_STATUS reply, heartbeats on the heartbeat namespace. Runs over a
 * cast_io byte stream (plaintext fd today; TLS-wrapped later). */
struct cast_ctrl {
  struct cast_io io;
  struct cast_reader rd;
  int fd;                       /* transport fd backing io->opaque */
  struct tls_hs *hs;            /* TLS session, or NULL on the plaintext path */
  int transport;                /* CAST_TP_* resolved/latched */
  char source[CAST_NS_MAX];     /* this sender's per-session id */
  char session_id[CAST_JSON_CAP];
  char transport_id[CAST_JSON_CAP];     /* media receiver's per-session channel */
  long rid;                     /* monotonic requestId, starts at 1 */
  uint64_t last_ping_ms;        /* last PING we sent, monotonic ms */
  uint64_t last_pong_ms;        /* last heartbeat seen from the device */
  int state;                    /* CTRL_* below */
  int end_class;                /* CTRL_END_*: terminal verdict classification */
  int media_started;            /* BUFFERING/PLAYING seen since the last LOAD */
};

/* DMR session terminal verdict (DOMAIN.md §Session supervision): NONE until a
 * media-ns MEDIA_STATUS says playerState:IDLE or an {"type":"ERROR"} frame
 * lands for an ESTABLISHED session (BUFFERING/PLAYING seen since the last
 * LOAD — the abort-shaped reply to litecast's own LOAD is the ack, not a
 * death, trace.20). FINISHED = played to completion (idleReason:FINISHED) —
 * the natural end; ABORT = the session died (ERROR frame, or IDLE with any
 * other idleReason) and is eligible for an automatic session restart. */
enum {
  CTRL_END_NONE = 0,
  CTRL_END_FINISHED = 1,
  CTRL_END_ABORT = 2,
};

/* Connection lifecycle state (conn.c). The loop reads it only through the
 * accessors (retry/attach/poll/fd/active/restarting); the internals are
 * conn.c-owned. */
struct cast_conn {
  struct cast_ctrl ctrl;
  struct cast_load load;
  int st;                       /* CONN_* in conn.c */
  unsigned attempt;             /* attempts consumed, 1..CONN_RETRY_MAX */
  unsigned status;              /* GET_STATUS sent once per handshake */
  uint64_t deadline;            /* handshake budget / backoff expiry */
  uint64_t restart_at;          /* session-restart backoff expiry */
  unsigned restarts;            /* session restarts since the last long-lived session */
  int restart;                  /* CONN_WAIT is a session restart, not a transport retry */
  uint64_t attached_ms;         /* monotonic ms of the last healthy attachment */
  int transport;                /* CAST_TP_*, latched across reconnects */
  char source[CAST_NS_MAX];     /* per-session sender id for re-attach */
};

/* A session restart is booked and waiting on its backoff — the media source
 * is expected to be pulled again, so nothing may be drained on the verdict's
 * say-so (DOMAIN.md §Producer behavior). */
static inline int cast_conn_restarting(const struct cast_conn *cn)
{
  return cn != NULL && cn->restart != 0;
}

enum {
  CTRL_TLS = 1,                 /* TLS handshake / transport probe first */
  CTRL_CONNECT = 2,             /* CONNECT to be sent on first step */
  CTRL_STATUS = 3,              /* GET_STATUS sent; awaiting response */
  CTRL_LAUNCH = 5,              /* LAUNCH Default Media Receiver sent; awaiting */
  CTRL_READY = 4,               /* receiver session + media channel established */
};

enum {                          /* heartbeats (DOMAIN.md §Heartbeats) */
  CAST_PING_MS = 10000,         /* send PING every 10s */
  CAST_LOST_MS = 20000,         /* no heartbeat for 20s -> connection lost */
};

/* framing.c */
int cast_io_fd(struct cast_io *io, int *fd);
int cast_reader_init(struct cast_reader *rd, struct cast_io *io);
void cast_reader_close(struct cast_reader *rd);
int cast_pump(struct cast_reader *rd);
int cast_reader_message(const struct cast_reader *rd, const unsigned char **p, size_t *n);
int cast_encode(const struct cast_msg *m, unsigned char *buf, size_t cap);
int cast_decode(const unsigned char *pb, size_t n, struct cast_decoded *d);
int cast_send(struct cast_io *io, const struct cast_msg *m);

/* json.c */
int json_bcast(char *out, size_t cap, const char *type);
int json_get_status(char *out, size_t cap, long rid);
int json_launch(char *out, size_t cap, long rid, const char *app_id);
int json_load(char *out, size_t cap, const struct cast_load *l);
int json_stop(char *out, size_t cap, long rid, const char *session_id);
int cast_json_get(const char *json, const char *key, char *out, size_t cap);

/* ctrl.c */
int cast_ctrl_init(struct cast_ctrl *c, int fd, const char *source, int transport);
void cast_ctrl_close(struct cast_ctrl *c);
int cast_ctrl_now(struct cast_ctrl *c); /* send GET_STATUS, fresh rid */
int cast_ctrl_load(struct cast_ctrl *c, const struct cast_load *l);
int cast_ctrl_stop(struct cast_ctrl *c);        /* STOP the DMR app on exit */
int cast_ctrl_step(struct cast_ctrl *c);        /* 1 msg, 0 block, -1 error */
int cast_ctrl_ready(const struct cast_ctrl *c);
int cast_ctrl_finished(const struct cast_ctrl *c);      /* any terminal verdict */
int cast_ctrl_end(const struct cast_ctrl *c);   /* CTRL_END_* terminal classification */
const char *cast_ctrl_session(const struct cast_ctrl *c);
int cast_ctrl_ping(struct cast_ctrl *c);        /* send PING on heartbeat ns */
uint64_t cast_ctrl_now_ms(void);        /* monotonic time, milliseconds */
int cast_ctrl_alive(const struct cast_ctrl *c, uint64_t now_ms);
int cast_ctrl_send(struct cast_ctrl *c, const char *ns, const char *json);
int cast_ctrl_send_to(struct cast_ctrl *c, const char *ns, const char *dest, const char *json);

/* launch.c — Default Media Receiver session acquisition (DOMAIN.md §Transport) */
int cast_ctrl_status(struct cast_ctrl *c, const struct cast_decoded *d);

/* conn.c */
int cast_conn_init(struct cast_conn *cn, const struct cast_load *load, const char *source);
void cast_conn_close(struct cast_conn *cn);
int cast_conn_attach(struct cast_conn *cn, int fd, uint64_t now_ms);
int cast_conn_poll(struct cast_conn *cn, uint64_t now_ms);
int cast_conn_retry(const struct cast_conn *cn, uint64_t now_ms);
int cast_conn_failed(const struct cast_conn *cn);
int cast_conn_fd(const struct cast_conn *cn);
int cast_conn_active(const struct cast_conn *cn);
int cast_conn_restart(struct cast_conn *cn, uint64_t now_ms);

#endif
