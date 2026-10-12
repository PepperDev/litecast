#include "test_util.h"

#include "cast/framing.c"
#include "cast/proto.c"
#include "cast/json.c"
#include "cast/json_get.c"
#include "cast/ctrl.c"
#include "cast/verb.c"
#include "cast/launch.c"
#include "cast/conn.c"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void nb(int fd)
{
  int fl = fcntl(fd, F_GETFL, 0);

  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static ssize_t read_all(int fd, void *buf, size_t n)
{
  size_t off = 0;

  while (off < n) {
    ssize_t r = read(fd, (char *)buf + off, n - off);

    if (r < 0 && errno == EINTR)
      continue;
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return (ssize_t) off;
}

/* Read and decode one frame the device would have sent us. */
static int frame_read(int fd, struct cast_decoded *d)
{
  unsigned char hdr[4];
  unsigned char *pb;
  uint32_t n;
  int r;

  if (read_all(fd, hdr, sizeof hdr) != 4)
    return -1;
  n = ((uint32_t) hdr[0] << 24) | ((uint32_t) hdr[1] << 16) | ((uint32_t) hdr[2] << 8) | hdr[3];
  if (n == 0 || n > CAST_MAX_FRAME)
    return -1;
  pb = malloc(n);
  if (pb == NULL)
    return -1;
  r = read_all(fd, pb, n) == (ssize_t) n && cast_decode(pb, n, d) == 0 ? 0 : -1;
  free(pb);
  return r;
}

/* The device pushes one complete frame at the conn's fd. */
static int dev_send(int fd, const char *ns, const char *source, const char *dest, const char *json)
{
  struct cast_msg m = { ns, source, dest, json };
  unsigned char wire[CAST_ENC_CAP + 4];
  int n = cast_encode(&m, wire + 4, CAST_ENC_CAP);

  if (n < 1)
    return -1;
  wire[0] = (unsigned char)((unsigned int)n >> 24);
  wire[1] = (unsigned char)((unsigned int)n >> 16);
  wire[2] = (unsigned char)((unsigned int)n >> 8);
  wire[3] = (unsigned char)n;
  return write(fd, wire, (size_t)n + 4) == (ssize_t) n + 4 ? 0 : -1;
}

/* Poll the conn until one complete outbound frame is readable (the nonzero
 * poll advances the handshake, which may split a frame across prefix/body
 * reads), then decode it into d. Returns 0 on success, -1 on budget/error. */
static int poll_frame(struct cast_conn *cn, int dev, uint64_t now, struct cast_decoded *d)
{
  int i;

  for (i = 0; i < 64; i++) {
    int r = cast_conn_poll(cn, now + (uint64_t) i);
    if (r == -1)
      return -1;
    if (frame_read(dev, d) == 0)
      return 0;
  }
  return -1;
}

/* Drive a session up to LOAD; the socketpair peer is the fake device. When
 * lod is non-NULL the LOAD frame the device saw is copied out for checks. */
static int setup(struct cast_conn *cn, int dev, struct cast_decoded *lod)
{
  struct cast_decoded d;

  if (cast_conn_poll(cn, 1000) != 1)    /* CONNECT out */
    return -1;
  if (frame_read(dev, &d) != 0)
    return -1;
  if (cast_conn_poll(cn, 1000) != 1)    /* GET_STATUS out */
    return -1;
  if (frame_read(dev, &d) != 0)
    return -1;
  if (dev_send(dev, CAST_NS_RECEIVER, "receiver-0", "sender-0",
               "{\"type\":\"RECEIVER_STATUS\",\"appId\":\"CC1AD845\",\"sessionId\":\"s\"}") != 0)
    return -1;
  if (cast_conn_poll(cn, 1001) != 0)    /* status: 4-byte prefix */
    return -1;
  if (cast_conn_poll(cn, 1001) != 1)    /* body -> ready -> LOAD */
    return -1;
  if (lod != NULL)
    return frame_read(dev, lod);
  return frame_read(dev, &d);
}

/* Full lifecycle: handshake, LOAD, inbound PING -> PONG, our own PING. */
static int t_lifecycle(void)
{
  int sv[2];
  struct cast_conn cn;
  struct cast_decoded d;
  struct cast_decoded lod;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN; /* the fake peer speaks plaintext legacy */
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);
  cn.ctrl.last_pong_ms = 1000;  /* pin fake time after attach */
  EXPECT(cast_conn_fd(&cn) == sv[1]);
  EXPECT(cast_conn_active(&cn) == 0);

  /* setup latched sessionId "s"; the LOAD must carry it, not the load
   * struct's placeholder "s-42". */
  EXPECT(setup(&cn, sv[0], &lod) == 0);
  EXPECT(cast_conn_active(&cn) == 1);
  EXPECT(strcmp(lod.ns, CAST_NS_MEDIA) == 0);
  EXPECT(strstr(lod.payload, "\"sessionId\":\"s\"") != NULL);
  EXPECT(cast_conn_retry(&cn, 1001) == 0);

  EXPECT(dev_send(sv[0], CAST_NS_HEARTBEAT, "receiver-0", "sender-0", "{\"type\":\"PING\"}") == 0);
  EXPECT(cast_conn_poll(&cn, 1010) == 0);       /* device PING prefix */
  EXPECT(cast_conn_poll(&cn, 1010) == 1);       /* body -> PONG reply */
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_HEARTBEAT) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"PONG\"") != NULL);
  cn.ctrl.last_pong_ms = 1000;  /* beat stamped real clock ms; pin the fake time */

  cn.ctrl.last_ping_ms = 1000;  /* force the 10s PING deadline */
  EXPECT(cast_conn_poll(&cn, 11001) == 1);
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_HEARTBEAT) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"PING\"") != NULL);

  cast_conn_close(&cn);
  EXPECT(cast_conn_fd(&cn) == -1);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Drive polls until one inbound MEDIA_STATUS frame is fully handled (a poll
 * returns 1), so ctrl_media/ctrl_finished ran; the caller then checks the
 * latch. Non-FINISHED verdicts must not latch playback_finished. */
static int media_until(struct cast_conn *cn, uint64_t now)
{
  int i;
  int r;

  for (i = 0; i < 32; i++) {
    r = cast_conn_poll(cn, now);
    if (r == -1)
      return -1;
    if (r == 1)
      return 0;
  }
  return -1;
}

static int t_media_finished(void)
{
  int sv[2];
  struct cast_conn cn;
  struct cast_decoded lod;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN;
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);
  EXPECT(setup(&cn, sv[0], &lod) == 0);
  cn.ctrl.last_ping_ms = 1000;  /* pin fake monotonic time (cf. t_lifecycle) */
  cn.ctrl.last_pong_ms = 1000;

  /* PLAYING: not finished. */
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"PLAYING\"}]}") == 0);
  EXPECT(media_until(&cn, 1010) == 0);
  EXPECT(cast_ctrl_finished(&cn.ctrl) == 0);

  /* IDLE + FINISHED: playback complete. */
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"FINISHED\"}]}") ==
         0);
  EXPECT(media_until(&cn, 1011) == 0);
  EXPECT(cast_ctrl_finished(&cn.ctrl) == 1);

  cast_conn_close(&cn);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Idle device: GET_STATUS yields no sessionId, so litecast LAUNCHes the
 * Default Media Receiver; its reply latches sessionId + transportId, routes
 * the media channel, and LOAD goes to the transport. */
static int t_idle_launch(void)
{
  int sv[2];
  struct cast_conn cn;
  struct cast_decoded d;
  struct cast_decoded lod;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN;
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);

  EXPECT(cast_conn_poll(&cn, 1000) == 1);       /* CONNECT out */
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(cast_conn_poll(&cn, 1000) == 1);       /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d) == 0);

  /* Idle reply: no sessionId -> LAUNCH out. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0", "{\"type\":\"RECEIVER_STATUS\"}") == 0);
  EXPECT(poll_frame(&cn, sv[0], 1001, &d) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"LAUNCH\"") != NULL);
  EXPECT(strstr(d.payload, "\"appId\":\"CC1AD845\"") != NULL);

  /* Launch reply carries the media session + transport. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"sessionId\":\"sL\"," "\"transportId\":\"tL\"}") == 0);
  EXPECT(poll_frame(&cn, sv[0], 1002, &d) == 0);        /* media CONNECT out */
  EXPECT(strcmp(d.ns, CAST_NS_CONNECTION) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"CONNECT\"") != NULL);
  EXPECT(poll_frame(&cn, sv[0], 1003, &lod) == 0);      /* LOAD out */
  EXPECT(strcmp(lod.ns, CAST_NS_MEDIA) == 0);
  EXPECT(strstr(lod.payload, "\"sessionId\":\"sL\"") != NULL);

  cast_conn_close(&cn);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* The AUTO transport probes TLS on first attach: the first poll writes a
 * ClientHello and blocks awaiting the device's reply. */
static int t_tls_probe(void)
{
  int sv[2];
  struct cast_conn cn;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };
  unsigned char raw[32];

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  EXPECT(cn.transport == CAST_TP_AUTO); /* default probes TLS */
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);
  EXPECT(cast_conn_poll(&cn, 1000) == 0);       /* hello queued, awaiting reply */
  EXPECT(read(sv[0], raw, sizeof raw) > 0);     /* consume the hello */
  EXPECT(raw[0] == 0x16);
  cast_conn_close(&cn);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Heartbeat silence schedules a reconnect after the backoff, and the re-
 * attached session gets a fresh handshake + re-LOAD. */
static int t_retry(void)
{
  int sv[2], sv2[2];
  struct cast_conn cn;
  struct cast_decoded d;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN;
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);
  EXPECT(setup(&cn, sv[0], NULL) == 0);

  cn.ctrl.last_pong_ms = 0;     /* 30s of silence, connection lost */
  EXPECT(cast_conn_poll(&cn, 30000) == 0);
  EXPECT(cast_conn_fd(&cn) == -1);      /* lost socket dropped */
  EXPECT(cast_conn_active(&cn) == 0);
  /* A transport loss terminates the latched session on the device before the
   * socket goes (§Exit) — otherwise a budget-exhausted abort leaves it
   * streaming a dead pull. */
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"STOP\"") != NULL);
  EXPECT(strstr(d.payload, "\"sessionId\":\"s\"") != NULL);
  EXPECT(cast_conn_retry(&cn, 30000) == 0);
  EXPECT(cast_conn_retry(&cn, 30999) == 0);
  EXPECT(cast_conn_retry(&cn, 31000) == 1);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
  nb(sv2[0]);
  nb(sv2[1]);
  EXPECT(cast_conn_attach(&cn, sv2[1], 31001) == 0);
  EXPECT(cast_conn_fd(&cn) == sv2[1]);
  EXPECT(setup(&cn, sv2[0], NULL) == 0);

  cast_conn_close(&cn);
  close(sv[0]);
  close(sv2[0]);
  close(sv2[1]);
  return 0;
}

/* Three losses burn the retry budget; the fourth marks the session failed. */
static int t_budget(void)
{
  int sv[2], sv2[2], sv3[2], sv4[2];
  struct cast_conn cn;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN;
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);
  EXPECT(setup(&cn, sv[0], NULL) == 0);

  cn.ctrl.last_pong_ms = 0;     /* silence -> loss 1 */
  EXPECT(cast_conn_poll(&cn, 30000) == 0);
  EXPECT(cast_conn_retry(&cn, 31000) == 1);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
  nb(sv2[0]);
  nb(sv2[1]);
  EXPECT(cast_conn_attach(&cn, sv2[1], 31001) == 0);
  EXPECT(setup(&cn, sv2[0], NULL) == 0);

  cn.ctrl.last_pong_ms = 0;     /* silence -> loss 2 */
  EXPECT(cast_conn_poll(&cn, 40000) == 0);
  EXPECT(cast_conn_retry(&cn, 42000) == 1);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv3) == 0);
  nb(sv3[0]);
  nb(sv3[1]);
  EXPECT(cast_conn_attach(&cn, sv3[1], 42001) == 0);
  EXPECT(setup(&cn, sv3[0], NULL) == 0);

  cn.ctrl.last_pong_ms = 0;     /* silence -> loss 3, budget full */
  EXPECT(cast_conn_poll(&cn, 50000) == 0);
  EXPECT(cast_conn_retry(&cn, 51000) == 0);     /* gap sequence capped at 2s */
  EXPECT(cast_conn_retry(&cn, 52000) == 1);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv4) == 0);
  nb(sv4[0]);
  nb(sv4[1]);
  EXPECT(cast_conn_attach(&cn, sv4[1], 52001) == 0);
  EXPECT(setup(&cn, sv4[0], NULL) == 0);

  cn.ctrl.last_pong_ms = 0;     /* loss 4: no attempts left */
  EXPECT(cast_conn_poll(&cn, 60000) == -1);
  EXPECT(cast_conn_failed(&cn) == 1);
  EXPECT(cast_conn_retry(&cn, 61000) == 0);

  cast_conn_close(&cn);
  close(sv[0]);
  close(sv2[0]);
  close(sv3[0]);
  close(sv4[0]);
  close(sv4[1]);
  return 0;
}

/* A silent device trips the 10s handshake budget and enables a reconnect. */
static int t_handshake_timeout(void)
{
  int sv[2];
  struct cast_conn cn;
  struct cast_decoded d;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN;
  EXPECT(cast_conn_attach(&cn, sv[1], 100) == 0);

  EXPECT(cast_conn_poll(&cn, 200) == 1);        /* CONNECT out */
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(cast_conn_poll(&cn, 300) == 1);        /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(cast_conn_poll(&cn, 10000) == 0);      /* still waiting */
  EXPECT(cast_conn_poll(&cn, 10200) == 0);      /* 10s budget burned */
  EXPECT(cast_conn_fd(&cn) == -1);      /* fd dropped on the wound */
  EXPECT(cast_conn_active(&cn) == 0);
  /* No session was ever latched, so the retire sends no STOP (nothing on the
   * device to terminate). */
  EXPECT(frame_read(sv[0], &d) == -1);
  EXPECT(cast_conn_retry(&cn, 11200) == 1);

  cast_conn_close(&cn);
  close(sv[0]);
  return 0;
}

/* A DMR session that ends abnormally while the source is still live is
 * auto-restarted (§Session supervision): the control socket is retired like a
 * transport loss, the dedicated restart backoff runs (1s, then 2s, ...) — the
 * transport retry budget is untouched — and a fresh attach re-runs the full
 * handshake to a new LOAD. */
static int t_session_restart(void)
{
  int sv[2], sv2[2];
  struct cast_conn cn;
  struct cast_decoded d;
  struct cast_decoded lod;
  struct cast_load load = { 0, "s-42", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_conn_init(&cn, &load, "sender-0") == 0);
  cn.transport = CAST_TP_PLAIN;
  EXPECT(cast_conn_attach(&cn, sv[1], 1000) == 0);
  EXPECT(setup(&cn, sv[0], &lod) == 0);
  cn.ctrl.last_ping_ms = 1000;
  cn.ctrl.last_pong_ms = 1000;
  EXPECT(cast_ctrl_end(&cn.ctrl) == CTRL_END_NONE);
  EXPECT(cast_conn_active(&cn) == 1);

  /* The DMR ack of our own LOAD is IDLE + idleReason INTERRUPTED (the
   * replaced playback torn down) — before the re-loaded session ever reaches
   * BUFFERING/PLAYING it is the ack, NOT a session death, and must not arm a
   * restart (trace.20): the verdict stays NONE and the session stays up. */
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"INTERRUPTED\"}]}")
         == 0);
  EXPECT(media_until(&cn, 1010) == 0);
  EXPECT(cast_ctrl_end(&cn.ctrl) == CTRL_END_NONE);
  EXPECT(cast_ctrl_finished(&cn.ctrl) == 0);
  EXPECT(cast_conn_active(&cn) == 1);

  /* Established (PLAYING seen) — now a terminal type=ERROR frame on the
   * media namespace is a real death. */
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"PLAYING\"}]}") == 0);
  EXPECT(media_until(&cn, 1011) == 0);
  EXPECT(cast_conn_active(&cn) == 1);
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"ERROR\",\"detailedErrorCode\":104}") == 0);
  EXPECT(media_until(&cn, 1012) == 0);
  EXPECT(cast_ctrl_end(&cn.ctrl) == CTRL_END_ABORT);
  EXPECT(cast_ctrl_finished(&cn.ctrl) == 1);

  /* Session restart: socket retired, restart backoff booked (1s), no budget
   * attempt consumed. */
  EXPECT(cast_conn_restart(&cn, 1011) == 0);
  EXPECT(cast_conn_fd(&cn) == -1);
  EXPECT(cast_conn_active(&cn) == 0);
  /* The retired session is terminated on the device first — one receiver STOP
   * with the latched sessionId, on the still-live socket (§Exit): a Ctrl-C that
   * lands in the restart backoff finds the device already idle (trace.23). */
  EXPECT(frame_read(sv[0], &d) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"STOP\"") != NULL);
  EXPECT(strstr(d.payload, "\"sessionId\":\"s\"") != NULL);
  EXPECT(cn.attempt == 0 && cn.restarts == 1 && cn.restart == 1);
  EXPECT(cast_conn_retry(&cn, 1011 + 999) == 0);
  EXPECT(cast_conn_retry(&cn, 1011 + 1000) == 1);
  close(sv[1]);                 /* restart closed the fd; plan the peer only */

  /* Fresh attach: restart lane cleared, handshake re-runs to a new LOAD. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
  nb(sv2[0]);
  nb(sv2[1]);
  EXPECT(cast_conn_attach(&cn, sv2[1], 2012) == 0);
  EXPECT(cn.attempt == 0 && cn.restarts == 1 && cn.restart == 0);
  EXPECT(cast_conn_retry(&cn, 2012) == 0);
  EXPECT(cast_conn_fd(&cn) == sv2[1]);
  EXPECT(setup(&cn, sv2[0], &lod) == 0);
  EXPECT(cast_conn_active(&cn) == 1);
  EXPECT(cast_ctrl_end(&cn.ctrl) == CTRL_END_NONE);     /* fresh ctrl, no verdict */
  cn.ctrl.last_ping_ms = 2000;
  cn.ctrl.last_pong_ms = 2000;

  /* Second abort via IDLE + idleReason ERROR: the escalation grows to 2s
   * (the reattached session is younger than RESTART_RESET_MS); still no
   * transport budget spent (attempt stays 0). The reattached session
   * establishes (PLAYING) before it dies. */
  EXPECT(dev_send(sv2[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"PLAYING\"}]}") == 0);
  EXPECT(media_until(&cn, 3000) == 0);
  EXPECT(dev_send(sv2[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"ERROR\"}]}") == 0);
  EXPECT(media_until(&cn, 3001) == 0);
  EXPECT(cast_ctrl_end(&cn.ctrl) == CTRL_END_ABORT);
  EXPECT(cast_conn_restart(&cn, 3001) == 0);
  EXPECT(frame_read(sv2[0], &d) == 0);  /* retired again, same STOP */
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"STOP\"") != NULL);
  EXPECT(cn.attempt == 0 && cn.restarts == 2 && cn.restart == 1);
  EXPECT(cast_conn_retry(&cn, 3001 + 1999) == 0);
  EXPECT(cast_conn_retry(&cn, 3001 + 2000) == 1);
  close(sv2[1]);

  /* A session that survived past RESTART_RESET_MS re-arms the 1s minimum:
   * back-dated attachment clears the escalation before the next gap. */
  cn.attached_ms = 2000;
  EXPECT(cast_conn_restart(&cn, 62001) == 0);
  EXPECT(cn.restarts == 1 && cn.restart == 1);
  EXPECT(frame_read(sv2[0], &d) == -1); /* already dropped: nothing to send */
  EXPECT(cast_conn_retry(&cn, 62001 + 999) == 0);
  EXPECT(cast_conn_retry(&cn, 62001 + 1000) == 1);

  cast_conn_close(&cn);
  close(sv[0]);
  close(sv2[0]);
  return 0;
}

/* Constructor and accessor contracts. */
static int t_api(void)
{
  struct cast_conn cn;
  struct cast_load load = { 0, "s", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };
  struct cast_ctrl ctrl;
  char src[CAST_NS_MAX + 8];

  EXPECT(cast_conn_init(NULL, &load, "sender-0") == -1);
  EXPECT(cast_conn_init(&cn, NULL, "sender-0") == -1);
  EXPECT(cast_conn_init(&cn, &load, NULL) == -1);
  EXPECT(cast_ctrl_init(&ctrl, -1, NULL, CAST_TP_PLAIN) == -1); /* NULL source */
  memset(src, 'x', sizeof src);
  src[sizeof src - 1] = '\0';
  EXPECT(cast_conn_init(&cn, &load, src) == -1);
  EXPECT(cast_conn_attach(NULL, 0, 1) == -1);
  EXPECT(cast_conn_attach(&cn, -1, 1) == -1);
  EXPECT(cast_conn_poll(NULL, 1) == -1);
  EXPECT(cast_conn_retry(NULL, 1) == 0);
  EXPECT(cast_conn_restart(NULL, 1) == -1);
  EXPECT(cast_conn_failed(NULL) == 0);
  EXPECT(cast_conn_fd(NULL) == -1);
  EXPECT(cast_conn_active(NULL) == 0);
  return 0;
}

int main(void)
{
  RUN(t_lifecycle);
  RUN(t_media_finished);
  RUN(t_idle_launch);
  RUN(t_retry);
  RUN(t_session_restart);
  RUN(t_budget);
  RUN(t_handshake_timeout);
  RUN(t_tls_probe);
  RUN(t_api);
  TEST_SUMMARY();
}
