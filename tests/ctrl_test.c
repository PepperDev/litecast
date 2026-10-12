#include "test_util.h"
#include "cast/framing.c"
#include "cast/proto.c"
#include "cast/json.c"
#include "cast/json_get.c"
#include "cast/ctrl.c"
#include "cast/verb.c"
#include "cast/launch.c"

#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Media-namespace status frames shared by the verdict tests. */
#define JFIN    "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"FINISHED\"}]}"
#define JINT    "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"INTERRUPTED\"}]}"
#define JSTOP   "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"USER_STOPPED\"}]}"
#define JCANCEL "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"CANCELLED\"}]}"
#define JERR    "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\",\"idleReason\":\"ERROR\"}]}"
#define JPLAY   "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"PLAYING\"}]}"
#define JBUF    "{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"BUFFERING\"}]}"

static void nb(int fd)
{
  int fl = fcntl(fd, F_GETFL, 0);

  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int read_full(int fd, unsigned char *p, size_t n)
{
  size_t off = 0;
  ssize_t r;

  while (off < n) {
    r = read(fd, p + off, n - off);
    if (r <= 0)
      return -1;
    off += (size_t)r;
  }
  return 0;
}

/* Read one frame off the wire and decode it; raw optionally receives the
 * protobuf bytes for byte-exact checks. */
static int frame_read(int fd, struct cast_decoded *d, unsigned char *raw, size_t cap)
{
  unsigned char hdr[4];
  unsigned char buf[CAST_ENC_CAP];
  size_t n;

  if (read_full(fd, hdr, 4) != 0)
    return -1;
  n = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) | ((size_t)hdr[2] << 8) | hdr[3];
  if (n < 1 || n > sizeof buf || (raw != NULL && n > cap))
    return -1;
  if (read_full(fd, buf, n) != 0)
    return -1;
  if (raw != NULL)
    memcpy(raw, buf, n);
  return cast_decode(buf, n, d);
}

/* Walk the CastMessage fields to recover the `destination_id` (field 3,
 * wire type 2, tag bytes 0x1A). Length-delimited fields are tagged
 * `(1<<3)|2 = 0x10 + field_num`; we only ever emit fields 1..3 here, so
 * scrub forward to the destination tag. */
static int raw_dest(const unsigned char *pb, size_t n, char *out, size_t cap)
{
  size_t i = 0;

  while (i < n) {
    unsigned char tag = pb[i];
    size_t len;

    if (tag == 0x1A) {          /* destination_id */
      i++;
      if (i >= n)
        return -1;
      len = pb[i++];
      if (len >= cap || len > n - i)
        return -1;
      memcpy(out, pb + i, len);
      out[len] = '\0';
      return 0;
    }
    if ((tag & 0x07) == 0) {    /* varint: skip tag + value bytes */
      i++;
      while (i < n && pb[i] & 0x80)
        i++;
      i++;
    } else if ((tag & 0x07) == 2) {     /* length-delimited non-dest: skip */
      i++;
      if (i >= n)
        return -1;
      len = pb[i++];
      i += len;
    } else {
      return -1;                /* unexpected field type before dest */
    }
  }
  return -1;
}

/* The device pushes one complete frame at the ctrl's fd. */
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

/* The record reader surfaces messages incrementally (4-byte prefix, then
 * body), so like the epoll loop the driver keeps stepping while there is
 * data. Terminates on the latch (0) or a protocol error (-1). */
static int ctrl_drive(struct cast_ctrl *c)
{
  int r;
  int i;

  for (i = 0; i < 64; i++) {
    if (cast_ctrl_ready(c))
      return 0;
    r = cast_ctrl_step(c);
    if (r == -1)
      return -1;
  }
  return -1;
}

/* The first step emits CONNECT: connection namespace, correct ids, and the
 * required proto2 fields 0x08 0x00 / 0x28 0x00 (DOMAIN.md §Cast V2). */
static int t_connect(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;
  unsigned char raw[256];
  size_t i;
  int pv = 0;
  int pt = 0;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_ready(&c) == 0);
  EXPECT(cast_ctrl_session(&c) == NULL);

  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT sent */
  EXPECT(frame_read(sv[0], &d, raw, sizeof raw) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_CONNECTION) == 0);
  EXPECT(strcmp(d.payload, "{\"type\":\"CONNECT\"}") == 0);
  for (i = 0; i < 128 && i < sizeof raw; i++) {
    if (raw[i] == 0x08 && raw[i + 1] == 0x00)
      pv = 1;
    if (raw[i] == 0x28 && raw[i + 1] == 0x00)
      pt = 1;
  }
  EXPECT(pv == 1);              /* protocol_version always emitted */
  EXPECT(pt == 1);              /* payload_type always emitted */

  EXPECT(cast_ctrl_step(&c) == 0);      /* no inbound data yet */
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* AUTO begins by probing TLS: the first step sends a ClientHello over the
 * transport and blocks awaiting the peer's first byte. */
static int t_tls_probe(void)
{
  int sv[2];
  struct cast_ctrl c;
  unsigned char raw[32];

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_AUTO) == 0);
  EXPECT(c.transport == CAST_TP_AUTO);
  EXPECT(c.state == CTRL_TLS);
  EXPECT(cast_ctrl_step(&c) == 0);      /* hello queued, awaiting reply */
  EXPECT(read(sv[0], raw, sizeof raw) > 0);
  EXPECT(raw[0] == 0x16);       /* TLS handshake record type */
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* GET_STATUS carries a fresh monotonic requestId on the receiver namespace. */
static int t_status(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"GET_STATUS\"") != NULL);
  EXPECT(strstr(d.payload, "\"requestId\":1") != NULL);

  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strstr(d.payload, "\"requestId\":2") != NULL);

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* RECEIVER_STATUS latches the sessionId (DOMAIN.md §Glossary). */
static int t_session(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"appId\":\"CC1AD845\",\"sessionId\":\"abc123\"}") == 0);
  EXPECT(ctrl_drive(&c) == 0);  /* drained; the latch fired */
  EXPECT(cast_ctrl_ready(&c) == 1);
  EXPECT(strcmp(cast_ctrl_session(&c), "abc123") == 0);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* A RECEIVER_STATUS without a sessionId is a protocol error; a malformed
 * length prefix on the wire is a connection-killing mistake. */
static int t_bad(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  /* An idle device reports RECEIVER_STATUS with no sessionId (no running
   * app). That is not an error: litecast must LAUNCH the Default Media
   * Receiver to create a media session. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0", "{\"type\":\"RECEIVER_STATUS\"}") == 0);
  EXPECT(ctrl_drive(&c) == -1); /* awaits the launch reply, which never comes */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);  /* 2nd read: LAUNCH lifted */
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"LAUNCH\"") != NULL);
  EXPECT(strstr(d.payload, "\"appId\":\"CC1AD845\"") != NULL);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  {
    unsigned char bad[8] = { 0x00, 0x00, 0x00, 0x00, 0x01 };    /* len 0 */

    EXPECT(write(sv[0], bad, sizeof bad) == (ssize_t) sizeof bad);
    EXPECT(ctrl_drive(&c) == -1);
  }
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Full idle-device flow: RECEIVER_STATUS with no sessionId triggers a LAUNCH
 * of the Default Media Receiver; its reply carries sessionId + transportId,
 * which latches READY and routes the media channel (CONNECT + LOAD) to the
 * transport. */
static int t_launch_flow(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;
  unsigned char raw[CAST_ENC_CAP];
  char dest[128];
  struct cast_load l = { 0, "sessL", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);       /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  /* Idle: no sessionId. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0", "{\"type\":\"RECEIVER_STATUS\"}") == 0);
  EXPECT(ctrl_drive(&c) == -1); /* pending the launch reply */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);  /* LAUNCH went out */
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"LAUNCH\"") != NULL);
  EXPECT(strstr(d.payload, "\"appId\":\"CC1AD845\"") != NULL);

  /* Launch reply carries the media session and its transport. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"sessionId\":\"sessL\"," "\"transportId\":\"trL\"}") == 0);
  EXPECT(ctrl_drive(&c) == 0);  /* READY + media CONNECT out */
  EXPECT(cast_ctrl_ready(&c) == 1);
  EXPECT(strcmp(cast_ctrl_session(&c), "sessL") == 0);
  EXPECT(strcmp(c.transport_id, "trL") == 0);

  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);  /* media CONNECT to trL */
  EXPECT(strcmp(d.ns, CAST_NS_CONNECTION) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"CONNECT\"") != NULL);

  EXPECT(cast_ctrl_load(&c, &l) == 1);  /* LOAD directed at the transport */
  {
    unsigned char hdr[4];
    size_t n;
    EXPECT(read_full(sv[0], hdr, 4) == 0);
    n = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16)
        | ((size_t)hdr[2] << 8) | hdr[3];
    EXPECT(n <= sizeof raw);
    EXPECT(read_full(sv[0], raw, n) == 0);
    EXPECT(strcmp(dest, "") == 0 || raw_dest(raw, n, dest, sizeof dest) == 0);
  }

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Receiver errors during launch are fatal; unrelated receiver-ns types are
 * ignored, not fatal. */
static int t_launch_edge(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  /* LAUNCH_ERROR abort the session acquisition. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0", "{\"type\":\"LAUNCH_ERROR\"}") == 0);
  EXPECT(ctrl_drive(&c) == -1);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);

  /* An unrelated receiver-ns type is ignored (non-fatal). */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0", "{\"type\":\"APPLICATION_STATUS\"}") == 0);
  EXPECT(cast_ctrl_step(&c) >= 0);
  EXPECT(cast_ctrl_ready(&c) == 0);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Non-DMR app (e.g. Backdrop) is running: RECEIVER_STATUS with an appId
 * other than CC1AD845 must trigger a LAUNCH, not skip straight to READY. */
static int t_backdrop_bypass(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  /* Backdrop running: has sessionId but wrong appId. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"appId\":\"E8C28D3C\",\"sessionId\":\"sessBD\"}") == 0);
  EXPECT(ctrl_drive(&c) == -1); /* LAUNCH goes out, awaiting reply */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"LAUNCH\"") != NULL);
  EXPECT(strstr(d.payload, "\"appId\":\"CC1AD845\"") != NULL);

  /* Launch reply carries the DMR session. */
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"sessionId\":\"sessDMR\",\"transportId\":\"trDMR\"}") == 0);
  EXPECT(ctrl_drive(&c) == 0);
  EXPECT(cast_ctrl_ready(&c) == 1);
  EXPECT(strcmp(cast_ctrl_session(&c), "sessDMR") == 0);
  EXPECT(strcmp(c.transport_id, "trDMR") == 0);

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Constructor and accessor contracts. */
static int t_api(void)
{
  struct cast_ctrl c;
  char src[CAST_NS_MAX + 8];

  EXPECT(cast_ctrl_init(NULL, -1, "sender-0", CAST_TP_PLAIN) == -1);
  EXPECT(cast_ctrl_init(&c, -1, NULL, CAST_TP_PLAIN) == -1);    /* NULL source */
  EXPECT(cast_ctrl_init(&c, -1, "sender-0", 9999) == -1);       /* invalid transport */
  memset(src, 'x', sizeof src);
  src[sizeof src - 1] = '\0';
  EXPECT(cast_ctrl_init(&c, -1, src, CAST_TP_PLAIN) == -1);
  EXPECT(cast_ctrl_init(&c, -1, "sender-0", CAST_TP_PLAIN) == 0);
  cast_ctrl_close(&c);
  /* load before the session is READY is refused */
  {
    struct cast_load l = { 0, "sid", "http://h/s", "video/mp4", "BUFFERED" };
    int sv[2];

    EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nb(sv[0]);
    nb(sv[1]);
    EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
    EXPECT(cast_ctrl_load(&c, &l) == -1);       /* not READY yet */
    cast_ctrl_close(&c);
    close(sv[0]);
    close(sv[1]);
  }
  EXPECT(cast_ctrl_now(NULL) == -1);
  EXPECT(cast_ctrl_step(NULL) == -1);
  EXPECT(cast_ctrl_ready(NULL) == 0);
  EXPECT(cast_ctrl_session(NULL) == NULL);
  EXPECT(cast_ctrl_ping(NULL) == -1);
  EXPECT(cast_ctrl_alive(NULL, 0) == 0);
  return 0;
}

/* Heartbeats: our PING goes out on the heartbeat namespace, a device PING
 * is answered with PONG, and liveness expires after CAST_LOST_MS. */
static int t_beat(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;
  uint64_t now;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  EXPECT(cast_ctrl_ping(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_HEARTBEAT) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"PING\"") != NULL);
  EXPECT(c.last_ping_ms != 0);

  EXPECT(dev_send(sv[0], CAST_NS_HEARTBEAT, "receiver-0", "sender-0", "{\"type\":\"PING\"}") == 0);
  {
    int i;

    for (i = 0; i < 4 && cast_ctrl_step(&c) != 1; i++) ;
    EXPECT(i < 4);
  }
  EXPECT(cast_ctrl_alive(&c, c.last_pong_ms) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_HEARTBEAT) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"PONG\"") != NULL);

  EXPECT(dev_send(sv[0], CAST_NS_HEARTBEAT, "receiver-0", "sender-0", "{\"type\":\"PONG\"}") == 0);
  {
    int i;

    for (i = 0; i < 4 && cast_ctrl_step(&c) != 1; i++) ;
    EXPECT(i < 4);
  }
  now = cast_ctrl_now_ms();
  EXPECT(cast_ctrl_alive(&c, now) == 1);
  EXPECT(cast_ctrl_alive(&c, now + CAST_LOST_MS + 1) == 0);

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* Read frames off the ctrl even after it is ready: bounded stepping like
 * the epoll loop on EPOLLIN. Returns -1 on the first fatal step. */
static int ctrl_flush(struct cast_ctrl *c)
{
  int r;
  int i;

  for (i = 0; i < 16; i++) {
    r = cast_ctrl_step(c);
    if (r == -1)
      return -1;
  }
  return 0;
}

/* LOAD on the media namespace: fresh requestId, sessionId/contentId inside;
 * LOAD_FAILED is fatal, other media frames are tolerated. */
static int t_load(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;
  struct cast_load l = { 0, "abc123", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"appId\":\"CC1AD845\",\"sessionId\":\"abc123\"}") == 0);
  EXPECT(ctrl_drive(&c) == 0);

  EXPECT(cast_ctrl_load(&c, &l) == 1);  /* rid 2: GET_STATUS took 1 */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_MEDIA) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"LOAD\"") != NULL);
  EXPECT(strstr(d.payload, "\"requestId\":2") != NULL);
  EXPECT(strstr(d.payload, "\"sessionId\":\"abc123\"") != NULL);
  EXPECT(strstr(d.payload, "\"contentId\":\"http://127.0.0.1:8090/stream\"") != NULL);
  EXPECT(strstr(d.payload, "\"streamType\":\"BUFFERED\"") != NULL);

  EXPECT(cast_ctrl_load(&c, NULL) == -1);
  EXPECT(cast_ctrl_load(NULL, &l) == -1);
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", "{\"type\":\"LOADED\"}") == 0);
  EXPECT(ctrl_flush(&c) == 0);  /* tolerated, session intact */
  EXPECT(cast_ctrl_ready(&c) == 1);

  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", "{}") == 0);
  EXPECT(ctrl_flush(&c) == 0);  /* no type: ignored, not fatal */
  EXPECT(cast_ctrl_ready(&c) == 1);

  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"LOAD_FAILED\",\"reason\":\"INVALID_MEDIA\"}") == 0);
  EXPECT(ctrl_flush(&c) == -1);

  EXPECT(strcmp(cast_ctrl_session(&c), "abc123") == 0);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* A RECEIVER_STATUS carrying a media session and its transportId must latch
 * READY and route the media channel: a CONNECT to the transportId, then a
 * LOAD directed at that transport, not at `receiver-0`. */
static int t_media_transport(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;
  unsigned char raw[CAST_ENC_CAP];
  char dest[128];
  struct cast_load l = { 0, "sess99", "http://127.0.0.1:8090/stream",
    "video/mp4", "BUFFERED"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);       /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"appId\":\"CC1AD845\",\"sessionId\":\"sess99\","
                  "\"transportId\":\"tr99\"}") == 0);
  EXPECT(ctrl_drive(&c) == 0);  /* READY + media CONNECT out */
  EXPECT(cast_ctrl_ready(&c) == 1);
  EXPECT(strcmp(cast_ctrl_session(&c), "sess99") == 0);
  EXPECT(strcmp(c.transport_id, "tr99") == 0);

  /* Next outbound frame: CONNECT on the connection ns toward "tr99". */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_CONNECTION) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"CONNECT\"") != NULL);

  /* LOAD must be addressed to the media transport, not the platform id. */
  EXPECT(cast_ctrl_load(&c, &l) == 1);
  {
    unsigned char hdr[4];
    size_t n;
    EXPECT(read_full(sv[0], hdr, 4) == 0);
    n = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16)
        | ((size_t)hdr[2] << 8) | hdr[3];
    EXPECT(n <= sizeof raw);
    EXPECT(read_full(sv[0], raw, n) == 0);
    EXPECT(raw_dest(raw, n, dest, sizeof dest) == 0);
    EXPECT(strcmp(dest, "tr99") == 0);
  }

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* A receiver STOP on exit must go out on the receiver namespace toward the
 * platform id, tagged with the latched sessionId and a fresh requestId
 * (mkchromecast parity: litecast terminating also stops the DMR app). No STOP
 * is emitted before a session is latched. */
static int t_stop(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  /* Not READY yet: STOP must not be sent before a session is latched. */
  EXPECT(cast_ctrl_stop(&c) == 0);

  EXPECT(cast_ctrl_now(&c) == 1);       /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_RECEIVER, "receiver-0", "sender-0",
                  "{\"type\":\"RECEIVER_STATUS\",\"appId\":\"CC1AD845\",\"sessionId\":\"abc123\"}") == 0);
  EXPECT(ctrl_drive(&c) == 0);
  EXPECT(cast_ctrl_ready(&c) == 1);

  EXPECT(cast_ctrl_stop(&c) == 0);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(strcmp(d.ns, CAST_NS_RECEIVER) == 0);
  EXPECT(strstr(d.payload, "\"type\":\"STOP\"") != NULL);
  EXPECT(strstr(d.payload, "\"sessionId\":\"abc123\"") != NULL);
  EXPECT(strstr(d.payload, "\"requestId\":2") != NULL); /* GET_STATUS took 1 */

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* The DMR reports playback via MEDIA_STATUS on the media namespace. A terminal
 * verdict ends the run: playerState:"IDLE" with any idleReason (FINISHED =
 * played to end, USER_STOPPED/ERROR/CANCELLED = stopped early) or an explicit
 * {"type":"ERROR"} frame. PLAYING/BUFFERING must not end the run. */
static int t_finished(void)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);       /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);

  /* Not done while PLAYING. */
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", JPLAY) == 0);
  EXPECT(ctrl_flush(&c) == 0);
  EXPECT(cast_ctrl_finished(&c) == 0);

  /* A FINISHED idleReason with playerState IDLE latches the verdict. */
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", JFIN) == 0);
  EXPECT(ctrl_flush(&c) == 0);
  EXPECT(cast_ctrl_finished(&c) == 1);

  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);

  /* A terminal IDLE with any idleReason latches once the session is
   * established (USER_STOPPED mid-playback, for example). */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", JPLAY) == 0);
  EXPECT(ctrl_flush(&c) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", JSTOP)
         == 0);
  EXPECT(ctrl_flush(&c) == 0);
  EXPECT(cast_ctrl_finished(&c) == 1);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);

  /* An explicit {"type":"ERROR"} frame latches too (the 104 not-exit case),
   * again for an established session. */
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", JPLAY) == 0);
  EXPECT(ctrl_flush(&c) == 0);
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0",
                  "{\"type\":\"ERROR\",\"detailedErrorCode\":104,\"itemId\":1}") == 0);
  EXPECT(ctrl_flush(&c) == 0);
  EXPECT(cast_ctrl_finished(&c) == 1);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* One latched verdict: its CTRL_END_* classification and whether the run layer
 * must treat it as an abandonment (cast_ctrl_abandoned — the session-restart
 * predicate). */
struct verdict {
  int end;
  int abandoned;
};

/* Drive one media-ns verdict through a fresh plain ctrl session and record both
 * verdicts. When established is nonzero a PLAYING status is pushed first,
 * arming the establishment gate (§Session supervision): abort-shaped verdicts
 * only count once the session reached BUFFERING/PLAYING since the last LOAD. */
static int drive_verdict(const char *json, int established, struct verdict *v)
{
  int sv[2];
  struct cast_ctrl c;
  struct cast_decoded d;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  nb(sv[0]);
  nb(sv[1]);
  EXPECT(cast_ctrl_init(&c, sv[1], "sender-0", CAST_TP_PLAIN) == 0);
  EXPECT(cast_ctrl_step(&c) == 1);      /* CONNECT out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  EXPECT(cast_ctrl_now(&c) == 1);       /* GET_STATUS out */
  EXPECT(frame_read(sv[0], &d, NULL, 0) == 0);
  if (established) {
    EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", JPLAY) == 0);
    EXPECT(ctrl_flush(&c) == 0);
  }
  EXPECT(dev_send(sv[0], CAST_NS_MEDIA, "receiver-0", "sender-0", json) == 0);
  EXPECT(ctrl_flush(&c) == 0);
  v->end = cast_ctrl_end(&c);
  v->abandoned = cast_ctrl_abandoned(&c);
  cast_ctrl_close(&c);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

static int verdict_end(const char *json, int established)
{
  struct verdict v;

  EXPECT(drive_verdict(json, established, &v) == 0);
  return v.end;
}

/* Session-supervision classification (§Session supervision): FINISHED =
 * played to completion, ABORT = a death of an ESTABLISHED session (ERROR
 * frame, or IDLE with any other idleReason), NONE = active — or an abort
 * verdict while the session never reached BUFFERING/PLAYING, which is the
 * LOAD acknowledgment (the replaced playback torn down, INTERRUPTED) and is
 * explicitly NOT a death (trace.20). */
static int t_end_class(void)
{
  EXPECT(verdict_end(JFIN, 0) == CTRL_END_FINISHED);
  EXPECT(verdict_end(JFIN, 1) == CTRL_END_FINISHED);
  /* Not established (the LOAD ack — trace.20): the abort-shaped verdicts are
   * NONE, they must never arm a session restart. */
  EXPECT(verdict_end(JINT, 0) == CTRL_END_NONE);
  EXPECT(verdict_end(JSTOP, 0) == CTRL_END_NONE);
  EXPECT(verdict_end(JERR, 0) == CTRL_END_NONE);
  EXPECT(verdict_end("{\"type\":\"ERROR\",\"detailedErrorCode\":104}", 0) == CTRL_END_NONE);
  /* Established: the same verdicts are session deaths. */
  EXPECT(verdict_end(JINT, 1) == CTRL_END_ABORT);
  EXPECT(verdict_end(JSTOP, 1) == CTRL_END_ABORT);
  EXPECT(verdict_end(JCANCEL, 1) == CTRL_END_ABORT);
  EXPECT(verdict_end(JERR, 1) == CTRL_END_ABORT);
  EXPECT(verdict_end("{\"type\":\"ERROR\",\"detailedErrorCode\":104}", 1) == CTRL_END_ABORT);
  /* Not terminal: playing/buffering/idle-without-a-reason never latch. */
  EXPECT(verdict_end(JPLAY, 0) == CTRL_END_NONE);
  EXPECT(verdict_end(JBUF, 0) == CTRL_END_NONE);
  EXPECT(verdict_end("{\"type\":\"MEDIA_STATUS\",\"status\":[{\"playerState\":\"IDLE\"}]}", 0) == CTRL_END_NONE);
  /* A FINISHED frame also reads as cast_ctrl_finished; routine status does not. */
  EXPECT(cast_ctrl_finished(NULL) == 0);
  return 0;
}

/* Abandonment vs natural end (trace.22): a FINISHED from a session that DID play
 * is an abandonment — the DMR gave up on a source the run can still feed, so the
 * restart lane takes it — while the same frame before the session ever played is
 * the LOAD ack, and a routine status is no verdict at all. */
static int t_abandoned(void)
{
  struct verdict v;
  struct cast_ctrl c;

  EXPECT(drive_verdict(JFIN, 1, &v) == 0);
  EXPECT(v.end == CTRL_END_FINISHED && v.abandoned == 1);
  EXPECT(drive_verdict(JFIN, 0, &v) == 0);
  EXPECT(v.end == CTRL_END_FINISHED && v.abandoned == 0);
  EXPECT(drive_verdict(JERR, 1, &v) == 0);
  EXPECT(v.end == CTRL_END_ABORT && v.abandoned == 1);
  EXPECT(drive_verdict(JERR, 0, &v) == 0);
  EXPECT(v.end == CTRL_END_NONE && v.abandoned == 0);
  EXPECT(drive_verdict(JINT, 1, &v) == 0);
  EXPECT(v.end == CTRL_END_ABORT && v.abandoned == 1);
  EXPECT(drive_verdict(JPLAY, 1, &v) == 0);
  EXPECT(v.end == CTRL_END_NONE && v.abandoned == 0);

  /* The predicate reads a latched ctrl directly (no socket). */
  memset(&c, 0, sizeof c);
  EXPECT(cast_ctrl_abandoned(&c) == 0);
  c.end_class = CTRL_END_FINISHED;
  EXPECT(cast_ctrl_abandoned(&c) == 0);
  c.media_started = 1;
  EXPECT(cast_ctrl_abandoned(&c) == 1);
  c.end_class = CTRL_END_ABORT;
  EXPECT(cast_ctrl_abandoned(&c) == 1);
  EXPECT(cast_ctrl_abandoned(NULL) == 0);
  EXPECT(cast_conn_restarting(NULL) == 0);
  return 0;
}

int main(void)
{
  RUN(t_connect);
  RUN(t_status);
  RUN(t_session);
  RUN(t_bad);
  RUN(t_api);
  RUN(t_beat);
  RUN(t_load);
  RUN(t_launch_flow);
  RUN(t_launch_edge);
  RUN(t_backdrop_bypass);
  RUN(t_media_transport);
  RUN(t_stop);
  RUN(t_tls_probe);
  RUN(t_finished);
  RUN(t_end_class);
  RUN(t_abandoned);
  TEST_SUMMARY();
}
