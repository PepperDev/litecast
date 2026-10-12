#include "test_util.h"
#include "cast/framing.c"
#include "cast/proto.c"
#include "cast/json.c"
#include "cast/json_get.c"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int t_encode_wire(void)
{
  struct cast_msg m = { "n", "a", "b", "{}" };
  const unsigned char exp[] = {
    0x08, 0x00, 0x12, 0x01, 0x61, 0x1a, 0x01, 0x62,
    0x22, 0x01, 0x6e, 0x28, 0x00, 0x32, 0x02, 0x7b, 0x7d
  };
  unsigned char out[128];
  int n;

  n = cast_encode(&m, out, sizeof out);
  EXPECT(n == (int)sizeof exp);
  EXPECT(memcmp(out, exp, sizeof exp) == 0);

  EXPECT(cast_encode(&m, out, 8) == -1);
  EXPECT(cast_encode(&m, out, 0) == -1);
  EXPECT(cast_encode(NULL, out, 128) == -1);
  m.source = NULL;
  EXPECT(cast_encode(&m, out, 128) == -1);
  return 0;
}

static int t_decode_wire(void)
{
  const unsigned char ok[] = {
    0x08, 0x00, 0x12, 0x01, 0x61, 0x1a, 0x01, 0x62,
    0x22, 0x01, 0x6e, 0x28, 0x00, 0x32, 0x02, 0x7b, 0x7d
  };
  const unsigned char unk[] = { 0x3a, 0x01, 0x78 };     /* field 7 string */
  const unsigned char w0[] = { 0x38, 0x7f };    /* field 7 varint */
  const unsigned char w1[] = { 0x39, 1, 2, 3, 4, 5, 6, 7, 8 };  /* 64-bit */
  const unsigned char w5[] = { 0x3d, 1, 2, 3, 4 };      /* 32-bit */
  const unsigned char tr[] = { 0x12, 0x05, 0x61 };      /* truncated */
  const unsigned char bw[] = { 0x0b };  /* group wire type */
  struct cast_decoded d;

  EXPECT(cast_decode(ok, sizeof ok, &d) == 0);
  EXPECT(strcmp(d.ns, "n") == 0);
  EXPECT(strcmp(d.payload, "{}") == 0);

  EXPECT(cast_decode(unk, sizeof unk, &d) == 0);
  EXPECT(d.ns[0] == '\0');
  EXPECT(cast_decode(w0, sizeof w0, &d) == 0);
  EXPECT(cast_decode(w1, sizeof w1, &d) == 0);
  EXPECT(cast_decode(w5, sizeof w5, &d) == 0);

  EXPECT(cast_decode(tr, sizeof tr, &d) == -1);
  EXPECT(cast_decode(bw, sizeof bw, &d) == -1);

  EXPECT(cast_decode(ok, 0, &d) == -1);
  EXPECT(cast_decode(NULL, 1, &d) == -1);

  {
    unsigned char ov[12];
    int i;

    for (i = 0; i < 11; i++)
      ov[i] = 0x80;
    ov[11] = 0x01;
    EXPECT(cast_decode(ov, sizeof ov, &d) == -1);
  }

  {
    unsigned char big[67];

    big[0] = 0x22;              /* field 4, wire 2 (namespace) */
    big[1] = CAST_NS_MAX;       /* one past the null-terminated buffer */
    memset(big + 2, 'x', CAST_NS_MAX);
    EXPECT(cast_decode(big, 2 + CAST_NS_MAX, &d) == -1);
  }

  {
    struct cast_msg m = {
      "urn:x-cast:com.google.cast.receiver", "sender-0", "receiver-0",
      "{\"type\":\"RECEIVER_STATUS\",\"sessionId\":\"abc\"}"
    };
    unsigned char buf[512];
    int n = cast_encode(&m, buf, sizeof buf);

    EXPECT(n > 0);
    EXPECT(cast_decode(buf, (size_t)n, &d) == 0);
    EXPECT(strcmp(d.ns, m.ns) == 0);
    EXPECT(strcmp(d.payload, m.json) == 0);
  }
  return 0;
}

static int read_all(int fd, unsigned char *p, size_t n)
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

static int t_send(void)
{
  int sv[2];
  int fd;
  struct cast_io io;
  struct cast_msg m = {
    CAST_NS_HEARTBEAT, "sender-0", "receiver-0", "{\"type\":\"PING\"}"
  };

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  fd = sv[1];
  EXPECT(cast_io_fd(&io, &fd) == 0);
  EXPECT(cast_io_fd(NULL, &fd) == -1);

  EXPECT(cast_send(&io, &m) == 0);
  {
    unsigned char hdr[4];
    unsigned char buf[512];
    struct cast_decoded d;
    size_t n;

    EXPECT(read_all(sv[0], hdr, 4) == 0);
    n = ((size_t)hdr[0] << 24) | ((size_t)hdr[1] << 16) | ((size_t)hdr[2] << 8) | hdr[3];
    EXPECT(n > 0 && n < sizeof buf);
    EXPECT(read_all(sv[0], buf, n) == 0);
    EXPECT(cast_decode(buf, n, &d) == 0);
    EXPECT(strcmp(d.ns, CAST_NS_HEARTBEAT) == 0);
    EXPECT(strstr(d.payload, "PING") != NULL);
  }
  close(sv[0]);
  close(sv[1]);
  return 0;
}

static int t_reader(void)
{
  int sv[2];
  int fd;
  struct cast_io io;
  struct cast_reader rd;
  const unsigned char *p;
  size_t n;
  int flags;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  flags = fcntl(sv[0], F_GETFL, 0);
  EXPECT(fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) == 0);
  fd = sv[0];
  EXPECT(cast_io_fd(&io, &fd) == 0);
  EXPECT(cast_reader_init(NULL, &io) == -1);
  EXPECT(cast_reader_init(&rd, &io) == 0);

  EXPECT(cast_pump(&rd) == 0);  /* nothing available: would-block */

  EXPECT(send(sv[1], "\x00\x00", 2, 0) == 2);
  EXPECT(cast_pump(&rd) == 0);  /* prefix partial */
  EXPECT(send(sv[1], "\x00\x03", 2, 0) == 2);
  EXPECT(cast_pump(&rd) == 0);  /* prefix complete, payload pending */
  EXPECT(send(sv[1], "AB", 2, 0) == 2);
  EXPECT(cast_pump(&rd) == 0);
  EXPECT(send(sv[1], "C", 1, 0) == 1);
  EXPECT(cast_pump(&rd) == 1);  /* full frame available */

  EXPECT(cast_reader_message(&rd, &p, &n) == 0);
  EXPECT(n == 3);
  EXPECT(memcmp(p, "ABC", 3) == 0);
  EXPECT(cast_reader_message(NULL, &p, &n) == -1);

  EXPECT(cast_pump(&rd) == 0);  /* next frame: nothing yet */

  close(sv[1]);
  EXPECT(cast_pump(&rd) == -1); /* peer closed: EOF is fatal */
  cast_reader_close(&rd);
  close(sv[0]);
  return 0;
}

static int t_reader_badlen(void)
{
  int sv[2];
  int fd;
  struct cast_io io;
  struct cast_reader rd;

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  fd = sv[0];
  EXPECT(cast_io_fd(&io, &fd) == 0);

  EXPECT(cast_reader_init(&rd, &io) == 0);
  EXPECT(send(sv[1], "\x00\x00\x00\x00", 4, 0) == 4);   /* N = 0 */
  EXPECT(cast_pump(&rd) == 0);
  EXPECT(cast_pump(&rd) == -1);
  cast_reader_close(&rd);

  EXPECT(cast_reader_init(&rd, &io) == 0);
  EXPECT(send(sv[1], "\x00\x02\x00\x01", 4, 0) == 4);   /* N = 131073 > max */
  EXPECT(cast_pump(&rd) == 0);
  EXPECT(cast_pump(&rd) == -1);
  cast_reader_close(&rd);

  close(sv[0]);
  close(sv[1]);
  return 0;
}

static int t_reader_big(void)
{
  unsigned char *msg;
  int sv[2];
  int fd;
  struct cast_io io;
  struct cast_reader rd;
  const unsigned char *p;
  size_t n;
  size_t i;

  msg = malloc(CAST_MAX_FRAME);
  EXPECT(msg != NULL);
  for (i = 0; i < CAST_MAX_FRAME; i++)
    msg[i] = (unsigned char)(i & 0xff);

  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  fd = sv[0];
  EXPECT(cast_io_fd(&io, &fd) == 0);
  EXPECT(cast_reader_init(&rd, &io) == 0);

  {
    unsigned char hdr[4] = {
      (unsigned char)(CAST_MAX_FRAME >> 24), (unsigned char)(CAST_MAX_FRAME >> 16),
      (unsigned char)(CAST_MAX_FRAME >> 8), (unsigned char)CAST_MAX_FRAME
    };

    EXPECT(send(sv[1], hdr, 4, 0) == 4);
    EXPECT(send(sv[1], msg, CAST_MAX_FRAME, 0) == CAST_MAX_FRAME);
  }
  while (cast_pump(&rd) != 1) {
  }
  EXPECT(cast_reader_message(&rd, &p, &n) == 0);
  EXPECT(n == CAST_MAX_FRAME);
  EXPECT(memcmp(p, msg, CAST_MAX_FRAME) == 0);

  cast_reader_close(&rd);
  close(sv[0]);
  close(sv[1]);
  free(msg);
  return 0;
}

static int t_json(void)
{
  struct cast_load l = {
    3, "sess", "http://x/stream", "video/mp4", "BUFFERED"
  };
  const char *rs =
      "{\"type\":\"RECEIVER_STATUS\",\"requestId\":1,\"status\":{" "\"applications\":[{\"sessionId\":\"abc123\"}]}}";
  char out[256];
  char got[64];

  EXPECT(json_bcast(out, sizeof out, "PING") > 0);
  EXPECT(strcmp(out, "{\"type\":\"PING\"}") == 0);
  EXPECT(json_bcast(out, 8, "PING") == -1);
  EXPECT(json_bcast(out, sizeof out, NULL) == -1);

  EXPECT(json_get_status(out, sizeof out, 7) > 0);
  EXPECT(strcmp(out, "{\"type\":\"GET_STATUS\",\"requestId\":7}") == 0);

  EXPECT(json_launch(out, sizeof out, 9, "CC1AD845") > 0);
  EXPECT(strcmp(out, "{\"type\":\"LAUNCH\",\"requestId\":9,\"appId\":\"CC1AD845\"}") == 0);
  EXPECT(json_launch(out, sizeof out, 9, NULL) == -1);

  EXPECT(json_stop(out, sizeof out, 11, "sess") > 0);
  EXPECT(strcmp(out, "{\"type\":\"STOP\",\"requestId\":11,\"sessionId\":\"sess\"}") == 0);
  EXPECT(json_stop(out, sizeof out, 11, NULL) > 0);
  EXPECT(strcmp(out, "{\"type\":\"STOP\",\"requestId\":11,\"sessionId\":\"\"}") == 0);
  EXPECT(json_stop(NULL, sizeof out, 11, "sess") == -1);

  EXPECT(json_load(out, sizeof out, &l) > 0);
  EXPECT(strcmp(out, "{\"requestId\":3,\"type\":\"LOAD\",\"sessionId\":\"sess\","
                "\"media\":{\"contentId\":\"http://x/stream\",\"contentType\":\"video/mp4\","
                "\"streamType\":\"BUFFERED\"},\"autoplay\":true}")
         == 0);
  EXPECT(json_load(out, 8, &l) == -1);
  EXPECT(json_load(out, sizeof out, NULL) == -1);

  l.content_id = "a\\b\"c";
  EXPECT(json_load(out, sizeof out, &l) > 0);
  EXPECT(strstr(out, "a\\\\b\\\"c") != NULL);

  EXPECT(cast_json_get(rs, "sessionId", got, sizeof got) == 0);
  EXPECT(strcmp(got, "abc123") == 0);
  EXPECT(cast_json_get(rs, "type", got, sizeof got) == 0);
  EXPECT(strcmp(got, "RECEIVER_STATUS") == 0);
  EXPECT(cast_json_get(rs, "missing", got, sizeof got) == -1);
  EXPECT(cast_json_get(rs, "sessionId", got, 4) == 0);
  EXPECT(strlen(got) <= 3);

  {
    const char *esc = "{\"sessionId\":\"a\\\"b\"}";

    EXPECT(cast_json_get(esc, "sessionId", got, sizeof got) == 0);
    EXPECT(strcmp(got, "a\"b") == 0);
  }

  EXPECT(cast_json_get("{\"sessionId\":\"abc", "sessionId", got, sizeof got)
         == -1);
  EXPECT(cast_json_get("{\"sessionId\" }", "sessionId", got, sizeof got) == -1);
  EXPECT(cast_json_get("", "sessionId", got, sizeof got) == -1);
  EXPECT(cast_json_get("{}", "x", NULL, 8) == -1);
  return 0;
}

int main(void)
{
  RUN(t_encode_wire);
  RUN(t_decode_wire);
  RUN(t_send);
  RUN(t_reader);
  RUN(t_reader_badlen);
  RUN(t_reader_big);
  RUN(t_json);
  TEST_SUMMARY();
}
