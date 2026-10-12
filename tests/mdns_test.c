#include "test_util.h"
#include "net/mdns.c"
#include "net/mdns_name.c"
#include "net/mdns_sel.c"
#include "net/mdns_browse.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef unsigned char u8in;

static size_t q_name(u8in *p, size_t off, const char *name)
{
  const char *s = name;

  while (*s != '\0') {
    const char *e = strchr(s, '.');
    size_t l = e ? (size_t)(e - s) : strlen(s);

    p[off++] = (u8in) l;
    memcpy(p + off, s, l);
    off += l;
    s = e ? e + 1 : s + l;
    if (e == NULL)
      break;
  }
  p[off++] = 0;
  return off;
}

static void put_u16(u8in *p, size_t off, unsigned int v)
{
  p[off] = (u8in) (v >> 8);
  p[off + 1] = (u8in) v;
}

static void hdr(u8in *p, unsigned int qd, unsigned int an)
{
  memset(p, 0, 12);
  put_u16(p, 4, qd);
  put_u16(p, 6, an);
}

/* Write a record header at *o and leave *o pointing at the start of the
 * rdata. Caller fills rdata then advances *o itself. */
static u8in *rec_hdr(u8in *p, size_t *o, unsigned int type, unsigned int cls, size_t rdlen)
{
  u8in *rd;

  put_u16(p, *o, type);
  *o += 2;
  put_u16(p, *o, cls);
  *o += 2;
  put_u16(p, *o, 120);
  *o += 4;
  put_u16(p, *o, (unsigned int)rdlen);
  *o += 2;
  rd = p + *o;
  return rd;
}

static int t_parse_valid(void)
{
  u8in pkt[512];
  struct mdns_device dev[MDNS_MAX_DEVICES];
  u8in *rd;
  size_t o;
  int count = 0;
  int i;

  hdr(pkt, 1, 4);
  o = q_name(pkt, 12, "_googlecast._tcp.local");
  put_u16(pkt, o, 0x000c);
  put_u16(pkt, o + 2, 0x0001);
  o += 4;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x0C;
  rd = rec_hdr(pkt, &o, 12, 1, 9);
  rd[0] = 6;
  memcpy(rd + 1, "tv-abc", 6);
  rd[7] = 0xC0;
  rd[8] = 0x0C;
  o += 9;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x34;
  rd = rec_hdr(pkt, &o, 33, 1, 8);
  put_u16(rd, 0, 0);
  put_u16(rd, 2, 0);
  put_u16(rd, 4, 8009);
  rd[6] = 0xC0;
  rd[7] = 0x34;
  o += 8;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x34;
  rd = rec_hdr(pkt, &o, 16, 1, 52);
  rd[0] = 16;
  memcpy(rd + 1, "fn=Friendly Room", 16);
  rd[17] = 9;
  memcpy(rd + 18, "id=abc123", 9);
  rd[27] = 13;
  memcpy(rd + 28, "md=Chromecast", 13);
  rd[41] = 10;
  memcpy(rd + 42, "rs=Netflix", 10);
  o += 52;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x34;
  rd = rec_hdr(pkt, &o, 1, 1, 4);
  rd[0] = 0xC0;
  rd[1] = 0xA8;
  rd[2] = 0x00;
  rd[3] = 0x14;
  o += 4;

  EXPECT(mdns_parse(pkt, o, dev, MDNS_MAX_DEVICES, &count) == 0);
  EXPECT(count == 1);
  EXPECT(strcmp(dev[0].name, "Friendly Room") == 0);
  EXPECT(strcmp(dev[0].uuid, "abc123") == 0);
  EXPECT(strcmp(dev[0].model, "Chromecast") == 0);
  EXPECT(strcmp(dev[0].app, "Netflix") == 0);
  EXPECT(strcmp(dev[0].host, "tv-abc._googlecast._tcp.local.") == 0);
  EXPECT(dev[0].port == 8009);
  for (i = 0; i < 4; i++) {
    static const unsigned char expect[4] = { 0xC0, 0xA8, 0x00, 0x14 };

    EXPECT(((const unsigned char *)&dev[0].ip)[i] == expect[i]);
  }
  return 0;
}

static void put_ptr_target(const char *label, size_t len, u8in *rd)
{
  rd[0] = (u8in) len;
  memcpy(rd + 1, label, len);
  rd[len + 1] = 0xC0;
  rd[len + 2] = 0x0C;
}

static int t_parse_dedup(void)
{
  u8in pkt[128];
  struct mdns_device dev[8];
  u8in *rd;
  size_t o;
  int count = 0;

  hdr(pkt, 1, 2);
  o = q_name(pkt, 12, "_googlecast._tcp.local");
  put_u16(pkt, o, 0x000c);
  put_u16(pkt, o + 2, 0x0001);
  o += 4;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x0C;
  rd = rec_hdr(pkt, &o, 12, 1, 5);
  put_ptr_target("aa", 2, rd);
  o = (size_t)(rd - pkt) + 5;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x0C;
  rd = rec_hdr(pkt, &o, 12, 1, 5);
  put_ptr_target("aa", 2, rd);
  o = (size_t)(rd - pkt) + 5;

  EXPECT(mdns_parse(pkt, o, dev, 8, &count) == 0);
  EXPECT(count == 1);
  return 0;
}

static int t_parse_maxdev(void)
{
  u8in pkt[192];
  struct mdns_device dev[2];
  u8in *rd;
  size_t o;
  int count = 0;
  int i;
  static const char *const targets[3] = { "cc", "dd", "ee" };

  hdr(pkt, 1, 3);
  o = q_name(pkt, 12, "_googlecast._tcp.local");
  put_u16(pkt, o, 0x000c);
  put_u16(pkt, o + 2, 0x0001);
  o += 4;
  for (i = 0; i < 3; i++) {
    pkt[o++] = 0xC0;
    pkt[o++] = 0x0C;
    rd = rec_hdr(pkt, &o, 12, 1, 5);
    put_ptr_target(targets[i], 2, rd);
    o = (size_t)(rd - pkt) + 5;
  }

  EXPECT(mdns_parse(pkt, o, dev, 2, &count) == 0);
  EXPECT(count == 2);
  return 0;
}

static int t_parse_bad(void)
{
  struct mdns_device dev[8];
  u8in pkt[64];
  int count;

  EXPECT(mdns_parse(NULL, 12, dev, 8, &count) == -1);
  EXPECT(mdns_parse((const u8in *)"abcde", 5, dev, 8, &count) == -1);

  memset(pkt, 0, sizeof(pkt));
  pkt[7] = 1;
  pkt[12] = 0xC0;
  pkt[13] = 0x0C;
  count = 0;
  EXPECT(mdns_parse(pkt, 14, dev, 8, &count) == 0);
  EXPECT(count == 0);

  hdr(pkt, 0, 1);
  pkt[12] = 0x50;
  pkt[13] = 'a';
  count = 0;
  EXPECT(mdns_parse(pkt, 20, dev, 8, &count) == 0);
  EXPECT(count == 0);

  hdr(pkt, 0, 1);
  pkt[12] = 0;
  put_u16(pkt, 13, 12);
  put_u16(pkt, 15, 1);
  put_u16(pkt, 17, 120);
  put_u16(pkt, 21, 0xFFFF);
  count = 0;
  EXPECT(mdns_parse(pkt, 23, dev, 8, &count) == 0);
  EXPECT(count == 0);

  hdr(pkt, 1, 0);
  count = 0;
  EXPECT(mdns_parse(pkt, 12, dev, 8, &count) == 0);
  EXPECT(count == 0);

  hdr(pkt, 0, 1);
  pkt[12] = 0x02;
  pkt[13] = 't';
  pkt[14] = 'v';
  pkt[15] = 0x00;
  count = 0;
  EXPECT(mdns_parse(pkt, 17, dev, 8, &count) == 0);
  EXPECT(count == 0);

  hdr(pkt, 0, 1);
  pkt[12] = 0xC0;
  count = 0;
  EXPECT(mdns_parse(pkt, 13, dev, 8, &count) == 0);
  EXPECT(count == 0);

  hdr(pkt, 0, 1);
  pkt[12] = 3;
  pkt[13] = 'x';
  pkt[14] = 'y';
  pkt[15] = 'z';
  pkt[16] = 0xC0;
  pkt[17] = 0x0C;
  count = 0;
  EXPECT(mdns_parse(pkt, 18, dev, 8, &count) == 0);
  EXPECT(count == 0);
  return 0;
}

static int t_parse_unrelated(void)
{
  u8in pkt[256];
  struct mdns_device dev[8];
  u8in *rd;
  size_t o;
  int count = 0;

  hdr(pkt, 1, 3);
  o = q_name(pkt, 12, "_googlecast._tcp.local");
  put_u16(pkt, o, 0x000c);
  put_u16(pkt, o + 2, 0x0001);
  o += 4;
  o = q_name(pkt, o, "other-site.site");
  rd = rec_hdr(pkt, &o, 1, 1, 4);
  rd[0] = 10;
  rd[1] = 0;
  rd[2] = 0;
  rd[3] = 1;
  o = (size_t)(rd - pkt) + 4;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x0C;
  rd = rec_hdr(pkt, &o, 99, 1, 3);
  rd[0] = 1;
  rd[1] = 2;
  rd[2] = 3;
  o = (size_t)(rd - pkt) + 3;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x0C;
  rd = rec_hdr(pkt, &o, 12, 1, 5);
  put_ptr_target("aa", 2, rd);
  o = (size_t)(rd - pkt) + 5;

  EXPECT(mdns_parse(pkt, o, dev, 8, &count) == 0);
  EXPECT(count == 1);
  EXPECT(strcmp(dev[0].host, "aa._googlecast._tcp.local.") == 0);
  return 0;
}

/* A real Chromecast owns the A record with the SRV *target* hostname
 * (`<uuid>.local.`), not the service instance name. The SRV/TXT records are
 * owned by the instance; the A record is owned by the SRV target. Without
 * capturing the SRV target and matching the A owner against it, the IP is
 * dropped and the device is never given an address (connect to 0.0.0.0). */
static int t_srv_target_amp(void)
{
  u8in pkt[256];
  struct mdns_device dev[8];
  u8in *rd;
  size_t o;
  size_t inst_off;
  u8in tname[16];
  size_t tlen;
  int count = 0;
  int i;
  static const char srv_target[] = "mycast.local.";

  /* Byte length of the SRV target name, computed off the packet. */
  tlen = q_name(tname, 0, srv_target);

  hdr(pkt, 0, 3);
  o = 12;
  /* PTR answer: owner = the service name spelled at offset 12 (as a real
   * device does), rdata = "tv-1" + C0 0C. The instance label lands at the
   * rdata start (offset 0x2e), so instance-owned records point at it. */
  o = q_name(pkt, o, "_googlecast._tcp.local.");
  rd = rec_hdr(pkt, &o, 12, 1, 7);
  inst_off = (size_t)(rd - pkt);
  rd[0] = 4;
  memcpy(rd + 1, "tv-1", 4);
  rd[5] = 0xC0;
  rd[6] = 0x0C;
  o += 7;
  /* SRV: owner = instance (C0 inst_off), rdata = prio0 weight0 port8009
   * target `mycast.local.` spelled explicitly. */
  pkt[o++] = 0xC0;
  pkt[o++] = (u8in) inst_off;
  rd = rec_hdr(pkt, &o, 33, 0x8001, (unsigned int)(6 + tlen));
  put_u16(rd, 0, 0);
  put_u16(rd, 2, 0);
  put_u16(rd, 4, 8009);
  q_name(pkt, (size_t)(rd - pkt) + 6, srv_target);
  o += 6 + tlen;
  /* A record: owner = the SRV target `mycast.local.` (not the instance),
   * CACHE_FLUSH class, ip .20. */
  o = q_name(pkt, o, srv_target);
  rd = rec_hdr(pkt, &o, 1, 0x8001, 4);
  rd[0] = 0xC0;
  rd[1] = 0xA8;
  rd[2] = 0x00;
  rd[3] = 0x14;
  o += 4;

  EXPECT(mdns_parse(pkt, o, dev, 8, &count) == 0);
  EXPECT(count == 1);
  EXPECT(strcmp(dev[0].host, "tv-1._googlecast._tcp.local.") == 0);
  EXPECT(strcmp(dev[0].srv_host, srv_target) == 0);
  EXPECT(dev[0].port == 8009);
  for (i = 0; i < 4; i++) {
    static const unsigned char expect[4] = { 0xC0, 0xA8, 0x00, 0x14 };

    EXPECT(((const unsigned char *)&dev[0].ip)[i] == expect[i]);
  }
  return 0;
}

/* A live device announces with CACHE_FLUSH set (class 0x8001) on the
 * additional-section records that carry the ip and port. The CLASS mask
 * must accept these: dropping them leaves ip=0.0.0.0 and the connect goes
 * to loopback. */
static int t_parse_cache_flush(void)
{
  u8in pkt[256];
  struct mdns_device dev[8];
  u8in *rd;
  size_t o;
  int count = 0;
  int i;

  hdr(pkt, 1, 3);
  o = q_name(pkt, 12, "_googlecast._tcp.local");
  put_u16(pkt, o, 0x000c);
  put_u16(pkt, o + 2, 0x0001);
  o += 4;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x0C;
  rd = rec_hdr(pkt, &o, 12, 1, 7);
  rd[0] = 4;
  memcpy(rd + 1, "tv-1", 4);
  rd[5] = 0xC0;
  rd[6] = 0x0C;
  o += 7;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x34;
  rd = rec_hdr(pkt, &o, 1, 0x8001, 4);
  rd[0] = 0xC0;
  rd[1] = 0xA8;
  rd[2] = 0x00;
  rd[3] = 0x15;
  o += 4;
  pkt[o++] = 0xC0;
  pkt[o++] = 0x34;
  rd = rec_hdr(pkt, &o, 33, 0x8001, 8);
  put_u16(rd, 0, 0);
  put_u16(rd, 2, 0);
  put_u16(rd, 4, 18719);
  rd[6] = 0xC0;
  rd[7] = 0x1C;
  o += 8;

  EXPECT(mdns_parse(pkt, o, dev, 8, &count) == 0);
  EXPECT(count == 1);
  EXPECT(strcmp(dev[0].host, "tv-1._googlecast._tcp.local.") == 0);
  EXPECT(dev[0].port == 8009);
  for (i = 0; i < 4; i++) {
    static const unsigned char expect[4] = { 0xC0, 0xA8, 0x00, 0x15 };

    EXPECT(((const unsigned char *)&dev[0].ip)[i] == expect[i]);
  }
  return 0;
}

static int t_internals(void)
{
  u8in tiny[8] = { 4, 't', 'e', 's', 't', 0 };
  u8in bad[3] = { 70, 'a', 0 };
  u8in pkt[64];
  char out[2] = { 0 };
  struct mdns_name_acc acc;
  size_t next;
  struct mdns_device dev[8];
  int count = 0;

  acc.buf = out;
  acc.cap = sizeof out;
  acc.len = 0;
  EXPECT(mdns_name(tiny, 6, 0, &acc, &next) == 0);
  EXPECT(next == 6);
  EXPECT(out[0] == '\0');

  acc.buf = out;
  acc.cap = sizeof out;
  acc.len = 0;
  EXPECT(mdns_name(bad, 3, 0, &acc, &next) == -1);

  hdr(pkt, 0, 1);
  pkt[12] = 0xC0;
  EXPECT(mdns_parse(pkt, 13, dev, 8, &count) == 0);
  EXPECT(count == 0);
  return 0;
}

static int t_select(void)
{
  struct mdns_device dev[3];

  memset(dev, 0, sizeof(dev));
  strcpy(dev[0].name, "Living Room");
  strcpy(dev[1].name, "Kitchen TV");
  strcpy(dev[2].name, "Bedroom");

  EXPECT(mdns_glob("living*", "Living Room") == 1);
  EXPECT(mdns_glob("*room", "Living Room") == 1);
  EXPECT(mdns_glob("Kitchen*", "Kitchen TV") == 1);
  EXPECT(mdns_glob("x*", "Living Room") == 0);
  EXPECT(mdns_glob(NULL, "anything") == 1);
  EXPECT(mdns_glob("", "anything") == 1);

  EXPECT(mdns_contains("ROOM", "living room") == 1);
  EXPECT(mdns_contains("orom", "living room") == 0);

  EXPECT(mdns_first(dev, 3, NULL) == 0);
  EXPECT(mdns_first(dev, 3, "living*") == 0);
  EXPECT(mdns_first(dev, 3, "bed*") == 2);
  EXPECT(mdns_first(dev, 3, "z*") == -1);
  EXPECT(mdns_first(dev, 0, "") == -1);

  EXPECT(mdns_select(dev, 3, "bed*") == 2);
  EXPECT(mdns_select(dev, 3, "kitche*") == 1);
  EXPECT(mdns_select(dev, 3, "itch") == 1);
  EXPECT(mdns_select(dev, 3, "zzz-gone") == 0);
  EXPECT(mdns_select(dev, 3, NULL) == 0);
  EXPECT(mdns_select(dev, 0, NULL) == -1);
  return 0;
}

static int t_socket(void)
{
  struct mdns_device dev[MDNS_MAX_DEVICES];
  u8in pkt[64];
  int sv[2];
  int fd;
  int r;
  int count = 0;

  hdr(pkt, 0, 0);
  EXPECT(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0);
  write(sv[0], pkt, 12);
  EXPECT(mdns_recv(sv[1], dev, MDNS_MAX_DEVICES, &count) == 0);
  EXPECT(count == 0);
  close(sv[0]);
  close(sv[1]);

  EXPECT(mdns_socket("999.999.1.1") == -1);
  EXPECT(sizeof BROWSE_QUERY == 73);
  EXPECT(BROWSE_QUERY[5] == 2);
  fd = mdns_socket("127.0.0.1");
  if (fd < 0)
    return 0;
  EXPECT(mdns_browse(fd) == 0);
  r = mdns_recv(fd, dev, MDNS_MAX_DEVICES, &count);
  EXPECT(r == 0 || r == -1);
  close(fd);
  return 0;
}

static int t_discover(void)
{
  struct mdns_device dev[MDNS_MAX_DEVICES];
  int r;

  EXPECT(mdns_discover_ms(NULL, NULL, NULL, 0, 20) == -1);
  EXPECT(mdns_discover_ms(NULL, NULL, dev, MDNS_MAX_DEVICES, -1) == -1);
  r = mdns_discover_ms(NULL, "zzz-no-matching-device", dev, MDNS_MAX_DEVICES, 40);
  EXPECT(r >= -1 && r < MDNS_MAX_DEVICES);
  r = mdns_discover_ms("255.255.255.255", "zzz-no-matching-device", dev, MDNS_MAX_DEVICES, 40);
  EXPECT(r >= -1 && r < MDNS_MAX_DEVICES);
  return 0;
}

int main(void)
{
  RUN(t_parse_valid);
  RUN(t_parse_dedup);
  RUN(t_parse_maxdev);
  RUN(t_parse_bad);
  RUN(t_parse_unrelated);
  RUN(t_srv_target_amp);
  RUN(t_parse_cache_flush);
  RUN(t_internals);
  RUN(t_select);
  RUN(t_socket);
  RUN(t_discover);
  TEST_SUMMARY();
}
