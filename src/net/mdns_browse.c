#include "net/mdns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

typedef unsigned char w8;

/* Wire-format mDNS browse for _googlecast._tcp.local: 12-byte header (QD=2)
 * plus two questions — the direct PTR and the DNS-SD `_sub.` subtype
 * wildcard — both (QNAME, QTYPE=0x000c PTR, QCLASS=0x0001 IN). */
static const w8 BROWSE_QUERY[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x0b, '_', 'g', 'o', 'o', 'g', 'l', 'e',
  'c', 'a', 's', 't',
  0x04, '_', 't', 'c', 'p',
  0x05, 'l', 'o', 'c', 'a', 'l',
  0x00, 0x00, 0x0c, 0x00, 0x01,
  0x04, '_', 's', 'u', 'b',
  0x0b, '_', 'g', 'o', 'o', 'g', 'l',
  'e', 'c', 'a', 's', 't',
  0x04, '_', 't', 'c', 'p',
  0x05, 'l', 'o', 'c', 'a', 'l',
  0x00, 0x00, 0x0c, 0x00, 0x01
};

/* Discovery window state threaded through the listen loop. */
struct dscan {
  struct mdns_device *devices;
  int maxdev;
  int count;
  int chosen;
};

static int sock_bind(int fd)
{
  struct sockaddr_in sa;
  int one = 1;

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
    return -1;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(MDNS_PORT);
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
    return -1;
  return 0;
}

static int sock_join(int fd, const char *local_addr)
{
  struct ip_mreq mreq;

  memset(&mreq, 0, sizeof(mreq));
  if (inet_pton(AF_INET, MDNS_GROUP, &mreq.imr_multiaddr) != 1)
    return -1;
  if (local_addr == NULL)
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  else if (inet_pton(AF_INET, local_addr, &mreq.imr_interface) != 1)
    return -1;
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0)
    return -1;
  return 0;
}

int mdns_socket(const char *local_addr)
{
  int fd;

  fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0)
    return -1;
  if (sock_bind(fd) != 0)
    goto fail;
  if (sock_join(fd, local_addr) != 0)
    goto fail;
  return fd;
 fail:
  close(fd);
  return -1;
}

int mdns_browse(int fd)
{
  struct sockaddr_in dst;

  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(MDNS_PORT);
  if (inet_pton(AF_INET, MDNS_GROUP, &dst.sin_addr) != 1)
    return -1;
  if (sendto(fd, BROWSE_QUERY, sizeof BROWSE_QUERY, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
    return -1;
  return 0;
}

int mdns_recv(int fd, struct mdns_device *devices, int maxdev, int *count)
{
  w8 pkt[MDNS_PKT_CAP];
  ssize_t r;

  for (;;) {
    r = recv(fd, pkt, sizeof(pkt), 0);
    if (r >= 0)
      break;
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN)
      return 0;
    return -1;
  }
  return mdns_parse(pkt, (size_t)r, devices, maxdev, count);
}

static long elapsed_ms(const struct timespec *t0)
{
  struct timespec now;

  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0->tv_sec) * 1000L + (now.tv_nsec - t0->tv_nsec) / 1000000L;
}

/* Poll for up to the remaining window; an absolute deadline (not a per-call
 * timeout) keeps discovery bounded even when announcements never stop. */
static int poll_until(struct pollfd *pf, const struct timespec *t0, int mswin)
{
  long rem = (long)mswin - elapsed_ms(t0);
  int r;

  if (rem <= 0)
    return 0;
  do {
    r = poll(pf, 1, (int)rem);
  } while (r < 0 && errno == EINTR);
  if (r < 0)
    return -1;
  return r;
}

static void listen_loop(int fd, const char *pattern, int mswin, struct dscan *s)
{
  struct pollfd pf = { fd, POLLIN, 0 };
  struct timespec t0;

  clock_gettime(CLOCK_MONOTONIC, &t0);
  while (s->chosen < 0) {
    int r = poll_until(&pf, &t0, mswin);

    if (r <= 0)
      break;
    if (mdns_recv(fd, s->devices, s->maxdev, &s->count) != 0)
      break;
    s->chosen = mdns_first(s->devices, s->count, pattern);
  }
}

static int valid_args(const struct mdns_device *devices, int maxdev, int mswin)
{
  return devices != NULL && maxdev > 0 && mswin >= 0;
}

int mdns_discover_ms(const char *local_addr, const char *pattern, struct mdns_device *devices, int maxdev, int mswin)
{
  struct dscan s = { devices, maxdev, 0, -1 };
  int fd;

  if (!valid_args(devices, maxdev, mswin))
    return -1;
  fd = mdns_socket(local_addr);
  if (fd < 0)
    return -1;
  if (mdns_browse(fd) != 0) {
    close(fd);
    return -1;
  }
  listen_loop(fd, pattern, mswin, &s);
  close(fd);
  if (s.chosen < 0)
    return mdns_select(s.devices, s.count, pattern);
  return s.chosen;
}

int mdns_discover(const char *local_addr, const char *pattern, struct mdns_device *devices, int maxdev)
{
  return mdns_discover_ms(local_addr, pattern, devices, maxdev, MDNS_WINDOW_MS);
}
