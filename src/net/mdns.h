#ifndef LITECAST_NET_MDNS_H
#define LITECAST_NET_MDNS_H

#include <stddef.h>
#include <stdint.h>

#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT 5353
#define MDNS_SERVICE "_googlecast._tcp.local."
#define MDNS_MAX_DEVICES 16
#define MDNS_PKT_CAP 4096
#define MDNS_WINDOW_MS 5000

#define MDNS_NAME_CAP 128

struct mdns_device {
  char name[64];
  char uuid[48];
  char model[32];
  char app[32];
  char host[MDNS_NAME_CAP];
  char srv_host[MDNS_NAME_CAP];
  uint32_t ip;
  uint16_t port;
};

/* Open the mDNS socket: UDP datagram bound to :5353, multicast-membership on
 * the IPv4 interface named by local_addr (or the default interface when
 * NULL), non-blocking. Returns the fd or -1. */
int mdns_socket(const char *local_addr);

/* Emit the PTR browse query for _googlecast._tcp.local. Returns 0 on
 * success, -1 on failure. */
int mdns_browse(int fd);

/* Receive and parse one datagram into devices (dedup by host), updating
 * *count up to maxdev. Returns 0 on success (ignoring malformed records),
 * -1 on a hard parse error. */
int mdns_recv(int fd, struct mdns_device *devices, int maxdev, int *count);

/* Pure single-pass DNS parser over an untrusted datagram. Only PTR/SRV/TXT/A
 * records for the Google Cast service are consumed; everything else is
 * skipped. Compression pointers are bounds-checked on every hop and must
 * point strictly backwards (RFC 1035); the at-most-20-pointer jump cap makes
 * decompression unwind even against adversarially nested/looping names. */
int mdns_parse(const unsigned char *pkt, size_t n, struct mdns_device *devices, int maxdev, int *count);

/* Case-insensitive `*`-only wildcard match; NULL/empty pattern matches any
 * name. Pure. */
int mdns_glob(const char *pattern, const char *name);

/* Case-insensitive substring test. Pure. */
int mdns_contains(const char *needle, const char *name);

/* Continuous-window selection: index of the first device whose name matches
 * pattern as a glob (first device when pattern is NULL/empty), or -1. */
int mdns_first(const struct mdns_device *devices, int n, const char *pattern);

/* Window-close selection per DOMAIN §Device selection: glob, then substring
 * fallback, then first discovered; -1 when none. Pure. */
int mdns_select(const struct mdns_device *devices, int n, const char *pattern);

/* Full discovery window: open, browse, poll up to MDNS_WINDOW_MS, returning
 * as soon as a device matches (glob / first). On timeout applies the
 * substring then first fallback. Returns the selected index or -1.
 * mdns_discover_ms lets the caller choose the window (tests use a short one). */
int mdns_discover(const char *local_addr, const char *pattern, struct mdns_device *devices, int maxdev);
int mdns_discover_ms(const char *local_addr, const char *pattern, struct mdns_device *devices, int maxdev, int mswin);

#endif
