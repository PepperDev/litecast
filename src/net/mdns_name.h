#ifndef LITECAST_NET_MDNS_NAME_H
#define LITECAST_NET_MDNS_NAME_H

#include <stddef.h>

struct mdns_name_acc {
  char *buf;
  size_t cap;
  size_t len;
};

/* Decode the (possibly compressed) DNS name at off in an untrusted datagram.
 * Labels are appended with '.' separators into acc->buf (truncated when
 * acc->cap is too small; acc->buf must be writable). *next is the stream
 * offset just past the name: after the first pointer, or right after the
 * root label. Bounded by a 20-pointer jump cap, so looping names decompress
 * to -1 instead of hanging. Returns 0 or -1. */
int mdns_name(const unsigned char *pkt, size_t n, size_t off, struct mdns_name_acc *acc, size_t *next);

#endif
