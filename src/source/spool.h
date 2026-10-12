#ifndef LITECAST_SOURCE_SPOOL_H
#define LITECAST_SOURCE_SPOOL_H

#include <stddef.h>

/* Create a dangling temp-file spool. tmpl is a writable path whose final six
 * characters are "XXXXXX" (mkstemp semantics); it is produced/collated by the
 * caller. On success the returned fd is the sole reference and tmpl is already
 * unlinked; returns -1 on failure. The file is created with mode 0600. */
int spool_open(char *tmpl);

/* Append all n bytes from p to the spool, looping over partial writes. Returns
 * 0 on success, -1 on any write failure (including ENOSPC). */
int spool_append(int fd, const void *p, size_t n);

/* Non-seek read of exactly up to n bytes of the spooled prefix starting at
 * stream offset off, bypassing the process-local file-position (pread). Fills
 * *got with the number of bytes actually read; 0 means the requested offset is
 * past the spooled EOF. Returns 0 on success, -1 on read failure. */
int spool_read(int fd, unsigned long long off, void *p, size_t n, size_t *got);

/* Close the spool fd exactly once. */
void spool_close(int fd);

#endif
