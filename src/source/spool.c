#include "source/spool.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef LITECAST_TEST
/* Test-only write injector. -1 = real path (default). Any negative (other than
 * -1) forces a write failure; 0 forces a zero-byte write (ENOSPC); a positive
 * value performs a real write capped at that many bytes, one-shot, so the
 * caller's partial-write loop is exercised against a consistent file offset. */
ssize_t _mock_write_result = -1;

void spool_mock_reset(void)
{
  _mock_write_result = -1;
}
#endif

static ssize_t spool_write_once(int fd, const void *p, size_t n)
{
#ifdef LITECAST_TEST
  /* -1 = real path (default). Any value <= 0 (other than -1) forces a failed
   * write (errno=ENOSPC); a positive value delivers a real write of at most
   * that many bytes, one-shot, so the loop is exercised at a consistent
   * offset. */
  if (_mock_write_result <= 0 && _mock_write_result != -1) {
    errno = ENOSPC;
    return -1;
  }
  if (_mock_write_result > 0 && (size_t)_mock_write_result < n)
    n = (size_t)_mock_write_result;
  _mock_write_result = -1;
#endif
  return write(fd, p, n);
}

static int spool_write_all(int fd, const void *p, size_t n)
{
  const unsigned char *s = p;

  while (n > 0) {
    ssize_t w = spool_write_once(fd, s, n);

    if (w < 0)
      return -1;
    if (w == 0) {
      errno = ENOSPC;
      return -1;
    }
    s += (size_t)w;
    n -= (size_t)w;
  }
  return 0;
}

int spool_open(char *tmpl)
{
  int fd;

  if (tmpl == NULL)
    return -1;
  fd = mkstemp(tmpl);
  if (fd < 0)
    return -1;
  /* Unlink immediately: keep a dangling fd only. */
  if (unlink(tmpl) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int spool_append(int fd, const void *p, size_t n)
{
  return spool_write_all(fd, p, n);
}

static int pread_retry(int fd, void *p, size_t n, off_t off, ssize_t *r)
{
  ssize_t got;

  do
    got = pread(fd, p, n, off);
  while (got < 0 && errno == EINTR);
  *r = got;
  return got < 0 ? -1 : 0;
}

int spool_read(int fd, unsigned long long off, void *p, size_t n, size_t *got)
{
  unsigned char *d = p;
  size_t i = 0;

  while (i < n) {
    ssize_t r;

    if (pread_retry(fd, d + i, n - i, (off_t) off, &r) != 0)
      return -1;
    if (r == 0)
      break;
    i += (size_t)r;
    off += (unsigned long long)r;
  }
  if (got != NULL)
    *got = i;
  return 0;
}

void spool_close(int fd)
{
  if (fd >= 0)
    close(fd);
}
