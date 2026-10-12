#include "test_util.h"
#include "source/spool.c"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define TMPL "/tmp/litecast-spool-test-XXXXXX"

static int t_open_unlink(void)
{
  char tmpl[] = TMPL;
  int fd;

  fd = spool_open(tmpl);
  EXPECT(fd >= 0);
  EXPECT(access(tmpl, F_OK) != 0);
  EXPECT(spool_append(fd, "hello", 5) == 0);
  spool_close(fd);
  EXPECT(close(fd) != 0);
  return 0;
}

static int t_open_null(void)
{
  EXPECT(spool_open(NULL) == -1);
  return 0;
}

static int t_enospc(void)
{
  char tmpl[] = TMPL;
  int fd;

  fd = spool_open(tmpl);
  EXPECT(fd >= 0);
  spool_mock_reset();
  _mock_write_result = 0;
  errno = 0;
  EXPECT(spool_append(fd, "data", 4) != 0);
  EXPECT(errno == ENOSPC);
  spool_mock_reset();
  spool_close(fd);
  return 0;
}

static int t_write_fail(void)
{
  char tmpl[] = TMPL;
  int fd;

  fd = spool_open(tmpl);
  EXPECT(fd >= 0);
  spool_mock_reset();
  _mock_write_result = -2;
  EXPECT(spool_append(fd, "data", 4) != 0);
  spool_mock_reset();
  spool_close(fd);
  return 0;
}

static int t_partial_write(void)
{
  char tmpl[] = TMPL;
  unsigned char tmp[10];
  int fd;
  int k;

  for (k = 0; k < 10; k++)
    tmp[k] = (unsigned char)('a' + k);
  fd = spool_open(tmpl);
  EXPECT(fd >= 0);
  spool_mock_reset();
  _mock_write_result = 3;
  EXPECT(spool_append(fd, tmp, sizeof tmp) == 0);
  spool_mock_reset();
  spool_close(fd);
  return 0;
}

static int t_read(void)
{
  char tmpl[] = TMPL;
  unsigned char out[32];
  size_t got;
  int fd;

  fd = spool_open(tmpl);
  EXPECT(fd >= 0);
  EXPECT(spool_append(fd, "abcdefgh", 8) == 0);

  /* Whole-span read. */
  memset(out, 0, sizeof out);
  EXPECT(spool_read(fd, 0, out, 8, &got) == 0);
  EXPECT(got == 8 && memcmp(out, "abcdefgh", 8) == 0);

  /* Mid-span read and offset. */
  memset(out, 0, sizeof out);
  EXPECT(spool_read(fd, 2, out, 4, &got) == 0);
  EXPECT(got == 4 && memcmp(out, "cdef", 4) == 0);

  /* Read past EOF: truncated to what exists. */
  memset(out, 0, sizeof out);
  EXPECT(spool_read(fd, 6, out, 16, &got) == 0);
  EXPECT(got == 2 && memcmp(out, "gh", 2) == 0);

  /* Offset past EOF: empty read. */
  EXPECT(spool_read(fd, 8, out, 4, &got) == 0 && got == 0);

  /* NULL got count is tolerated. */
  EXPECT(spool_read(fd, 0, out, 2, NULL) == 0);

  spool_close(fd);
  return 0;
}

int main(void)
{
  RUN(t_open_unlink);
  RUN(t_open_null);
  RUN(t_enospc);
  RUN(t_write_fail);
  RUN(t_partial_write);
  RUN(t_read);
  TEST_SUMMARY();
}
