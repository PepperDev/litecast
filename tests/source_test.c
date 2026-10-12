#include "test_util.h"
#include "source/source.c"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int make_fixture(char *path, size_t path_cap, const unsigned char *data, size_t len)
{
  char tmpl[] = "/tmp/litecast-src-test-XXXXXX";
  int fd;
  ssize_t w;

  fd = mkstemp(tmpl);
  if (fd < 0)
    return -1;
  w = write(fd, data, len);
  close(fd);
  if (w != (ssize_t) len)
    return -1;
  if (snprintf(path, path_cap, "%s", tmpl) >= (int)path_cap)
    return -1;
  return 0;
}

static int t_file_open_read(void)
{
  char path[64];
  const char *operands[1];
  struct source s;
  unsigned char buf[16];
  int r;

  EXPECT(make_fixture(path, sizeof path, (const unsigned char *)"hello world\n", 12) == 0);
  operands[0] = path;
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 1, operands) == 0);
  r = source_read(&s, buf, sizeof buf);
  EXPECT(r == 12);
  EXPECT(memcmp(buf, "hello world\n", 12) == 0);
  EXPECT(source_read(&s, buf, sizeof buf) == 0);
  EXPECT(source_fd(&s) == SOURCE_FD_NONE);
  EXPECT(source_eof(&s) == 1);
  source_close(&s);
  unlink(path);
  return 0;
}

static int t_file_trusted(void)
{
  char path[64];
  const char *operands[1];
  struct source s;

  EXPECT(make_fixture(path, sizeof path, (const unsigned char *)"abcdefgh", 8) == 0);
  operands[0] = path;
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 1, operands) == 0);
  EXPECT(source_size_trusted(&s) == 1);
  EXPECT(source_size(&s) == 8);
  source_close(&s);
  unlink(path);
  return 0;
}

static int t_cat_multi(void)
{
  char path1[64], path2[64];
  const char *operands[2];
  struct source s;
  unsigned char buf[32];
  int off = 0;
  int r;

  EXPECT(make_fixture(path1, sizeof path1, (const unsigned char *)"AAA", 3) == 0);
  EXPECT(make_fixture(path2, sizeof path2, (const unsigned char *)"BBBB", 4) == 0);
  operands[0] = path1;
  operands[1] = path2;
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 2, operands) == 0);
  while ((r = source_read(&s, buf + off, sizeof buf - (size_t)off)) > 0)
    off += r;
  EXPECT(source_eof(&s) == 1);
  EXPECT(off == 7);
  EXPECT(memcmp(buf, "AAABBBB", 7) == 0);
  EXPECT(source_size(&s) == 4);
  source_close(&s);
  unlink(path1);
  unlink(path2);
  return 0;
}

static int t_file_missing(void)
{
  const char *operands[1];
  struct source s;

  operands[0] = "/nonexistent/litecast/missing-file";
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 1, operands) != 0);
  return 0;
}

static int t_no_operands(void)
{
  struct source s;
  const char *path = "x";

  EXPECT(source_open(&s, SOURCE_MODE_FILE, 0, &path) != 0);
  EXPECT(source_open(&s, SOURCE_MODE_COMMAND, 0, &path) != 0);
  EXPECT(source_open(NULL, SOURCE_MODE_FILE, 1, &path) != 0);
  return 0;
}

static int t_cmd_read(void)
{
  char path[64];
  const char *operands[2];
  struct source s;
  unsigned char buf[16];
  int r;
  int count = 0;
  int rc = 0;
  int i;

  EXPECT(make_fixture(path, sizeof path, (const unsigned char *)"cmd bytes!", 10) == 0);
  operands[0] = "cat";
  operands[1] = path;
  EXPECT(source_open(&s, SOURCE_MODE_COMMAND, 2, operands) == 0);
  while (!source_eof(&s)) {
    r = source_read(&s, buf + count, sizeof buf - (size_t)count);
    if (r > 0)
      count += r;
    else if (r < 0 && errno != EAGAIN)
      break;
  }
  EXPECT(source_eof(&s) == 1);
  EXPECT(count == 10);
  EXPECT(memcmp(buf, "cmd bytes!", 10) == 0);
  i = 0;
  while ((rc = source_reap(&s)) == -1 && i < 10000)
    i++;
  EXPECT(rc == 1);
  EXPECT(source_reap(&s) == 1);
  source_close(&s);
  unlink(path);
  return 0;
}

static int t_read_error(void)
{
  const char *operands[1];
  struct source s;
  unsigned char buf[8];

  operands[0] = "/";
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 1, operands) == 0);
  EXPECT(source_size_trusted(&s) == 0);
  EXPECT(source_read(&s, buf, sizeof buf) == -1);
  source_close(&s);
  return 0;
}

/* A zero-length source_read is a no-op, never an EOF: read(2) answers 0 to a
 * 0-length read regardless of pipe state, and treating that as EOF closes the
 * read end and SIGPIPE-kills a still-live command (no-spool false-EOF
 * regression, `.tmp/.trace-lc.8`). The fd must stay open and eof unset. */
static int t_cmd_read_zero(void)
{
  char path[64];
  const char *operands[2];
  struct source s;
  unsigned char buf[16];

  EXPECT(make_fixture(path, sizeof path, (const unsigned char *)"data", 4) == 0);
  operands[0] = "cat";
  operands[1] = path;
  EXPECT(source_open(&s, SOURCE_MODE_COMMAND, 2, operands) == 0);
  EXPECT(source_read(&s, buf, 0) == 0); /* no-op: fd open, eof unset */
  EXPECT(source_eof(&s) == 0);
  EXPECT(source_fd(&s) != SOURCE_FD_NONE);
  while (!source_eof(&s)) {
    int r = source_read(&s, buf, sizeof buf);

    if (r < 0 && errno != EAGAIN)
      break;
  }
  EXPECT(source_eof(&s) == 1);
  EXPECT(source_read(&s, buf, 0) == 0); /* still a no-op after EOF */
  source_close(&s);
  unlink(path);
  return 0;
}

static int t_cmd_exec_fail(void)
{
  const char *operands[1];
  struct source s;
  unsigned char buf[8];
  int count = 0;
  int rc = 0;
  int r;
  int i;

  operands[0] = "litecast-no-such-cmd-xyz";
  EXPECT(source_open(&s, SOURCE_MODE_COMMAND, 1, operands) == 0);
  while (!source_eof(&s)) {
    r = source_read(&s, buf, sizeof buf);
    if (r > 0)
      count += r;
    else if (r < 0 && errno != EAGAIN)
      break;
  }
  EXPECT(source_eof(&s) == 1);
  EXPECT(count == 0);
  i = 0;
  while ((rc = source_reap(&s)) == -1 && i < 10000)
    i++;
  EXPECT(rc == 0);
  source_close(&s);
  return 0;
}

/* Regression: source_teardown's child reap must stay bounded even when the
 * --command child catches SIGINT/SIGTERM and ignores SIGPIPE (ffmpeg) and
 * refuses to die on SIGTERM. A blocking waitpid after kill(SIGTERM) would
 * stall the exit forever; SIGKILL is the final word. */
static int t_source_teardown(void)
{
  struct sigaction sa;
  struct timespec t0, t1;
  struct source s;
  pid_t child;
  int syncp[2];
  char rbuf;
  int st;
  long elapsed;

  /* Ignores SIGTERM (set in the child only): must burn the full grace, be
   * SIGKILLed and reaped within the bound. A pipe syncs the child's handler
   * install so the SIGTERM cannot race ahead of sigaction(). */
  EXPECT(pipe(syncp) == 0);
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGTERM, &sa, NULL);
    (void)write(syncp[1], "r", 1);
    (void)sleep(60);
    _exit(0);
  }
  close(syncp[1]);
  EXPECT(read(syncp[0], &rbuf, 1) == 1);
  close(syncp[0]);
  memset(&s, 0, sizeof s);
  s.fd = SOURCE_FD_NONE;
  s.child = child;
  EXPECT(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
  source_teardown(&s);
  EXPECT(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
  elapsed = (long)(((t1.tv_sec - t0.tv_sec) * 1000000000L) + (t1.tv_nsec - t0.tv_nsec)) / 1000000L;
  EXPECT(elapsed >= 950);       /* full grace burned (SIGTERM ignored) */
  EXPECT(elapsed < 5000);       /* still bounded */
  EXPECT(s.child == 0);         /* reaped and cleared by the teardown */
  EXPECT(waitpid(child, &st, 0) == -1 && errno == ECHILD);      /* already reaped */
  EXPECT(kill(child, 0) == -1 && errno == ESRCH);       /* and gone */

  /* Default SIGTERM kills (dies at once): prompt reap well under the grace. */
  child = fork();
  EXPECT(child >= 0);
  if (child == 0) {
    (void)sleep(60);
    _exit(0);
  }
  memset(&s, 0, sizeof s);
  s.fd = SOURCE_FD_NONE;
  s.child = child;
  EXPECT(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
  source_teardown(&s);
  EXPECT(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
  elapsed = (long)(((t1.tv_sec - t0.tv_sec) * 1000000000L) + (t1.tv_nsec - t0.tv_nsec)) / 1000000L;
  EXPECT(elapsed < 1000);       /* no SIGKILL needed */
  EXPECT(s.child == 0);
  EXPECT(waitpid(child, &st, 0) == -1 && errno == ECHILD);
  EXPECT(kill(child, 0) == -1 && errno == ESRCH);

  /* No child (file mode): a no-op that never blocks. */
  memset(&s, 0, sizeof s);
  source_teardown(&s);
  source_teardown(&s);
  return 0;
}

static int t_total(void)
{
  char path1[64];
  char path2[64];
  const char *operands[3];
  struct source s;

  /* Single trusted regular file: total known. */
  EXPECT(make_fixture(path1, sizeof path1, (const unsigned char *)"hello world\n", 12) == 0);
  operands[0] = path1;
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 1, operands) == 0);
  EXPECT(source_total(&s) == 12);
  source_close(&s);

  /* Multi-file cat: total is the concatenated sum. */
  EXPECT(make_fixture(path2, sizeof path2, (const unsigned char *)"BBBB", 4) == 0);
  operands[0] = path1;
  operands[1] = path2;
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 2, operands) == 0);
  EXPECT(source_total(&s) == 16);
  source_close(&s);

  /* A non-regular operand voids the whole-stream total. */
  operands[1] = "/";
  EXPECT(source_open(&s, SOURCE_MODE_FILE, 2, operands) == 0);
  EXPECT(source_total(&s) == 0);
  source_close(&s);

  /* Command mode never has a total. */
  {
    const char *cmdops[] = { "cat", path1 };

    EXPECT(source_open(&s, SOURCE_MODE_COMMAND, 2, cmdops) == 0);
    EXPECT(source_total(&s) == 0);
    EXPECT(source_total(NULL) == 0);
    source_close(&s);
  }
  unlink(path1);
  unlink(path2);
  return 0;
}

/* Regression: the spawned --command child must run with a DEFAULT signal
 * mask. run_init() blocks SIGINT/SIGTERM/SIGCHLD for the signalfd, and that
 * mask survives fork + exec, so without a restore in child_exec the command
 * runs with SIGINT/SIGTERM blocked — a terminal Ctrl-C (foreground group) or
 * the teardown SIGTERM never lands and the cast appears deaf to stop signals
 * (trace.14 operator report: Ctrl-C ignored). parent blocks the signals first
 * to reproduce the inheritance, then a direct kill(SIGTERM) must reap the
 * child promptly. */
static int t_cmd_simask(void)
{
  struct timespec t0, t1;
  struct source s;
  const char *ops[2];
  sigset_t set, old;
  long elapsed;
  int st;
  int i = 0;

  ops[0] = "sleep";
  ops[1] = "30";
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGCHLD);
  EXPECT(sigprocmask(SIG_BLOCK, &set, &old) == 0);
  EXPECT(source_open(&s, SOURCE_MODE_COMMAND, 2, ops) == 0);
  EXPECT(sigprocmask(SIG_SETMASK, &old, NULL) == 0);

  (void)kill(s.child, SIGTERM);
  EXPECT(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
  do {
    if (waitpid(s.child, &st, WNOHANG) == s.child) {
      EXPECT(WIFSIGNALED(st) != 0 && WTERMSIG(st) == SIGTERM);
      s.child = 0;
      source_close(&s);
      EXPECT(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
      elapsed = (long)(((t1.tv_sec - t0.tv_sec) * 1000000000L) + (t1.tv_nsec - t0.tv_nsec)) / 1000000L;
      EXPECT(elapsed < 2000);   /* prompt: SIGTERM landed, no blocked-signal hang */
      return 0;
    }
    (void)nanosleep(&(struct timespec) { 0, 20 * 1000000L }, NULL);
  } while (++i < 150);          /* ~3 s bound: pre-fix the SIGTERM is blocked */
  source_teardown(&s);
  source_close(&s);
  EXPECT(0 && "command child blocked SIGTERM via inherited mask");
  return -1;
}

int main(void)
{
  RUN(t_file_open_read);
  RUN(t_file_trusted);
  RUN(t_cat_multi);
  RUN(t_file_missing);
  RUN(t_no_operands);
  RUN(t_cmd_read);
  RUN(t_cmd_read_zero);
  RUN(t_read_error);
  RUN(t_cmd_exec_fail);
  RUN(t_source_teardown);
  RUN(t_cmd_simask);
  RUN(t_total);
  TEST_SUMMARY();
}
