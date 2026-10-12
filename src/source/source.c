#include "source/source.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { SOURCE_GRACE_MS = 1000, SOURCE_POLL_MS = 50 };

static int stat_current(struct source *s)
{
  struct stat st;

  if (fstat(s->fd, &st) != 0) {
    s->size_trusted = 0;
    s->size = 0;
    return 0;
  }
  s->size_trusted = S_ISREG(st.st_mode);
  s->size = s->size_trusted ? (unsigned long long)st.st_size : 0;
  return 0;
}

static int open_file(struct source *s, int i)
{
  s->fd = open(s->files[i], O_RDONLY);
  if (s->fd < 0)
    return -1;
  s->index = i;
  (void)stat_current(s);
  return 0;
}

/* Whole-stream total: the current file reuses the fstat verdict, the
 * remainders get one stat(2) each. A non-regular or untrustworthy operand
 * voids the total (a pipe of unknown size can never be announced). */
static int add_known(unsigned long long sz, int ok, unsigned long long *sum)
{
  if (!ok)
    return 0;
  *sum += sz;
  return 1;
}

static int file_known(struct source *s, int i, unsigned long long *sum)
{
  struct stat st;

  if (i == 0)
    return add_known(s->size, s->size_trusted, sum);
  if (stat(s->files[i], &st) != 0 || !S_ISREG(st.st_mode))
    return 0;
  return add_known((unsigned long long)st.st_size, 1, sum);
}

static int compute_total(struct source *s)
{
  unsigned long long sum = 0;
  int trusted = 1;
  int i;

  for (i = 0; i < s->nfiles && trusted; i++)
    trusted = file_known(s, i, &sum);
  s->total_trusted = trusted;
  s->total = trusted ? sum : 0;
  return 0;
}

static char **argv_dup(const char **operands, int n)
{
  char **argv;
  int i;

  argv = malloc(((size_t)n + 1) * sizeof(*argv));
  if (argv == NULL)
    return NULL;
  for (i = 0; i < n; i++)
    argv[i] = (char *)operands[i];
  argv[n] = NULL;
  return argv;
}

static int free_cmd(struct source *s)
{
  free(s->cmd);
  s->cmd = NULL;
  return -1;
}

/* The read end turns non-blocking here, before exec: the OFD is shared, so it
 * applies to the parent's copy too. Every drain read is EPOLLIN-gated, so the
 * set is in place by any read that could block; the child's stdout stays
 * blocking — pipe backpressure still gates no-spool producers. */
static void child_exec(char **argv, int rfd, int wfd)
{
  sigset_t set;

  (void)fcntl(rfd, F_SETFL, O_NONBLOCK);
  /* The parent's signalfd mask is inherited across fork+exec, deafening the
   * command to Ctrl-C and teardown SIGTERM (.tmp/trace.14); clear it — exec
   * resets caught handlers to default anyway. */
  sigemptyset(&set);
  (void)sigprocmask(SIG_SETMASK, &set, NULL);
  close(rfd);
  dup2(wfd, STDOUT_FILENO);
  close(wfd);
  execvp(argv[0], argv);
  _exit(127);
}

static int open_command(struct source *s, int noperands, const char **operands)
{
  int fds[2];

  s->cmd = argv_dup(operands, noperands);
  if (s->cmd == NULL)
    return -1;
  if (pipe(fds) != 0)
    return free_cmd(s);
  s->child = fork();
  if (s->child < 0) {
    close(fds[0]);
    close(fds[1]);
    return free_cmd(s);
  }
  if (s->child == 0)
    child_exec(s->cmd, fds[0], fds[1]);
  close(fds[1]);
  s->fd = fds[0];
  return 0;
}

int source_open(struct source *s, int mode, int noperands, const char **operands)
{
  if (s == NULL || operands == NULL || noperands <= 0)
    return -1;
  memset(s, 0, sizeof(*s));
  s->fd = SOURCE_FD_NONE;
  s->mode = mode;

  if (mode == SOURCE_MODE_COMMAND)
    return open_command(s, noperands, operands);
  s->files = operands;
  s->nfiles = noperands;
  if (open_file(s, 0) != 0)
    return -1;
  (void)compute_total(s);
  return 0;
}

int source_fd(const struct source *s)
{
  return s->fd;
}

static int more_input(const struct source *s)
{
  return s->mode == SOURCE_MODE_FILE && s->index + 1 < s->nfiles;
}

static int read_current(struct source *s, void *dst, size_t cap, ssize_t *out)
{
  ssize_t r;

  do {
    r = read(s->fd, dst, cap);
  } while (r < 0 && errno == EINTR);
  *out = r;
  return r < 0 ? -1 : 0;
}

static int eof_advance(struct source *s)
{
  int r;

  close(s->fd);
  s->fd = SOURCE_FD_NONE;
  if (!more_input(s)) {
    s->eof_seen = 1;
    return 0;
  }
  r = open_file(s, s->index + 1);
  return r == 0 ? 1 : -1;
}

int source_read(struct source *s, void *dst, size_t cap)
{
  ssize_t r;

  /* A zero-length read is a no-op, never an EOF: read(2) returns 0 regardless
   * of pipe state, so treating it as EOF would kill a still-producing command
   * (no-spool false-EOF, .tmp/.trace-lc.8); callers with no room must wait. */
  if (cap == 0)
    return 0;
  while (s->fd != SOURCE_FD_NONE) {
    int a;

    if (read_current(s, dst, cap, &r) != 0)
      return -1;
    if (r > 0)
      return (int)r;
    a = eof_advance(s);         /* latches eof_seen on the natural end */
    if (a != 1)
      return a;                 /* 0 = end (eof latched), -1 = error */
  }
  return 0;
}

int source_eof(const struct source *s)
{
  return s->eof_seen;
}

int source_size_trusted(const struct source *s)
{
  return s->size_trusted;
}

unsigned long long source_size(const struct source *s)
{
  return s->size;
}

unsigned long long source_total(const struct source *s)
{
  if (s == NULL)
    return 0;
  return s->total_trusted ? s->total : 0;
}

int source_reap(struct source *s)
{
  int status;

  if (s->child == 0)
    return 1;
  if (waitpid(s->child, &status, WNOHANG) != s->child)
    return -1;
  s->child = 0;
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 1;
  return 0;
}

/* Poll waitpid(WNOHANG) up to grace_ms (sleeping SOURCE_POLL_MS in between).
 * Returns 1 once the child is reaped. */
static int child_died(pid_t child, int grace_ms, const struct timespec *step)
{
  int waited = 0;

  while (waited < grace_ms) {
    int st;

    if (waitpid(child, &st, WNOHANG) == child)
      return 1;
    (void)nanosleep(step, NULL);
    waited += SOURCE_POLL_MS;
  }
  return 0;
}

/* Terminate the command child without ever blocking the exit: SIGTERM, then a
 * bounded WNOHANG grace window, then SIGKILL and a second bounded window to
 * reap it. A child that swallows SIGTERM (ffmpeg ignores SIGPIPE) while the
 * cast already ended and no write can detect the dead pipe would ride out a
 * blocking wait; each phase is bounded (≤ 2 * SOURCE_GRACE_MS), so teardown
 * never stalls. */
void source_teardown(struct source *s)
{
  struct timespec step = { 0, (long)SOURCE_POLL_MS * 1000000L };
  int phase;

  if (s == NULL || s->child <= 0)
    return;
  (void)kill(s->child, SIGTERM);
  for (phase = 0; phase < 2; phase++) {
    if (child_died(s->child, SOURCE_GRACE_MS, &step)) {
      s->child = 0;
      return;
    }
    (void)kill(s->child, SIGKILL);
  }
  s->child = 0;
}

void source_close(struct source *s)
{
  if (s->fd != SOURCE_FD_NONE) {
    close(s->fd);
    s->fd = SOURCE_FD_NONE;
  }
  free(s->cmd);
  s->cmd = NULL;
}
