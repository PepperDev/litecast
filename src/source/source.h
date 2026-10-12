#ifndef LITECAST_SOURCE_SOURCE_H
#define LITECAST_SOURCE_SOURCE_H

#include <stddef.h>
#include <sys/types.h>

#define SOURCE_MODE_FILE 0
#define SOURCE_MODE_COMMAND 1
#define SOURCE_FD_NONE (-1)

/* Pushes bytes into the ring/retention window. Holds the current input fd and
 * the one-shot per-file stat; in command mode owns the child pid and the pipe
 * read end. */
struct source {
  int mode;
  int fd;
  const char **files;
  int nfiles;
  int index;
  int size_trusted;
  unsigned long long size;
  int total_trusted;
  unsigned long long total;
  char **cmd;
  pid_t child;
  int eof_seen;
};

/* Open the stream. File mode: opens operands[0] (fatal if it cannot be
 * opened). Command mode: pipe+fork+execvp(operands[0], operands) with no shell.
 * Returns 0 on success, -1 on failure (no operands, first file missing, or
 * fork/pipe failure). */
int source_open(struct source *s, int mode, int noperands, const char **operands);

/* The fd to poll for EPOLLIN (current file fd or pipe read end). */
int source_fd(const struct source *s);

/* Read up to cap bytes from the current input. With cat semantics: on EOF of
 * one file it advances to the next (re-stat'ing it) and continues, returning
 * the first non-empty read; returns 0 only once every input has been consumed
 * (whole-stream EOF) and -1 on an I/O or open error. */
int source_read(struct source *s, void *dst, size_t cap);

/* Non-zero once the whole stream is finished (all files concatenated, or the
 * command pipe drained). */
int source_eof(const struct source *s);

/* Trustworthy regular-file size of the current file (0 if pipe/special). */
int source_size_trusted(const struct source *s);
unsigned long long source_size(const struct source *s);

/* Whole-stream byte total, trustworthy only when every operand is a regular
 * file (file mode); 0 when unknown (command mode, or any pipe/special
 * operand, or the family of files is empty). */
unsigned long long source_total(const struct source *s);

/* Reap the command child via waitpid(WNOHANG) (called from the SIGCHLD loop,
 * never from a signal handler). Returns 1 if a child exited cleanly (or none
 * to reap), 0 if a child was reaped with a non-zero/abnormal status, -1 if it
 * is still running. */
int source_reap(struct source *s);

/* Terminate any live command child with a bounded reap (SIGTERM → grace →
 * SIGKILL → grace): never blocks the teardown path, so the exit stays
 * responsive to signals. Reaped child is cleared. */
void source_teardown(struct source *s);

/* Close the current fd and release command-mode resources. */
void source_close(struct source *s);

#endif
