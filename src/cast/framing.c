#include "cast/cast.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

/* === Transport: plaintext fd === */

static ssize_t sock_in(ssize_t r)
{
  if (r > 0)
    return r;
  if (r == 0)
    return -1;
  if (errno == EAGAIN || errno == EWOULDBLOCK)
    return 0;
  return -1;
}

static ssize_t plain_read(struct cast_io *io, unsigned char *buf, size_t cap)
{
  ssize_t r;
  int fd = *(const int *)io->opaque;

  do
    r = recv(fd, buf, cap, 0);
  while (r < 0 && errno == EINTR);
  return sock_in(r);
}

static ssize_t plain_write(struct cast_io *io, const unsigned char *buf, size_t cap)
{
  ssize_t r;
  int fd = *(const int *)io->opaque;

  do
    r = send(fd, buf, cap, MSG_NOSIGNAL);
  while (r < 0 && errno == EINTR);
  if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  return r;
}

int cast_io_fd(struct cast_io *io, int *fd)
{
  if (io == NULL || fd == NULL)
    return -1;
  io->read = plain_read;
  io->write = plain_write;
  io->opaque = fd;
  return 0;
}

/* === Frame reader === */

int cast_reader_init(struct cast_reader *rd, struct cast_io *io)
{
  if (rd == NULL || io == NULL)
    return -1;
  rd->io = io;
  rd->frame_len = 0;
  rd->len = 0;
  rd->ready = 0;
  rd->alloc = 0;
  rd->buf = malloc(4);
  if (rd->buf == NULL)
    return -1;
  rd->alloc = 4;
  return 0;
}

void cast_reader_close(struct cast_reader *rd)
{
  if (rd != NULL) {
    free(rd->buf);
    rd->buf = NULL;
    rd->alloc = 0;
  }
}

static int cast_alloc(struct cast_reader *rd, uint32_t n)
{
  unsigned char *nb;

  if (n <= rd->alloc)
    return 0;
  nb = realloc(rd->buf, n);
  if (nb == NULL)
    return -1;
  rd->buf = nb;
  rd->alloc = n;
  return 0;
}

/* Parse a just-collected 4-byte prefix; returns 0 unless a new prefix is
 * complete, -1 on a length out of [1, CAST_MAX_FRAME] or allocation failure. */
static int cast_begin(struct cast_reader *rd)
{
  uint32_t n;

  if (rd->frame_len != 0 || rd->len != 4)
    return 0;
  n = ((uint32_t) rd->buf[0] << 24) | ((uint32_t) rd->buf[1] << 16) | ((uint32_t) rd->buf[2] << 8) | rd->buf[3];
  if (n < 1 || n > CAST_MAX_FRAME)
    return -1;
  rd->frame_len = n;
  return cast_alloc(rd, 4 + n);
}

static int cast_frame_done(const struct cast_reader *rd)
{
  return rd->frame_len != 0 && rd->len == 4 + rd->frame_len;
}

static ssize_t cast_fill(struct cast_reader *rd)
{
  size_t room;
  ssize_t r;

  room = rd->frame_len ? 4 + rd->frame_len - rd->len : 4 - rd->len;
  r = rd->io->read(rd->io, rd->buf + rd->len, room);
  if (r > 0)
    rd->len += (uint32_t) r;
  return r;
}

int cast_pump(struct cast_reader *rd)
{
  ssize_t r;

  if (rd->ready) {
    rd->ready = 0;
    rd->frame_len = 0;
    rd->len = 0;
  }
  if (cast_begin(rd) != 0)
    return -1;
  r = cast_fill(rd);
  if (r < 0)
    return -1;
  if (r == 0)
    return 0;
  rd->ready = cast_frame_done(rd);
  return rd->ready ? 1 : 0;
}

int cast_reader_message(const struct cast_reader *rd, const unsigned char **p, size_t *n)
{
  if (rd == NULL || p == NULL || n == NULL)
    return -1;
  if (rd->ready == 0)
    return -1;
  *p = rd->buf + 4;
  *n = rd->frame_len;
  return 0;
}

/* === Send === */

static ssize_t io_write_all(struct cast_io *io, const unsigned char *p, size_t n)
{
  size_t off = 0;

  while (off < n) {
    ssize_t r = io->write(io, p + off, n - off);
    if (r < 0)
      return -1;
    if (r == 0)
      return 0;                 /* would-block, nothing further written */
    off += (size_t)r;
  }
  return (ssize_t) off;
}

/* Stuff the big-endian 4-byte length prefix ahead of the payload. */
static void wire_prefix(unsigned char *p, unsigned int n)
{
  unsigned int i;

  for (i = 0; i < 4; i++)
    p[i] = (unsigned char)(n >> (24 - 8 * i));
}

/* Write a full frame and release it; reports failure on any short write. */
static int wire_tx(struct cast_io *io, unsigned char *wire, size_t n)
{
  int ok = io_write_all(io, wire, n) == (ssize_t) n;

  free(wire);
  return ok ? 0 : -1;
}

int cast_send(struct cast_io *io, const struct cast_msg *m)
{
  unsigned char *wire;
  int e;

  if (io == NULL || m == NULL)
    return -1;
  wire = malloc(CAST_ENC_CAP + 4);
  if (wire == NULL)
    return -1;
  e = cast_encode(m, wire + 4, CAST_ENC_CAP);
  if (e < 1) {
    free(wire);
    return -1;
  }
  wire_prefix(wire, (unsigned int)e);
  return wire_tx(io, wire, (size_t)e + 4);
}
