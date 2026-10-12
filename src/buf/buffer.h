#ifndef LITECAST_BUF_BUFFER_H
#define LITECAST_BUF_BUFFER_H

#include "buf/cvec.h"
#include "cli/cache.h"

#define BUFFER_MODE_FILE 0
#define BUFFER_MODE_COMMAND 1

struct buf_source {
  int mode;
  int size_trustworthy;
  size_t size;
};

struct buffer {
  unsigned char *data;
  size_t cap;
  size_t len;
  size_t received;
  size_t target;
  size_t pct;
  size_t page_size;
  size_t cap_limit;
  unsigned int percent_dyn:1;
  struct cvec cons;
};

int buffer_open(struct buffer *b, size_t page_size, const struct cache_cfg *cfg, const struct buf_source *src);
void buffer_close(struct buffer *b);
int buffer_append(struct buffer *b, const unsigned char *p, size_t n);
void buffer_compact(struct buffer *b, size_t need);
size_t buffer_len(const struct buffer *b);
size_t buffer_cap(const struct buffer *b);
size_t buffer_target(const struct buffer *b);
size_t buffer_received(const struct buffer *b);
size_t buffer_lowest(const struct buffer *b);
size_t buffer_offset(const struct buffer *b);
const unsigned char *buffer_data(const struct buffer *b);
int buffer_read_at(const struct buffer *b, size_t off, void *dst, size_t n);
int buffer_add_consumer(struct buffer *b, size_t start, size_t *idx);
void buffer_remove_consumer(struct buffer *b, size_t idx);
int buffer_consumer_read(struct buffer *b, size_t idx, void *dst, size_t n, size_t *got);

#endif
