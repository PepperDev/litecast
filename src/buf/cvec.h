#ifndef LITECAST_BUF_CVEC_H
#define LITECAST_BUF_CVEC_H

#include <stddef.h>

#define CVEC_INLINE 4U

struct buf_consumer {
  size_t read_off;
};

struct cvec {
  struct buf_consumer *el;
  struct buf_consumer inl[CVEC_INLINE];
  size_t len;
  size_t cap;
};

int cvec_init(struct cvec *v);
void cvec_clear(struct cvec *v);
int cvec_push(struct cvec *v, struct buf_consumer c, size_t *idx);
void cvec_pop(struct cvec *v, size_t idx);

#endif
