#include "buf/cvec.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static size_t cvec_max(size_t a, size_t b)
{
  return a > b ? a : b;
}

static size_t cvec_min(size_t a, size_t b)
{
  return a < b ? a : b;
}

static void cvec_shrink(struct cvec *v)
{
  size_t ncap;
  struct buf_consumer *tmp;

  if (v->cap <= CVEC_INLINE || v->len > v->cap / 4)
    return;
  ncap = v->cap / 2;
  if (ncap <= CVEC_INLINE) {
    tmp = v->el;
    v->el = v->inl;
    v->cap = CVEC_INLINE;
    free(tmp);
    return;
  }
  tmp = realloc(v->el, ncap * sizeof(*tmp));
  if (tmp != NULL) {
    v->el = tmp;
    v->cap = ncap;
  }
}

int cvec_init(struct cvec *v)
{
  if (v == NULL)
    return -1;
  v->el = v->inl;
  v->len = 0;
  v->cap = CVEC_INLINE;
  return 0;
}

void cvec_clear(struct cvec *v)
{
  if (v == NULL)
    return;
  if (v->el != v->inl)
    free(v->el);
  v->el = v->inl;
  v->len = 0;
  v->cap = CVEC_INLINE;
}

static struct buf_consumer *cvec_alloc(const struct cvec *v, size_t ncap)
{
  if (v->el == v->inl) {
    struct buf_consumer *tmp = malloc(ncap * sizeof(*tmp));

    if (tmp != NULL)
      memcpy(tmp, v->inl, v->len * sizeof(*tmp));
    return tmp;
  }
  return realloc(v->el, ncap * sizeof(struct buf_consumer));
}

static int cvec_grow(struct cvec *v)
{
  size_t need = v->len + 1;
  size_t step;
  size_t ncap;
  struct buf_consumer *tmp;

  step = cvec_max(cvec_min(cvec_max(v->cap, CVEC_INLINE), 65536), need - v->cap);
  if (step > SIZE_MAX - v->cap)
    return -1;
  ncap = v->cap + step;
  if (ncap > SIZE_MAX / sizeof(*tmp))
    return -1;
  tmp = cvec_alloc(v, ncap);
  if (tmp == NULL)
    return -1;
  v->el = tmp;
  v->cap = ncap;
  return 0;
}

int cvec_push(struct cvec *v, struct buf_consumer c, size_t *idx)
{
  if (v == NULL) {
    if (idx != NULL)
      *idx = 0;
    return -1;
  }
  if (v->len == v->cap && cvec_grow(v) != 0)
    return -1;
  if (idx != NULL)
    *idx = v->len;
  v->el[v->len] = c;
  v->len++;
  return 0;
}

void cvec_pop(struct cvec *v, size_t idx)
{
  if (v == NULL || v->len == 0 || idx >= v->len)
    return;
  v->len--;
  if (idx != v->len)
    v->el[idx] = v->el[v->len];
  cvec_shrink(v);
}
