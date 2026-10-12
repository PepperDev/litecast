#include "cli/cache.h"

#include <stdint.h>
#include <string.h>

static const struct suf {
  char c;
  unsigned char pow;
} SUFFIXES[] = {
  {'K', 1}, {'k', 1}, {'M', 2}, {'m', 2}, {'G', 3}, {'g', 3},
};

#define SUFFIXES_LEN (sizeof(SUFFIXES) / sizeof(SUFFIXES[0]))

static const char *parse_u64(const char *s, size_t *out)
{
  size_t acc = 0;

  if (*s < '0' || *s > '9')
    return NULL;
  do {
    size_t d = (size_t)(*s - '0');

    if (acc > (SIZE_MAX - d) / 10)
      return NULL;
    acc = acc * 10 + d;
    s++;
  } while (*s >= '0' && *s <= '9');
  *out = acc;
  return s;
}

static int mul1024(size_t *v, unsigned pow)
{
  while (pow != 0) {
    if (*v > SIZE_MAX / 1024)
      return -1;
    *v *= 1024;
    pow--;
  }
  return 0;
}

static int suffix_pow(unsigned char c)
{
  unsigned k;

  for (k = 0; k < SUFFIXES_LEN; k++)
    if (SUFFIXES[k].c == c)
      return SUFFIXES[k].pow;
  return 0;
}

static int parse_pct(size_t v, struct cache_cfg *cfg)
{
  if (v > 100)
    return -1;
  cfg->kind = CACHE_PCT;
  cfg->pct = (unsigned int)v;
  return 0;
}

static int parse_bytes(size_t v, const char *end, size_t page_size, struct cache_cfg *cfg)
{
  size_t bytes = v;
  unsigned pow = suffix_pow((unsigned char)*end);

  if (pow == 0)
    return -1;
  end++;
  if (*end != '\0')
    return -1;
  if (mul1024(&bytes, pow) != 0)
    return -1;
  if (bytes < page_size)
    bytes = page_size;
  cfg->kind = CACHE_BYTES;
  cfg->bytes = bytes;
  return 0;
}

int cli_parse_cache(const char *s, size_t page_size, struct cache_cfg *cfg)
{
  size_t v;
  const char *end;

  end = parse_u64(s, &v);
  if (end == NULL)
    return -1;
  if (*end == '%') {
    if (*(end + 1) != '\0')
      return -1;
    return parse_pct(v, cfg);
  }
  return parse_bytes(v, end, page_size, cfg);
}
