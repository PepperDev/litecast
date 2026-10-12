#ifndef LITECAST_CLI_CACHE_H
#define LITECAST_CLI_CACHE_H

#include <stddef.h>

enum cache_kind {
  CACHE_BYTES = 0,
  CACHE_PCT,
};

struct cache_cfg {
  enum cache_kind kind;
  unsigned int pct;
  size_t bytes;
};

int cli_parse_cache(const char *s, size_t page_size, struct cache_cfg *cfg);

#endif
