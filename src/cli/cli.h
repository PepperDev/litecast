#ifndef LITECAST_CLI_CLI_H
#define LITECAST_CLI_CLI_H

#include "cli/cache.h"

enum { CLI_DEVICE_MAX = 256 };

struct cli_options {
  int command_mode;
  int cache_to_fs;
  int no_arbitrary_range;
  int show_help;
  int show_version;
  struct cache_cfg cache;
  char device[CLI_DEVICE_MAX];
  int operands_count;
  const char **operands;
};

int cli_parse(int argc, char **argv, struct cli_options *opts);

#endif
