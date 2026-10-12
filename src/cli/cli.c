#include "cli/cli.h"

#include <string.h>
#include <unistd.h>

#define DEFAULT_CACHE (64UL * 1024 * 1024)

struct cli_options;

typedef int (*opt_fn)(const char *value, size_t page_size, struct cli_options * opts);

struct opt_ent {
  const char *name;
  opt_fn fn;
  int has_value;
};

static int opt_cache(const char *value, size_t page_size, struct cli_options *opts);
static int opt_cache_to_fs(const char *value, size_t page_size, struct cli_options *opts);
static int opt_device(const char *value, size_t page_size, struct cli_options *opts);
static int opt_file(const char *value, size_t page_size, struct cli_options *opts);
static int opt_command(const char *value, size_t page_size, struct cli_options *opts);
static int opt_no_arbitrary_range(const char *value, size_t page_size, struct cli_options *opts);
static int opt_help(const char *value, size_t page_size, struct cli_options *opts);
static int opt_version(const char *value, size_t page_size, struct cli_options *opts);

static const struct opt_ent OPT_TABLE[] = {
  {"--cache", opt_cache, 1},
  {"-b", opt_cache, 1},
  {"--cache-to-fs", opt_cache_to_fs, 0},
  {"-s", opt_cache_to_fs, 0},
  {"--device", opt_device, 1},
  {"-d", opt_device, 1},
  {"--file", opt_file, 0},
  {"-f", opt_file, 0},
  {"--command", opt_command, 0},
  {"-c", opt_command, 0},
  {"--no-arbitrary-range", opt_no_arbitrary_range, 0},
  {"-n", opt_no_arbitrary_range, 0},
  {"--help", opt_help, 0},
  {"-h", opt_help, 0},
  {"--version", opt_version, 0},
  {"-V", opt_version, 0},
};

#define OPT_TABLE_LEN (sizeof(OPT_TABLE) / sizeof(OPT_TABLE[0]))

struct scan {
  int argc;
  char **argv;
  size_t page_size;
  struct cli_options *opts;
  int no_more;
};

static int opt_cache(const char *value, size_t page_size, struct cli_options *opts)
{
  return cli_parse_cache(value, page_size, &opts->cache);
}

static int opt_device(const char *value, size_t page_size, struct cli_options *opts)
{
  size_t n;

  (void)page_size;
  n = strlen(value);
  if (n == 0 || n >= sizeof(opts->device))
    return -1;
  memcpy(opts->device, value, n + 1);
  return 0;
}

static int opt_cache_to_fs(const char *value, size_t page_size, struct cli_options *opts)
{
  (void)value;
  (void)page_size;
  opts->cache_to_fs = 1;
  return 0;
}

static int opt_file(const char *value, size_t page_size, struct cli_options *opts)
{
  (void)value;
  (void)page_size;
  opts->command_mode = 0;
  return 0;
}

static int opt_command(const char *value, size_t page_size, struct cli_options *opts)
{
  (void)value;
  (void)page_size;
  opts->command_mode = 1;
  return 0;
}

static int opt_no_arbitrary_range(const char *value, size_t page_size, struct cli_options *opts)
{
  (void)value;
  (void)page_size;
  opts->no_arbitrary_range = 1;
  return 0;
}

static int opt_help(const char *value, size_t page_size, struct cli_options *opts)
{
  (void)value;
  (void)page_size;
  opts->show_help = 1;
  return 0;
}

static int opt_version(const char *value, size_t page_size, struct cli_options *opts)
{
  (void)value;
  (void)page_size;
  opts->show_version = 1;
  return 0;
}

static int find_opt(const char *tok)
{
  unsigned k;

  for (k = 0; k < OPT_TABLE_LEN; k++)
    if (strcmp(tok, OPT_TABLE[k].name) == 0)
      return (int)k;
  return -1;
}

static int is_operand(const char *tok)
{
  return tok[0] != '-' || tok[1] == '\0';
}

static void set_operands(struct cli_options *opts, char **argv, int count)
{
  opts->operands = (const char **)argv;
  opts->operands_count = count;
}

static int apply_idx(struct scan *sc, int *ip, int idx)
{
  const char *value = NULL;
  int i = *ip;

  if (OPT_TABLE[idx].has_value) {
    if (i + 1 >= sc->argc)
      return -1;
    value = sc->argv[i + 1];
    *ip = i + 1;
  }
  return OPT_TABLE[idx].fn(value, sc->page_size, sc->opts);
}

static int step(struct scan *sc, int *ip)
{
  const char *tok = sc->argv[*ip];
  int idx;

  if (sc->no_more) {
    set_operands(sc->opts, &sc->argv[*ip], sc->argc - *ip);
    return 1;
  }
  if (is_operand(tok)) {
    set_operands(sc->opts, &sc->argv[*ip], sc->argc - *ip);
    return 1;
  }
  if (strcmp(tok, "--") == 0) {
    sc->no_more = 1;
    return 0;
  }
  idx = find_opt(tok);
  if (idx < 0)
    return -1;
  return apply_idx(sc, ip, idx);
}

int cli_parse(int argc, char **argv, struct cli_options *opts)
{
  struct scan sc;
  int i;

  memset(opts, 0, sizeof(*opts));
  sc.argc = argc;
  sc.argv = argv;
  sc.opts = opts;
  sc.no_more = 0;
  sc.page_size = (size_t)sysconf(_SC_PAGESIZE);
  opts->cache.kind = CACHE_BYTES;
  opts->cache.bytes = DEFAULT_CACHE;
  for (i = 1; i < argc; i++) {
    int rc = step(&sc, &i);

    if (rc != 0)
      return rc < 0 ? -1 : 0;
  }
  set_operands(opts, &argv[argc], 0);
  return 0;
}
