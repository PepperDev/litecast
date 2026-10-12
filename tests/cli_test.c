#include "test_util.h"

#include "../src/cli/cache.c"
#include "../src/cli/cli.c"

static int t_defaults(void)
{
  struct cli_options opts;
  char *a[] = { "litecast", "song.flac" };

  EXPECT(cli_parse(2, a, &opts) == 0);
  EXPECT(opts.command_mode == 0);
  EXPECT(opts.cache_to_fs == 0);
  EXPECT(opts.no_arbitrary_range == 0);
  EXPECT(opts.show_help == 0 && opts.show_version == 0);
  EXPECT(opts.cache.kind == CACHE_BYTES);
  EXPECT(opts.cache.bytes == 64UL * 1024 * 1024);
  EXPECT(opts.device[0] == '\0');
  EXPECT(opts.operands_count == 1);
  EXPECT(strcmp(opts.operands[0], "song.flac") == 0);
  return 0;
}

static int t_options(void)
{
  struct cli_options opts;
  char *a[] = { "litecast", "-d", "Living Room TV", "-s", "-b", "1M",
    "-c", "ffmpeg", "-i", "x"
  };

  EXPECT(cli_parse(10, a, &opts) == 0);
  EXPECT(strcmp(opts.device, "Living Room TV") == 0);
  EXPECT(opts.cache_to_fs == 1);
  EXPECT(opts.cache.kind == CACHE_BYTES && opts.cache.bytes == 1024UL * 1024);
  EXPECT(opts.command_mode == 1);
  EXPECT(opts.operands_count == 3);
  EXPECT(strcmp(opts.operands[0], "ffmpeg") == 0);
  EXPECT(strcmp(opts.operands[2], "x") == 0);
  return 0;
}

static int t_long_forms(void)
{
  struct cli_options opts;
  char *a[] = { "litecast", "--help", "--cache", "25%", "--device", "TV",
    "--cache-to-fs", "--command", "yes"
  };

  EXPECT(cli_parse(9, a, &opts) == 0);
  EXPECT(opts.cache.kind == CACHE_PCT && opts.cache.pct == 25);
  EXPECT(strcmp(opts.device, "TV") == 0);
  EXPECT(opts.cache_to_fs == 1);
  EXPECT(opts.command_mode == 1);
  EXPECT(opts.show_help == 1);
  EXPECT(opts.operands_count == 1);
  return 0;
}

static int t_mode_last_wins(void)
{
  struct cli_options opts;
  char *a1[] = { "litecast", "-c", "-f", "file" };
  char *a2[] = { "litecast", "-f", "-c", "file" };
  char *a3[] = { "litecast", "--command", "--file", "file" };

  EXPECT(cli_parse(4, a1, &opts) == 0 && opts.command_mode == 0);
  EXPECT(cli_parse(4, a2, &opts) == 0 && opts.command_mode == 1);
  EXPECT(cli_parse(4, a3, &opts) == 0 && opts.command_mode == 0);
  return 0;
}

static int t_ddash(void)
{
  struct cli_options opts;
  char *a1[] = { "litecast", "--", "-x", "-n" };
  char *a2[] = { "litecast", "--file", "--", "-song", "tail" };
  char *a3[] = { "litecast", "-", "-b" };

  EXPECT(cli_parse(4, a1, &opts) == 0);
  EXPECT(opts.operands_count == 2);
  EXPECT(strcmp(opts.operands[0], "-x") == 0);
  EXPECT(strcmp(opts.operands[1], "-n") == 0);
  EXPECT(cli_parse(5, a2, &opts) == 0);
  EXPECT(opts.command_mode == 0);
  EXPECT(opts.operands_count == 2);
  EXPECT(strcmp(opts.operands[0], "-song") == 0);
  EXPECT(cli_parse(3, a3, &opts) == 0);
  EXPECT(opts.operands_count == 2);
  EXPECT(strcmp(opts.operands[0], "-") == 0);
  EXPECT(strcmp(opts.operands[1], "-b") == 0);
  return 0;
}

static int t_no_operands(void)
{
  struct cli_options opts;
  char *a[] = { "litecast" };

  EXPECT(cli_parse(1, a, &opts) == 0);
  EXPECT(opts.operands_count == 0);
  return 0;
}

static int t_errors(void)
{
  struct cli_options opts;
  char *aBad1[] = { "litecast", "-z" };
  char *aBad2[] = { "litecast", "--nope" };
  char *aBad3[] = { "litecast", "-b" };
  char *aBad4[] = { "litecast", "-d", "" };
  char *aBad5[] = { "litecast", "-b", "12x", "f" };
  char *aBad6[] = { "litecast", "-d", "x", "-b", "101%", "f" };
  char *aBad7[] = { "litecast", "--cache=1M", "f" };
  char *aBad8[] = { "litecast", "-b", "M", "f" };
  char *aBad9[] = { "litecast", "-b", "999999999999999999999999999999", "f" };

  EXPECT(cli_parse(2, aBad1, &opts) != 0);
  EXPECT(cli_parse(2, aBad2, &opts) != 0);
  EXPECT(cli_parse(2, aBad3, &opts) != 0);
  EXPECT(cli_parse(3, aBad4, &opts) != 0);
  EXPECT(cli_parse(4, aBad5, &opts) != 0);
  EXPECT(cli_parse(5, aBad6, &opts) != 0);
  EXPECT(cli_parse(3, aBad7, &opts) != 0);
  EXPECT(cli_parse(3, aBad8, &opts) != 0);
  EXPECT(cli_parse(3, aBad9, &opts) != 0);
  return 0;
}

static int t_repeated_cache_last_wins(void)
{
  struct cli_options opts;
  char *a[] = { "litecast", "-b", "1M", "--cache", "33%", "f" };

  EXPECT(cli_parse(6, a, &opts) == 0);
  EXPECT(opts.cache.kind == CACHE_PCT && opts.cache.pct == 33);
  return 0;
}

static int t_no_arbitrary_range(void)
{
  struct cli_options opts;
  char *a1[] = { "litecast", "-n", "-c", "ffmpeg", "x" };
  char *a2[] = { "litecast", "--no-arbitrary-range", "song.flac" };
  char *a3[] = { "litecast", "song.flac" };

  EXPECT(cli_parse(5, a1, &opts) == 0);
  EXPECT(opts.no_arbitrary_range == 1);
  EXPECT(opts.command_mode == 1);
  EXPECT(cli_parse(3, a2, &opts) == 0);
  EXPECT(opts.no_arbitrary_range == 1);
  EXPECT(opts.operands_count == 1);
  EXPECT(cli_parse(2, a3, &opts) == 0);
  EXPECT(opts.no_arbitrary_range == 0); /* off by default */
  return 0;
}

int main(void)
{
  RUN(t_defaults);
  RUN(t_options);
  RUN(t_long_forms);
  RUN(t_mode_last_wins);
  RUN(t_ddash);
  RUN(t_no_operands);
  RUN(t_errors);
  RUN(t_repeated_cache_last_wins);
  RUN(t_no_arbitrary_range);
  TEST_SUMMARY();
}
