#include "test_util.h"

#include "../src/cli/cache.c"

#define PAGE 4096UL

static int t_suffixes(void)
{
  struct cache_cfg cfg;

  EXPECT(cli_parse_cache("1K", PAGE, &cfg) == 0);
  EXPECT(cfg.kind == CACHE_BYTES && cfg.bytes == PAGE);
  EXPECT(cli_parse_cache("1k", PAGE, &cfg) == 0 && cfg.bytes == PAGE);
  EXPECT(cli_parse_cache("2M", PAGE, &cfg) == 0 && cfg.bytes == 2UL * 1024 * 1024);
  EXPECT(cli_parse_cache("2m", PAGE, &cfg) == 0 && cfg.bytes == 2UL * 1024 * 1024);
  EXPECT(cli_parse_cache("1G", PAGE, &cfg) == 0 && cfg.bytes == 1UL << 30);
  EXPECT(cli_parse_cache("1g", PAGE, &cfg) == 0 && cfg.bytes == 1UL << 30);
  return 0;
}

static int t_percent(void)
{
  struct cache_cfg cfg;

  EXPECT(cli_parse_cache("0%", PAGE, &cfg) == 0);
  EXPECT(cfg.kind == CACHE_PCT && cfg.pct == 0);
  EXPECT(cli_parse_cache("50%", PAGE, &cfg) == 0 && cfg.pct == 50);
  EXPECT(cli_parse_cache("100%", PAGE, &cfg) == 0 && cfg.pct == 100);
  EXPECT(cli_parse_cache("101%", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("200%", PAGE, &cfg) != 0);
  return 0;
}

static int t_bare_number_and_junk(void)
{
  struct cache_cfg cfg;

  EXPECT(cli_parse_cache("1024", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("%", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("1.5M", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("1MB", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("64 M", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("12x", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("B", PAGE, &cfg) != 0);
  return 0;
}

static int t_overflow(void)
{
  struct cache_cfg cfg;

  EXPECT(cli_parse_cache("99999999999999999999G", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("18446744073709551615K", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("18446744073709551616", PAGE, &cfg) != 0);
  EXPECT(cli_parse_cache("7G7", PAGE, &cfg) != 0);
  return 0;
}

static int t_page_clamp(void)
{
  struct cache_cfg cfg;

  EXPECT(cli_parse_cache("1K", PAGE, &cfg) == 0 && cfg.bytes == PAGE);
  EXPECT(cli_parse_cache("0K", PAGE, &cfg) == 0 && cfg.bytes == PAGE);
  EXPECT(cli_parse_cache("4K", PAGE, &cfg) == 0 && cfg.bytes == PAGE);
  EXPECT(cli_parse_cache("8K", PAGE, &cfg) == 0 && cfg.bytes == 2 * PAGE);
  return 0;
}

int main(void)
{
  RUN(t_suffixes);
  RUN(t_percent);
  RUN(t_bare_number_and_junk);
  RUN(t_overflow);
  RUN(t_page_clamp);
  TEST_SUMMARY();
}
