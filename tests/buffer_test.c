#include "test_util.h"

#include "../src/buf/buffer.c"
#include "../src/buf/cvec.c"

#define PAGE 4096UL

static void make_cfg(struct cache_cfg *cfg, int kind, size_t bytes, unsigned int pct)
{
  memset(cfg, 0, sizeof(*cfg));
  cfg->kind = kind;
  cfg->bytes = bytes;
  cfg->pct = pct;
}

static int t_open_close_fixed(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;

  make_cfg(&cfg, CACHE_BYTES, 1024UL * 1024, 0);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_cap(&b) == 1024UL * 1024);
  EXPECT(buffer_len(&b) == 0);
  EXPECT(buffer_data(&b) != NULL);
  buffer_close(&b);
  EXPECT(b.data == NULL && b.cap == 0);
  return 0;
}

static int t_boundary_args(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;

  make_cfg(&cfg, CACHE_BYTES, 1000, 0);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  EXPECT(buffer_open(&b, 0, &cfg, &src) != 0);
  EXPECT(buffer_open(&b, PAGE, NULL, &src) != 0);
  EXPECT(buffer_open(&b, PAGE, &cfg, NULL) != 0);
  EXPECT(buffer_open(NULL, PAGE, &cfg, &src) != 0);
  return 0;
}

static int t_file_plain_fill(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char raw[2000];
  unsigned char out[2000];
  size_t n;

  make_cfg(&cfg, CACHE_BYTES, 1000, 0);
  memset(raw, 0x5A, sizeof(raw));
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_cap(&b) == PAGE);
  EXPECT(buffer_append(&b, raw, 1000) == 0);
  EXPECT(buffer_len(&b) == 1000);
  EXPECT(buffer_append(&b, raw, 1000) == 0);
  EXPECT(buffer_len(&b) == 2000);
  EXPECT(buffer_append(&b, raw, 2000) == 0);
  EXPECT(buffer_len(&b) == 4000);
  EXPECT(buffer_append(&b, raw, 96) == 0);
  EXPECT(buffer_len(&b) == PAGE);
  EXPECT(buffer_append(&b, raw, 1) != 0);
  EXPECT(buffer_read_at(&b, 0, out, 2000) == 0);
  EXPECT(memcmp(out, raw, 2000) == 0);
  EXPECT(buffer_read_at(&b, 2000, out, 2000) == 0);
  EXPECT(buffer_read_at(&b, PAGE - 1, out, 2) != 0);
  EXPECT(buffer_consumer_read(&b, 0, out, 10, &n) != 0);
  buffer_close(&b);
  return 0;
}

static int t_file_pct_trusted(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char raw[5000];

  make_cfg(&cfg, CACHE_PCT, 0, 50);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 10000;
  memset(raw, 0x11, sizeof(raw));
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_cap(&b) == 5000);
  EXPECT(buffer_target(&b) == 5000);
  EXPECT(buffer_append(&b, raw, 5000) == 0);
  EXPECT(buffer_append(&b, raw, 1) != 0);
  EXPECT(buffer_received(&b) == 5000);
  buffer_close(&b);
  return 0;
}

static int t_pct_overflow(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;

  make_cfg(&cfg, CACHE_PCT, 0, 100);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = (size_t)-1;
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) != 0);
  return 0;
}

static int t_file_pct_untrusted(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char raw[64];

  make_cfg(&cfg, CACHE_PCT, 0, 50);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 0;
  src.size = 0;
  memset(raw, 0x22, sizeof(raw));
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_cap(&b) == PAGE);
  EXPECT(buffer_append(&b, raw, 64) == 0);
  EXPECT(buffer_received(&b) == 64);
  EXPECT(buffer_target(&b) == PAGE);
  for (size_t i = 0; i < 100; i++)
    EXPECT(buffer_append(&b, raw, 64) == 0);
  EXPECT(buffer_received(&b) == 6464);
  EXPECT(buffer_target(&b) >= 4096);
  buffer_close(&b);
  return 0;
}

static int t_command_plain(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char raw[2048];

  make_cfg(&cfg, CACHE_BYTES, 4096, 0);
  src.mode = BUFFER_MODE_COMMAND;
  src.size_trustworthy = 0;
  src.size = 0;
  memset(raw, 0x33, sizeof(raw));
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_cap(&b) == PAGE);
  EXPECT(buffer_append(&b, raw, 2048) == 0);
  EXPECT(buffer_append(&b, raw, 2048) == 0);
  EXPECT(buffer_cap(&b) == 4096);
  EXPECT(buffer_append(&b, raw, 2048) != 0);
  buffer_close(&b);
  return 0;
}

static int t_command_pct100(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char raw[256];

  make_cfg(&cfg, CACHE_PCT, 0, 100);
  src.mode = BUFFER_MODE_COMMAND;
  src.size_trustworthy = 0;
  src.size = 0;
  memset(raw, 0x44, sizeof(raw));
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  for (size_t i = 0; i < 200; i++)
    EXPECT(buffer_append(&b, raw, 256) == 0);
  EXPECT(buffer_len(&b) == 51200);
  EXPECT(buffer_cap(&b) >= 51200);
  EXPECT(buffer_received(&b) == 51200);
  EXPECT(buffer_target(&b) == 51200);
  buffer_close(&b);
  return 0;
}

static int t_offset(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char raw[200];
  unsigned char out[200];
  size_t cidx;
  size_t got;

  make_cfg(&cfg, CACHE_BYTES, 4096, 0);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  memset(raw, 0x66, sizeof raw);
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_offset(&b) == 0);
  EXPECT(buffer_append(&b, raw, 100) == 0);
  EXPECT(buffer_append(&b, raw, 100) == 0);
  EXPECT(buffer_received(&b) == 200);
  EXPECT(buffer_offset(&b) == 0);

  /* A consumer at the head plus compaction drops the prefix: the offset
   * reports where the retained window begins in the stream. */
  EXPECT(buffer_add_consumer(&b, 0, &cidx) == 0);
  EXPECT(buffer_consumer_read(&b, cidx, out, 50, &got) == 0);
  EXPECT(got == 50);
  buffer_compact(&b, 50);
  EXPECT(buffer_len(&b) == 150);
  EXPECT(buffer_received(&b) == 200);
  EXPECT(buffer_offset(&b) == 50);
  buffer_remove_consumer(&b, cidx);
  buffer_close(&b);
  return 0;
}

static int t_compact_anchor(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char in[512];
  unsigned char out[512];
  size_t idx_a;
  size_t idx_b;
  size_t got;
  unsigned int k;

  make_cfg(&cfg, CACHE_BYTES, 4096, 0);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  for (k = 0; k < 200; k++)
    in[k] = (unsigned char)k;
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_append(&b, in, 200) == 0);
  EXPECT(buffer_add_consumer(&b, 0, &idx_a) == 0);
  EXPECT(buffer_consumer_read(&b, idx_a, out, 50, &got) == 0);
  EXPECT(got == 50);
  EXPECT(buffer_append(&b, in, 200) == 0);
  EXPECT(buffer_add_consumer(&b, 100, &idx_b) == 0);
  EXPECT(buffer_lowest(&b) == 50);
  buffer_compact(&b, 50);
  EXPECT(buffer_lowest(&b) == 0);
  EXPECT(buffer_len(&b) == 350);
  EXPECT(buffer_consumer_read(&b, idx_a, out, 20, &got) == 0);
  EXPECT(got == 20);
  EXPECT(out[0] == 50 && out[19] == 69);
  EXPECT(buffer_consumer_read(&b, idx_b, out, 10, &got) == 0);
  EXPECT(got == 10);
  EXPECT(out[0] == 100);
  buffer_remove_consumer(&b, idx_a);
  EXPECT(buffer_lowest(&b) == 60);
  buffer_close(&b);
  return 0;
}

static int t_waiting_consumer(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char in[512];
  unsigned char out[32];
  size_t idx;
  size_t got;
  unsigned int k;

  make_cfg(&cfg, CACHE_BYTES, 4096, 0);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  for (k = 0; k < 200; k++)
    in[k] = (unsigned char)k;
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_append(&b, in, 8) == 0);

  /* A consumer attached ahead of the produced frontier (wait-for-position)
   * reads nothing until the producer reaches it. */
  EXPECT(buffer_add_consumer(&b, 12, &idx) == 0);
  EXPECT(buffer_consumer_read(&b, idx, out, 4, &got) == 0);
  EXPECT(got == 0);
  EXPECT(buffer_append(&b, in + 8, 4) == 0);    /* position 8..12 */
  EXPECT(buffer_consumer_read(&b, idx, out, 4, &got) == 0);
  EXPECT(got == 0);             /* not reached position 12 yet */
  EXPECT(buffer_append(&b, in + 12, 8) == 0);   /* position 12 now produced */
  EXPECT(buffer_consumer_read(&b, idx, out, 4, &got) == 0);
  EXPECT(got == 4 && out[0] == 12 && out[3] == 15);

  buffer_remove_consumer(&b, idx);
  buffer_close(&b);
  return 0;
}

/* A sole waiting consumer (claim ahead of the frontier) must not underflow
 * compaction: the whole unclaimed window yields and slides with the base —
 * but only as far as the room the next package needs (DOMAIN.md §Compaction:
 * free = min(read_off_lowest, need)), never past the least-behind consumer. */
static int t_waiting_compact(void)
{
  struct cache_cfg cfg;
  struct buf_source src;
  struct buffer b;
  unsigned char in[128];
  unsigned char out[32];
  size_t idx;
  size_t got;
  size_t i;

  make_cfg(&cfg, CACHE_BYTES, 64, 0);
  src.mode = BUFFER_MODE_FILE;
  src.size_trustworthy = 1;
  src.size = 999;
  for (i = 0; i < sizeof in; i++)
    in[i] = (unsigned char)i;

  /* A producer fills the capped window while the waiting consumer claims a
   * deep start: a full window must compact (drop the unclaimed head) and
   * keep producing, sliding the window until it retains the claimed start. */
  EXPECT(buffer_open(&b, PAGE, &cfg, &src) == 0);
  EXPECT(buffer_append(&b, in, 64) == 0);
  EXPECT(buffer_add_consumer(&b, 100, &idx) == 0);
  buffer_compact(&b, 20);       /* the producer needs room for the next read */
  EXPECT(buffer_len(&b) == 44); /* only the needed 20 bytes yielded */
  EXPECT(buffer_offset(&b) == 20);
  EXPECT(buffer_lowest(&b) == 80);      /* claim slid with the base */
  EXPECT(buffer_append(&b, in + 64, 20) == 0);  /* offsets 64..83 */
  EXPECT(buffer_consumer_read(&b, idx, out, 4, &got) == 0);
  EXPECT(got == 0);             /* claim still ahead */
  EXPECT(buffer_append(&b, in + 84, 30) == 0);  /* offsets 84..113 */
  EXPECT(buffer_consumer_read(&b, idx, out, 4, &got) == 0);
  EXPECT(got == 4 && out[0] == 100 && out[3] == 103);

  buffer_remove_consumer(&b, idx);
  buffer_close(&b);
  return 0;
}

static int t_cvec_growth(void)
{
  struct cvec v;
  struct buf_consumer c;
  size_t idx;
  int k;

  c.read_off = 7;
  EXPECT(cvec_init(&v) == 0);
  EXPECT(v.el == v.inl && v.cap == CVEC_INLINE);
  for (k = 0; k < 10; k++)
    EXPECT(cvec_push(&v, c, &idx) == 0 && idx == (size_t)k);
  EXPECT(v.cap >= 10 && v.el != v.inl);
  EXPECT(v.el[5].read_off == 7);
  cvec_pop(&v, 3);
  EXPECT(v.len == 9 && v.el[3].read_off == 7);
  cvec_clear(&v);
  EXPECT(v.el == v.inl && v.len == 0 && v.cap == CVEC_INLINE);
  return 0;
}

static int t_cvec_shrink(void)
{
  struct cvec v;
  struct buf_consumer c;
  size_t idx;
  int k;

  c.read_off = 3;
  EXPECT(cvec_init(&v) == 0);
  for (k = 0; k < 20; k++)
    EXPECT(cvec_push(&v, c, &idx) == 0);
  EXPECT(v.cap >= 32 && v.el != v.inl);
  while (v.len > 0)
    cvec_pop(&v, v.len - 1);
  EXPECT(v.len == 0 && v.el == v.inl && v.cap == CVEC_INLINE);
  cvec_clear(&v);
  return 0;
}

static int t_cvec_boundary(void)
{
  struct cvec v;
  struct buf_consumer c;
  size_t idx;

  c.read_off = 1;
  EXPECT(cvec_init(NULL) != 0);
  cvec_clear(NULL);
  EXPECT(cvec_push(NULL, c, &idx) != 0);
  EXPECT(cvec_init(&v) == 0);
  cvec_pop(&v, 0);
  cvec_pop(NULL, 0);
  cvec_pop(&v, 5);
  cvec_clear(&v);
  return 0;
}

int main(void)
{
  RUN(t_open_close_fixed);
  RUN(t_boundary_args);
  RUN(t_file_plain_fill);
  RUN(t_file_pct_trusted);
  RUN(t_pct_overflow);
  RUN(t_file_pct_untrusted);
  RUN(t_command_plain);
  RUN(t_command_pct100);
  RUN(t_compact_anchor);
  RUN(t_waiting_consumer);
  RUN(t_waiting_compact);
  RUN(t_offset);
  RUN(t_cvec_growth);
  RUN(t_cvec_shrink);
  RUN(t_cvec_boundary);
  TEST_SUMMARY();
}
