#include "cast/cast.h"

#include <stdint.h>
#include <string.h>

/* === Tiny JSON lookups (cast_json_get) ===
 *
 * Extract one string value by key from a Cast JSON payload. A pragmatic
 * scanner (no full JSON parser): it matches a `"key"` close-quote anywhere
 * and returns the quoted value that follows it, so fields nested inside
 * `applications[]` (e.g. sessionId, transportId) are reachable too. */

/* Find the next `"key"` in a scan starting at *off; store its opening-quote
 * index there. Values are assumed to be at most one level deep. */
static int jv_find(const char *j, const char *key, size_t *off)
{
  size_t k = strlen(key);
  size_t n = strlen(j);
  size_t i;

  for (i = *off; i + k + 2 <= n; i++) {
    if (j[i] == '"' && memcmp(j + i + 1, key, k) == 0 && j[i + k + 1] == '"') {
      *off = i;
      return 0;
    }
  }
  return -1;
}

/* Advance past `"key"`, optional whitespace, ':', whitespace and the opening
 * quote; SIZE_MAX when the shape does not match (e.g. key without a value). */
static size_t jv_after(const char *j, size_t i)
{
  i += strcspn(j + i, ":");
  if (j[i] != ':')
    return SIZE_MAX;
  i++;
  i += strspn(j + i, " \t");
  if (j[i] != '"')
    return SIZE_MAX;
  return i + 1;
}

/* Read one value byte; returns 0 at the closing quote, -1 on an unterminated
 * escape. Common escapes are unescaped; unknown ones pass through. */
static int jv_read(const char *j, size_t *i, char *c)
{
  char ch = j[*i];

  if (ch == '"')
    return 0;
  if (ch == '\\') {
    (*i)++;
    ch = j[*i];
    if (ch == '\0')
      return -1;
  }
  if (ch == '\0')
    return -1;
  *c = ch;
  (*i)++;
  return 1;
}

static int jv_str(const char *j, size_t i, char *out, size_t cap)
{
  size_t o = 0;
  char c;

  for (;;) {
    int r = jv_read(j, &i, &c);

    if (r < 0)
      return -1;
    if (r == 0)
      break;
    if (o + 1 < cap)
      out[o++] = c;
  }
  out[o] = '\0';
  return 0;
}

int cast_json_get(const char *json, const char *key, char *out, size_t cap)
{
  size_t i = 0;

  if (out == NULL || cap == 0)
    return -1;
  for (;;) {
    size_t v;

    if (jv_find(json, key, &i) != 0)
      return -1;
    v = jv_after(json, i);
    if (v != SIZE_MAX)
      return jv_str(json, v, out, cap);
    i += strlen(key) + 2;       /* `"key"` without a value: try the next match */
  }
}
