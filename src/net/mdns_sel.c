#include "net/mdns.h"

#include <ctype.h>
#include <string.h>

static int sel_ci(int c)
{
  return tolower(c);
}

static int match_char(const char *a, const char *b)
{
  return sel_ci((unsigned char)*a) == sel_ci((unsigned char)*b) || *a == '*';
}

/* `*`-only glob over a non-empty pattern; mdns_glob handles the empty case. */
static int glob_match(const char *p, const char *n)
{
  const char *star = NULL;
  const char *ss = NULL;

  while (*n != '\0') {
    if (match_char(p, n)) {
      if (*p == '*') {
        star = p++;
        ss = n;
      } else {
        p++;
        n++;
      }
    } else if (star != NULL) {
      p = star + 1;
      n = ++ss;
    } else {
      return 0;
    }
  }
  while (*p == '*')
    p++;
  return *p == '\0';
}

int mdns_glob(const char *pattern, const char *name)
{
  if (pattern == NULL || *pattern == '\0')
    return 1;
  return glob_match(pattern, name);
}

static int sel_eqn(const char *a, const char *b, size_t n)
{
  size_t k;

  for (k = 0; k < n; k++) {
    if (sel_ci((unsigned char)a[k]) != sel_ci((unsigned char)b[k]))
      return 0;
  }
  return 1;
}

int mdns_contains(const char *needle, const char *name)
{
  size_t nl;
  size_t len;
  size_t i;

  if (needle == NULL || *needle == '\0')
    return 1;
  nl = strlen(needle);
  len = strlen(name);
  if (len < nl)
    return 0;
  for (i = 0; i + nl <= len; i++) {
    if (sel_eqn(name + i, needle, nl))
      return 1;
  }
  return 0;
}

int mdns_first(const struct mdns_device *devices, int n, const char *pattern)
{
  int i;

  if (pattern == NULL || *pattern == '\0')
    return n > 0 ? 0 : -1;
  for (i = 0; i < n; i++) {
    if (mdns_glob(pattern, devices[i].name))
      return i;
  }
  return -1;
}

static int sel_sub_first(const struct mdns_device *devices, int n, const char *pattern)
{
  int i;

  for (i = 0; i < n; i++) {
    if (mdns_contains(pattern, devices[i].name))
      return i;
  }
  return -1;
}

/* DOMAIN §Device selection: glob during the window, then substring fallback
 * at close, then the first discovered device. */
int mdns_select(const struct mdns_device *devices, int n, const char *pattern)
{
  int g;

  if (pattern == NULL || *pattern == '\0')
    return mdns_first(devices, n, NULL);
  g = mdns_first(devices, n, pattern);
  if (g >= 0)
    return g;
  g = sel_sub_first(devices, n, pattern);
  if (g >= 0)
    return g;
  return mdns_first(devices, n, NULL);
}
