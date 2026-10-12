#include "cast/cast.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* === Tiny JSON writer === */

struct json_w {
  char *out;
  size_t cap;
  size_t len;
  int err;
};

struct jp {
  const char *key;
  const char *str;              /* string value, or NULL for a number pair */
  long num;
  int raw;                      /* str holds pre-serialized JSON, unquoted */
};

static void json_begin(struct json_w *w, char *out, size_t cap)
{
  w->out = out;
  w->cap = cap;
  w->len = 0;
  w->err = 0;
}

static void jw_raw(struct json_w *w, const char *s, size_t n)
{
  size_t room;

  room = w->cap > w->len ? w->cap - w->len : 0;
  if (n > room) {
    w->err = 1;
    n = room;
  }
  memcpy(w->out + w->len, s, n);
  w->len += n;
}

static void jw_char(struct json_w *w, char c)
{
  if (c == '"' || c == '\\') {
    const char tmp[2] = { '\\', c };
    jw_raw(w, tmp, 2);
  } else {
    jw_raw(w, &c, 1);
  }
}

static void jw_pair(struct json_w *w, const char *key, const char *value)
{
  size_t i;

  jw_raw(w, "\"", 1);
  jw_raw(w, key, strlen(key));
  jw_raw(w, "\":\"", 3);
  for (i = 0; value[i] != '\0'; i++)
    jw_char(w, value[i]);
  jw_raw(w, "\"", 1);
}

static void jw_num(struct json_w *w, const char *key, long v)
{
  char nb[24];
  int n;

  jw_raw(w, "\"", 1);
  jw_raw(w, key, strlen(key));
  jw_raw(w, "\":", 2);
  n = snprintf(nb, sizeof nb, "%ld", v);
  jw_raw(w, nb, (size_t)n);
}

/* Emit `"key":<raw>` where raw is pre-serialized JSON (an object or scalar). */
static void jw_raw_pair(struct json_w *w, const char *key, const char *raw)
{
  jw_raw(w, "\"", 1);
  jw_raw(w, key, strlen(key));
  jw_raw(w, "\":", 2);
  jw_raw(w, raw, strlen(raw));
}

static void jw_sep(struct json_w *w, int *first)
{
  if (*first) {
    *first = 0;
  } else {
    jw_raw(w, ",", 1);
  }
}

static int json_result(struct json_w *w)
{
  if (w->err != 0)
    return -1;
  if (w->len + 1 > w->cap)
    return -1;
  w->out[w->len] = '\0';
  return (int)w->len;
}

/* Emit one field per its kind: raw (pre-serialized JSON), string, or number. */
static void jf_emit(struct json_w *w, const struct jp *p)
{
  if (p->raw)
    jw_raw_pair(w, p->key, p->str);
  else if (p->str != NULL)
    jw_pair(w, p->key, p->str);
  else
    jw_num(w, p->key, p->num);
}

static int json_obj(struct json_w *w, const struct jp *pairs, int np)
{
  int i;
  int first = 1;

  if (w == NULL || pairs == NULL)
    return -1;
  jw_raw(w, "{", 1);
  for (i = 0; i < np; i++) {
    jw_sep(w, &first);
    jf_emit(w, &pairs[i]);
  }
  jw_raw(w, "}", 1);
  return json_result(w);
}

int json_bcast(char *out, size_t cap, const char *type)
{
  struct json_w w;
  struct jp p[1];

  if (out == NULL || type == NULL || cap < 1)
    return -1;
  json_begin(&w, out, cap);
  p[0] = (struct jp) { "type", type, 0, 0 };
  return json_obj(&w, p, 1);
}

int json_get_status(char *out, size_t cap, long rid)
{
  struct json_w w;
  struct jp p[2];

  if (out == NULL || cap < 1)
    return -1;
  json_begin(&w, out, cap);
  p[0] = (struct jp) { "type", "GET_STATUS", 0, 0 };
  p[1] = (struct jp) { "requestId", NULL, rid, 0 };
  return json_obj(&w, p, 2);
}

static const struct jp launch_def[3] = {
  {"type", "LAUNCH", 0, 0}, {"requestId", NULL, 0, 0}, {"appId", NULL, 0, 0},
};

int json_launch(char *out, size_t cap, long rid, const char *app_id)
{
  struct json_w w;
  struct jp p[3];

  if (out == NULL || app_id == NULL || cap < 1)
    return -1;
  memcpy(p, launch_def, sizeof p);
  p[1].num = rid;
  p[2].str = app_id;
  json_begin(&w, out, cap);
  return json_obj(&w, p, 3);
}

/* Build the `media` object for LOAD: {contentId, contentType, streamType}. */
static int jm_media(char *buf, size_t cap, const struct cast_load *l)
{
  struct jp p[3] = {
    {.key = "contentId"}, {.key = "contentType"}, {.key = "streamType"},
  };
  struct json_w w;

  p[0].str = l->content_id;
  p[1].str = l->content_type;
  p[2].str = l->stream_type;
  json_begin(&w, buf, cap);
  return json_obj(&w, p, 3);
}

/* Build `{type:STOP, requestId, sessionId}` to stop the running receiver
 * application (DOMAIN.md §Close, mkchromecast parity). */
int json_stop(char *out, size_t cap, long rid, const char *session_id)
{
  struct json_w w;
  struct jp p[3];

  if (out == NULL || cap < 1)
    return -1;
  json_begin(&w, out, cap);
  p[0] = (struct jp) { "type", "STOP", 0, 0 };
  p[1] = (struct jp) { "requestId", NULL, rid, 0 };
  p[2] = (struct jp) { "sessionId", session_id ? session_id : "", 0, 0 };
  return json_obj(&w, p, 3);
}

static const struct jp load_def[5] = {
  {"requestId", NULL, 0, 0}, {"type", "LOAD", 0, 0},
  {"sessionId", NULL, 0, 0}, {"media", NULL, 0, 1},
  {"autoplay", "true", 0, 1},
};

int json_load(char *out, size_t cap, const struct cast_load *l)
{
  struct json_w w;
  struct jp p[5];
  char media[CAST_JSON_CAP];

  if (out == NULL || l == NULL)
    return -1;
  if (jm_media(media, sizeof media, l) < 0)
    return -1;
  memcpy(p, load_def, sizeof p);
  p[0].num = l->rid;
  p[2].str = l->session_id ? l->session_id : "";
  p[3].str = media;
  json_begin(&w, out, cap);
  return json_obj(&w, p, 5);
}
