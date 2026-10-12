#include "cast/cast.h"
#include "cast/verb.h"

#include <string.h>

/* === Media-namespace verdicts (DOMAIN.md §Session supervision) ===
 * One media frame is classified into the CTRL_END_* tri-state so the run
 * layer can tell a natural finish from a dead session. LOAD_FAILED stays
 * transport-fatal; PLAYING/BUFFERING never latch. */

static int ctrl_media_end(const struct cast_decoded *d, const char *type)
{
  char v[64];

  if (strcmp(type, "ERROR") == 0)
    return CTRL_END_ABORT;
  if (cast_json_get(d->payload, "playerState", v, sizeof v) != 0)
    return CTRL_END_NONE;
  if (strcmp(v, "IDLE") != 0)
    return CTRL_END_NONE;
  if (cast_json_get(d->payload, "idleReason", v, sizeof v) != 0)
    return CTRL_END_NONE;
  return strcmp(v, "FINISHED") == 0 ? CTRL_END_FINISHED : CTRL_END_ABORT;
}

/* Establishment gate: a BUFFERING/PLAYING status marks the session
 * established for the current LOAD; an abort verdict before that is the DMR
 * acking litecast's own LOAD (the replaced playback torn down, idleReason
 * INTERRUPTED — trace.20), not a session death, and must never arm a
 * restart. FINISHED is immune: a natural play-to-end implies the session
 * played. */
static int ctrl_media_est(struct cast_ctrl *c, const struct cast_decoded *d, const char *type)
{
  char v[64];
  int end;

  if (cast_json_get(d->payload, "playerState", v, sizeof v) == 0
      && (strcmp(v, "BUFFERING") == 0 || strcmp(v, "PLAYING") == 0))
    c->media_started = 1;
  end = ctrl_media_end(d, type);
  if (end == CTRL_END_ABORT && !c->media_started)
    return CTRL_END_NONE;
  return end;
}

int cast_ctrl_media(struct cast_ctrl *c, const struct cast_decoded *d)
{
  char type[64];
  int end;

  if (strcmp(d->ns, CAST_NS_MEDIA) != 0)
    return 0;
  if (cast_json_get(d->payload, "type", type, sizeof type) != 0)
    return 1;
  if (strcmp(type, "LOAD_FAILED") == 0)
    return -1;
  end = ctrl_media_est(c, d, type);
  if (end != CTRL_END_NONE)
    c->end_class = end;
  return 1;
}

int cast_ctrl_abandoned(const struct cast_ctrl *c)
{
  if (c == NULL)
    return 0;
  /* ABORT only ever latches for an established session (the gate above), so
   * the FINISHED arm is the only one that needs the mark re-tested. */
  return c->end_class == CTRL_END_ABORT || (c->end_class == CTRL_END_FINISHED && c->media_started);
}
