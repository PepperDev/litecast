#ifndef LITECAST_CAST_VERB_H
#define LITECAST_CAST_VERB_H

#include "cast/cast.h"

/* Media-namespace frames feed session supervision (DOMAIN.md §Session
 * supervision). cast_ctrl_media drives one media frame: it arms the
 * establishment gate on the first BUFFERING/PLAYING status since the last
 * LOAD, classifies the terminal verdict (CTRL_END_*), and latches it on the
 * ctrl. LOAD_FAILED is transport-fatal (returns -1); routine status returns 1. */
int cast_ctrl_media(struct cast_ctrl *c, const struct cast_decoded *d);

/* Non-zero when the latched verdict means the DMR abandoned the pull rather
 * than playing the media out: an established session's ABORT (trace.12), or an
 * established session reporting FINISHED while the run can still feed a fresh
 * pull (trace.22 — the device gave up on a still-producing source, it is not a
 * natural play-to-end). Such a verdict belongs to the session-restart lane; a
 * FINISHED before the session ever played is the LOAD ack, not an
 * abandonment. */
int cast_ctrl_abandoned(const struct cast_ctrl *c);

#endif
