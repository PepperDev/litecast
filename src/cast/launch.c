#include "cast/cast.h"

#include <string.h>

/* === Default Media Receiver session acquisition (DOMAIN.md §Transport) ===
 *
 * A working media LOAD needs a Cast receiver session. The device's receiver
 * status (RECEIVER_STATUS) has no `type` field and, when idle, no `sessionId`
 * (no application is running). To cast, litecast LAUNCHes the Default Media
 * Receiver (CC1AD845) and routes the media channel to the reply's per-session
 * transportId rather than to the platform `receiver-0`. This module owns that
 * acquisition; ctrl.c owns the byte-stream pump and heartbeats. */

/* Send LAUNCH of the Default Media Receiver on the receiver namespace. A new
 * receiver session exposes no `sessionId` until an application is running, so
 * the idle device must be launched before LOAD is possible. */
static int ctrl_launch(struct cast_ctrl *c)
{
  char json[CAST_JSON_CAP];
  int n;

  if (c->state != CTRL_LAUNCH)
    return 0;
  n = json_launch(json, sizeof json, ++c->rid, CAST_DMR_APPID);
  if (n < 0)
    return -1;
  if (cast_ctrl_send(c, CAST_NS_RECEIVER, json) != 0)
    return -1;
  c->state = CTRL_LAUNCH;       /* stay in LAUNCH awaiting the reply */
  return 1;
}

/* Establish the media channel: when a transportId is available, connect to it
 * (a per-session virtual channel, not `receiver-0`) before any media frames. */
static int ctrl_media_connect(struct cast_ctrl *c)
{
  if (c->transport_id[0] == '\0')
    return 0;
  return cast_ctrl_send_to(c, CAST_NS_CONNECTION, c->transport_id, "{\"type\":\"CONNECT\"}") == 0 ? 1 : -1;
}

/* Check whether a RECEIVER_STATUS payload refers to the DMR by appId. */
static int is_dmr_status(const struct cast_decoded *d)
{
  char appid[64];

  appid[0] = '\0';
  (void)cast_json_get(d->payload, "appId", appid, sizeof appid);
  return strcmp(appid, CAST_DMR_APPID) == 0;
}

/* Parse sessionId/transportId out of a receiver status and acquire the media
 * session: use an existing DMR session directly, or (idle) request a LAUNCH.
 * Returns 1 on progress, 0 when awaiting launch reply, -1 on error. */
static int ctrl_acquire(struct cast_ctrl *c, const struct cast_decoded *d)
{
  c->session_id[0] = '\0';
  (void)cast_json_get(d->payload, "sessionId", c->session_id, sizeof c->session_id);
  c->transport_id[0] = '\0';
  (void)cast_json_get(d->payload, "transportId", c->transport_id, sizeof c->transport_id);
  if (c->session_id[0] != '\0' && (is_dmr_status(d) || c->state == CTRL_LAUNCH)) {
    c->state = CTRL_READY;
    return ctrl_media_connect(c);
  }
  if (c->state == CTRL_LAUNCH)
    return 0;
  c->state = CTRL_LAUNCH;
  return ctrl_launch(c);
}

/* Receiver status on the receiver namespace drives the session acquisition.
 * The reply is a RECEIVER_STATUS: real devices emit it *without* a `type`
 * field, and when idle it carries no `sessionId`. */
int cast_ctrl_status(struct cast_ctrl *c, const struct cast_decoded *d)
{
  char type[64];
  int has_type;

  if (strcmp(d->ns, CAST_NS_RECEIVER) != 0)
    return 0;
  has_type = cast_json_get(d->payload, "type", type, sizeof type) == 0;
  if (!has_type)
    return ctrl_acquire(c, d);  /* no type: still a RECEIVER_STATUS */
  if (strcmp(type, "LAUNCH_ERROR") == 0 || strcmp(type, "INVALID_REQUEST") == 0)
    return -1;                  /* receiver refused the launch/request */
  if (strcmp(type, "RECEIVER_STATUS") != 0)
    return 0;
  return ctrl_acquire(c, d);
}
