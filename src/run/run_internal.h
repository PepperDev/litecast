#ifndef LITECAST_RUN_INTERNAL_H
#define LITECAST_RUN_INTERNAL_H

#include "run/run.h"

#include <stdint.h>

/* Cross-file internals of the event loop. Declared here so the loop,
 * pump, and init units can call one another while each stays a standalone
 * .c (and thus a per-file 80% coverage unit when included by main_test). */

/* init.c — epoll set reconciliation used by the pump on every iteration. */
void run_sync(struct run_ctx *ctx);

/* pump.c — per-wake event handlers, each bounded (QA §Event-loop fairness). */
void run_sigs(struct run_ctx *ctx);
void tick_drain(int fd);
int producer_drive_all(struct run_ctx *ctx);
int accept_drive(struct run_ctx *ctx);
int ctrl_drive(struct run_ctx *ctx, uint64_t now_ms);
void conn_drive(struct run_ctx *ctx, size_t slot, uint32_t evs);
int run_pump(struct run_ctx *ctx, uint64_t now_ms);
int cast_done(struct run_ctx *ctx, uint64_t now_ms);

/* prod.c — producer opening, spawn + gating + idle termination. */
int producer_spawn(struct run_ctx *ctx);
int producer_gated(const struct run_ctx *ctx, size_t i);
void producer_idle_reap(struct run_ctx *ctx, uint64_t now_ms);

#endif
