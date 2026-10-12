#ifndef LITECAST_TLS_CTRL_H
#define LITECAST_TLS_CTRL_H

/* TLS transport for the Cast control channel (DOMAIN.md §Encrypted vs
 * plaintext). This small seam sits between the frame reader/writer and the
 * raw fd: before any Cast frame it runs the TLS handshake to the security
 * latch, then carries every frame inside TLS app-data records. */

#include <sys/types.h>          /* ssize_t */

struct cast_io;
struct cast_ctrl;

/* Classify the transport enum: 1 = TLS/AUTO, 0 = PLAIN, -1 = invalid. */
int tls_ctrl_mode(int transport);

/* Set up the control channel transport: allocate the TLS session for an
 * encrypted transport (state = CTRL_TLS), otherwise enter the plaintext
 * CONNECT path. Cleans up on failure. Returns 0 or -1. */
int tls_ctrl_setup(struct cast_ctrl *c, int tls);

/* Drive one step of the TLS transport handshake stage. Returns 1 = security
 * latch set (the caller installs the TLS io and starts the Cast handshake
 * as the very next frame), 0 = needs more I/O, -1 = handshake error,
 * -2 = a plaintext legacy peer was detected (caller reconnects as PLAIN). */
int tls_ctrl_step(struct cast_ctrl *c);

/* TLS io hooks: read serves decrypted app-data, write seals plaintext. */
ssize_t tls_io_read(struct cast_io *io, unsigned char *buf, size_t cap);
ssize_t tls_io_write(struct cast_io *io, const unsigned char *buf, size_t cap);

#endif
