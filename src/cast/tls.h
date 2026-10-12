#ifndef LITECAST_TLS_H
#define LITECAST_TLS_H

#include "cast/cast.h"

#include <stddef.h>
#include <stdint.h>

/* Client-side TLS 1.2 (RFC 5246 / 4492 / 8422) over a cast_io byte stream.
 * The ClientHello builder lives in tls/hello.c, session/io in tls/io.c,
 * the record + handshake framing in tls/record.c, and the handshake
 * message semantics in tls.c. Only the suites in TLS_SUITE_* are ever
 * offered; a peer negotiating anything else aborts the handshake — never a
 * silent downgrade (DOMAIN.md §Minimal TLS client). */

enum {
  TLS_MAX_MSG = CAST_MAX_FRAME, /* QA.md §TLS: record & message bounds */
  TLS_REC_CHANGE_CIPHER_SPEC = 20,      /* record content type: CCS */
  TLS_REC_ALERT = 21,           /* record content type: alert (fatal) */
  TLS_REC_HANDSHAKE = 22,       /* record content type: handshake */
  TLS_REC_APP_DATA = 23,        /* record content type: application */
  TLS_HELLO_CAP = 256,          /* ClientHello fits here, record-included */
  TLS_P256_POINT_LEN = 65,      /* uncompressed P-256 point (0x04||X||Y) */
  TLS_CURVE_TYPE_NAMED = 0x03,
  TLS_POINT_UNCOMPRESSED = 0x04,
  TLS_VERSION_1_2 = 0x0303      /* negotiated_version / client_version */
};

enum {
  TLS_DETECT_WAIT = 0,          /* no byte received yet; keep probing */
  TLS_DETECT_TLS = 1,           /* first byte: TLS record content type */
  TLS_DETECT_PLAINTEXT = 2      /* any other byte: legacy, drop TLS framing */
};

enum {
  TLS_SUITE_CHACHA = 0xCCA8,    /* ECDHE-RSA-CHACHA20-POLY1305 (primary) */
  TLS_SUITE_AES_GCM = 0xC02F,   /* ECDHE-RSA-AES128-GCM-SHA256 (alt) */
  TLS_CURVE_P256 = 0x0017       /* secp256r1, the only curve we do */
};

enum {
  TLS_EXT_CURVES = 0x000A,      /* elliptic_curves */
  TLS_EXT_POINTS = 0x000B,      /* ec_point_formats */
  TLS_EXT_SIGALGS = 0x000D,     /* signature_algorithms */
  TLS_EXT_RENEG = 0xFF01,       /* renegotiation_info */
  TLS_SIG_RSA = 0x01,
  TLS_HASH_SHA256 = 0x04,
  TLS_HASH_SHA1 = 0x02
};

enum {
  TLS_HS_CLIENT_HELLO = 1,
  TLS_HS_SERVER_HELLO = 2,
  TLS_HS_CERTIFICATE = 11,
  TLS_HS_SERVER_KEY_EXCHANGE = 12,
  TLS_HS_SERVER_HELLO_DONE = 14,
  TLS_HS_CLIENT_KEY_EXCHANGE = 16,
  TLS_HS_FINISHED = 20
};

enum {
  TLS_KEY_BLOCK = 88            /* 32 key + 32 key + 12 IV + 12 IV */
};

/* Parsed ServerKeyExchange (RFC 4492 §5.4): the ECDH params and the signed
 * payload, as opaque blobs. server_params is the RFC 4492 §5.4
 * ServerECDHParams copied verbatim; the signature (RSA-PKCS1 v1.5) is
 * verified over client_random || server_random || server_params before any
 * point is used. */
struct tls_ske {
  uint16_t curve;
  unsigned char point[TLS_P256_POINT_LEN + 1];
  size_t point_n;
  uint16_t sigalg;
  unsigned char *params;        /* signed body, owned */
  size_t params_n;
  unsigned char *sig;           /* owned */
  size_t sig_n;
};

enum {
  TLS_PH_SEND_HELLO = 0,
  TLS_PH_READ = 1
};

/* Session state. All buffers are owned; tls_hs_close() releases them. */
struct tls_hs {
  struct cast_io *io;
  int phase;

  /* outbound pending write (ClientHello record) */
  unsigned char tx[TLS_HELLO_CAP];
  size_t tx_n;
  size_t tx_off;

  /* raw unparsed input queue */
  unsigned char *inq;
  size_t inq_n;
  size_t inq_off;
  size_t inq_cap;

  /* incoming record */
  unsigned char rh[5];          /* record header accumulation */
  size_t rh_n;
  int rec_type;                 /* record content type */
  size_t rlen;                  /* payload length from the header */
  unsigned char *rec;           /* record payload */
  size_t rec_n;
  size_t rec_cap;
  size_t rec_off;               /* payload consumed into the handshake */
  int rec_dec;                  /* this record already decrypted */

  /* one handshake message being assembled (may span records) */
  int hs_type;
  uint32_t hs_len;
  int hs_hdr_done;
  unsigned char hs_phdr[4];     /* partial 4-byte handshake header */
  size_t hs_phdr_n;
  unsigned char *hs_body;
  size_t hs_n;
  size_t hs_cap;
  int hs_ready;

  /* negotiated values */
  uint16_t version;
  uint16_t suite;
  unsigned char client_random[32];      /* echoed into ServerHello & Finished */
  unsigned char server_random[32];
  unsigned char *leaf;          /* server leaf cert DER, owned */
  size_t leaf_n;
  struct tls_ske ske;

  /* client ECDHE (tls/ecdh.c); premaster = x-coordinate of the shared
   * point, a 32-byte field element (RFC 8422 §5.10) */
  struct tls_ecdhe {
    unsigned char priv[32];
    unsigned char pub[TLS_P256_POINT_LEN];
    unsigned char premaster[32];
    int keyed;                  /* ephemeral key pair generated */
    int done;                   /* shared secret derived, priv wiped */
  } ecdhe;

  /* TLS handshake transcript (RFC 5246 §7.4.9): raw type||len||body of every
   * handshake message, both directions, up to but excluding Finished. */
  unsigned char *trans;
  size_t trans_n;
  size_t trans_cap;

  /* post-handshake decrypted application data, buffered for the transport
   * reader. Only populated once the security latch (fin.verified) is set and
   * an APP_DATA record is decrypted. */
  unsigned char *ap;
  size_t ap_n;
  size_t ap_cap;
  size_t ap_off;

  /* cipher state; only live once the key schedule runs (tls_fin_begin) */
  unsigned char master[48];
  unsigned char c_key[32];      /* client-write key (our send) */
  unsigned char c_iv[12];
  unsigned char s_key[32];      /* server-write key (our recv) */
  unsigned char s_iv[12];
  struct {
    int stage;                  /* 0 idle, 1 keys, 2 client Finished sent */
    uint64_t c_seq;             /* client outbound record seq (0 = Finished) */
    uint64_t s_seq;             /* server inbound record seq (0 = Finished) */
    int cipher_on;              /* client Finished / later records encrypted */
    int peer_cipher;            /* server records are now encrypted */
    int verified;               /* server Finished verified: latch set */
  } fin;
};

/* tls/ecdh.c */
#define TLS_ECDHE_RETRIES 4     /* bad-luck scalars in [1, n-1]; 2^-254 */
int tls_ecdhe_pub(const unsigned char sk[32], unsigned char out[TLS_P256_POINT_LEN]);
int tls_ecdhe_shared(const unsigned char sk[32], const unsigned char peer[TLS_P256_POINT_LEN], unsigned char out[32]);
int tls_ecdhe_keygen(struct tls_hs *s); /* 0, or -1 aborts */
int tls_ecdhe_derive(struct tls_hs *s); /* wipes priv on success */
#ifdef LITECAST_TEST
void tls_test_prng_reset(void); /* replay hook; never in bin/ */
#endif

/* tls/hello.c */
int tls_hs_init(struct tls_hs *s, struct cast_io *io);
void tls_hs_close(struct tls_hs *s);
int tls_random(unsigned char out[32]);
int tls_client_hello(unsigned char out[TLS_HELLO_CAP], const unsigned char random[32]);

/* tls/detect.c — one-shot first-byte transport decision (DOMAIN.md
 * §Encrypted vs plaintext, QA.md §TLS): TLS_DETECT_*, or -1 on bad args. */
int tls_hs_detect(const unsigned char *p, size_t n);

/* tls/io.c */
int tls_hs_send_hello(struct tls_hs *s, const unsigned char random[32]);
int tls_hs_step(struct tls_hs *s);      /* flush tx, then pump; same returns */

/* tls/record.c */
int tls_hs_feed(struct tls_hs *s, const unsigned char *p, size_t n);
int tls_hs_pump(struct tls_hs *s);      /* 1 = hs msg ready, 0 = wb, -1 = err */
int tls_hs_message(const struct tls_hs *s, int *type, const unsigned char **body, size_t *n);

/* Post-latch record transport (the frame-carrying record IO):
 * - tls_rec_seal seals one application-data plaintext chunk into a full TLS
 *   APP_DATA record (header || ciphertext || tag), advancing c_seq.
 * - tls_rec_available reports buffered decrypted app-data bytes (after a
 *   pump that drained APP_DATA records post-latch). */
int tls_rec_seal(struct tls_hs *s, const unsigned char *pt, size_t n, unsigned char *out, size_t *out_n);
size_t tls_rec_available(const struct tls_hs *s);
const unsigned char *tls_rec_peek(const struct tls_hs *s, size_t *n);
void tls_rec_consume(struct tls_hs *s, size_t n);

/* tls.c */
int tls_parse_server_msg(struct tls_hs *s);     /* 0 parsed, -1 aborts */

/* tls/finish.c — the post-ServerHelloDone completion (T15): derive the key
 * schedule, send ClientKeyExchange + ChangeCipherSpec + Finished, then
 * verify the server Finished and set the security latch. */
int tls_fin_begin(struct tls_hs *s);    /* key schedule from premaster */
int tls_fin_send(struct tls_hs *s);     /* CKE, CCS, encrypted Finished */
int tls_fin_verify(struct tls_hs *s, const unsigned char *vd, size_t n);        /* latches */
void tls_trans(struct tls_hs *s, int type, const void *body, size_t n); /* transcript */

#endif
