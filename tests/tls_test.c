#include "test_util.h"
#include "tls_capture.h"
#include "cast/tls/crypt.h"
#include "cast/tls/rsa.h"
#include "cast/tls/p256.c"
#include "cast/tls/ecdh.c"
#include "cast/tls/ecdhe.c"
#include "cast/tls/hello.c"
#include "cast/tls/finish.c"
#include "cast/tls/detect.c"
#include "cast/tls/record_cipher.c"
#include "cast/tls/record_inq.c"
#include "cast/tls/record.c"
#include "cast/tls/io.c"
#include "cast/tls.c"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* === test-side wire builders === */

static size_t mk_rec(unsigned char *o, int type, const unsigned char *p, size_t n)
{
  o[0] = (unsigned char)type;
  o[1] = 3;
  o[2] = 3;
  o[3] = (unsigned char)(n >> 8);
  o[4] = (unsigned char)(n & 0xff);
  memcpy(o + 5, p, n);
  return n + 5;
}

static size_t mk_hs(unsigned char *o, int t, const unsigned char *b, size_t n)
{
  o[0] = (unsigned char)t;
  o[1] = (unsigned char)(n >> 16);
  o[2] = (unsigned char)(n >> 8);
  o[3] = (unsigned char)(n & 0xff);
  if (n)
    memcpy(o + 4, b, n);
  return n + 4;
}

static size_t mk_shbody(unsigned char *o, unsigned int suite, int version)
{
  size_t p = 0;
  size_t i;

  o[p++] = (unsigned char)(version >> 8);
  o[p++] = (unsigned char)(version & 0xff);
  for (i = 0; i < 32; i++)
    o[p++] = (unsigned char)i;
  o[p++] = 0;                   /* empty session id */
  o[p++] = (unsigned char)(suite >> 8);
  o[p++] = (unsigned char)(suite & 0xff);
  o[p++] = 0;                   /* null compression */
  return p;
}

static int rd_all(int fd, unsigned char *p, size_t n)
{
  size_t off = 0;

  while (off < n) {
    ssize_t r = read(fd, p + off, n - off);
    EXPECT(r > 0);
    off += (size_t)r;
  }
  return 0;
}

static ssize_t tio_read(struct cast_io *io, unsigned char *b, size_t cap)
{
  int fd = *(int *)io->opaque;
  ssize_t r = recv(fd, b, cap, 0);

  if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  return r;
}

static ssize_t tio_write(struct cast_io *io, const unsigned char *b, size_t cap)
{
  int fd = *(int *)io->opaque;
  ssize_t r = send(fd, b, cap, MSG_NOSIGNAL);

  if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  return r;
}

static int hs_init(struct tls_hs *s)
{
  struct cast_io io = { NULL, NULL, NULL };

  EXPECT(tls_hs_init(s, &io) == 0);
  return 0;
}

/* A capture stream: writes are appended to an owned buffer so the client's
 * outbound records can be inspected and decrypted by the test (the server
 * view). */
struct ciocap {
  unsigned char buf[1024];
  size_t len;
};

static ssize_t cap_write(struct cast_io *io, const unsigned char *b, size_t n)
{
  struct ciocap *c = (struct ciocap *)io->opaque;

  EXPECT(c->len + n <= sizeof c->buf);
  memcpy(c->buf + c->len, b, n);
  c->len += n;
  return (ssize_t) n;
}

static int hs_init_cap(struct tls_hs *s, struct ciocap *c, struct cast_io *io)
{
  memset(c, 0, sizeof *c);
  memset(io, 0, sizeof *io);
  io->opaque = c;
  io->write = cap_write;
  EXPECT(tls_hs_init(s, io) == 0);
  return 0;
}

/* Feed one record; return the handshake message type it surfaces. */
static int feed_msg(struct tls_hs *s, const unsigned char *wire, size_t n, int *type)
{
  const unsigned char *body;
  size_t blen;

  EXPECT(tls_hs_feed(s, wire, n) == 0);
  EXPECT(tls_hs_pump(s) == 1);
  EXPECT(tls_hs_message(s, type, &body, &blen) == 0);
  return 0;
}

/* === ClientHello construction === */

static int t_hello(void)
{
  unsigned char rnd[32];
  unsigned char o[TLS_HELLO_CAP];
  size_t i;
  int n;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 7);
  n = tls_client_hello(o, rnd);
  EXPECT(n == 83);              /* 5 rec hdr + 4 hs hdr + 74 body */

  EXPECT(o[0] == TLS_REC_HANDSHAKE);
  EXPECT(o[1] == 3 && o[2] == 3);
  EXPECT((o[3] << 8 | o[4]) == n - 5);
  EXPECT(o[5] == TLS_HS_CLIENT_HELLO);
  EXPECT((o[6] << 16 | o[7] << 8 | o[8]) == n - 9);

  EXPECT((o[9] << 8 | o[10]) == TLS_VERSION_1_2);
  EXPECT(memcmp(o + 11, rnd, 32) == 0);
  EXPECT(o[43] == 0);           /* empty session id */

  EXPECT((o[44] << 8 | o[45]) == 4);
  EXPECT((o[46] << 8 | o[47]) == TLS_SUITE_CHACHA);
  EXPECT((o[48] << 8 | o[49]) == TLS_SUITE_AES_GCM);
  EXPECT(o[50] == 1 && o[51] == 0);     /* null compression */

  {
    size_t ext = (o[52] << 8 | o[53]);

    EXPECT(ext == 29);
    EXPECT(54 + ext == (size_t)n);
    EXPECT((o[54] << 8 | o[55]) == TLS_EXT_CURVES);
    EXPECT((o[58] << 8 | o[59]) == 2);
    EXPECT((o[60] << 8 | o[61]) == TLS_CURVE_P256);
    EXPECT((o[62] << 8 | o[63]) == TLS_EXT_POINTS);
    /* ec_point_formats carries its vector length and the three formats */
    EXPECT((o[64] << 8 | o[65]) == 4);
    EXPECT(o[66] == 0x03);
    EXPECT(o[67] == 0x00);
    EXPECT(o[68] == 0x01);
    EXPECT(o[69] == 0x02);
    /* signature_algorithms carries its vector length before the pair */
    EXPECT((o[70] << 8 | o[71]) == TLS_EXT_SIGALGS);
    EXPECT((o[72] << 8 | o[73]) == 4);
    EXPECT(o[74] == 0x00);
    EXPECT(o[75] == 0x02);
    EXPECT((o[76] << 8 | o[77]) == (TLS_HASH_SHA256 << 8 | TLS_SIG_RSA));
    EXPECT((o[78] << 8 | o[79]) == 0xFF01);
    EXPECT((o[80] << 8 | o[81]) == 1);
    EXPECT(o[82] == 0x00);
  }
  return 0;
}

static int t_random(void)
{
  unsigned char a[32];
  unsigned char b[32];

  EXPECT(tls_random(a) == 0);
  EXPECT(tls_random(b) == 0);
  EXPECT(memcmp(a, b, 32) != 0);
  return 0;
}

/* === outbound path over a real socket === */

static int t_send_hello(void)
{
  int fd;
  struct cast_io io;
  int sv[2];
  int flags;
  struct tls_hs s;
  unsigned char rnd[32];
  unsigned char rec[256];
  unsigned char sh_body[64];
  unsigned char hs[512];
  size_t m;
  size_t i;
  int type;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 3);
  EXPECT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  flags = fcntl(sv[0], F_GETFL, 0);
  EXPECT(fcntl(sv[0], F_SETFL, flags | O_NONBLOCK) == 0);

  fd = sv[0];
  io.opaque = &fd;
  io.read = tio_read;
  io.write = tio_write;
  EXPECT(tls_hs_init(&s, &io) == 0);
  EXPECT(tls_hs_send_hello(&s, rnd) == 0);
  EXPECT(s.phase == TLS_PH_READ);
  EXPECT(s.ecdhe.keyed == 1);   /* the ephemeral key pair was generated */
  EXPECT(tls_hs_step(&s) == 0); /* ClientHello flushed; wants SH */

  {
    unsigned char exp[TLS_HELLO_CAP];
    unsigned char got[256];
    int en = tls_client_hello(exp, rnd);

    EXPECT(rd_all(sv[1], got, (size_t)en) == 0);
    EXPECT(memcmp(got, exp, (size_t)en) == 0);
  }

  /* ServerHello arrives; step surfaces the message without an explicit feed. */
  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  m = mk_hs(hs, TLS_HS_SERVER_HELLO, sh_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, hs, m);
  EXPECT(tls_hs_feed(&s, rec, m) == 0);
  EXPECT(tls_hs_step(&s) == 1);
  {
    const unsigned char *body;
    size_t blen;

    EXPECT(tls_hs_message(&s, &type, &body, &blen) == 0);
    EXPECT(type == TLS_HS_SERVER_HELLO);
  }
  EXPECT(tls_parse_server_msg(&s) == 0);

  tls_hs_close(&s);
  close(sv[0]);
  close(sv[1]);
  return 0;
}

/* === the happy path: ServerHello, Certificate, SKE, ServerHelloDone === */

/* ECDHE P-256 vectors from an independent Python reference (secp256r1). */
static const char KAT_D1[] = "09c4d3f8a7b2e1f6a5d4c3b2a19f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d";
static const char KAT_D2[] = "01a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80";
static const char KAT_D3[] = "09c4d3f8a7b2e1f6a5d4c3b2a19f8e7d6c5b4a39281706f5e4d3c2b1a09f8e97";
static const char KAT_N[] = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
static const char KAT_Q1[] =
    "0445ea50b4a4d9ffd57c3aca02f3d8052d6ca6202c88f818f32e6d90e87a587d47"
    "670e6a109bf7c1d622a7e888b796590502dedc9e42b1055f208f78c5a0f49ee0";
static const char KAT_Q2[] =
    "04817c32bffcf0b7e5fa000e728800cb3b8ad199d1c3e1c3db9a278f0d2d05ebc"
    "bc89e3d09bf31a8f5e8357797064dc7c664926f26654dad757d6d52df92f367bd";
/* RSA test key: a 1024-bit key whose SPKI uses n=78a5... and e=65537; the
 * SKE below is signed by Python (PKCS1 v1.5/SHA-256) over
 * client_random || server_random || params with these exact randoms/scalars. */
static const char RSA_LEAF_DER[] =
    "308201273081d2a003020102020101300d06092a864886f70d01010b05003007"
    "02050102030405300602010102010230070205010203040530819e300d06092a"
    "864886f70d010101050003818c0030818802818078a54ed5a2b43a511d70c935"
    "054e839cfbf10bdaaa2ac771ef75b59e0021b9afba8df715425d167224e541b1"
    "e758c290640f32ba1870a36552dd0266b86229870ed5b3dd726c9bbf7bbbb56a"
    "935cc57012c3e22bac7742a70971103cbec04fe6b05ee317cff28998ade271e8"
    "62b9472a47dc9a84484c8530cc60765673ddfbdf0203010001300d06092a8648"
    "86f70d01010b0500034100000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000" "0000000000000000000000";
static const char RSA_SKE_SIG[] =
    "7667e9091e9b7aed83b7ea9936f15cde58bc5e65ed172bb3493122b7dc10a4e9"
    "f1f6f7c11863db9ea922040408382225995387d7df009215e45d18d7609ac54a"
    "ec6b70a59f9fc205c82e8670fede505a683fec0d5fe108f431d09603a6273d75"
    "65f4b34ded9ccbbd304cc95f622e17f510c4540e45d2e8ba420e61056cccd7b7";
/* Q3 has a leading-zero y coordinate, so its encoding must pad the coordinate */
static const char KAT_Q3[] =
    "0497cb40ed648ddc7a2165531152a534981a5f79237b415fb557a1eb7c5f267709"
    "00aeb523f303f48a7bbc449221b548b7d4cac45af7e215efd2e37391997c4795";
/* Reference S is the x-coordinate of the ECDH shared point (RFC 8422 §5.10
 * premaster), not the full uncompressed point. */
static const char KAT_S[] = "efc0052bafd014367505c702540a42d6f7dcb50070fb160185a9c6e69cf3a177";

static int hx(unsigned char *o, const char *h)
{
  unsigned int v;
  size_t i;

  for (i = 0; h[i * 2] != '\0'; i++) {
    EXPECT(sscanf(h + i * 2, "%2x", &v) == 1);
    o[i] = (unsigned char)v;
  }
  return 0;
}

/* === PRF and the ChaCha20-Poly1305 record cipher (RFC 5246/7905) === */

static const char PRF48_HEX[] =
    "e3ca3d781a094dcfbe25b40107db5e15ccf15746fa1dcb90a7475c7fecb953a9" "69a12e73682f6cdbc8093602ffe6acd9";
static const char PREMASTER_HEX[] =
    "04efc0052bafd014367505c702540a42d6f7dcb50070fb160185a9c6e69cf3a1"
    "77266667cc99c02724693a6c470c92594cae230de5cfd92ee61dc2bbddc7c8e8ee";
static const char MASTER_HEX[] =
    "27020f132f9870ddfe97e6406051c3b39758b6cf1b39f8d059e981d276693cd7" "fc5ffa6da54cec2f12b76779baa0fcbc";
static const char KEYBLOCK_HEX[] =
    "c14779b8eed393c6739504ffd99eceed21b1a40075d301d9c4189e83314321c3"
    "c9226099cf9ec5753636cffa7059a43a8ecfe45b0d5f4c91658cb3ab58c52ba9"
    "63adbcb306bef41daa0a21db6b37eb60a4a56df65f4c91fd";

static int t_crypto(void)
{
  struct tls_cc cc;
  struct tls_seed ps;
  unsigned char out[96];
  unsigned char ref[96];
  unsigned char secret[32];
  unsigned char seed[20];
  unsigned char premaster[65];
  unsigned char cr[32];
  unsigned char sr[32];
  unsigned char master[48];
  unsigned char key[32];
  unsigned char iv[12];
  unsigned char aad[13];
  unsigned char in[48];
  unsigned char ct[64];
  unsigned char pt[64];
  size_t i;
  size_t ct_n;

  for (i = 0; i < sizeof secret; i++)
    secret[i] = (unsigned char)i;
  for (i = 0; i < sizeof seed; i++)
    seed[i] = (unsigned char)i;

  /* RFC 5246 §5 PRF P_hash(SHA-256) matches the independent reference */
  ps.label = "test label";
  ps.seed = seed;
  ps.seed_n = 20;
  EXPECT(tls_prf_sha256(out, 48, secret, 32, &ps) == 0);
  hx(ref, PRF48_HEX);
  EXPECT(memcmp(out, ref, 48) == 0);

  /* master secret and key block match the reference derivation */
  hx(premaster, PREMASTER_HEX);
  for (i = 0; i < 32; i++)
    cr[i] = (unsigned char)i;
  for (i = 0; i < 32; i++)
    sr[i] = (unsigned char)(31 - i);
  tls_master_secret(master, premaster, sizeof premaster, cr, sr);
  hx(ref, MASTER_HEX);
  EXPECT(memcmp(master, ref, 48) == 0);
  tls_key_block(out, 88, master, cr, sr);
  hx(ref, KEYBLOCK_HEX);
  EXPECT(memcmp(out, ref, 88) == 0);

  /* AEAD round trip: seal then open with the RFC 7905 nonce and the
   * §6.2.3.3 13-byte additional-data (seq || type || version || length) */
  for (i = 0; i < sizeof key; i++)
    key[i] = (unsigned char)(i + 1);
  for (i = 0; i < sizeof iv; i++)
    iv[i] = (unsigned char)(i + 0x40);
  aad[0] = 0;
  aad[1] = 0;
  aad[2] = 0;
  aad[3] = 0;
  aad[4] = 0;
  aad[5] = 0;
  aad[6] = 0;
  aad[7] = 7;                   /* sequence number 7 */
  aad[8] = TLS_REC_APP_DATA;
  aad[9] = 3;
  aad[10] = 3;
  aad[11] = 0;
  aad[12] = (unsigned char)sizeof in;
  for (i = 0; i < sizeof in; i++)
    in[i] = (unsigned char)(i + 0x10);

  cc.key = key;
  cc.iv = iv;
  cc.seq = 7;
  cc.aad = aad;
  cc.aad_n = 13;

  EXPECT(tls_chacha_seal(&cc, ct, &ct_n, in, sizeof in) == 0);
  EXPECT(ct_n == sizeof in + 16);
  EXPECT(tls_chacha_open(&cc, pt, ct, ct_n) == 0);
  EXPECT(memcmp(pt, in, sizeof in) == 0);

  /* wrong sequence number and wrong key fail to authenticate */
  cc.seq = 8;
  EXPECT(tls_chacha_open(&cc, pt, ct, ct_n) == -1);
  key[0] ^= 1;
  cc.seq = 7;
  EXPECT(tls_chacha_open(&cc, pt, ct, ct_n) == -1);

  /* empty plaintext seals to a bare 16-byte tag */
  in[0] = 0;
  cc.seq = 0;
  EXPECT(tls_chacha_seal(&cc, ct, &ct_n, in, 0) == 0);
  EXPECT(ct_n == 16);

  return 0;
}

/* RSA PKCS#1 v1.5 verify over the SKE signed body (RFC 4492 §5.4). */
static int t_rsa(void)
{
  struct tls_rsa_pub k;
  unsigned char params[4 + TLS_P256_POINT_LEN];
  unsigned char body[64 + 4 + TLS_P256_POINT_LEN];
  unsigned char digest[32];
  unsigned char cr[32];
  unsigned char sr[32];
  unsigned char q2[TLS_P256_POINT_LEN];
  unsigned char leaf[400];
  unsigned char sig[128];
  unsigned char badsig[128];
  size_t leaf_n = (size_t)(strlen(RSA_LEAF_DER) / 2);
  size_t sig_n = (size_t)(strlen(RSA_SKE_SIG) / 2);
  size_t i;

  for (i = 0; i < 32; i++) {
    cr[i] = (unsigned char)(i * 5);
    sr[i] = (unsigned char)i;
  }
  hx(q2, KAT_Q2);
  hx(leaf, RSA_LEAF_DER);
  hx(sig, RSA_SKE_SIG);

  /* extract the RSA public key from the X.509 leaf */
  EXPECT(tls_rsa_leaf_pub(&k, leaf, leaf_n) == 0);

  /* good signature validates against SHA-256(client||server||params) */
  params[0] = TLS_CURVE_TYPE_NAMED;
  params[1] = 0;
  params[2] = TLS_CURVE_P256;
  params[3] = TLS_P256_POINT_LEN;
  memcpy(params + 4, q2, TLS_P256_POINT_LEN);
  memcpy(body, cr, 32);
  memcpy(body + 32, sr, 32);
  memcpy(body + 64, params, sizeof params);
  EXPECT(tls_sha256(digest, body, 64 + sizeof params) == 0);
  EXPECT(tls_rsa_verify(&k, digest, sig, sig_n) == 0);

  /* a flipped signature byte and a corrupted digest both fail */
  memcpy(badsig, sig, sig_n);
  badsig[0] ^= 1;
  EXPECT(tls_rsa_verify(&k, digest, badsig, sig_n) == -1);
  digest[0] ^= 1;
  EXPECT(tls_rsa_verify(&k, digest, sig, sig_n) == -1);

  mp_clear_multi(&k.n, &k.e, NULL);
  return 0;
}

/* Run the client through ServerHelloDone with a capture stream; the caller
 * provides the client random seed. On return exp[0..*exp_n) is the
 * independently reconstructed transcript (ClientHello .. ServerHelloDone),
 * ready for the ClientKeyExchange that follows. */
static int fin_csetup(struct tls_hs *s, struct cast_io *io, struct ciocap *cap,
                      const unsigned char rnd[32], unsigned char exp[], size_t *exp_n)
{
  unsigned char sh_body[64];
  unsigned char cert_body[600];
  unsigned char ske_body[600];
  unsigned char msg[1024];
  unsigned char rec[1100];
  unsigned char q2[TLS_P256_POINT_LEN];
  unsigned char leaf[400];
  unsigned char sig[128];
  size_t leaf_n = (size_t)(strlen(RSA_LEAF_DER) / 2);
  size_t sig_n = (size_t)(strlen(RSA_SKE_SIG) / 2);
  size_t m;
  int type;

  hx(q2, KAT_Q2);
  hx(leaf, RSA_LEAF_DER);
  hx(sig, RSA_SKE_SIG);
  *exp_n = 0;
  EXPECT(hs_init_cap(s, cap, io) == 0);
  EXPECT(tls_hs_send_hello(s, rnd) == 0);
  EXPECT(s->ecdhe.keyed == 1);

  {
    unsigned char ch[TLS_HELLO_CAP];
    int cn = tls_client_hello(ch, rnd);

    memcpy(exp + *exp_n, ch + 5, (size_t)(cn - 5));
    *exp_n += (size_t)(cn - 5);
  }

  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  sh_body[m++] = 0;
  sh_body[m++] = 10;
  sh_body[m++] = 0;
  sh_body[m++] = 5;
  sh_body[m++] = 0;
  sh_body[m++] = 1;
  sh_body[m++] = 1;
  sh_body[m++] = 0xff;
  sh_body[m++] = 0x01;
  sh_body[m++] = 0;
  sh_body[m++] = 1;
  sh_body[m++] = 0;
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m);
  memcpy(exp + *exp_n, msg, m);
  *exp_n += m;
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_SERVER_HELLO);
  EXPECT(tls_parse_server_msg(s) == 0);

  m = 0;
  cert_body[m] = (unsigned char)((3 + leaf_n) >> 16);
  cert_body[m + 1] = (unsigned char)((3 + leaf_n) >> 8);
  cert_body[m + 2] = (unsigned char)(3 + leaf_n);
  m += 3;
  cert_body[m] = (unsigned char)(leaf_n >> 16);
  cert_body[m + 1] = (unsigned char)(leaf_n >> 8);
  cert_body[m + 2] = (unsigned char)leaf_n;
  m += 3;
  memcpy(cert_body + m, leaf, leaf_n);
  m += leaf_n;
  m = mk_hs(msg, TLS_HS_CERTIFICATE, cert_body, m);
  memcpy(exp + *exp_n, msg, m);
  *exp_n += m;
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_CERTIFICATE);
  EXPECT(tls_parse_server_msg(s) == 0);

  m = 0;
  ske_body[m++] = TLS_CURVE_TYPE_NAMED;
  ske_body[m++] = 0;
  ske_body[m++] = TLS_CURVE_P256;
  ske_body[m++] = TLS_P256_POINT_LEN;
  memcpy(ske_body + m, q2, TLS_P256_POINT_LEN);
  m += TLS_P256_POINT_LEN;
  ske_body[m++] = TLS_HASH_SHA256;
  ske_body[m++] = TLS_SIG_RSA;
  ske_body[m++] = (unsigned char)(sig_n >> 8);
  ske_body[m++] = (unsigned char)(sig_n & 0xff);
  memcpy(ske_body + m, sig, sig_n);
  m += sig_n;
  m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, ske_body, m);
  memcpy(exp + *exp_n, msg, m);
  *exp_n += m;
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_SERVER_KEY_EXCHANGE);
  EXPECT(tls_parse_server_msg(s) == 0);
  EXPECT(s->ecdhe.done == 1);

  m = mk_hs(msg, TLS_HS_SERVER_HELLO_DONE, NULL, 0);
  memcpy(exp + *exp_n, msg, m);
  *exp_n += m;
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_SERVER_HELLO_DONE);
  EXPECT(tls_parse_server_msg(s) == 0);
  return 0;
}

/* The Finished exchange both ways plus the plaintext security-latch: the
 * client derives the key schedule, sends CKE/CCS/Finished (encrypted), then
 * verifies the server Finished — no application data passes before it. */
static int t_finish(void)
{
  struct tls_hs s;
  struct cast_io io;
  struct ciocap cap;
  unsigned char rnd[32];
  unsigned char exp[2048];
  unsigned char cke[4 + 66];
  unsigned char vd_cli[12];
  unsigned char master[48], kb[TLS_KEY_BLOCK];
  size_t exp_n = 0;
  size_t i;
  int type;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 5);
  EXPECT(fin_csetup(&s, &io, &cap, rnd, exp, &exp_n) == 0);
  EXPECT(tls_fin_begin(&s) == 0);
  EXPECT(s.fin.stage == 1);
  EXPECT(s.fin.verified == 0);
  EXPECT(s.trans_n == exp_n);
  EXPECT(memcmp(s.trans, exp, exp_n) == 0);     /* transcript so far matches */

  /* independent key schedule reconstruction */
  tls_master_secret(master, s.ecdhe.premaster, sizeof s.ecdhe.premaster, s.client_random, s.server_random);
  tls_key_block(kb, sizeof kb, master, s.client_random, s.server_random);
  EXPECT(memcmp(s.master, master, 48) == 0);
  EXPECT(memcmp(s.c_key, kb, 32) == 0);
  EXPECT(memcmp(s.s_key, kb + 32, 32) == 0);
  EXPECT(memcmp(s.c_iv, kb + 64, 12) == 0);
  EXPECT(memcmp(s.s_iv, kb + 76, 12) == 0);

  cke[0] = TLS_HS_CLIENT_KEY_EXCHANGE;
  cke[1] = 0;
  cke[2] = 0;
  cke[3] = 66;
  cke[4] = TLS_P256_POINT_LEN;
  memcpy(cke + 5, s.ecdhe.pub, TLS_P256_POINT_LEN);

  EXPECT(tls_fin_send(&s) == 0);
  EXPECT(s.fin.stage == 2);
  EXPECT(s.fin.cipher_on == 1);
  memcpy(exp + exp_n, cke, sizeof cke);
  exp_n += sizeof cke;

  /* inspect the captured outbound: CKE | CCS | encrypted Finished */
  {
    struct tls_cc cc;
    unsigned char aad[13], pt[1024];
    size_t off = 0, ct_n;

    EXPECT(cap.buf[off] == TLS_REC_HANDSHAKE);
    EXPECT(((cap.buf[off + 3] << 8) | cap.buf[off + 4]) == 70);
    EXPECT(cap.buf[off + 5] == TLS_HS_CLIENT_KEY_EXCHANGE);
    EXPECT(memcmp(cap.buf + off + 9, cke + 4, 66) == 0);
    off += 5 + 70;
    EXPECT(cap.buf[off] == TLS_REC_CHANGE_CIPHER_SPEC);
    EXPECT(cap.buf[off + 4] == 1 && cap.buf[off + 5] == 1);
    off += 6;
    EXPECT(cap.buf[off] == TLS_REC_HANDSHAKE);
    ct_n = (size_t)((cap.buf[off + 3] << 8) | cap.buf[off + 4]);
    EXPECT(ct_n == 16 + 16);
    tls_record_aad(aad, 0, TLS_REC_HANDSHAKE, 16);
    cc.key = s.c_key;
    cc.iv = s.c_iv;
    cc.seq = 0;
    cc.aad = aad;
    cc.aad_n = 13;
    EXPECT(tls_chacha_open(&cc, pt, cap.buf + off + 5, ct_n) == 0);
    EXPECT(pt[0] == TLS_HS_FINISHED);
    EXPECT(((pt[1] << 16) | (pt[2] << 8) | pt[3]) == 12);
    memcpy(vd_cli, pt + 4, 12);

    /* expected client verify_data = PRF(master,"client finished",h(trans)) */
    {
      unsigned char h[32], want[12];
      struct tls_seed sd = { "client finished", NULL, 0 };

      EXPECT(tls_sha256(h, exp, exp_n) == 0);
      sd.seed = h;
      sd.seed_n = 32;
      EXPECT(tls_prf_sha256(want, 12, s.master, 48, &sd) == 0);
      EXPECT(memcmp(vd_cli, want, 12) == 0);
    }
  }

  /* the client Finished is appended to the transcript for server verify */
  {
    unsigned char fin_hs[16];

    fin_hs[0] = TLS_HS_FINISHED;
    fin_hs[1] = 0;
    fin_hs[2] = 0;
    fin_hs[3] = 12;
    memcpy(fin_hs + 4, vd_cli, 12);
    memcpy(exp + exp_n, fin_hs, sizeof fin_hs);
    exp_n += sizeof fin_hs;
    EXPECT(s.trans_n == exp_n);
    EXPECT(memcmp(s.trans, exp, exp_n) == 0);
  }

  /* the security latch: application data before the server Finished is
   * verified is rejected — covered in t_finish_latch with a fresh session. */

  /* server sends ChangeCipherSpec then an encrypted (valid) Finished */
  {
    struct tls_cc cc;
    unsigned char hdr[5], aad[13], hs[16], ct[64], frec[128], crec[8];
    unsigned char h[32], want[12];
    unsigned char ccs[1] = { 1 };
    struct tls_seed sd = { "server finished", NULL, 0 };
    const unsigned char *body;
    size_t blen, ct_n, nccs;

    nccs = mk_rec(crec, TLS_REC_CHANGE_CIPHER_SPEC, ccs, 1);
    EXPECT(tls_hs_feed(&s, crec, nccs) == 0);
    EXPECT(tls_hs_pump(&s) == 0);       /* CCS consumed; waits */
    EXPECT(s.fin.verified == 0);

    EXPECT(tls_sha256(h, exp, exp_n) == 0);
    sd.seed = h;
    sd.seed_n = 32;
    EXPECT(tls_prf_sha256(want, 12, s.master, 48, &sd) == 0);
    hs[0] = TLS_HS_FINISHED;
    hs[1] = 0;
    hs[2] = 0;
    hs[3] = 12;
    memcpy(hs + 4, want, 12);
    tls_record_aad(aad, 0, TLS_REC_HANDSHAKE, 16);
    cc.key = s.s_key;
    cc.iv = s.s_iv;
    cc.seq = 0;
    cc.aad = aad;
    cc.aad_n = 13;
    EXPECT(tls_chacha_seal(&cc, ct, &ct_n, hs, 16) == 0);
    hdr[0] = TLS_REC_HANDSHAKE;
    hdr[1] = 3;
    hdr[2] = 3;
    hdr[3] = (unsigned char)(ct_n >> 8);
    hdr[4] = (unsigned char)ct_n;
    memcpy(frec, hdr, 5);
    memcpy(frec + 5, ct, ct_n);
    EXPECT(tls_hs_feed(&s, frec, 5 + ct_n) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_hs_message(&s, &type, &body, &blen) == 0);
    EXPECT(type == TLS_HS_FINISHED);
    EXPECT(tls_parse_server_msg(&s) == 0);
    EXPECT(s.fin.verified == 1);        /* latched */
    EXPECT(tls_hs_pump(&s) == 0);       /* Finished record fully drained */

    /* after the latch, an encrypted application-data record is accepted */
    {
      unsigned char aad[13], ct[64], hdr[5], arec[80];
      const unsigned char hello[] = "commitdata";

      tls_record_aad(aad, 1, TLS_REC_APP_DATA, 10);
      cc.key = s.s_key;
      cc.iv = s.s_iv;
      cc.seq = 1;
      cc.aad = aad;
      cc.aad_n = 13;
      EXPECT(tls_chacha_seal(&cc, ct, &ct_n, hello, sizeof hello - 1) == 0);
      hdr[0] = TLS_REC_APP_DATA;
      hdr[1] = 3;
      hdr[2] = 3;
      hdr[3] = (unsigned char)(ct_n >> 8);
      hdr[4] = (unsigned char)ct_n;
      memcpy(arec, hdr, 5);
      memcpy(arec + 5, ct, ct_n);
      EXPECT(tls_hs_feed(&s, arec, 5 + ct_n) == 0);
      EXPECT(tls_hs_pump(&s) == 0);     /* decrypted and consumed */
      EXPECT(s.fin.s_seq == 2);
    }

    /* a ciphertext record carrying only the 16-byte tag is malformed
     * (plaintext length 0): rejected by the record layer */
    {
      unsigned char trec[21];

      trec[0] = TLS_REC_HANDSHAKE;
      trec[1] = 3;
      trec[2] = 3;
      trec[3] = 0;
      trec[4] = 16;
      EXPECT(tls_hs_feed(&s, trec, 21) == 0);
      EXPECT(tls_hs_pump(&s) == -1);
      EXPECT(s.fin.verified == 1);      /* latch unaffected */
    }
  }

  s.io = NULL;
  tls_hs_close(&s);
  return 0;
}

/* A forged server Finished must not set the latch. */
static int t_finish_bad(void)
{
  struct tls_hs s;
  struct cast_io io;
  struct ciocap cap;
  unsigned char rnd[32];
  unsigned char exp[2048];
  unsigned char cke[4 + 66];
  size_t exp_n = 0;
  size_t i;
  int type;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 5);
  EXPECT(fin_csetup(&s, &io, &cap, rnd, exp, &exp_n) == 0);
  EXPECT(tls_fin_begin(&s) == 0);
  cke[0] = TLS_HS_CLIENT_KEY_EXCHANGE;
  cke[1] = 0;
  cke[2] = 0;
  cke[3] = 66;
  cke[4] = TLS_P256_POINT_LEN;
  memcpy(cke + 5, s.ecdhe.pub, TLS_P256_POINT_LEN);
  EXPECT(tls_fin_send(&s) == 0);
  memcpy(exp + exp_n, cke, sizeof cke);
  exp_n += sizeof cke;
  /* append the client Finished (its vd decrypted from the capture) */
  {
    struct tls_cc cc;
    unsigned char aad[13], pt[64], fin_hs[16];
    size_t off = 5 + 70 + 6, ct_n;

    ct_n = (size_t)((cap.buf[off + 3] << 8) | cap.buf[off + 4]);
    tls_record_aad(aad, 0, TLS_REC_HANDSHAKE, 16);
    cc.key = s.c_key;
    cc.iv = s.c_iv;
    cc.seq = 0;
    cc.aad = aad;
    cc.aad_n = 13;
    EXPECT(tls_chacha_open(&cc, pt, cap.buf + off + 5, ct_n) == 0);
    fin_hs[0] = TLS_HS_FINISHED;
    fin_hs[1] = 0;
    fin_hs[2] = 0;
    fin_hs[3] = 12;
    memcpy(fin_hs + 4, pt + 4, 12);
    memcpy(exp + exp_n, fin_hs, sizeof fin_hs);
    exp_n += sizeof fin_hs;
  }

  /* server CCS + encrypted Finished with a corrupted verify_data */
  {
    struct tls_cc cc;
    unsigned char hdr[5], aad[13], hs[16], ct[64], frec[128], crec[8];
    unsigned char ccs[1] = { 1 };
    const unsigned char *body;
    size_t blen, ct_n, nccs;

    nccs = mk_rec(crec, TLS_REC_CHANGE_CIPHER_SPEC, ccs, 1);
    EXPECT(tls_hs_feed(&s, crec, nccs) == 0);
    EXPECT(tls_hs_pump(&s) == 0);
    memset(hs, 0xab, sizeof hs);
    hs[0] = TLS_HS_FINISHED;
    hs[1] = 0;
    hs[2] = 0;
    hs[3] = 12;
    tls_record_aad(aad, 0, TLS_REC_HANDSHAKE, 16);
    cc.key = s.s_key;
    cc.iv = s.s_iv;
    cc.seq = 0;
    cc.aad = aad;
    cc.aad_n = 13;
    EXPECT(tls_chacha_seal(&cc, ct, &ct_n, hs, 16) == 0);
    hdr[0] = TLS_REC_HANDSHAKE;
    hdr[1] = 3;
    hdr[2] = 3;
    hdr[3] = (unsigned char)(ct_n >> 8);
    hdr[4] = (unsigned char)ct_n;
    memcpy(frec, hdr, 5);
    memcpy(frec + 5, ct, ct_n);
    EXPECT(tls_hs_feed(&s, frec, 5 + ct_n) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_hs_message(&s, &type, &body, &blen) == 0);
    EXPECT(type == TLS_HS_FINISHED);
    EXPECT(tls_parse_server_msg(&s) == -1);     /* forged: verify fails */
    EXPECT(s.fin.verified == 0);        /* latch stays closed */
  }

  s.io = NULL;
  tls_hs_close(&s);
  return 0;
}

/* The security latch in isolation: no application data is decrypted before
 * the server Finished verifies. A fresh session, then it aborts on the first
 * app-data record. */
static int t_finish_latch(void)
{
  struct tls_hs s;
  struct cast_io io;
  struct ciocap cap;
  unsigned char rnd[32];
  unsigned char exp[2048];
  unsigned char cke[4 + 66];
  const unsigned char hello[] = "secretdata";
  size_t exp_n = 0;
  size_t i;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 5);
  EXPECT(fin_csetup(&s, &io, &cap, rnd, exp, &exp_n) == 0);
  EXPECT(tls_fin_begin(&s) == 0);
  cke[0] = TLS_HS_CLIENT_KEY_EXCHANGE;
  cke[1] = 0;
  cke[2] = 0;
  cke[3] = 66;
  cke[4] = TLS_P256_POINT_LEN;
  memcpy(cke + 5, s.ecdhe.pub, TLS_P256_POINT_LEN);
  EXPECT(tls_fin_send(&s) == 0);

  /* app-data arrives before any server Finished: must be rejected */
  {
    unsigned char arec[300];
    size_t n = mk_rec(arec, TLS_REC_APP_DATA, hello, sizeof hello - 1);

    EXPECT(tls_hs_feed(&s, arec, n) == 0);
    EXPECT(tls_hs_pump(&s) == -1);
    EXPECT(s.fin.verified == 0);
  }

  s.io = NULL;
  tls_hs_close(&s);
  return 0;
}

/* Replay the captured live exchange (tests/tls_capture.h) byte-for-byte.
 * The fixed LITECAST_TEST PRNG seed reproduces the ephemeral ECDHE key of
 * the capture, so both Finished records and the security latch match. */
static int t_recorded(void)
{
  struct tls_hs s;
  struct cast_io io;
  struct ciocap cap;
  int guard;
  int type;

  tls_test_prng_reset();
  hs_init_cap(&s, &cap, &io);
  EXPECT(tls_hs_send_hello(&s, cap_cr) == 0);
  EXPECT(tls_hs_step(&s) == 0); /* hello flushed to the sink */
  EXPECT(cap.len == 83);
  EXPECT(tls_hs_feed(&s, cap_srv, CAP_SRV_N) == 0);

  for (guard = 0; guard < 64 && !s.fin.verified; guard++) {
    int r = tls_hs_pump(&s);
    const unsigned char *body;
    size_t bn;

    if (r == 1) {
      EXPECT(tls_hs_message(&s, &type, &body, &bn) == 0);
      EXPECT(tls_parse_server_msg(&s) == 0);
      if (type == TLS_HS_SERVER_HELLO_DONE) {
        EXPECT(tls_fin_begin(&s) == 0);
        EXPECT(tls_fin_send(&s) == 0);
      }
      continue;
    }
    EXPECT(r == 0);             /* never a mid-handshake error */
  }
  EXPECT(s.fin.verified == 1);  /* the server Finished latched */
  EXPECT(cap.len == CAP_CLI_N);
  EXPECT(memcmp(cap.buf, cap_cli, CAP_CLI_N) == 0);
  tls_hs_close(&s);
  return 0;
}

static int t_full_handshake(void)
{
  struct tls_hs s;
  unsigned char sh_body[64];
  unsigned char cert_body[400];
  unsigned char ske_body[400];
  unsigned char msg[600];
  unsigned char rec[700];
  unsigned char rnd[32];
  unsigned char q2[TLS_P256_POINT_LEN];
  unsigned char pms[32];
  unsigned char leaf[400];
  unsigned char sig[128];
  unsigned char zero[32] = { 0 };
  size_t m;
  size_t i;
  size_t leaf_n;
  size_t sig_n;
  int type;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 5);
  hx(q2, KAT_Q2);
  leaf_n = (size_t)(strlen(RSA_LEAF_DER) / 2);
  hx(leaf, RSA_LEAF_DER);
  sig_n = (size_t)(strlen(RSA_SKE_SIG) / 2);
  hx(sig, RSA_SKE_SIG);
  hs_init(&s);
  EXPECT(tls_hs_send_hello(&s, rnd) == 0);
  EXPECT(s.ecdhe.keyed == 1);   /* the client ephemeral key exists */

  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  sh_body[m++] = 0;
  sh_body[m++] = 10;            /* extension block: 2 exts, 5 bytes each */
  sh_body[m++] = 0;
  sh_body[m++] = 5;             /* status_request */
  sh_body[m++] = 0;
  sh_body[m++] = 1;
  sh_body[m++] = 1;             /* status_type: OCSP */
  sh_body[m++] = 0xff;
  sh_body[m++] = 0x01;          /* renegotiation_info */
  sh_body[m++] = 0;
  sh_body[m++] = 1;
  sh_body[m++] = 0;             /* empty renegotiated_connection */
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_SERVER_HELLO);
  EXPECT(tls_parse_server_msg(&s) == 0);
  EXPECT(s.suite == TLS_SUITE_CHACHA);
  EXPECT(s.version == TLS_VERSION_1_2);
  EXPECT(memcmp(s.server_random, sh_body + 2, 32) == 0);

  m = 0;
  cert_body[m] = (unsigned char)((3 + leaf_n) >> 16);
  cert_body[m + 1] = (unsigned char)((3 + leaf_n) >> 8);
  cert_body[m + 2] = (unsigned char)(3 + leaf_n);
  m += 3;
  cert_body[m] = (unsigned char)(leaf_n >> 16);
  cert_body[m + 1] = (unsigned char)(leaf_n >> 8);
  cert_body[m + 2] = (unsigned char)leaf_n;
  m += 3;
  memcpy(cert_body + m, leaf, leaf_n);
  m += leaf_n;
  m = mk_hs(msg, TLS_HS_CERTIFICATE, cert_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_CERTIFICATE);
  EXPECT(tls_parse_server_msg(&s) == 0);
  EXPECT(s.leaf_n == leaf_n);
  EXPECT(memcmp(s.leaf, leaf, leaf_n) == 0);

  m = 0;
  ske_body[m++] = TLS_CURVE_TYPE_NAMED;
  ske_body[m++] = 0;
  ske_body[m++] = TLS_CURVE_P256;
  ske_body[m++] = TLS_P256_POINT_LEN;
  memcpy(ske_body + m, q2, TLS_P256_POINT_LEN);
  m += TLS_P256_POINT_LEN;
  EXPECT(tls_ecdhe_shared(s.ecdhe.priv, q2, pms) == 0); /* premaster = x */
  ske_body[m++] = (unsigned char)(TLS_HASH_SHA256);
  ske_body[m++] = (unsigned char)(TLS_SIG_RSA);
  ske_body[m++] = (unsigned char)(sig_n >> 8);
  ske_body[m++] = (unsigned char)(sig_n & 0xff);
  memcpy(ske_body + m, sig, sig_n);
  m += sig_n;
  m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, ske_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_SERVER_KEY_EXCHANGE);
  EXPECT(tls_parse_server_msg(&s) == 0);
  EXPECT(s.ske.curve == TLS_CURVE_P256);
  EXPECT(s.ske.point_n == TLS_P256_POINT_LEN);
  EXPECT(s.ske.point[0] == TLS_POINT_UNCOMPRESSED);
  EXPECT(s.ske.sigalg == (TLS_HASH_SHA256 << 8 | TLS_SIG_RSA));
  EXPECT(s.ske.sig_n == sig_n);
  EXPECT(memcmp(s.ske.sig, sig, sig_n) == 0);
  EXPECT(s.ecdhe.done == 1);
  EXPECT(memcmp(s.ecdhe.premaster, pms, 32) == 0);
  EXPECT(memcmp(s.ecdhe.priv, zero, sizeof zero) == 0); /* scrubbed */

  m = mk_hs(msg, TLS_HS_SERVER_HELLO_DONE, NULL, 0);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(type == TLS_HS_SERVER_HELLO_DONE);
  EXPECT(tls_parse_server_msg(&s) == 0);

  EXPECT(tls_hs_pump(&s) == 0); /* nothing further */
  tls_hs_close(&s);
  return 0;
}

/* Multiple handshake messages packed into a single record. */
static int t_multi_msg(void)
{
  struct tls_hs s;
  unsigned char sh_body[64];
  unsigned char cert_body[32];
  unsigned char msg[512];
  unsigned char rec[600];
  size_t m1;
  size_t m2;
  int type;

  hs_init(&s);

  m1 = mk_shbody(sh_body, TLS_SUITE_AES_GCM, TLS_VERSION_1_2);
  m1 = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m1);
  m2 = 0;
  cert_body[m2++] = 0;
  cert_body[m2++] = 0;
  cert_body[m2++] = 7;
  cert_body[m2++] = 0;
  cert_body[m2++] = 0;
  cert_body[m2++] = 4;
  memcpy(cert_body + m2, "EFGH", 4);
  m2 += 4;
  m2 = mk_hs(msg + m1, TLS_HS_CERTIFICATE, cert_body, m2);
  EXPECT(mk_rec(rec, TLS_REC_HANDSHAKE, msg, m1 + m2) == m1 + m2 + 5);

  EXPECT(tls_hs_feed(&s, rec, m1 + m2 + 5) == 0);
  EXPECT(tls_hs_pump(&s) == 1);
  {
    const unsigned char *b;
    size_t n;

    EXPECT(tls_hs_message(&s, &type, &b, &n) == 0);
    EXPECT(type == TLS_HS_SERVER_HELLO);
  }
  EXPECT(tls_parse_server_msg(&s) == 0);
  EXPECT(s.suite == TLS_SUITE_AES_GCM);

  EXPECT(tls_hs_pump(&s) == 1);
  EXPECT(tls_hs_message(&s, &type, NULL, NULL) == -1);  /* NULL body */
  {
    const unsigned char *b;
    size_t n;

    EXPECT(tls_hs_message(&s, &type, &b, &n) == 0);
    EXPECT(type == TLS_HS_CERTIFICATE);
  }
  EXPECT(tls_parse_server_msg(&s) == 0);
  EXPECT(s.leaf_n == 4);
  EXPECT(memcmp(s.leaf, "EFGH", 4) == 0);

  EXPECT(tls_hs_pump(&s) == 0);
  tls_hs_close(&s);
  return 0;
}

/* Byte-at-a-time feeding; a handshake message split across two records. */
static int t_fifo_drip(void)
{
  struct tls_hs s;
  unsigned char sh_body[64];
  unsigned char msg[512];
  unsigned char rec[600];
  const unsigned char *body;
  size_t n;
  size_t m;
  size_t i;
  int type;

  hs_init(&s);

  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  for (i = 0; i < m; i++) {
    EXPECT(tls_hs_feed(&s, rec + i, 1) == 0);
    EXPECT(tls_hs_pump(&s) == (i == m - 1 ? 1 : 0));
  }
  EXPECT(tls_hs_message(&s, &type, &body, &n) == 0);
  EXPECT(type == TLS_HS_SERVER_HELLO);
  EXPECT(n == 38);
  EXPECT(tls_parse_server_msg(&s) == 0);
  tls_hs_close(&s);
  return 0;
}

static int t_span_records(void)
{
  struct tls_hs s;
  unsigned char rec1[32];
  unsigned char rec2[32];
  unsigned char body[16];
  const unsigned char *got;
  size_t n;
  int type;

  hs_init(&s);

  /* Handshake body of 10 bytes split 3/7 across two records. */
  memset(body, 'Q', 10);
  {
    unsigned char h1[7];

    h1[0] = TLS_HS_SERVER_HELLO;
    h1[1] = 0;
    h1[2] = 0;
    h1[3] = 10;
    memcpy(h1 + 4, body, 3);
    EXPECT(mk_rec(rec1, TLS_REC_HANDSHAKE, h1, 7) == 12);
    memset(rec2, 0, sizeof rec2);
    EXPECT(mk_rec(rec2, TLS_REC_HANDSHAKE, body + 3, 7) == 12);
  }

  EXPECT(tls_hs_feed(&s, rec1, 12) == 0);
  EXPECT(tls_hs_pump(&s) == 0); /* mid-message: needs the next record */
  EXPECT(tls_hs_feed(&s, rec2, 12) == 0);
  EXPECT(tls_hs_pump(&s) == 1);
  EXPECT(tls_hs_message(&s, &type, &got, &n) == 0);
  EXPECT(type == TLS_HS_SERVER_HELLO);
  EXPECT(n == 10);
  EXPECT(memcmp(got, body, 10) == 0);
  tls_hs_close(&s);
  return 0;
}

/* === record/handshake level rejections === */

static int t_oversize_span(void)
{
  struct tls_hs s;
  unsigned char rec[8];
  const unsigned char p1[2] = { TLS_HS_SERVER_HELLO, 0x02 };
  const unsigned char p2[2] = { 0x00, 0x01 };

  /* handshake length 0x020001 (> TLS_MAX_MSG), the 4-byte header split
   * 2/2 across two records; rejected when the second fragment completes. */
  hs_init(&s);
  EXPECT(mk_rec(rec, TLS_REC_HANDSHAKE, p1, 2) == 7);
  EXPECT(tls_hs_feed(&s, rec, 7) == 0);
  EXPECT(tls_hs_pump(&s) == 0); /* header fragment: waits */
  EXPECT(mk_rec(rec, TLS_REC_HANDSHAKE, p2, 2) == 7);
  EXPECT(tls_hs_feed(&s, rec, 7) == 0);
  EXPECT(tls_hs_pump(&s) == -1);        /* oversized at header completion */
  tls_hs_close(&s);

  /* record length field 0xFFFF (the encodable maximum) is accepted and
   * simply waits for the payload: the 16-bit field never hits the cap. */
  hs_init(&s);
  rec[0] = TLS_REC_HANDSHAKE;
  rec[1] = 3;
  rec[2] = 3;
  rec[3] = 0xff;
  rec[4] = 0xff;
  EXPECT(tls_hs_feed(&s, rec, 5) == 0);
  EXPECT(tls_hs_pump(&s) == 0);
  tls_hs_close(&s);
  return 0;
}

static int t_bad_records(void)
{
  struct tls_hs s;
  unsigned char rec[16];

  hs_init(&s);
  memset(rec, 0, sizeof rec);
  rec[0] = TLS_REC_HANDSHAKE;
  rec[1] = 3;
  rec[2] = 3;
  EXPECT(tls_hs_feed(&s, rec, 5) == 0); /* record length 0 */
  EXPECT(tls_hs_pump(&s) == -1);
  tls_hs_close(&s);

  hs_init(&s);
  memset(rec, 0, sizeof rec);
  rec[0] = TLS_REC_ALERT;       /* alert is fatal, not legacy */
  rec[1] = 3;
  rec[2] = 3;
  rec[3] = 0;
  rec[4] = 2;
  rec[5] = 0x02;                /* fatal */
  rec[6] = 0x46;                /* protocol_version */
  EXPECT(tls_hs_feed(&s, rec, 7) == 0);
  EXPECT(tls_hs_pump(&s) == -1);
  tls_hs_close(&s);

  hs_init(&s);
  memset(rec, 0, sizeof rec);
  rec[0] = TLS_REC_HANDSHAKE;
  rec[1] = 4;                   /* bad record major version */
  rec[2] = 3;
  rec[3] = 0;
  rec[4] = 2;
  rec[5] = 'x';
  rec[6] = 'y';
  EXPECT(tls_hs_feed(&s, rec, 7) == 0);
  EXPECT(tls_hs_pump(&s) == -1);
  tls_hs_close(&s);

  hs_init(&s);
  memset(rec, 0, sizeof rec);
  rec[0] = TLS_REC_HANDSHAKE;
  rec[1] = 3;
  rec[2] = 3;
  rec[3] = 0;
  rec[4] = 9;
  rec[5] = 2;                   /* handshake type */
  rec[6] = 0x02;                /* length 0x020001 > cap */
  rec[7] = 0x00;
  rec[8] = 0x01;
  memcpy(rec + 9, "AAAAA", 5);
  EXPECT(tls_hs_feed(&s, rec, 14) == 0);
  EXPECT(tls_hs_pump(&s) == -1);        /* oversized handshake */
  tls_hs_close(&s);
  return 0;
}

static int t_buffer_garbage(void)
{
  struct tls_hs s;
  const unsigned char g1[] = { 0x00, 0x03, 0x03, 0x00, 0x01, 0x00 };
  const unsigned char g2[] = { 0x16 };
  const unsigned char g3[] = { 0x16 };

  hs_init(&s);
  EXPECT(tls_hs_feed(&s, g1, sizeof g1) == 0);
  EXPECT(tls_hs_pump(&s) == -1);
  tls_hs_close(&s);

  hs_init(&s);
  EXPECT(tls_hs_feed(&s, g2, 1) == 0);  /* header fragment: block */
  EXPECT(tls_hs_pump(&s) == 0);
  EXPECT(tls_hs_feed(&s, g3, 1) == 0);
  EXPECT(tls_hs_pump(&s) == 0);
  tls_hs_close(&s);
  return 0;
}

/* === parser rejections === */

static int t_parse_bad(void)
{
  struct tls_hs s;
  unsigned char sh_body[64];
  unsigned char msg[512];
  unsigned char rec[600];
  unsigned char cert_body[32];
  size_t m;
  int type;

  hs_init(&s);

  /* wrong TLS version */
  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, 0x0301);
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* unknown cipher suite: never downgrade */
  hs_init(&s);
  m = mk_shbody(sh_body, 0xC02C, TLS_VERSION_1_2);
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* non-null compression */
  hs_init(&s);
  {
    unsigned char b[40];
    size_t k = mk_shbody(b, TLS_SUITE_CHACHA, TLS_VERSION_1_2);

    b[k - 1] = 0x01;            /* compression = deflate */
    k = mk_hs(msg, TLS_HS_SERVER_HELLO, b, k);
    k = mk_rec(rec, TLS_REC_HANDSHAKE, msg, k);
    EXPECT(tls_hs_feed(&s, rec, k) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* renegotiation_info with a non-empty payload */
  hs_init(&s);
  {
    unsigned char b[48];
    size_t k = 0;

    b[k++] = 3;
    b[k++] = 3;
    for (m = 0; m < 32; m++)
      b[k++] = (unsigned char)m;
    b[k++] = 0;                 /* empty session id */
    b[k++] = 0xcc;
    b[k++] = 0xa8;              /* suite */
    b[k++] = 0;                 /* null compression */
    b[k++] = 0;
    b[k++] = 4;                 /* 4 extension bytes follow */
    b[k++] = 0xff;
    b[k++] = 0x01;              /* renegotiation_info */
    b[k++] = 0x00;
    b[k++] = 0x01;              /* length 1 */
    b[k++] = 0x01;              /* non-empty renegotiated_connection */
    k = mk_hs(msg, TLS_HS_SERVER_HELLO, b, k);
    k = mk_rec(rec, TLS_REC_HANDSHAKE, msg, k);
    EXPECT(tls_hs_feed(&s, rec, k) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* broken extension block length */
  hs_init(&s);
  {
    unsigned char b[40];
    size_t k = mk_shbody(b, TLS_SUITE_CHACHA, TLS_VERSION_1_2);

    b[k++] = 0x00;
    b[k++] = 0xFF;              /* bogus ext length */
    k = mk_hs(msg, TLS_HS_SERVER_HELLO, b, k);
    k = mk_rec(rec, TLS_REC_HANDSHAKE, msg, k);
    EXPECT(tls_hs_feed(&s, rec, k) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* certificate: total length disagrees with the message size */
  hs_init(&s);
  memset(cert_body, 0, sizeof cert_body);
  cert_body[0] = 0;
  cert_body[1] = 0;
  cert_body[2] = 9;             /* claims more than present */
  cert_body[3] = 0;
  cert_body[4] = 0;
  cert_body[5] = 4;
  memcpy(cert_body + 6, "ABCD", 4);
  m = mk_hs(msg, TLS_HS_CERTIFICATE, cert_body, 10);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* SKE: wrong curve */
  hs_init(&s);
  {
    unsigned char b[80];

    memset(b, 0, sizeof b);
    b[0] = TLS_CURVE_TYPE_NAMED;
    b[1] = 0;
    b[2] = 0x18;                /* unsupported curve */
    b[3] = 65;
    b[4] = TLS_POINT_UNCOMPRESSED;
    memcpy(b + 5, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 64);
    b[69] = TLS_HASH_SHA256;
    b[70] = TLS_SIG_RSA;
    b[71] = 0;
    b[72] = 2;
    b[73] = 0xaa;
    b[74] = 0xbb;
    m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, b, 75);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(tls_hs_feed(&s, rec, m) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(s.ske.sig_n == 0);   /* sig untouched until a valid SKE parses */
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* SKE: ecdsa signature (not rsa) */
  hs_init(&s);
  {
    unsigned char b[80];

    memset(b, 0, sizeof b);
    b[0] = TLS_CURVE_TYPE_NAMED;
    b[1] = 0;
    b[2] = TLS_CURVE_P256;
    b[3] = 65;
    b[4] = TLS_POINT_UNCOMPRESSED;
    memcpy(b + 5, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 64);
    b[69] = TLS_HASH_SHA256;
    b[70] = 0x03;               /* ecdsa */
    b[71] = 0;
    b[72] = 2;
    b[73] = 0xaa;
    b[74] = 0xbb;
    m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, b, 75);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(tls_hs_feed(&s, rec, m) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* SKE: signature does not fill the message tail */
  hs_init(&s);
  {
    unsigned char b[80];

    memset(b, 0, sizeof b);
    b[0] = TLS_CURVE_TYPE_NAMED;
    b[1] = 0;
    b[2] = TLS_CURVE_P256;
    b[3] = 65;
    b[4] = TLS_POINT_UNCOMPRESSED;
    memcpy(b + 5, "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 64);
    b[69] = TLS_HASH_SHA256;
    b[70] = TLS_SIG_RSA;
    b[71] = 0;
    b[72] = 2;                  /* claims 2 sig bytes but 4 remain */
    b[73] = 0xaa;
    b[74] = 0xbb;
    b[75] = 0xcc;
    b[76] = 0xdd;
    m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, b, 77);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(tls_hs_feed(&s, rec, m) == 0);
    EXPECT(tls_hs_pump(&s) == 1);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* ServerHelloDone with a non-empty body is malformed */
  hs_init(&s);
  m = mk_hs(msg, TLS_HS_SERVER_HELLO_DONE, (const unsigned char *)"X", 1);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* unexpected handshake message type */
  hs_init(&s);
  m = mk_hs(msg, 0x00, (const unsigned char *)"X", 1);  /* hello_request */
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* ServerHello body shorter than version + random */
  hs_init(&s);
  memset(sh_body, 0, sizeof sh_body);
  sh_body[0] = 3;
  sh_body[1] = 3;
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, 33);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* session id length overruns the body */
  hs_init(&s);
  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  sh_body[34] = 1;              /* claims a 1-byte session id */
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, 35);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* body ends right after the cipher suite (no compression byte) */
  hs_init(&s);
  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m - 1);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* certificate body too short for the list length */
  hs_init(&s);
  m = mk_hs(msg, TLS_HS_CERTIFICATE, (const unsigned char *)"X", 1);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == -1);
  tls_hs_close(&s);

  /* certificate_list is empty (total length 0) */
  hs_init(&s);
  {
    unsigned char b[3] = { 0, 0, 0 };

    m = mk_hs(msg, TLS_HS_CERTIFICATE, b, 3);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(feed_msg(&s, rec, m, &type) == 0);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* empty leaf certificate */
  hs_init(&s);
  {
    unsigned char b[6] = { 0, 0, 3, 0, 0, 0 };  /* total 3, leaf len 0 */

    m = mk_hs(msg, TLS_HS_CERTIFICATE, b, 6);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(feed_msg(&s, rec, m, &type) == 0);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* SKE: curve type is not named_curve */
  hs_init(&s);
  {
    unsigned char b[75];

    memset(b, 0, sizeof b);
    b[0] = 0x02;
    m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, b, 75);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(feed_msg(&s, rec, m, &type) == 0);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* SKE: params truncated before the point */
  hs_init(&s);
  {
    unsigned char b[60];

    memset(b, 0, sizeof b);
    m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, b, 60);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(feed_msg(&s, rec, m, &type) == 0);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* SKE: point has the wrong length for P-256 */
  hs_init(&s);
  {
    unsigned char b[75];

    memset(b, 0, sizeof b);
    b[0] = TLS_CURVE_TYPE_NAMED;
    b[2] = TLS_CURVE_P256;
    b[3] = 64;                  /* not 65 */
    b[4] = TLS_POINT_UNCOMPRESSED;
    m = mk_hs(msg, TLS_HS_SERVER_KEY_EXCHANGE, b, 75);
    m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
    EXPECT(feed_msg(&s, rec, m, &type) == 0);
    EXPECT(tls_parse_server_msg(&s) == -1);
  }
  tls_hs_close(&s);

  /* pump consumes the ready message; parse afterwards must fail */
  hs_init(&s);
  m = mk_shbody(sh_body, TLS_SUITE_CHACHA, TLS_VERSION_1_2);
  m = mk_hs(msg, TLS_HS_SERVER_HELLO, sh_body, m);
  m = mk_rec(rec, TLS_REC_HANDSHAKE, msg, m);
  EXPECT(feed_msg(&s, rec, m, &type) == 0);
  EXPECT(tls_parse_server_msg(&s) == 0);
  EXPECT(tls_hs_pump(&s) == 0); /* nothing further arrives */
  EXPECT(tls_parse_server_msg(&s) == -1);       /* message gone */
  tls_hs_close(&s);
  return 0;
}

/* === legacy transport detection (one-shot, first byte only) === */

static int t_detect(void)
{
  const unsigned char nil = 0;
  unsigned char raw[4];
  unsigned char alert[7] = { 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46 };
  unsigned char sh[5] = { 0x16, 0x03, 0x01, 0x00, 0x02 };
  unsigned char frame[9] = { 0x00, 0x00, 0x00, 0x05, 'C', 'O', 'N', 'N', 'E' };
  size_t t;

  EXPECT(tls_hs_detect(NULL, 0) == -1);
  EXPECT(tls_hs_detect(NULL, 1) == -1);
  EXPECT(tls_hs_detect(&nil, 0) == TLS_DETECT_WAIT);

  /* every TLS record content type keeps the TLS framing */
  for (t = TLS_REC_CHANGE_CIPHER_SPEC; t <= TLS_REC_APP_DATA; t++) {
    raw[0] = (unsigned char)t;
    raw[1] = 0xff;              /* only the first byte may matter */
    EXPECT(tls_hs_detect(raw, 1) == TLS_DETECT_TLS);
    EXPECT(tls_hs_detect(raw, 2) == TLS_DETECT_TLS);
  }

  /* a TLS alert is TLS, never reinterpreted as a legacy plaintext reply */
  EXPECT(tls_hs_detect(alert, sizeof alert) == TLS_DETECT_TLS);
  /* a ServerHello handshake record keeps TLS framing */
  EXPECT(tls_hs_detect(sh, sizeof sh) == TLS_DETECT_TLS);

  /* a plaintext Cast V2 frame and any non-record first byte → legacy */
  EXPECT(tls_hs_detect(frame, sizeof frame) == TLS_DETECT_PLAINTEXT);
  raw[0] = 0x01;
  EXPECT(tls_hs_detect(raw, 1) == TLS_DETECT_PLAINTEXT);
  raw[0] = 0x7f;
  EXPECT(tls_hs_detect(raw, 1) == TLS_DETECT_PLAINTEXT);
  raw[0] = 0xff;
  EXPECT(tls_hs_detect(raw, 1) == TLS_DETECT_PLAINTEXT);
  return 0;
}

static int t_api(void)
{
  struct tls_hs s;
  struct cast_io io = { NULL, NULL, NULL };
  unsigned char x[32] = { 0 };

  EXPECT(tls_hs_init(NULL, &io) == -1);
  EXPECT(tls_hs_init(&s, NULL) == -1);
  EXPECT(tls_hs_init(&s, &io) == 0);
  EXPECT(tls_hs_feed(NULL, x, 32) == -1);
  EXPECT(tls_hs_feed(&s, NULL, 1) == -1);
  EXPECT(tls_hs_feed(&s, NULL, 0) == 0);
  EXPECT(tls_hs_message(&s, NULL, NULL, NULL) == -1);
  EXPECT(tls_hs_message(&s, &(int) { 0 }, NULL, NULL) == -1);
  EXPECT(tls_hs_send_hello(NULL, x) == -1);
  EXPECT(tls_hs_send_hello(&s, NULL) == -1);
  {
    const unsigned char *b;
    size_t n;
    int t;

    EXPECT(tls_hs_message(&s, &t, &b, &n) == -1);       /* nothing ready */
  }
  tls_hs_close(&s);
  tls_hs_close(NULL);
  return 0;
}

/* === ECDHE P-256: KAT vectors, scalar/peer rejects, priv scrubbing === */

static int t_ecdhe(void)
{
  unsigned char d1[32], d2[32], d3[32], nbe[32], zero[32] = { 0 };
  unsigned char pms[32], q1[TLS_P256_POINT_LEN], q2[TLS_P256_POINT_LEN];
  unsigned char q3[TLS_P256_POINT_LEN];
  unsigned char pq[TLS_P256_POINT_LEN], sref[32], out[32];
  unsigned char bad[TLS_P256_POINT_LEN];
  struct tls_hs s;
  unsigned char rnd[32];
  size_t i;

  hx(d1, KAT_D1);
  hx(d2, KAT_D2);
  hx(d3, KAT_D3);
  hx(nbe, KAT_N);
  hx(q1, KAT_Q1);
  hx(q2, KAT_Q2);
  hx(q3, KAT_Q3);
  hx(sref, KAT_S);

  /* pub(d) reproduces the reference points, shared(d, Q) the reference S */
  EXPECT(tls_ecdhe_pub(d1, pq) == 0);
  EXPECT(memcmp(pq, q1, sizeof q1) == 0);
  EXPECT(tls_ecdhe_pub(d2, pq) == 0);
  EXPECT(memcmp(pq, q2, sizeof q2) == 0);
  EXPECT(tls_ecdhe_pub(d3, pq) == 0);
  EXPECT(memcmp(pq, q3, sizeof q3) == 0);       /* has a zero-padded coord */
  EXPECT(tls_ecdhe_shared(d1, q2, out) == 0);
  EXPECT(memcmp(out, sref, sizeof sref) == 0);
  EXPECT(tls_ecdhe_shared(d2, q1, out) == 0);
  EXPECT(memcmp(out, sref, sizeof sref) == 0);

  /* scalars outside [1, n-1] are rejected */
  EXPECT(tls_ecdhe_pub(zero, pq) == -1);
  EXPECT(tls_ecdhe_pub(nbe, pq) == -1);
  EXPECT(tls_ecdhe_shared(zero, q2, out) == -1);
  EXPECT(tls_ecdhe_shared(nbe, q2, out) == -1);

  /* malformed peer points are rejected */
  memcpy(bad, q2, sizeof bad);
  bad[0] = TLS_POINT_UNCOMPRESSED + 1;  /* bad prefix byte */
  EXPECT(tls_ecdhe_shared(d1, bad, out) == -1);
  memcpy(bad, q2, sizeof bad);
  bad[1] = 0xff;                /* original: 0x81 side-changes to 0xff... */
  EXPECT(tls_ecdhe_shared(d1, bad, out) == -1);
  memcpy(bad, q2, sizeof bad);
  /* x == p exactly (0xffffffff000000010000...) -> rejected */
  bad[1] = 0xff;
  bad[2] = 0xff;
  bad[3] = 0xff;
  bad[4] = 0xff;
  bad[7] = 0x01;
  EXPECT(tls_ecdhe_shared(d1, bad, out) == -1);
  memcpy(bad, q2, sizeof bad);
  /* y > p (0xffffffff00000002...) -> rejected */
  bad[33] = 0xff;
  bad[34] = 0xff;
  bad[35] = 0xff;
  bad[36] = 0xff;
  bad[37] = 0x00;
  bad[38] = 0x00;
  bad[39] = 0x02;
  EXPECT(tls_ecdhe_shared(d1, bad, out) == -1);
  memcpy(bad, q2, sizeof bad);
  bad[64] ^= 0x01;              /* last y byte flipped: off-curve */
  EXPECT(tls_ecdhe_shared(d1, bad, out) == -1);
  EXPECT(tls_ecdhe_shared(d1, q1, out) == 0);   /* valid peer: ok */

  /* NULL argument rejects */
  EXPECT(tls_ecdhe_keygen((struct tls_hs *)0) == -1);

  /* keygen then derive: private key is scrubbed, premaster kept */
  memset(&s, 0, sizeof s);
  hs_init(&s);
  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)i;
  EXPECT(tls_hs_send_hello(&s, rnd) == 0);
  EXPECT(s.ecdhe.keyed == 1);
  EXPECT(s.ecdhe.pub[0] == TLS_POINT_UNCOMPRESSED);
  EXPECT(tls_ecdhe_pub(s.ecdhe.priv, pq) == 0);
  EXPECT(memcmp(pq, s.ecdhe.pub, sizeof pq) == 0);
  EXPECT(memcmp(s.ecdhe.priv, zero, sizeof zero) != 0); /* not yet */
  memcpy(s.ske.point, s.ecdhe.pub, TLS_P256_POINT_LEN);
  s.ske.point_n = TLS_P256_POINT_LEN;
  EXPECT(tls_ecdhe_shared(s.ecdhe.priv, s.ske.point, pms) == 0);
  EXPECT(tls_ecdhe_derive(&s) == 0);
  EXPECT(s.ecdhe.done == 1);
  EXPECT(memcmp(s.ecdhe.premaster, pms, 32) == 0);
  EXPECT(memcmp(s.ecdhe.priv, zero, sizeof zero) == 0); /* wiped */
  EXPECT(tls_ecdhe_derive(&s) == 0);    /* idempotent */
  tls_hs_close(&s);

  /* derive without a keyed pair, or without a server point, fails */
  hs_init(&s);
  EXPECT(tls_ecdhe_derive(&s) == -1);
  memcpy(s.ske.point, q2, TLS_P256_POINT_LEN);
  s.ske.point_n = TLS_P256_POINT_LEN;
  EXPECT(tls_ecdhe_derive(&s) == -1);   /* not keyed */
  EXPECT(tls_ecdhe_keygen(&s) == 0);
  s.ske.point_n = 0;
  EXPECT(tls_ecdhe_derive(&s) == -1);   /* server point not provided */
  memcpy(s.ske.point, q2, TLS_P256_POINT_LEN);
  s.ske.point[64] ^= 0x01;      /* off-curve peer: shared fails */
  s.ske.point_n = TLS_P256_POINT_LEN;
  EXPECT(tls_ecdhe_derive(&s) == -1);
  tls_hs_close(&s);
  return 0;
}

/* After the security latch the transport seals outbound Cast frames with
 * tls_rec_seal and decodes inbound APP_DATA records into the ap buffer
 * (tls_rec_available/peek/consume). Seal one plaintext, feed it back through
 * the record layer, and verify the round-trip lands in the app-data buffer. */
static int t_app_roundtrip(void)
{
  struct tls_hs s;
  struct cast_io io;
  struct ciocap cap;
  unsigned char rnd[32];
  unsigned char exp[2048];
  unsigned char rec[300];
  const unsigned char *p;
  size_t exp_n = 0;
  size_t out_n = 0;
  size_t n;
  size_t i;

  for (i = 0; i < sizeof rnd; i++)
    rnd[i] = (unsigned char)(i * 5);
  EXPECT(fin_csetup(&s, &io, &cap, rnd, exp, &exp_n) == 0);

  /* Force the security latch: keys are established, ciphertext flows. */
  s.fin.verified = 1;
  s.fin.peer_cipher = 1;
  s.fin.c_seq = 0;
  s.fin.s_seq = 0;
  /* tls_rec_seal writes with the client-write key; rec_decrypt reads with
   * the server-write key. Align them so the sealed record opens back up. */
  memcpy(s.s_key, s.c_key, sizeof s.c_key);
  memcpy(s.s_iv, s.c_iv, sizeof s.c_iv);

  EXPECT(tls_rec_seal(&s, (const unsigned char *)"hello", 5, rec, &out_n) == 0);
  EXPECT(out_n > 5 && rec[0] == TLS_REC_APP_DATA);
  EXPECT(s.fin.c_seq == 1);     /* outbound seq advanced */

  /* fin_csetup leaves the record frame mid-SKE; reset the framing state so
   * the sealed record above is parsed as a fresh record. */
  s.rh_n = 0;
  s.rec_n = 0;
  s.rec_off = 0;
  s.rec_dec = 0;
  s.hs_hdr_done = 0;
  s.hs_phdr_n = 0;
  s.hs_ready = 0;
  s.hs_n = 0;
  s.inq_n = 0;
  s.inq_off = 0;

  EXPECT(tls_hs_feed(&s, rec, out_n) == 0);
  EXPECT(tls_hs_pump(&s) == 0); /* one record drained into the ap buffer */
  EXPECT(tls_rec_available(&s) == 5);
  p = tls_rec_peek(&s, &n);
  EXPECT(n == 5 && memcmp(p, "hello", 5) == 0);
  tls_rec_consume(&s, 3);       /* partial consume */
  EXPECT(tls_rec_available(&s) == 2);
  tls_rec_consume(&s, 2);       /* drains the buffer */
  EXPECT(tls_rec_available(&s) == 0);

  /* app-data is rejected while the latch is closed */
  s.fin.verified = 0;
  EXPECT(rec_kind_ok(&s, rec) == 0);

  /* NULL-safe accessors */
  EXPECT(tls_rec_available(NULL) == 0);
  EXPECT(tls_rec_peek(NULL, &n) == NULL);

  tls_hs_close(&s);
  return 0;
}

int main(void)
{
  RUN(t_hello);
  RUN(t_random);
  RUN(t_crypto);
  RUN(t_rsa);
  RUN(t_send_hello);
  RUN(t_full_handshake);
  RUN(t_ecdhe);
  RUN(t_multi_msg);
  RUN(t_fifo_drip);
  RUN(t_span_records);
  RUN(t_bad_records);
  RUN(t_oversize_span);
  RUN(t_buffer_garbage);
  RUN(t_parse_bad);
  RUN(t_finish);
  RUN(t_finish_bad);
  RUN(t_finish_latch);
  RUN(t_recorded);
  RUN(t_detect);
  RUN(t_api);
  RUN(t_app_roundtrip);
  TEST_SUMMARY();
}
