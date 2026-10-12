/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * litecast: pruned configuration. Based on the upstream v1.18.2
 * tomcrypt_custom.h with LTC_NOTHING enabled and only the modules
 * litecast's minimal TLS client needs re-enabled:
 *   - ChaCha20-Poly1305 AEAD (TLS 1.2 record protection, RFC 7905)
 *   - SHA-256 (PRF P_hash) + HMAC (P_hash building block)
 *   - RNG (ephemeral key material) + mem_neq / zero helpers
 *   - LibTomMath (MPI) under LTM_DESC for big-number PK ops
 * All structural macro definitions from upstream are preserved
 * verbatim; only the feature-enable section differs. License headers
 * are preserved per DOMAIN.md.
 */

#ifndef TOMCRYPT_CUSTOM_H_
#define TOMCRYPT_CUSTOM_H_

/* macros for various libc functions you can change for embedded targets */
#ifndef XMALLOC
#define XMALLOC  malloc
#endif
#ifndef XREALLOC
#define XREALLOC realloc
#endif
#ifndef XCALLOC
#define XCALLOC  calloc
#endif
#ifndef XFREE
#define XFREE    free
#endif

#ifndef XMEMSET
#define XMEMSET  memset
#endif
#ifndef XMEMCPY
#define XMEMCPY  memcpy
#endif
#ifndef XMEMMOVE
#define XMEMMOVE memmove
#endif
#ifndef XMEMCMP
#define XMEMCMP  memcmp
#endif
/* A memory compare function that has to run in constant time */
#ifndef XMEM_NEQ
#define XMEM_NEQ  mem_neq
#endif
#ifndef XSTRCMP
#define XSTRCMP strcmp
#endif

#ifndef XCLOCK
#define XCLOCK   clock
#endif

#ifndef XQSORT
#define XQSORT qsort
#endif

#if ( defined(malloc) || defined(realloc) || defined(calloc) || defined(free) || \
      defined(memset) || defined(memcpy) || defined(memcmp) || defined(strcmp) || \
      defined(clock) || defined(qsort) ) && !defined(LTC_NO_PROTOTYPES)
#define LTC_NO_PROTOTYPES
#endif

/* Disable everything not explicitly re-enabled below. */
#define LTC_NOTHING

/* disable all file related functions */
#define LTC_NO_FILE

/* Enable self-test test vector checking */
/* (compiled out for the minimal build) */
#define LTC_NO_TEST

/* Use small code where possible */
/* #define LTC_SMALL_CODE */

/* clean the stack of functions which put private information on stack */
#define LTC_CLEAN_STACK

/* disable all forms of ASM */
#define LTC_NO_ASM

/* ---> math provider? <--- */
/* LibTomMath */
#define LTM_DESC

/* ---> Symmetric Block Ciphers <--- */
/* litecast needs no block ciphers */

/* ---> Stream ciphers <--- */
#define LTC_CHACHA

/* ---> Block Cipher Modes <--- */
/* none */

/* ---> One-Way Hash Functions <--- */
#define LTC_SHA256
#define LTC_HASH_HELPERS

/* ---> MAC functions <--- */
#define LTC_HMAC
#define LTC_POLY1305

/* ---> Encrypt + Authenticate Modes <--- */
#define LTC_CHACHA20POLY1305_MODE

/* --> Pseudo Random Number Generators <--- */
/* rng_get_bytes() */
#define LTC_RNG_GET_BYTES

/* ---> Public Key Crypto <--- */
/* (RSA/MECC wired when the handshake milestone lands) */
/* #define LTC_MRSA */
/* #define LTC_MECC */

/* ---> PKCS / ASN.1 --- */
/* (DER enabled when x509/RSA pubkey verification lands) */
/* #define LTC_PKCS_1 */
/* #define LTC_DER */

/* ---> misc stuff <--- */
/* (HMAC off the LTC_NO_MISC path is enabled above) */

/*
 * MPI requirement note: LTC_MPI is auto-derived in upstream when
 * LTC_MECC || LTC_MRSA || LTC_MDSA || LTC_MKAT. For the pairing smoke
 * test we define LTM_DESC so ltm_desc.c / crypt_ltc_mp_descriptor.c
 * link against libtommath; no PK descriptor is compiled yet.
 */
#ifndef LTC_MPI
/* #define LTC_MPI */
#endif

/* cleanup */

#if defined(LTC_MECC)
   #ifndef LTC_NO_CURVES
      #define LTC_ECC112
      #define LTC_ECC128
      #define LTC_ECC160
      #define LTC_ECC192
      #define LTC_ECC224
      #define LTC_ECC256
      #define LTC_ECC384
      #define LTC_ECC521
   #endif
#endif

#if defined(LTC_DER)
   #ifndef LTC_DER_MAX_RECURSION
      #define LTC_DER_MAX_RECURSION 30
   #endif
#endif

#if defined(LTC_MECC) || defined(LTC_MRSA) || defined(LTC_MDSA) || defined(LTC_MKAT)
   /* Include the MPI functionality?  (required by the PK algorithms) */
   #define LTC_MPI
#endif

/* THREAD management */
#ifdef LTC_PTHREAD

#include <pthread.h>

#define LTC_MUTEX_GLOBAL(x)   pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;
#define LTC_MUTEX_PROTO(x)    extern pthread_mutex_t x;
#define LTC_MUTEX_TYPE(x)     pthread_mutex_t x;
#define LTC_MUTEX_INIT(x)     LTC_ARGCHK(pthread_mutex_init(x, NULL) == 0);
#define LTC_MUTEX_LOCK(x)     LTC_ARGCHK(pthread_mutex_lock(x) == 0);
#define LTC_MUTEX_UNLOCK(x)   LTC_ARGCHK(pthread_mutex_unlock(x) == 0);
#define LTC_MUTEX_DESTROY(x)  LTC_ARGCHK(pthread_mutex_destroy(x) == 0);

#else

/* default no functions */
#define LTC_MUTEX_GLOBAL(x)
#define LTC_MUTEX_PROTO(x)
#define LTC_MUTEX_TYPE(x)
#define LTC_MUTEX_INIT(x)
#define LTC_MUTEX_LOCK(x)
#define LTC_MUTEX_UNLOCK(x)
#define LTC_MUTEX_DESTROY(x)

#endif

/* Debuggers */

/* #define LTC_VALGRIND */

#endif /* TOMCRYPT_CUSTOM_H_ */
