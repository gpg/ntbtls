/* util.h - Utility functions
 * Copyright (C) 2014 g10 Code GmbH
 *
 * This file is part of NTBTLS
 *
 * NTBTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * NTBTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NTBTLS_UTIL_H
#define NTBTLS_UTIL_H

#include "wipemem.h"

/* Some handy macros */
#ifndef STR
#define STR(v) #v
#endif
#define STR2(v) STR(v)
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#define DIMof(type,member)   DIM(((type *)0)->member)

/* Macros to replace ctype macros so o avoid locale problems.  */
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define alphap(p)   ((*(p) >= 'A' && *(p) <= 'Z')       \
                     || (*(p) >= 'a' && *(p) <= 'z'))
#define alnump(p)   (alphap (p) || digitp (p))
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
  /* Note this isn't identical to a C locale isspace() without \f and
     \v, but works for the purposes used here. */
#define ascii_isspace(a) ((a)==' ' || (a)=='\n' || (a)=='\r' || (a)=='\t')

/* The atoi macros assume that the buffer has only valid digits. */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))
#define xtoi_4(p)   ((xtoi_2(p) * 256) + xtoi_2((p)+2))


/* Return the size of a OID string without the nul.  */
/* FIXME: Do we use it? */
#define OID_SIZE(x) (sizeof(x) - 1)


/*
 * Object to hold X.509 certificates.
 */
struct x509_cert_s;
typedef struct x509_cert_s *x509_cert_t;


/* Constant-time compare of two buffers.  Returns 0 if buffers are
   equal, and 1 if buffers differ.  At most places this function can
   be used as a memcmp replacement.  However, -1 will never be
   returned, thus it can't be used for sorting etc.  */
static inline int
memcmpct (const void *_a, const void *_b, size_t len)
{
  const unsigned char *a = _a;
  const unsigned char *b = _b;
  size_t diff, i;

  /* Constant-time compare. */
  for (i = 0, diff = 0; i < len; i++)
    diff -= !!(a[i] - b[i]);

  return !!diff;
}


/* Buffer to integer functions.  */

static inline unsigned int
buf16_to_uint (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((unsigned int)p[0] << 8) | p[1]);
}

static inline size_t
buf16_to_size_t (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((size_t)p[0] << 8) | p[1]);
}

static inline size_t
buf24_to_size_t (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((size_t)p[0] << 16) | (p[1] << 8) | p[1]);
}

static inline uint32_t
buf32_to_u32 (const void *buffer)
{
  const unsigned char *p = buffer;

  return (((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}




/*-- debug.c --*/
void _ntbtls_set_debug (int level, const char *prefix, gpgrt_stream_t stream);
void _ntbtls_set_log_handler (ntbtls_log_handler_t cb, void *cb_value);

void _ntbtls_debug_msg (int level, const char *format,
                        ...) GPGRT_ATTR_PRINTF(2,3);
void _ntbtls_debug_buf (int level, const char *text,
                        const void *buf, size_t len);
void _ntbtls_debug_bug (const char *file, int line);
void _ntbtls_debug_ret (int level, const char *name, gpg_error_t err);
void _ntbtls_debug_mpi (int level, const char *text, gcry_mpi_t a);
void _ntbtls_debug_pnt (int level, const char *text,
                        gcry_mpi_point_t a, gcry_ctx_t ctx);
void _ntbtls_debug_sxp (int level, const char *text, gcry_sexp_t a);
void _ntbtls_debug_crt (int level, const char *text, x509_cert_t chain);

#define debug_msg          _ntbtls_debug_msg
#define debug_buf(a,b,c,d) _ntbtls_debug_buf ((a),(b),(c),(d))
#define debug_bug()        _ntbtls_debug_bug (__FILE__, __LINE__)
#define debug_ret(l,n,e)   _ntbtls_debug_ret ((l),(n),(e))
#define debug_mpi(l,t,a)   _ntbtls_debug_mpi ((l),(t),(a))
#define debug_pnt(l,t,a,c) _ntbtls_debug_pnt ((l),(t),(a),(c))
#define debug_sxp(l,t,a)   _ntbtls_debug_sxp ((l),(t),(a))
#define debug_crt(l,t,a)   _ntbtls_debug_crt ((l),(t),(a))



/* These error codes are used but not defined in the required
   libgpg-error version.  Define them here. */
#if GPG_ERROR_VERSION_NUMBER < 0x011b00 /* 1.27 */
# define GPG_ERR_WRONG_NAME  313
#endif
#if GPG_ERROR_VERSION_NUMBER < 0x011a00 /* 1.26 */
# define GPG_ERR_UNKNOWN_FLAG     309
# define GPG_ERR_INV_ORDER	  310
# define GPG_ERR_ALREADY_FETCHED  311
# define GPG_ERR_TRY_LATER        312
# define GPG_ERR_SYSTEM_BUG	  666
# define GPG_ERR_DNS_UNKNOWN	  711
# define GPG_ERR_DNS_SECTION	  712
# define GPG_ERR_DNS_ADDRESS	  713
# define GPG_ERR_DNS_NO_QUERY	  714
# define GPG_ERR_DNS_NO_ANSWER	  715
# define GPG_ERR_DNS_CLOSED	  716
# define GPG_ERR_DNS_VERIFY	  717
# define GPG_ERR_DNS_TIMEOUT	  718
#endif




#endif /*NTBTLS_UTIL_H*/
