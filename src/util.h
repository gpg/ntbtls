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


/* Return the size of a OID string without the nul.  */
//FIXME: Do we use it?
#define OID_SIZE(x) (sizeof(x) - 1)


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



/*-- debug.c --*/
void _ntbtls_set_debug (int level, const char *prefix, gpgrt_stream_t stream);

/* FIXME: Add a public version of _GPGRT_GCC_A_PRINTF to libgpg-error.
   Use variadic macros is possibel to check the level before calling
   the function.  */
void _ntbtls_debug_msg (int level, const char *format,
                        ...) _GPGRT_GCC_A_PRINTF(2,0);
void _ntbtls_debug_buf (int level, const char *text,
                        const void *buf, size_t len);
void _ntbtls_debug_bug (const char *file, int line);
void _ntbtls_debug_ret (int level, const char *name, gpg_error_t err);
void _ntbtls_debug_mpi (int level, const char *text, gcry_mpi_t a);
void _ntbtls_debug_sxp (int level, const char *text, gcry_sexp_t a);

#define debug_msg          _ntbtls_debug_msg
#define debug_buf(a,b,c,d) _ntbtls_debug_buf ((a),(b),(c),(d))
#define debug_bug()        _ntbtls_debug_bug (__FILE__, __LINE__)
#define debug_ret(l,n,e)   _ntbtls_debug_ret ((l),(n),(e))
#define debug_mpi(l,t,a)   _ntbtls_debug_mpi ((l),(t),(a))
#define debug_sxp(l,t,a)   _ntbtls_debug_sxp ((l),(t),(a))



/* These error codes are used but not defined in the required
   libgpg-error version.  Define them here. */
#if GPG_ERROR_VERSION_NUMBER < 0x011200  /* 1.18 */
# define GPG_ERR_REQUEST_TOO_SHORT 223
# define GPG_ERR_REQUEST_TOO_LONG  224
#endif




#endif /*NTBTLS_UTIL_H*/
