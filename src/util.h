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


/*-- debug.c --*/

/* FIXME: Add a public version of _GPGRT_GCC_A_PRINTF to libgpg-error.
   Use variadic macros is possibel to check the level before calling
   the function.  */
void _ntbtls_debug_msg (int level, const char *format,
                        ...) _GPGRT_GCC_A_PRINTF(2,0);
void _ntbtls_debug_buf (int level, const char *text,
                        const void *buf, size_t len);
void _ntbtls_debug_bug (const char *file, int line);
void _ntbtls_debug_ret (int level, const char *name, gpg_error_t err);

#define debug_msg          _ntbtls_debug_msg
#define debug_buf(a,b,c,d) _ntbtls_debug_buf ((a),(b),(c),(d))
#define debug_bug()        _ntbtls_debug_bug (__FILE__, __LINE__)
#define debug_ret(l,n,e)   _ntbtls_debug_ret ((l),(n),(e))






#endif /*NTBTLS_UTIL_H*/
