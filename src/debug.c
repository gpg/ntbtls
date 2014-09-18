/* debug.c - Debug functions
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

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ntbtls-int.h"


/* FIXME: For now we print to stderr.  */
void
_ntbtls_debug_msg (int level, const char *format, ...)
{
  va_list arg_ptr;
  int saved_errno;

  (void)level;

  saved_errno = errno;
  va_start (arg_ptr, format);
  gpgrt_fputs ("ntbtls: ", es_stderr);
  gpgrt_vfprintf (es_stderr, format, arg_ptr);
  va_end (arg_ptr);
  gpg_err_set_errno (saved_errno);
}


void
_ntbtls_debug_bug (const char *file, int line)
{
  const char *s;

  s = strrchr (s, '/');
  if (s)
    file = s + 1;
  _ntbtls_debug_msg (0, "bug detected at %s:%d\n", file, line);
}


void
_ntbtls_debug_buf (int level, const char *text, const void *buf, size_t len)
{
  (void)level;

  gpgrt_fputs ("ntbtls: ", es_stderr);
  gcry_log_debughex (text, buf, len);
}
