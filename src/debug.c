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

static int debug_level;
static const char *debug_prefix;
static estream_t debug_stream;
static ntbtls_log_handler_t log_handler;
static void *log_handler_value;


/* Set the Debug level up to which debug messages are shown. 0
 * disables debug messages except for those which will always be
 * shown.  PREFIX is prefix to prefix all output; the default is
 * "ntbtls".  STREAM is the output stream; the default is es_stderr.
 * Changing STREAM and PREFIX is not thread-safe and their values are
 * ignored if a log handler has been set.  */
void
_ntbtls_set_debug (int level, const char *prefix, gpgrt_stream_t stream)
{
  static char *debug_prefix_buffer;

  if (!debug_prefix)
    debug_prefix = "ntbtls";

  if (prefix)
    {
      free (debug_prefix_buffer);
      debug_prefix_buffer = malloc (strlen (prefix));
      if (debug_prefix_buffer)
        debug_prefix = debug_prefix_buffer;
    }

  debug_stream = stream? stream : es_stderr;

  debug_level = level > 0? level : 0;
}


/* Set a dedicated log handler.  See the description of
 * ntbtls_log_handler_t for details.  This is not thread-safe.  */
void
_ntbtls_set_log_handler (ntbtls_log_handler_t cb, void *cb_value)
{
  log_handler = cb;
  log_handler_value = cb_value;
}


/* Note that a LEVEL of -1 will always print even when debugging has
 * not been enabled.  */
void
_ntbtls_debug_msg (int level, const char *format, ...)
{
  va_list arg_ptr;
  int saved_errno;
  int no_lf;

  if (level != -1 && (!debug_level || level > debug_level))
    return;

  va_start (arg_ptr, format);
  saved_errno = errno;
  if (log_handler)
    {
      log_handler (log_handler_value, level, format, arg_ptr);
    }
  else
    {
      if ((no_lf = (*format == '\b')))
        format++;

      gpgrt_fputs ("ntbtls: ", es_stderr);
      gpgrt_vfprintf (es_stderr, format, arg_ptr);
      if (no_lf)
        gpgrt_fflush (es_stderr); /* To sync with stderr.  */
      else if (*format && format[strlen(format)-1] != '\n')
        gpgrt_fputc ('\n', es_stderr);
    }

  va_end (arg_ptr);
  gpg_err_set_errno (saved_errno);
}


void
_ntbtls_debug_bug (const char *file, int line)
{
  const char *s;

  s = strrchr (file, '/');
  if (s)
    file = s + 1;
  _ntbtls_debug_msg (-1, "bug detected at %s:%d\n", file, line);
}


void
_ntbtls_debug_ret (int level, const char *name, gpg_error_t err)
{
  if (!debug_level || level > debug_level)
    return;

  if (err)
    _ntbtls_debug_msg (level, "%s returned: %s <%s>\n",
                       name, gpg_strerror (err), gpg_strsource (err));
  else
    _ntbtls_debug_msg (level, "%s returned: success\n", name);
}


void
_ntbtls_debug_buf (int level, const char *text, const void *buf, size_t len)
{
  if (!debug_level || level > debug_level)
    return;

  gcry_log_debughex (text, buf, len);
}


void
_ntbtls_debug_mpi (int level, const char *text, gcry_mpi_t a)
{
  if (!debug_level || level > debug_level)
    return;

  gcry_log_debugmpi (text, a);
}


void
_ntbtls_debug_pnt (int level, const char *text,
                   gcry_mpi_point_t a, gcry_ctx_t ctx)
{
  if (!debug_level || level > debug_level)
    return;

  gcry_log_debugpnt (text, a, ctx);
}


void
_ntbtls_debug_sxp (int level, const char *text, gcry_sexp_t a)
{
  if (!debug_level || level > debug_level)
    return;

  gcry_log_debugsxp (text, a);
}


void
_ntbtls_debug_crt (int level, const char *text, x509_cert_t chain)
{
  if (!debug_level || level > debug_level)
    return;

  _ntbtls_x509_log_cert (text, chain, (debug_level > 1));
}
