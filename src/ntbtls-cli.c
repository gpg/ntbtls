/* ntbtls-cli.h - NTBTLS client test program
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "ntbtls.h"

#define PGMNAME "ntbtls-cli"

static int verbose;
static int errorcount;


/*
 * Reporting functions.
 */
static void
die (const char *format, ...)
{
  va_list arg_ptr ;

  fflush (stdout);
#ifdef HAVE_FLOCKFILE
  flockfile (stderr);
#endif
  fprintf (stderr, "%s: ", PGMNAME);
  va_start (arg_ptr, format) ;
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
#ifdef HAVE_FLOCKFILE
  funlockfile (stderr);
#endif
  exit (1);
}


static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  fflush (stdout);
#ifdef HAVE_FLOCKFILE
  flockfile (stderr);
#endif
  fprintf (stderr, "%s: ", PGMNAME);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
#ifdef HAVE_FLOCKFILE
  funlockfile (stderr);
#endif
  errorcount++;
  if (errorcount >= 50)
    die ("stopped after 50 errors.");
}


static void
info (const char *format, ...)
{
  va_list arg_ptr;

  if (!verbose)
    return;
#ifdef HAVE_FLOCKFILE
  flockfile (stderr);
#endif
  fprintf (stderr, "%s: ", PGMNAME);
  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
  va_end (arg_ptr);
#ifdef HAVE_FLOCKFILE
  funlockfile (stderr);
#endif
}




static void
simple_client (void)
{
  gpg_error_t err;
  ntbtls_t tls;

  err = ntbtls_new (&tls, NTBTLS_CLIENT);
  if (err)
    die ("ntbtls_init failed: %s <%s>\n",
         gpg_strerror (err), gpg_strsource (err));

  err = ntbtls_set_transport (tls, es_stdin, es_stdout);
  if (err)
    die ("ntbtls_set_transport failed: %s <%s>\n",
         gpg_strerror (err), gpg_strsource (err));

  info ("starting handshake");
  while ((err = ntbtls_handshake (tls)))
    {
      info ("handshake error: %s <%s>", gpg_strerror (err),gpg_strsource (err));
      switch (gpg_err_code (err))
        {
        default:
          break;
        }
      die ("handshake failed");
    }
  info ("handshake done");

  ntbtls_release (tls);
}



int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (strncmp (*argv, "--", 2))
        die ("Invalid option '%s'\n", *argv);
    }

  simple_client ();
  return 0;
}
