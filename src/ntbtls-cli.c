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

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_W32_SYSTEM
# define WIN32_LEAN_AND_MEAN
# ifdef HAVE_WINSOCK2_H
#  include <winsock2.h>
# endif
# include <windows.h>
#else
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif

#include "ntbtls.h"

#define PGMNAME "ntbtls-cli"

static int verbose;
static int errorcount;
static char *opt_hostname;
static int opt_head;



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



/* Until we support send/recv in estream we need to use es_fopencookie
 * under Windows.  */
#ifdef HAVE_W32_SYSTEM
static gpgrt_ssize_t
w32_cookie_read (void *cookie, void *buffer, size_t size)
{
  int sock = (int)cookie;
  int nread;

  do
    {
      /* Under Windows we need to use recv for a socket.  */
      nread = recv (sock, buffer, size, 0);
    }
  while (nread == -1 && errno == EINTR);

  return (gpgrt_ssize_t)nread;
}

static gpg_error_t
w32_write_server (int sock, const char *data, size_t length)
{
  int nleft;
  int nwritten;

  nleft = length;
  while (nleft > 0)
    {
      nwritten = send (sock, data, nleft, 0);
      if ( nwritten == SOCKET_ERROR )
        {
          info ("network write failed: ec=%d\n", (int)WSAGetLastError ());
          return gpg_error (GPG_ERR_NETWORK);
        }
      nleft -= nwritten;
      data += nwritten;
    }

  return 0;
}

/* Write handler for estream.  */
static gpgrt_ssize_t
w32_cookie_write (void *cookie, const void *buffer_arg, size_t size)
{
  int sock = (int)cookie;
  const char *buffer = buffer_arg;
  int nwritten = 0;

  if (w32_write_server (sock, buffer, size))
    {
      gpg_err_set_errno (EIO);
      nwritten = -1;
    }
  else
    nwritten = size;

  return (gpgrt_ssize_t)nwritten;
}

static es_cookie_io_functions_t w32_cookie_functions =
  {
    w32_cookie_read,
    w32_cookie_write,
    NULL,
    NULL
  };
#endif /*HAVE_W32_SYSTEM*/



static int
connect_server (const char *server, unsigned short port)
{
  gpg_error_t err;
  int sock = -1;
  struct sockaddr_in addr;
  struct hostent *host;
  union {
    char *addr;
    struct in_addr *in_addr;
  } addru;

  addr.sin_family = AF_INET;
  addr.sin_port = htons (port);
  host = gethostbyname ((char*)server);
  if (!host)
    {
      err = gpg_error_from_syserror ();
      fail ("host '%s' not found: %s\n", server, gpg_strerror (err));
      return -1;
    }

  addru.addr = host->h_addr;
  addr.sin_addr = *addru.in_addr;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock == -1)
    {
      err = gpg_error_from_syserror ();
      die ("error creating socket: %s\n", gpg_strerror (err));
      return -1;
    }

  if (connect (sock, (struct sockaddr *)&addr, sizeof addr) == -1)
    {
      err = gpg_error_from_syserror ();
      fail ("error connecting '%s': %s\n", server, gpg_strerror (err));
      close (sock);
      return -1;
    }

  info ("connected to '%s' port %hu\n", server, port);

  return sock;
}


static int
connect_estreams (const char *server, int port,
                  estream_t *r_in, estream_t *r_out)
{
  gpg_error_t err;
  int sock;

  *r_in = *r_out = NULL;

  sock = connect_server (server, port);
  if (sock == -1)
    return gpg_error (GPG_ERR_GENERAL);

#ifdef HAVE_W32_SYSTEM
  *r_in = es_fopencookie ((void*)(unsigned int)sock, "rb",
                          w32_cookie_functions);
#else
  *r_in = es_fdopen (sock, "rb");
#endif
  if (!*r_in)
    {
      err = gpg_error_from_syserror ();
      close (sock);
      return err;
    }
#ifdef HAVE_W32_SYSTEM
  *r_out = es_fopencookie ((void*)(unsigned int)sock, "wb",
                           w32_cookie_functions);
#else
  *r_out = es_fdopen (sock, "wb");
#endif
  if (!*r_out)
    {
      err = gpg_error_from_syserror ();
      es_fclose (*r_in);
      *r_in = NULL;
      close (sock);
      return err;
    }

  return 0;
}



static void
simple_client (const char *server, int port)
{
  gpg_error_t err;
  ntbtls_t tls;
  estream_t inbound, outbound;
  estream_t readfp, writefp;
  int c;

  err = ntbtls_new (&tls, NTBTLS_CLIENT);
  if (err)
    die ("ntbtls_init failed: %s <%s>\n",
         gpg_strerror (err), gpg_strsource (err));

  err = connect_estreams (server, port, &inbound, &outbound);
  if (err)
    die ("error connecting server: %s <%s>\n",
         gpg_strerror (err), gpg_strsource (err));

  err = ntbtls_set_transport (tls, inbound, outbound);
  if (err)
    die ("ntbtls_set_transport failed: %s <%s>\n",
         gpg_strerror (err), gpg_strsource (err));

  err = ntbtls_get_stream (tls, &readfp, &writefp);
  if (err)
    die ("ntbtls_get_stream failed: %s <%s>\n",
         gpg_strerror (err), gpg_strsource (err));

  if (opt_hostname)
    {
      err = ntbtls_set_hostname (tls, opt_hostname);
      if (err)
        die ("ntbtls_set_hostname failed: %s <%s>\n",
             gpg_strerror (err), gpg_strsource (err));
    }

  info ("starting handshake");
  while ((err = ntbtls_handshake (tls)))
    {
      const char *s;

      if ((s = ntbtls_get_last_alert (tls, NULL, NULL)))
        info ("received alert: %s", s);
      info ("handshake error: %s <%s>", gpg_strerror (err),gpg_strsource (err));
      switch (gpg_err_code (err))
        {
        default:
          break;
        }
      die ("handshake failed");
    }
  info ("handshake done");

  do
    {
      es_fprintf (writefp, "%s / HTTP/1.0\r\n", opt_head? "HEAD":"GET");
      if (opt_hostname)
        es_fprintf (writefp, "Host: %s\r\n", opt_hostname);
      es_fprintf (writefp, "X-ntbtls: %s\r\n",
                  ntbtls_check_version (PACKAGE_VERSION));
      es_fputs ("\r\n", writefp);
      es_fflush (writefp);
      while (/*es_pending (readfp) &&*/ (c = es_fgetc (readfp)) != EOF)
        putchar (c);
    }
  while (c != EOF);

  ntbtls_release (tls);
  es_fclose (inbound);
  es_fclose (outbound);
}



int
main (int argc, char **argv)
{
  int last_argc = -1;
  int debug_level = 0;
  int port = 443;
  char *host;

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
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("Usage: " PGMNAME " [OPTIONS] HOST\n"
                 "Connect via TLS to HOST\n"
                 "Options:\n"
                 "  --version       print the library version\n"
                 "  --verbose       show more diagnostics\n"
                 "  --debug LEVEL   enable debugging at LEVEL\n"
                 "  --port N        connect to port N (default is 443)\n"
                 "  --hostname NAME use NAME instead of HOST for SNI\n"
                 "  --head          send a HEAD and not a GET request\n"
                 "\n", stdout);
          return 0;
        }
      else if (!strcmp (*argv, "--version"))
        {
          printf ("%s\n", ntbtls_check_version (NULL));
          if (verbose)
            printf ("%s", ntbtls_check_version ("\001\001"));
          return 0;
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = 1;
          argc--; argv++;
          if (argc)
            {
              debug_level = atoi (*argv);
              argc--; argv++;
            }
          else
            debug_level = 1;
        }
      else if (!strcmp (*argv, "--port"))
        {
          argc--; argv++;
          if (argc)
            {
              port = atoi (*argv);
              argc--; argv++;
            }
          else
            port = 8443;
        }
      else if (!strcmp (*argv, "--hostname"))
        {
          if (argc < 2)
            die ("argument missing for option '%s'\n", *argv);
          argc--; argv++;
          opt_hostname = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--head"))
        {
          opt_head = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2) && (*argv)[2])
        die ("Invalid option '%s'\n", *argv);
    }

  host = argc? *argv : "localhost";
  if (!opt_hostname)
    opt_hostname = host;
  if (!*opt_hostname)
    opt_hostname = NULL;

#ifdef HAVE_W32_SYSTEM
  {
    WSADATA wsadat;
    WSAStartup (0x202, &wsadat);
  }
#endif

  if (!ntbtls_check_version (PACKAGE_VERSION))
    die ("NTBTLS library too old (need %s, have %s)\n",
         PACKAGE_VERSION, ntbtls_check_version (NULL));

  if (debug_level)
    ntbtls_set_debug (debug_level, NULL, NULL);

  simple_client (host, port);
  return 0;
}
