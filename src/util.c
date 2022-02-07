/* util.c - Utility functions
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
#include <ctype.h>

#include "ntbtls-int.h"


const char *
compat_identification (void)
{
  /* For a complete list of copyright holders see the file AUTHORS in
     the source distribution.  */
  static const char blurb[] =
    "\n\n"
    "This is NTBTLS " PACKAGE_VERSION " - Not Too Bad TLS\n"
    "Copyright (C) 2014-2022 g10 Code GmbH\n"
    "Copyright (C) 2006-2014 Brainspark B.V.\n"
    "\n"
    "(" BUILD_REVISION " " BUILD_TIMESTAMP ")\n"
    "\n\n";
  return blurb;
}


/* Version number parsing.  */

/* This function parses the first portion of the version number S and
   stores it in *NUMBER.  On success, this function returns a pointer
   into S starting with the first character, which is not part of the
   initial number portion; on failure, NULL is returned.  */
static const char*
parse_version_number (const unsigned char *s, int *number)
{
  int val = 0;

  if (*s == '0' && isdigit(s[1]))
    return NULL; /* Leading zeros are not allowed.  */
  for ( ; isdigit (*s); s++)
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0? NULL : s;
}


/* This function breaks up the complete string representation of the
   version number S, which is of the following structure:

     <major number>.<minor number>.<micro number><patch level>

   The major, minor and micro number components will be stored in
   *MAJOR, *MINOR and *MICRO.

   On success, the last component, the patch level, will be returned;
   in failure, NULL will be returned.  */

static const char *
parse_version_string (const char *s, int *major, int *minor, int *micro )
{
  s = parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, micro);
  return s; /* Patchlevel or NULL on error in MICRO. */
}


/* If REQ_VERSION is non-NULL, check that the version of the library
   is at minimum the requested one.  Returns the string representation
   of the library version if the condition is satisfied; return NULL
   if the requested version is newer than that of the library.

   If a NULL is passed to this function, no check is done, but the
   string representation of the library version is returned.  */
const char *
_ntbtls_check_version (const char *req_version)
{
  const char *ver = PACKAGE_VERSION;
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl;

  if (req_version && req_version[0] == 1 && req_version[1] == 1)
    return compat_identification ();

  /* Initialize library.  */

  /* Check whether the caller only want the version number.  */
  if  (!req_version)
    return ver;

  /* Parse own version number.  */
  my_plvl = parse_version_string (ver, &my_major, &my_minor, &my_micro);
  if  (!my_plvl)
    return NULL;  /* Can't happen.  */

  /* Parse requested version number.  */
  if (!parse_version_string (req_version, &rq_major, &rq_minor, &rq_micro))
    return NULL;  /* Req version string is invalid.  */

  /* Compare version numbers.  */
  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor		                           		 && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
          && my_micro == rq_micro))
    {
      return ver; /* Okay.  */
    }

  return NULL; /* Not sufficent.  */
}


/*
 * Remove trailing white spaces from STRING.  Returns STRING.
 */
char *
_ntbtls_trim_trailing_spaces (char *string)
{
  char *p, *mark;

  for (mark = NULL, p = string; *p; p++ )
    {
      if (isspace (*(unsigned char*)p))
        {
          if (!mark)
            mark = p;
	}
      else
        mark = NULL;
    }
  if (mark)
    *mark = 0;

  return string;
}


static inline int
ascii_toupper (int c)
{
  if (c >= 'a' && c <= 'z')
    c &= ~0x20;
  return c;
}

int
_ntbtls_ascii_strcasecmp (const char *a, const char *b)
{
  if (a == b)
    return 0;

  for (; *a && *b; a++, b++)
    {
      if (*a != *b && ascii_toupper (*a) != ascii_toupper (*b))
        break;
    }
  return *a == *b? 0 : (ascii_toupper (*a) - ascii_toupper (*b));
}
