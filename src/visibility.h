/* visibility.c - Public API
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

#ifndef NTBTLS_VISIBILITY_H
#define NTBTLS_VISIBILITY_H

#ifdef _NTBTLS_INCLUDED_BY_VISIBILITY_C
# include "ntbtls-int.h"
#endif

/* Our use of the ELF visibility feature works by passing
   -fvisibiliy=hidden on the command line and by explicitly marking
   all exported functions as visible.

   NOTE: When adding new functions, please make sure to add them to
         libntbtls.vers and libntbtls.def as well.  */

#ifdef _NTBTLS_INCLUDED_BY_VISIBILITY_C

/* A macro to flag a function as visible.  */
#ifdef NTBTLS_USE_VISIBILITY
# define MARK_VISIBLE(name) \
  extern __typeof__ (name) name __attribute__ ((visibility("default")));
#else
# define MARK_VISIBLE(name) /* */
#endif

MARK_VISIBLE (ntbtls_check_version)
MARK_VISIBLE (ntbtls_set_debug)
MARK_VISIBLE (ntbtls_set_log_handler)
MARK_VISIBLE (ntbtls_new)
MARK_VISIBLE (_ntbtls_check_context)
MARK_VISIBLE (ntbtls_release)
MARK_VISIBLE (ntbtls_set_transport)
MARK_VISIBLE (ntbtls_get_stream)
MARK_VISIBLE (ntbtls_set_hostname)
MARK_VISIBLE (ntbtls_get_hostname)
MARK_VISIBLE (ntbtls_handshake)
MARK_VISIBLE (ntbtls_set_verify_cb)
MARK_VISIBLE (ntbtls_x509_get_peer_cert)
MARK_VISIBLE (ntbtls_get_last_alert)


#undef MARK_VISIBLE

#else /*!_NTBTLS_INCLUDED_BY_VISIBILITY_C*/

/* To avoid accidental use of the public functions inside ntbtls,
   we redefine them to catch such errors.  */

#define ntbtls_check_version         _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_set_debug             _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_set_log_handler       _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_new                   _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_released              _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_set_transport         _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_get_stream            _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_set_hostname          _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_get_hostname          _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_handshake             _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_set_verify_cb         _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_x509_get_peer_cert    _ntbtls_USE_THE_UNDERSCORED_FUNCTION
#define ntbtls_get_last_alert        _ntbtls_USE_THE_UNDERSCORED_FUNCTION

#endif /*!_NTBTLS_INCLUDED_BY_VISIBILITY_C*/
#endif /*NTBTLS_VISIBILITY_H*/
