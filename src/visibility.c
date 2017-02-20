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

#include <config.h>
#include <stdlib.h>

#define _NTBTLS_INCLUDED_BY_VISIBILITY_C
#include "visibility.h"


const char *
ntbtls_check_version (const char *req_version)
{
  return _ntbtls_check_version (req_version);
}


void
ntbtls_set_debug (int level, const char *prefix, gpgrt_stream_t stream)
{
  _ntbtls_set_debug (level, prefix, stream);
}


void
ntbtls_set_log_handler (ntbtls_log_handler_t cb, void *cb_value)
{
  _ntbtls_set_log_handler (cb, cb_value);
}


gpg_error_t
ntbtls_new (ntbtls_t *r_tls, unsigned int flags)
{
  return _ntbtls_new (r_tls, flags);
}


void
ntbtls_release (ntbtls_t tls)
{
  _ntbtls_release (tls);
}


gpg_error_t
ntbtls_set_transport (ntbtls_t tls,
                      gpgrt_stream_t inbound, gpgrt_stream_t outbound)
{
  return _ntbtls_set_transport (tls, inbound, outbound);
}


gpg_error_t
ntbtls_get_stream (ntbtls_t tls,
                   gpgrt_stream_t *r_readfp, gpgrt_stream_t *r_writefp)
{
  return _ntbtls_get_stream (tls, r_readfp, r_writefp);
}


gpg_error_t
ntbtls_set_hostname (ntbtls_t tls, const char *hostname)
{
  return _ntbtls_set_hostname (tls, hostname);
}


gpg_error_t
ntbtls_handshake (ntbtls_t tls)
{
  return _ntbtls_handshake (tls);
}


gpg_error_t
ntbtls_set_verify_cb (ntbtls_t tls,  ntbtls_verify_cb_t cb, void *cb_value)
{
  return _ntbtls_set_verify_cb (tls, cb, cb_value);
}


gpg_error_t
ntbtls_x509_cert_new (x509_cert_t *r_cert)
{
  return _ntbtls_x509_cert_new (r_cert);
}


void
ntbtls_x509_cert_release (x509_cert_t cert)
{
  _ntbtls_x509_cert_release (cert);
}


gpg_error_t
ntbtls_x509_append_cert (x509_cert_t cert, const void *der, size_t derlen)
{
  return _ntbtls_x509_append_cert (cert, der, derlen);
}

ksba_cert_t
ntbtls_x509_get_peer_cert (ntbtls_t tls, int idx)
{
  return _ntbtls_x509_get_peer_cert (tls, idx);
}
