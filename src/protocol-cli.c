/* protocol-cli.c - TLS 1.2 client side protocol
 * Copyright (C) 2006-2014, Brainspark B.V.
 * Copyright (C) 2014 g10 code GmbH
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
 *
 * This file was part of PolarSSL (http://www.polarssl.org).  Former
 * Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>.
 * Please do not file bug reports to them but to the address given in
 * the file AUTHORS in the top directory of NTBTLS.
 */

#include <config.h>
#include <stdlib.h>
#include <time.h>

#include "ntbtls-int.h"
#include "ciphersuites.h"


static void
write_hostname_ext (ntbtls_t tls, unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;
  size_t len;

  *olen = 0;

  if (!tls->hostname)
    return;

  debug_msg (3, "client_hello, adding server name extension: '%s'",
             tls->hostname);

  len = strlen (tls->hostname);

  /*
   * struct {
   *     NameType name_type;
   *     select (name_type) {
   *         case host_name: HostName;
   *     } name;
   * } ServerName;
   *
   * enum {
   *     host_name(0), (255)
   * } NameType;
   *
   * opaque HostName<1..2^16-1>;
   *
   * struct {
   *     ServerName server_name_list<1..2^16-1>
   * } ServerNameList;
   */
  *p++ = (unsigned char) ((TLS_EXT_SERVERNAME >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SERVERNAME) & 0xFF);

  *p++ = (unsigned char) (((len + 5) >> 8) & 0xFF);
  *p++ = (unsigned char) (((len + 5)) & 0xFF);

  *p++ = (unsigned char) (((len + 3) >> 8) & 0xFF);
  *p++ = (unsigned char) (((len + 3)) & 0xFF);

  *p++ = (unsigned char) ((TLS_EXT_SERVERNAME) & 0xFF);
  *p++ = (unsigned char) ((len >> 8) & 0xFF);
  *p++ = (unsigned char) ((len) & 0xFF);

  memcpy (p, tls->hostname, len);

  *olen = len + 9;
}


static void
write_cli_renegotiation_ext (ntbtls_t ssl,
                             unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;

  *olen = 0;

  if (ssl->renegotiation != TLS_RENEGOTIATION)
    return;

  debug_msg (3, "client_hello, adding renegotiation extension");

  /*
   * Secure renegotiation
   */
  *p++ = (unsigned char) ((TLS_EXT_RENEGOTIATION_INFO >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_RENEGOTIATION_INFO) & 0xFF);

  *p++ = 0x00;
  *p++ = (ssl->verify_data_len + 1) & 0xFF;
  *p++ = ssl->verify_data_len & 0xFF;

  memcpy (p, ssl->own_verify_data, ssl->verify_data_len);

  *olen = 5 + ssl->verify_data_len;
}


static void
write_signature_algorithms_ext (ntbtls_t ssl,
                                unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;
  size_t sig_alg_len = 0;
  unsigned char *sig_alg_list = buf + 6;

  *olen = 0;

  if (ssl->max_minor_ver != TLS_MINOR_VERSION_3)
    return;

  debug_msg (3, "client_hello, adding signature_algorithms extension");

  /*
   * Prepare signature_algorithms extension (TLS 1.2)
   */
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA512;
  sig_alg_list[sig_alg_len++] = TLS_SIG_RSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA384;
  sig_alg_list[sig_alg_len++] = TLS_SIG_RSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA256;
  sig_alg_list[sig_alg_len++] = TLS_SIG_RSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA224;
  sig_alg_list[sig_alg_len++] = TLS_SIG_RSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA1;
  sig_alg_list[sig_alg_len++] = TLS_SIG_RSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA512;
  sig_alg_list[sig_alg_len++] = TLS_SIG_ECDSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA384;
  sig_alg_list[sig_alg_len++] = TLS_SIG_ECDSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA256;
  sig_alg_list[sig_alg_len++] = TLS_SIG_ECDSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA224;
  sig_alg_list[sig_alg_len++] = TLS_SIG_ECDSA;
  sig_alg_list[sig_alg_len++] = TLS_HASH_SHA1;
  sig_alg_list[sig_alg_len++] = TLS_SIG_ECDSA;


  /*
   * enum {
   *     none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
   *     sha512(6), (255)
   * } HashAlgorithm;
   *
   * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
   *   SignatureAlgorithm;
   *
   * struct {
   *     HashAlgorithm hash;
   *     SignatureAlgorithm signature;
   * } SignatureAndHashAlgorithm;
   *
   * SignatureAndHashAlgorithm
   *   supported_signature_algorithms<2..2^16-2>;
   */
  *p++ = (unsigned char) ((TLS_EXT_SIG_ALG >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SIG_ALG) & 0xFF);

  *p++ = (unsigned char) (((sig_alg_len + 2) >> 8) & 0xFF);
  *p++ = (unsigned char) (((sig_alg_len + 2)) & 0xFF);

  *p++ = (unsigned char) ((sig_alg_len >> 8) & 0xFF);
  *p++ = (unsigned char) ((sig_alg_len) & 0xFF);

  *olen = 6 + sig_alg_len;
}


static void
write_supported_elliptic_curves_ext (ntbtls_t tls,
                                     unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;
  unsigned char *elliptic_curve_list = p + 6;
  size_t elliptic_curve_len = 0;

  (void)tls;

  debug_msg (3, "client hello, adding supported_elliptic_curves extension");

  /* The 8 curves we support; see _ntbtls_ecdh_read_params.  */
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 23;
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 24;
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 25;
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 26;
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 27;
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 28;
#ifdef SUPPORT_X25519
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 29;
#endif
#ifdef SUPPORT_X448
  elliptic_curve_list[elliptic_curve_len++] = 0;
  elliptic_curve_list[elliptic_curve_len++] = 30;
#endif

  *p++ = (unsigned char) ((TLS_EXT_SUPPORTED_ELLIPTIC_CURVES >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SUPPORTED_ELLIPTIC_CURVES) & 0xFF);

  *p++ = (unsigned char) (((elliptic_curve_len + 2) >> 8) & 0xFF);
  *p++ = (unsigned char) (((elliptic_curve_len + 2)) & 0xFF);

  *p++ = (unsigned char) (((elliptic_curve_len) >> 8) & 0xFF);
  *p++ = (unsigned char) (((elliptic_curve_len)) & 0xFF);

  *olen = 6 + elliptic_curve_len;
}


static void
write_cli_supported_point_formats_ext (ntbtls_t tls,
                                       unsigned char *buf, size_t *olen)
{
  unsigned char *p = buf;

  (void)tls;

  debug_msg (3, "client hello, adding supported_point_formats extension");

  *p++ = (unsigned char) ((TLS_EXT_SUPPORTED_POINT_FORMATS >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SUPPORTED_POINT_FORMATS) & 0xFF);

  *p++ = 0;
  *p++ = 2;

  *p++ = 1; /* One item.  */
  *p++ = 0; /* Uncompressed.  */

  *olen = 6;
}


static void
write_cli_max_fragment_length_ext (ntbtls_t tls,
                                   unsigned char *buf, size_t *olen)
{
  unsigned char *p = buf;

  if (tls->mfl_code == TLS_MAX_FRAG_LEN_NONE)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "client_hello, adding max_fragment_length extension");

  *p++ = (unsigned char) ((TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_MAX_FRAGMENT_LENGTH) & 0xFF);

  *p++ = 0x00;
  *p++ = 1;

  *p++ = tls->mfl_code;

  *olen = 5;
}


static void
write_cli_truncated_hmac_ext (ntbtls_t tls,
                              unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;

  if (!tls->use_trunc_hmac)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "client_hello, adding truncated_hmac extension");

  *p++ = (unsigned char) ((TLS_EXT_TRUNCATED_HMAC >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_TRUNCATED_HMAC) & 0xFF);

  *p++ = 0x00;
  *p++ = 0x00;

  *olen = 4;
}


static void
write_cli_session_ticket_ext (ntbtls_t ssl,
                              unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;
  size_t tlen = ssl->session_negotiate->ticket_len;

  if (!ssl->use_session_tickets)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "client_hello, adding session ticket extension");

  *p++ = (unsigned char) ((TLS_EXT_SESSION_TICKET >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SESSION_TICKET) & 0xFF);

  *p++ = (unsigned char) ((tlen >> 8) & 0xFF);
  *p++ = (unsigned char) ((tlen) & 0xFF);

  *olen = 4;

  if (ssl->session_negotiate->ticket == NULL ||
      ssl->session_negotiate->ticket_len == 0)
    {
      return;
    }

  debug_msg (3, "sending session_ticket of length %zu", tlen);

  memcpy (p, ssl->session_negotiate->ticket, tlen);

  *olen += tlen;
}


static void
write_cli_alpn_ext (ntbtls_t ssl, unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;
  const char **cur;

  if (ssl->alpn_list == NULL)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "client hello, adding alpn extension");

  *p++ = (unsigned char) ((TLS_EXT_ALPN >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_ALPN) & 0xFF);

  /*
   * opaque ProtocolName<1..2^8-1>;
   *
   * struct {
   *     ProtocolName protocol_name_list<2..2^16-1>
   * } ProtocolNameList;
   */

  /* Skip writing extension and list length for now */
  p += 4;

  for (cur = ssl->alpn_list; *cur != NULL; cur++)
    {
      *p = (unsigned char) (strlen (*cur) & 0xFF);
      memcpy (p + 1, *cur, *p);
      p += 1 + *p;
    }

  *olen = p - buf;

  /* List length = olen - 2 (ext_type) - 2 (ext_len) - 2 (list_len) */
  buf[4] = (unsigned char) (((*olen - 6) >> 8) & 0xFF);
  buf[5] = (unsigned char) (((*olen - 6)) & 0xFF);

  /* Extension length = olen - 2 (ext_type) - 2 (ext_len) */
  buf[2] = (unsigned char) (((*olen - 4) >> 8) & 0xFF);
  buf[3] = (unsigned char) (((*olen - 4)) & 0xFF);
}


static gpg_error_t
write_client_hello (ntbtls_t tls)
{
  gpg_error_t err;
  size_t i, n, olen;
  size_t ext_len = 0;
  unsigned char *buf;
  unsigned char *p, *q;
  time_t t;
  const int *ciphersuites;
  ciphersuite_t suite;

  debug_msg (2, "write client_hello");

  if (tls->renegotiation == TLS_INITIAL_HANDSHAKE)
    {
      tls->major_ver = tls->min_major_ver;
      tls->minor_ver = tls->min_minor_ver;
    }

  if (tls->max_major_ver == 0 && tls->max_minor_ver == 0)
    {
      tls->max_major_ver = TLS_MAX_MAJOR_VERSION;
      tls->max_minor_ver = TLS_MAX_MINOR_VERSION;
    }

  /*
   *     0  .   0   handshake type
   *     1  .   3   handshake length
   *     4  .   5   highest version supported
   *     6  .   9   current UNIX time
   *    10  .  37   random bytes
   */
  buf = tls->out_msg;
  p = buf + 4;

  *p++ = (unsigned char) tls->max_major_ver;
  *p++ = (unsigned char) tls->max_minor_ver;

  debug_msg (3, "client_hello, max version: [%d:%d]", buf[4], buf[5]);

  t = time (NULL);
  *p++ = (unsigned char) (t >> 24);
  *p++ = (unsigned char) (t >> 16);
  *p++ = (unsigned char) (t >> 8);
  *p++ = (unsigned char) (t);

  debug_msg (3, "client_hello, current time: %lu", t);

  //FIXME: Check RNG requirements.
  gcry_create_nonce (p, 28);
  p += 28;

  memcpy (tls->handshake->randbytes, buf + 6, 32);

  debug_buf (3, "client_hello, random bytes", buf + 6, 32);

  /*
   *    38  .  38   session id length
   *    39  . 39+n  session id
   *   40+n . 41+n  ciphersuitelist length
   *   42+n . ..    ciphersuitelist
   *   ..   . ..    compression methods length
   *   ..   . ..    compression methods
   *   ..   . ..    extensions length
   *   ..   . ..    extensions
   */
  n = tls->session_negotiate->length;

  if (tls->renegotiation != TLS_INITIAL_HANDSHAKE || n < 16 || n > 32 ||
      tls->handshake->resume == 0)
    {
      n = 0;
    }

  /*
   * RFC 5077 section 3.4: "When presenting a ticket, the client MAY
   * generate and include a Session ID in the TLS ClientHello."
   */
  if (tls->renegotiation == TLS_INITIAL_HANDSHAKE &&
      tls->session_negotiate->ticket != NULL &&
      tls->session_negotiate->ticket_len != 0)
    {
      gcry_create_nonce (tls->session_negotiate->id, 32);
      tls->session_negotiate->length = n = 32;
    }

  *p++ = (unsigned char) n;

  for (i = 0; i < n; i++)
    *p++ = tls->session_negotiate->id[i];

  debug_msg (3, "client_hello, session id len.: %zu", n);
  debug_buf (3, "client_hello, session id", buf + 39, n);

  // Fixme: We do not have a way to set the ciphersuites.  Thus
  // consider to replace this with simpler code.
  ciphersuites = tls->ciphersuite_list[tls->minor_ver];
  n = 0;
  q = p;

  /* Skip writing ciphersuite length for now.  */
  p += 2;

  /*
   * Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
   */
  if (tls->renegotiation == TLS_INITIAL_HANDSHAKE)
    {
      *p++ = (unsigned char) (TLS_EMPTY_RENEGOTIATION_INFO >> 8);
      *p++ = (unsigned char) (TLS_EMPTY_RENEGOTIATION_INFO);
      n++;
    }

  /*FIXME: We should add an explicit limit and not rely on the known
    length of the ciphersuites.  */
  for (i = 0; ciphersuites && ciphersuites[i]; i++)
    {
      suite = _ntbtls_ciphersuite_from_id (ciphersuites[i]);
      if (!suite)
        continue;

      if (!_ntbtls_ciphersuite_version_ok (suite, tls->min_minor_ver,
                                           tls->max_minor_ver))
        continue;

      debug_msg (5, "client_hello, add ciphersuite: %5d %s",
                 ciphersuites[i],
                 _ntbtls_ciphersuite_get_name (ciphersuites[i]));

      n++;
      *p++ = (unsigned char) (ciphersuites[i] >> 8);
      *p++ = (unsigned char) (ciphersuites[i]);
    }

  /* Fixup the ciphersuite length.  */
  *q++ = (unsigned char) (n >> 7);
  *q++ = (unsigned char) (n << 1);

  debug_msg (3, "client_hello, got %zu ciphersuites", n);

  debug_msg (3, "client_hello, compress len.: %d", 2);
  debug_msg (3, "client_hello, compress alg.: %d %d",
             TLS_COMPRESS_DEFLATE, TLS_COMPRESS_NULL);

  *p++ = 2;
  *p++ = TLS_COMPRESS_DEFLATE;
  *p++ = TLS_COMPRESS_NULL;

  /* First write extensions, then the total length.  */
  write_hostname_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_cli_renegotiation_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_signature_algorithms_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_supported_elliptic_curves_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_cli_supported_point_formats_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_cli_max_fragment_length_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_cli_truncated_hmac_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_cli_session_ticket_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_cli_alpn_ext (tls, p + 2 + ext_len, &olen);
  ext_len += olen;

  debug_msg (3, "client_hello, total extension length: %zu", ext_len);

  if (ext_len > 0)
    {
      *p++ = (unsigned char) ((ext_len >> 8) & 0xFF);
      *p++ = (unsigned char) ((ext_len) & 0xFF);
      p += ext_len;
    }

  tls->out_msglen = p - buf;
  tls->out_msgtype = TLS_MSG_HANDSHAKE;
  tls->out_msg[0] = TLS_HS_CLIENT_HELLO;

  tls->state++;

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return 0;
}


static gpg_error_t
parse_renegotiation_info (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  gpg_error_t err;

  if (tls->renegotiation == TLS_INITIAL_HANDSHAKE)
    {
      if (len != 1 || buf[0] != 0x0)
        {
          debug_msg (1, "non-zero length renegotiated connection field");

          err = _ntbtls_send_fatal_handshake_failure (tls);
          if (!err)
            err = gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
          return err;
        }

      tls->secure_renegotiation = TLS_SECURE_RENEGOTIATION;
    }
  else
    {
      /* Check verify-data in constant-time. The length OTOH is no secret */
      if (len != 1 + tls->verify_data_len * 2
          || buf[0] != tls->verify_data_len * 2
          || memcmpct (buf + 1,
                       tls->own_verify_data, tls->verify_data_len)
          || memcmpct (buf + 1 + tls->verify_data_len,
                       tls->peer_verify_data, tls->verify_data_len))
        {
          debug_msg (1, "non-matching renegotiated connection field");

          err = _ntbtls_send_fatal_handshake_failure (tls);
          if (!err)
            err = gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
          return err;
        }
    }

  return 0;
}


static gpg_error_t
parse_max_fragment_length_ext (ntbtls_t tls,
                               const unsigned char *buf, size_t len)
{
  /*
   * server should use the extension only if we did,
   * and if so the server's value should match ours (and len is always 1)
   */
  if (tls->mfl_code == TLS_MAX_FRAG_LEN_NONE
      || len != 1
      || buf[0] != tls->mfl_code)
    {
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  return 0;
}


static gpg_error_t
parse_truncated_hmac_ext (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  (void)buf;

  if (!tls->use_trunc_hmac || len)
    {
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  tls->session_negotiate->use_trunc_hmac = 1;

  return 0;
}


static gpg_error_t
parse_session_ticket_ext (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  (void)buf;

  if (!tls->use_session_tickets || len)
    {
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  tls->handshake->new_session_ticket = 1;

  return 0;
}


static gpg_error_t
parse_supported_point_formats_ext (ntbtls_t ssl,
                                   const unsigned char *buf, size_t len)
{
  size_t list_size;
  const unsigned char *p;

  list_size = buf[0];
  if (list_size + 1 != len)
    {
      debug_msg (1, "bad server hello message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  p = buf + 1;
  while (list_size > 0)
    {
      if (p[0] == 0)
        {
          /* Fixme: Store the format - right now not required because
           * we support only one format.  */
          /* ssl->handshake->ecdh_ctx.point_format = p[0]; */
          (void)ssl;
          debug_msg (4, "point format selected: %d", p[0]);
          return 0;
        }

      list_size--;
      p++;
    }

  debug_msg (1, "no point format in common");
  return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
}


static gpg_error_t
parse_alpn_ext (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  size_t list_len, name_len;
  const char **p;

  /* If we didn't send it, the server shouldn't send it */
  if (!tls->alpn_list)
    return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);

  /*
   * opaque ProtocolName<1..2^8-1>;
   *
   * struct {
   *     ProtocolName protocol_name_list<2..2^16-1>
   * } ProtocolNameList;
   *
   * the "ProtocolNameList" MUST contain exactly one "ProtocolName"
   */

  /* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
  if (len < 4)
    return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);

  list_len = buf16_to_size_t (buf);
  if (list_len != len - 2)
    return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);

  name_len = buf[2];
  if (name_len != list_len - 1)
    return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);

  /* Check that the server chosen protocol was in our list and save it */
  for (p = tls->alpn_list; *p; p++)
    {
      if (name_len == strlen (*p) && !memcmp (buf + 3, *p, name_len))
        {
          tls->alpn_chosen = *p;
          return 0;
        }
    }

  return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
}


static gpg_error_t
read_server_hello (ntbtls_t tls)
{
  gpg_error_t err;
  int i, suite_id, comp;
  size_t n;
  size_t ext_len = 0;
  unsigned char *buf, *ext;
  int renegotiation_info_seen = 0;
  int handshake_failure = 0;
  const int *ciphersuites;
  uint32_t t;

  debug_msg (2, "read server_hello");

  /*
   *     0  .   0   handshake type
   *     1  .   3   handshake length
   *     4  .   5   protocol version
   *     6  .   9   UNIX time()
   *    10  .  37   random bytes
   */
  buf = tls->in_msg;

  err = _ntbtls_read_record (tls);
  if (err)
    {
      debug_ret (1, "read_record", err);
      return err;
    }

  if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad server_hello message");
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  debug_msg (1, "server_hello, chosen version: [%d:%d]",  buf[4], buf[5]);

  if (tls->in_hslen < 42
      || buf[0] != TLS_HS_SERVER_HELLO
      || buf[4] != TLS_MAJOR_VERSION_3)
    {
      debug_msg (1, "bad server_hello message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  if (buf[5] > tls->max_minor_ver)
    {
      debug_msg (1, "bad server_hello message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  tls->minor_ver = buf[5];

  if (tls->minor_ver < tls->min_minor_ver)
    {
      debug_msg (1, "server only supports TLS smaller than minimum"
                 " [%d:%d] < [%d:%d]", tls->major_ver,
                 tls->minor_ver, buf[4], buf[5]);

      _ntbtls_send_alert_message (tls, TLS_ALERT_LEVEL_FATAL,
                                  TLS_ALERT_MSG_PROTOCOL_VERSION);

      return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);
    }

  t = buf32_to_u32 (buf+6);
  debug_msg (3, "server_hello, current time: %lu", (unsigned long)t);

  memcpy (tls->handshake->randbytes + 32, buf + 6, 32);

  n = buf[38];

  debug_buf (3, "server_hello, random bytes", buf + 6, 32);

  if (n > 32)
    {
      debug_msg (1, "bad server_hello message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }

  /*
   *    38  .  38   session id length
   *    39  . 38+n  session id
   *   39+n . 40+n  chosen ciphersuite
   *   41+n . 41+n  chosen compression alg.
   *   42+n . 43+n  extensions length
   *   44+n . 44+n+m extensions
   */
  if (tls->in_hslen > 42 + n)
    {
      ext_len = buf16_to_size_t (buf + 42 + n);
      if ((ext_len > 0 && ext_len < 4) || tls->in_hslen != 44 + n + ext_len)
        {
          debug_msg (1, "bad server_hello message");
          return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
        }
    }

  suite_id = buf16_to_uint (buf + 39 + n);
  comp = buf[41 + n];

  /*
   * Initialize update checksum functions
   */
  tls->transform_negotiate->ciphersuite
    = _ntbtls_ciphersuite_from_id (suite_id);
  if (!tls->transform_negotiate->ciphersuite)
    {
      debug_msg (1, "ciphersuite info for %04x not found", suite_id);
      return gpg_error (GPG_ERR_INV_ARG);
    }

  _ntbtls_optimize_checksum (tls, tls->transform_negotiate->ciphersuite);

  debug_msg (3, "server_hello, session id len.: %zu", n);
  debug_buf (3, "server_hello, session id", buf + 39, n);

  /*
   * Check if the session can be resumed
   */
  if (tls->renegotiation != TLS_INITIAL_HANDSHAKE
      || !tls->handshake->resume
      || !n
      || tls->session_negotiate->ciphersuite != suite_id
      || tls->session_negotiate->compression != comp
      || tls->session_negotiate->length != n
      || memcmp (tls->session_negotiate->id, buf + 39, n))
    {
      tls->state++;
      tls->handshake->resume = 0;
      tls->session_negotiate->start = time (NULL);
      tls->session_negotiate->ciphersuite = suite_id;
      tls->session_negotiate->compression = comp;
      tls->session_negotiate->length = n;
      memcpy (tls->session_negotiate->id, buf + 39, n);
    }
  else
    {
      tls->state = TLS_SERVER_CHANGE_CIPHER_SPEC;

      err = _ntbtls_derive_keys (tls);
      if (err)
        {
          debug_ret (1, "derive_keys", err);
          return err;
        }
    }

  debug_msg (3, "%s session has been resumed",
             tls->handshake->resume ? "a" : "no");

  debug_msg (1, "server_hello, chosen ciphersuite: %d (%s)",
             suite_id, _ntbtls_ciphersuite_get_name (suite_id));
  debug_msg (3, "server_hello, compress alg.: %d", buf[41 + n]);

  /* Check that we support the cipher suite.  */
  ciphersuites = tls->ciphersuite_list[tls->minor_ver];
  if (ciphersuites)
    {
      for (i=0; ciphersuites[i]; i++)
        if (ciphersuites[i] == tls->session_negotiate->ciphersuite)
          break;
    }
  if (!ciphersuites || !ciphersuites[i])
    {
      debug_msg (1, "bad server_hello message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }


  if (comp != TLS_COMPRESS_NULL && comp != TLS_COMPRESS_DEFLATE)
    {
      debug_msg (1, "bad server_hello message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
    }
  tls->session_negotiate->compression = comp;

  ext = buf + 44 + n;

  debug_msg (2, "server_hello, total extension length: %zu", ext_len);

  while (ext_len)
    {
      unsigned int ext_id   = buf16_to_uint (ext);
      unsigned int ext_size = buf16_to_uint (ext+2);

      if (ext_size + 4 > ext_len)
        {
          debug_msg (1, "bad server_hello message");
          return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
        }

      switch (ext_id)
        {
        case TLS_EXT_RENEGOTIATION_INFO:
          debug_msg (2, "found renegotiation extension");
          renegotiation_info_seen = 1;
          err = parse_renegotiation_info (tls, ext + 4, ext_size);
          if (err)
            return err;
          break;

        case TLS_EXT_MAX_FRAGMENT_LENGTH:
          debug_msg (2, "found max_fragment_length extension");
          err = parse_max_fragment_length_ext (tls, ext + 4, ext_size);
          if (err)
            return err;
          break;

        case TLS_EXT_TRUNCATED_HMAC:
          debug_msg (2, "found truncated_hmac extension");
          err = parse_truncated_hmac_ext (tls, ext + 4, ext_size);
          if (err)
            return err;
          break;

        case TLS_EXT_SESSION_TICKET:
          debug_msg (2, "found session_ticket extension");
          err = parse_session_ticket_ext (tls, ext + 4, ext_size);
          if (err)
            return err;
          break;

        case TLS_EXT_SUPPORTED_POINT_FORMATS:
          debug_msg (2, "found supported_point_formats extension");
          err = parse_supported_point_formats_ext (tls, ext + 4, ext_size);
          if (err)
            return err;
          break;

        case TLS_EXT_ALPN:
          debug_msg (2, "found alpn extension");
          err = parse_alpn_ext (tls, ext + 4, ext_size);
          if (err)
            return err;
          break;

        default:
          debug_msg (2, "unknown extension found: %d (ignoring)", ext_id);
          break;
        }

      ext_len -= 4 + ext_size;
      ext += 4 + ext_size;

      if (ext_len > 0 && ext_len < 4)
        {
          debug_msg (1, "bad server_hello message");
          return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
        }
    }

  /*
   * Renegotiation security checks
   */
  if (tls->secure_renegotiation == TLS_LEGACY_RENEGOTIATION
      && tls->allow_legacy_renegotiation == TLS_LEGACY_BREAK_HANDSHAKE)
    {
      debug_msg (1, "legacy renegotiation, breaking off handshake");
      handshake_failure = 1;
    }
  else if (tls->renegotiation == TLS_RENEGOTIATION
           && tls->secure_renegotiation == TLS_SECURE_RENEGOTIATION
           && !renegotiation_info_seen)
    {
      debug_msg (1, "renegotiation_info extension missing (secure)");
      handshake_failure = 1;
    }
  else if (tls->renegotiation == TLS_RENEGOTIATION
           && tls->secure_renegotiation == TLS_LEGACY_RENEGOTIATION
           && tls->allow_legacy_renegotiation == TLS_LEGACY_NO_RENEGOTIATION)
    {
      debug_msg (1, "legacy renegotiation not allowed");
      handshake_failure = 1;
    }
  else if (tls->renegotiation == TLS_RENEGOTIATION
           && tls->secure_renegotiation == TLS_LEGACY_RENEGOTIATION &&
           renegotiation_info_seen)
    {
      debug_msg (1, "renegotiation_info extension present (legacy)");
      handshake_failure = 1;
    }

  if (handshake_failure)
    {
      err = _ntbtls_send_fatal_handshake_failure (tls);
      if (!err)
        err = gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO);
      return err;
    }

  return 0;
}


static gpg_error_t
parse_server_dh_params (ntbtls_t tls, unsigned char **p, unsigned char *end)
{
  gpg_error_t err;
  unsigned int nbits;
  size_t n;

  /*
   * Ephemeral DH parameters:
   *
   * struct {
   *     opaque dh_p<1..2^16-1>;
   *     opaque dh_g<1..2^16-1>;
   *     opaque dh_Ys<1..2^16-1>;
   * } ServerDHParams;
   */

  err = _ntbtls_dhm_read_params (tls->handshake->dhm_ctx, *p, end - *p, &n);
  if (err)
    {
      debug_ret (2, "dhm_read_params", err);
      return err;
    }
  *p += n;
  nbits = _ntbtls_dhm_get_nbits (tls->handshake->dhm_ctx);
  if (nbits < 1024 || nbits > 4096)
    {
      debug_msg (1, "bad server key exchange message (DHM length: %u)", nbits);
      return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
    }

  return 0;
}


static int
parse_server_ecdh_params (ntbtls_t tls, unsigned char **p, unsigned char *end)
{
  gpg_error_t err;
  size_t n;

  if ((err = _ntbtls_ecdh_read_params (tls->handshake->ecdh_ctx,
                                       *p, end - *p, &n)))
    {
      debug_ret (1, "ecdh_read_params", err);
      return err;
    }
  *p += n;

  return 0;
}


static gpg_error_t
parse_server_psk_hint (ntbtls_t tls, unsigned char **p, unsigned char *end)
{
  size_t len;

  (void)tls;

  /*
   * PSK parameters:
   *
   * opaque psk_identity_hint<0..2^16-1>;
   */
  if (*p + 1 < end)
    {
      debug_msg (1, "bad server key exchange message"
                 " (psk_identity_hint too short)");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
    }
  len = buf16_to_size_t (*p);
  *p += 2;

  if ((*p) + len > end)
    {
      debug_msg (1, "bad server key exchange message"
                 " (psk_identity_hint too long)");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
    }

  // TODO: Retrieve PSK identity hint and callback to app
  //
  *p += len;

  return 0;
}


/*
 * Generate a pre-master secret and encrypt it with the server's RSA key
 */
static gpg_error_t
write_encrypted_pms (ntbtls_t tls,
                     size_t offset, size_t *olen, size_t pms_offset)
{
  gpg_error_t err;
  size_t len_bytes = tls->minor_ver == TLS_MINOR_VERSION_0 ? 0 : 2;
  unsigned char *p = tls->handshake->premaster + pms_offset;

  /*
   * Generate (part of) the pre-master as
   *  struct {
   *      ProtocolVersion client_version;
   *      opaque random[46];
   *  } PreMasterSecret;
   */
  p[0] = (unsigned char) tls->max_major_ver;
  p[1] = (unsigned char) tls->max_minor_ver;

  gcry_randomize (p + 2, 46, GCRY_STRONG_RANDOM);

  tls->handshake->pmslen = 48;

  /*
   * Now write it out, encrypted
   */
  //FIXME: Need a cert related can_do function.
  /* if (!_ntbtls_x509_foo_can_do (tls->session_negotiate->peer_chain, GCRY_PK_RSA)) */
  /*   { */
  /*     debug_msg (1, "certificate key type mismatch"); */
  /*     return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO); */
  /*   } */

  err = _ntbtls_pk_encrypt (tls->session_negotiate->peer_chain,
                            p, tls->handshake->pmslen,
                            tls->out_msg + offset + len_bytes, olen,
                            TLS_MAX_CONTENT_LEN - offset - len_bytes);
  if (err)
    {
      debug_ret (1, "rsa_pkcs1_encrypt", err);
      return err;
    }

  if (len_bytes == 2)
    {
      tls->out_msg[offset + 0] = (unsigned char) (*olen >> 8);
      tls->out_msg[offset + 1] = (unsigned char) (*olen);
      *olen += 2;
    }

  return 0;
}


static gpg_error_t
parse_signature_algorithm (ntbtls_t tls, unsigned char **p, unsigned char *end,
                           md_algo_t *md_alg, pk_algo_t *pk_alg)
{

  *md_alg = 0;
  *pk_alg = 0;

  /* Only in TLS 1.2 */
  if (tls->minor_ver != TLS_MINOR_VERSION_3)
    {
      return 0;
    }

  if ((*p) + 2 > end)
    return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);

  /*
   * Get hash algorithm
   */
  *md_alg = _ntbtls_md_alg_from_hash ((*p)[0]);
  if (!*md_alg)
    {
      debug_msg (2, "Server used unsupported HashAlgorithm %d", *(p)[0]);
      return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
    }

  /*
   * Get signature algorithm
   */
  *pk_alg = _ntbtls_pk_alg_from_sig ((*p)[1]);
  if (!*pk_alg)
    {
      debug_msg (2, "server used unsupported SignatureAlgorithm %d", (*p)[1]);
      return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
    }

  debug_msg (2, "Server used HashAlgo %s",
             gcry_md_algo_name (*md_alg));
  debug_msg (2, "Server used SignAlgo %s",
             gcry_pk_algo_name (*pk_alg));
  *p += 2;

  return 0;
}


static gpg_error_t
get_ecdh_params_from_cert (ntbtls_t tls)
{
  (void)tls;

  //FIXME:
  /* int ret; */
  /* const ecp_keypair *peer_key; */

  /* if (!pk_can_do (&ssl->session_negotiate->peer_chain->pk, POLARSSL_PK_ECKEY)) */
  /*   { */
  /*     debug_msg (1, "server key not ECDH capable"); */
  /*     return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO); */
  /*   } */

  /* peer_key = pk_ec (ssl->session_negotiate->peer_chain->pk); */

  /* if ((ret = ecdh_get_params (&ssl->handshake->ecdh_ctx, peer_key, */
  /*                             POLARSSL_ECDH_THEIRS)) != 0) */
  /*   { */
  /*     debug_ret (1, ("ecdh_get_params"), ret); */
  /*     return (ret); */
  /*   } */

  /* if (ssl_check_server_ecdh_params (ssl) != 0) */
  /*   { */
  /*     debug_msg (1, "bad server certificate (ECDH curve)"); */
  /*     return gpg_error (GPG_ERR_BAD_HS_CERT); */
  /*   } */

  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


static gpg_error_t
read_server_key_exchange (ntbtls_t tls)
{
  gpg_error_t err;
  const ciphersuite_t suite = tls->transform_negotiate->ciphersuite;
  key_exchange_type_t kex = _ntbtls_ciphersuite_get_kex (suite);
  unsigned char *p, *end;
  size_t sig_len, params_len;
  unsigned char hash[64];
  md_algo_t md_alg = 0;
  size_t hashlen;
  pk_algo_t pk_alg = 0;


  if (kex == KEY_EXCHANGE_RSA)
    {
      debug_msg (2, "skipping read server_key_exchange");
      tls->state++;
      return 0;
    }

  if (kex == KEY_EXCHANGE_ECDH_RSA || kex == KEY_EXCHANGE_ECDH_ECDSA)
    {
      err = get_ecdh_params_from_cert (tls);
      if (err)
        {
          debug_ret (1, "get_ecdh_params_from_cert", err);
          return err;
        }

      debug_msg (2, "skipping read server_key_exchange");
      tls->state++;
      return 0;
    }

  debug_msg (2, "read server_key_exchange");

  err = _ntbtls_read_record (tls);
  if (err)
    {
      debug_ret (1, "read_record", err);
      return err;
    }

  if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad server_key_exchange message (%d)", __LINE__);
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  /*
   * ServerKeyExchange may be skipped with PSK and RSA-PSK when the server
   * doesn't use a psk_identity_hint.
   */
  if (tls->in_msg[0] != TLS_HS_SERVER_KEY_EXCHANGE)
    {
      if (kex == KEY_EXCHANGE_PSK || kex == KEY_EXCHANGE_RSA_PSK)
        {
          tls->record_read = 1;
          goto leave;
        }

      debug_msg (1, "bad server_key_exchange message (%d)", __LINE__);
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  p = tls->in_msg + 4;
  end = tls->in_msg + tls->in_hslen;
  debug_buf (3, "server_key_exchange", p, tls->in_hslen - 4);

  if (kex == KEY_EXCHANGE_PSK
      || kex == KEY_EXCHANGE_RSA_PSK
      || kex == KEY_EXCHANGE_DHE_PSK
      || kex == KEY_EXCHANGE_ECDHE_PSK)
    {
      err = parse_server_psk_hint (tls, &p, end);
      if (err)
        {
          debug_msg (1, "bad server_key_exchange message (%d)", __LINE__);
          return err;
        }
    }

  if (kex == KEY_EXCHANGE_PSK
      || kex == KEY_EXCHANGE_RSA_PSK)
    ; /* Nothing more to do.  */
  else if (kex == KEY_EXCHANGE_DHE_RSA
           || kex == KEY_EXCHANGE_DHE_PSK)
    {
      err = parse_server_dh_params (tls, &p, end);
      if (err)
        {
          debug_msg (1, "bad server_key_exchange message (%d)", __LINE__);
          return err;
        }
    }
  else if (kex == KEY_EXCHANGE_ECDHE_RSA
           || kex == KEY_EXCHANGE_ECDHE_PSK
           || kex == KEY_EXCHANGE_ECDHE_ECDSA)
    {
      err = parse_server_ecdh_params (tls, &p, end);
      if (err)
        {
          debug_msg (1, "bad server_key_exchange message (%d)", __LINE__);
          return err;
        }
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }


  if (kex == KEY_EXCHANGE_DHE_RSA
      || kex == KEY_EXCHANGE_ECDHE_RSA
      || kex == KEY_EXCHANGE_ECDHE_ECDSA)
    {
      params_len = p - (tls->in_msg + 4);

      /*
       * Handle the digitally-signed structure
       */
      if (tls->minor_ver == TLS_MINOR_VERSION_3)
        {
          err = parse_signature_algorithm (tls, &p, end, &md_alg, &pk_alg);
          if (err)
            {
              debug_msg (1, "bad server_key_exchange message (%d): %s",
                         __LINE__, gpg_strerror (err));
              return err;
            }

          if (pk_alg != _ntbtls_ciphersuite_get_sig_pk_alg (suite))
            {
              debug_msg (1, "bad server_key_exchange message (%d): %s",
                         __LINE__, gpg_strerror (err));
              return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
            }
          //FIXME: Check that the ECC subtype matches.  */
        }
      else
        {
          debug_bug ();
          return gpg_error (GPG_ERR_INTERNAL);
        }

      /*
       * Read signature
       */
      sig_len = buf16_to_size_t (p);
      p += 2;

      if (end != p + sig_len)
        {
          debug_msg (1, "bad server_key_exchange message (%d)", __LINE__);
          return gpg_error (GPG_ERR_BAD_HS_SERVER_KEX);
        }

      debug_buf (3, "signature", p, sig_len);

      /*
       * Compute the hash that has been signed
       */
      if (md_alg)
        {
          gcry_buffer_t iov[2];

          memset (iov, 0, sizeof iov);

          /*
           * digitally-signed struct {
           *     opaque client_random[32];
           *     opaque server_random[32];
           *     ServerDHParams params;
           * };
           */

          iov[0].data = tls->handshake->randbytes;
          iov[0].len  = 64;
          iov[1].data = tls->in_msg + 4;
          iov[1].len  = params_len;
          hashlen = gcry_md_get_algo_dlen (md_alg);
          if (hashlen > sizeof hash)
            err = gpg_error (GPG_ERR_BUG);
          else
            err = gcry_md_hash_buffers (md_alg, 0, hash, iov, 2);
          if (err)
            return err;
        }
      else
        {
          debug_bug ();
          return gpg_error (GPG_ERR_INTERNAL);
        }

      debug_buf (3, "parameters hash", hash, hashlen);


      /*
       * Verify signature
       */

      err = _ntbtls_pk_verify (tls->session_negotiate->peer_chain,
                               pk_alg, md_alg, hash, hashlen, p, sig_len);
      debug_ret (1, "pk_verify", err);
      if (err)
        return err;
    }

 leave:
  tls->state++;

  return 0;
}


static gpg_error_t
read_certificate_request (ntbtls_t tls)
{
  gpg_error_t err;
  unsigned char *buf, *p;
  size_t n = 0, m = 0;
  size_t cert_type_len = 0;
  size_t dn_len = 0;
  const ciphersuite_t suite = tls->transform_negotiate->ciphersuite;
  key_exchange_type_t kex = _ntbtls_ciphersuite_get_kex (suite);

  if (kex == KEY_EXCHANGE_PSK
      || kex == KEY_EXCHANGE_RSA_PSK
      || kex == KEY_EXCHANGE_DHE_PSK
      || kex == KEY_EXCHANGE_ECDHE_PSK)
    {
      debug_msg (2, "skipping read certificate_request");
      tls->state++;
      return 0;
    }

  debug_msg (2, "read certificate_request");

  /*
   *     0  .   0   handshake type
   *     1  .   3   handshake length
   *     4  .   4   cert type count
   *     5  .. m-1  cert types
   *     m  .. m+1  sig alg length (TLS 1.2 only)
   *    m+1 .. n-1  SignatureAndHashAlgorithms (TLS 1.2 only)
   *     n  .. n+1  length of all DNs
   *    n+2 .. n+3  length of DN 1
   *    n+4 .. ...  Distinguished Name #1
   *    ... .. ...  length of DN 2, etc.
   */
  if (!tls->record_read)
    {
      err = _ntbtls_read_record (tls);
      if (err)
        {
          debug_ret (1, "read_record", err);
          return err;
        }

      if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
        {
          debug_msg (1, "bad certificate_request message");
          return gpg_error (GPG_ERR_UNEXPECTED_MSG);
        }

      tls->record_read = 1;
    }

  tls->client_auth = 0;
  tls->state++;

  if (tls->in_msg[0] == TLS_HS_CERTIFICATE_REQUEST)
    tls->client_auth++;

  debug_msg (3, "got %s certificate_request", tls->client_auth ? "a" : "no");

  if (!tls->client_auth)
    goto leave;

  tls->record_read = 0;

  // TODO: handshake_failure alert for an anonymous server to request
  // client authentication

  buf = tls->in_msg;

  // Retrieve cert types
  //
  cert_type_len = buf[4];
  n = cert_type_len;

  if (tls->in_hslen < 6 + n)
    {
      debug_msg (1, "bad certificate_request message");
      return gpg_error (GPG_ERR_BAD_HS_CERT_REQ);
    }

  p = buf + 5;
  while (cert_type_len > 0)
    {
      if (*p == TLS_CERT_TYPE_RSA_SIGN
          && _ntbtls_x509_can_do (tls_own_key (tls), GCRY_PK_RSA))
        {
          tls->handshake->cert_type = TLS_CERT_TYPE_RSA_SIGN;
          break;
        }
      else if (*p == TLS_CERT_TYPE_ECDSA_SIGN
               && _ntbtls_x509_can_do (tls_own_key (tls), GCRY_PK_ECDSA))
        {
          tls->handshake->cert_type = TLS_CERT_TYPE_ECDSA_SIGN;
          break;
        }
      else
        {
          /* Unsupported cert type, ignore */
        }

      cert_type_len--;
      p++;
    }

  if (tls->minor_ver == TLS_MINOR_VERSION_3)
    {
      /* Ignored, see comments about hash in write_certificate_verify */
      // TODO: should check the signature part against our pk_key though
      size_t sig_alg_len = buf16_to_size_t (buf + 5 + n);

      p = buf + 7 + n;
      m += 2;
      n += sig_alg_len;

      if (tls->in_hslen < 6 + n)
        {
          debug_msg (1, "bad certificate_request message");
          return gpg_error (GPG_ERR_BAD_HS_CERT_REQ);
        }
    }

  /* Ignore certificate_authorities, we only have one cert anyway */
  // TODO: should not send cert if no CA matches
  dn_len = buf16_to_size_t (buf + 5 + m + n);

  n += dn_len;
  if (tls->in_hslen != 7 + m + n)
    {
      debug_msg (1, "bad certificate_request message");
      return gpg_error (GPG_ERR_BAD_HS_CERT_REQ);
    }

 leave:

  return 0;
}


static gpg_error_t
read_server_hello_done (ntbtls_t tls)
{
  gpg_error_t err;

  debug_msg (2, "read server_hello_done");

  if (!tls->record_read)
    {
      err = _ntbtls_read_record (tls);
      if (err)
        {
          debug_ret (1, "read_record", err);
          return err;
        }

      if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
        {
          debug_msg (1, "bad server_hello_done message");
          return gpg_error (GPG_ERR_UNEXPECTED_MSG);
        }
    }
  tls->record_read = 0;

  if (tls->in_hslen != 4 || tls->in_msg[0] != TLS_HS_SERVER_HELLO_DONE)
    {
      debug_msg (1, "bad server_hello_done message");
      return gpg_error (GPG_ERR_BAD_HS_SERVER_HELLO_DONE);
    }

  tls->state++;

  return 0;
}


static gpg_error_t
write_client_key_exchange (ntbtls_t tls)
{
  gpg_error_t err;
  size_t i, n;
  const ciphersuite_t suite = tls->transform_negotiate->ciphersuite;
  key_exchange_type_t kex = _ntbtls_ciphersuite_get_kex (suite);

  debug_msg (2, "write client_key_exchange");

  if (kex == KEY_EXCHANGE_DHE_RSA)
    {
      /*
       * DHM key exchange -- send G^X mod P
       *
       * We don't have the remaining size of the buffer available,
       * thus we use a value which will always fit into our buffer. */
      i = 4;
      err = _ntbtls_dhm_make_public (tls->handshake->dhm_ctx,
                                     tls->out_msg + i, 514, &n);
      if (err)
        {
          debug_ret (1, "dhm_make_public", err);
          return err;
        }

      err = _ntbtls_dhm_calc_secret (tls->handshake->dhm_ctx,
                                     tls->handshake->premaster,
                                     TLS_PREMASTER_SIZE,
                                     &tls->handshake->pmslen);
      if (err)
        {
          debug_ret (1, "dhm_calc_secret", err);
          return err;
        }
    }
  else if (kex == KEY_EXCHANGE_ECDHE_RSA
           || kex == KEY_EXCHANGE_ECDHE_ECDSA
           || kex == KEY_EXCHANGE_ECDH_RSA
           || kex == KEY_EXCHANGE_ECDH_ECDSA)
    {
      /*
       * ECDH key exchange -- send client public value
       */
      i = 4;

      err = _ntbtls_ecdh_make_public (tls->handshake->ecdh_ctx,
                                      tls->out_msg + i, 1000, &n);
      if (err)
        {
          debug_ret (1, "ecdh_make_public", err);
          return err;
        }


      err = _ntbtls_ecdh_calc_secret (tls->handshake->ecdh_ctx,
                                      tls->handshake->premaster,
                                      TLS_PREMASTER_SIZE,
                                      &tls->handshake->pmslen);
      if (err)
        {
          debug_ret (1, "ecdh_calc_secret", err);
          return err;
        }
    }
  else if (kex == KEY_EXCHANGE_PSK
           || kex == KEY_EXCHANGE_RSA_PSK
           || kex == KEY_EXCHANGE_DHE_PSK
           || kex == KEY_EXCHANGE_ECDHE_PSK)
    {
      /*
       * opaque psk_identity<0..2^16-1>;
       */
      if (!tls->psk || !tls->psk_identity)
        return gpg_error (GPG_ERR_NO_SECKEY);

      i = 4;
      n = tls->psk_identity_len;
      tls->out_msg[i++] = (unsigned char) (n >> 8);
      tls->out_msg[i++] = (unsigned char) (n);

      memcpy (tls->out_msg + i, tls->psk_identity, tls->psk_identity_len);
      i += tls->psk_identity_len;

      if (kex == KEY_EXCHANGE_PSK)
        {
          n = 0;
        }
      else if (kex == KEY_EXCHANGE_RSA_PSK)
        {
          err = write_encrypted_pms (tls, i, &n, 2);
          if (err)
            return err;
        }
      else if (kex == KEY_EXCHANGE_DHE_PSK)
        {
          /*
           * ClientDiffieHellmanPublic public (DHM send G^X mod P)
           */
          n = 0; //FIXME: tls->handshake->dhm_ctx.len;
          tls->out_msg[i++] = (unsigned char) (n >> 8);
          tls->out_msg[i++] = (unsigned char) (n);

          /* err = dhm_make_public (&tls->handshake->dhm_ctx, */
          /*                        (int) mpi_size (&tls->handshake->dhm_ctx.P), */
          /*                        &tls->out_msg[i], n); */
          err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
          if (err)
            {
              debug_ret (1, "dhm_make_public", err);
              return err;
            }
        }
      else if (kex == KEY_EXCHANGE_ECDHE_PSK)
        {
          /*
           * ClientECDiffieHellmanPublic public;
           */
          /* err = ecdh_make_public (&tls->handshake->ecdh_ctx, &n, */
          /*                         &tls->out_msg[i], TLS_MAX_CONTENT_LEN - i); */
          err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
          if (err)
            {
              debug_ret (1, "ecdh_make_public", err);
              return err;
            }

          /* SSL_DEBUG_ECP (3, "ECDH: Q", &tls->handshake->ecdh_ctx.Q); */
        }
      else
        {
          debug_bug ();
          return gpg_error (GPG_ERR_INTERNAL);
        }

      err = _ntbtls_psk_derive_premaster (tls, kex);
      if (err)
        {
          debug_ret (1, "psk_derive_premaster", err);
          return err;
        }
    }
  else if (kex == KEY_EXCHANGE_RSA)
    {
      i = 4;
      err = write_encrypted_pms (tls, i, &n, 0);
      if (err)
        return err;
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  err = _ntbtls_derive_keys (tls);
  if (err)
    {
      debug_ret (1, "derive_keys", err);
      return err;
    }

  tls->out_msglen = i + n;
  tls->out_msgtype = TLS_MSG_HANDSHAKE;
  tls->out_msg[0] = TLS_HS_CLIENT_KEY_EXCHANGE;

  tls->state++;

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return 0;
}


static gpg_error_t
write_certificate_verify (ntbtls_t tls)
{
  gpg_error_t err;
  const ciphersuite_t suite = tls->transform_negotiate->ciphersuite;
  key_exchange_type_t kex = _ntbtls_ciphersuite_get_kex (suite);
  size_t n = 0;
  size_t offset = 0;
  unsigned char hash[48];
  unsigned char *hash_start = hash;
  md_algo_t md_alg = 0;
  unsigned int hashlen;

  if (kex == KEY_EXCHANGE_PSK
      || kex == KEY_EXCHANGE_RSA_PSK
      || kex == KEY_EXCHANGE_ECDHE_PSK
      || kex == KEY_EXCHANGE_DHE_PSK
      || !tls->client_auth
      || !tls_own_cert (tls))
    {
      debug_msg (2, "skipping write certificate_verify");
      tls->state++;
      return 0;
    }

  debug_msg (2, "write certificate_verify");

  if (!tls_own_key (tls))
    {
      debug_msg (1, "got no private key");
      return gpg_error (GPG_ERR_NO_SECKEY);
    }

  /*
   * Make an RSA signature of the handshake digests
   */
  tls->handshake->calc_verify (tls, hash);

  if (tls->minor_ver == TLS_MINOR_VERSION_3)
    {
      /*
       * digitally-signed struct {
       *     opaque handshake_messages[handshake_messages_length];
       * };
       *
       * Taking shortcut here. We assume that the server always allows the
       * PRF Hash function and has sent it in the allowed signature
       * algorithms list received in the Certificate Request message.
       *
       * Until we encounter a server that does not, we will take this
       * shortcut.
       *
       * Reason: Otherwise we should have running hashes for SHA512 and SHA224
       *         in order to satisfy 'weird' needs from the server side.
       */
      if (_ntbtls_ciphersuite_get_mac
          (tls->transform_negotiate->ciphersuite) == GCRY_MAC_HMAC_SHA384)
        {
          md_alg = GCRY_MD_SHA384;
          tls->out_msg[4] = TLS_HASH_SHA384;
          hashlen = 48;
        }
      else
        {
          md_alg = GCRY_MD_SHA256;
          tls->out_msg[4] = TLS_HASH_SHA256;
          hashlen = 32;
        }
      tls->out_msg[5] = 0; //FIXME: ssl_sig_from_pk (ssl_own_key (tls));

      offset = 2;
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  /* err = pk_sign (tls_own_key (tls), md_alg, hash_start, hashlen, */
  /*                tls->out_msg + 6 + offset, &n); */
  (void)md_alg;
  (void)hash_start;
  (void)hashlen;
  err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  if (err)
    {
      debug_ret (1, "pk_sign", err);
      return err;
    }

  tls->out_msg[4 + offset] = (unsigned char) (n >> 8);
  tls->out_msg[5 + offset] = (unsigned char) (n);

  tls->out_msglen = 6 + n + offset;
  tls->out_msgtype = TLS_MSG_HANDSHAKE;
  tls->out_msg[0] = TLS_HS_CERTIFICATE_VERIFY;

  tls->state++;

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return 0;
}


static gpg_error_t
parse_new_session_ticket (ntbtls_t tls)
{
  gpg_error_t err;
  uint32_t lifetime;
  size_t ticket_len;
  unsigned char *ticket;

  debug_msg (2, "read new_session_ticket");

  err = _ntbtls_read_record (tls);
  if (err)
    {
      debug_ret (1, "read_record", err);
      return err;
    }

  if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad new_session_ticket message");
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  /*
   * struct {
   *     uint32 ticket_lifetime_hint;
   *     opaque ticket<0..2^16-1>;
   * } NewSessionTicket;
   *
   * 0  .  0   handshake message type
   * 1  .  3   handshake message length
   * 4  .  7   ticket_lifetime_hint
   * 8  .  9   ticket_len (n)
   * 10 .  9+n ticket content
   */
  if (tls->in_msg[0] != TLS_HS_NEW_SESSION_TICKET || tls->in_hslen < 10)
    {
      debug_msg (1, "bad new_session_ticket message");
      return gpg_error (GPG_ERR_BAD_TICKET);
    }

  lifetime   = buf32_to_u32 (tls->in_msg + 4);
  ticket_len = buf16_to_size_t (tls->in_msg + 8);

  if (ticket_len + 10 != tls->in_hslen)
    {
      debug_msg (1, "bad new_session_ticket message");
      return gpg_error (GPG_ERR_BAD_TICKET);
    }

  debug_msg (3, "ticket length: %zu", ticket_len);

  /* We're not waiting for a NewSessionTicket message any more */
  tls->handshake->new_session_ticket = 0;

  /*
   * Zero-length ticket means the server changed his mind and doesn't want
   * to send a ticket after all, so just forget it
   */
  if (!ticket_len)
    return 0;

  wipememory (tls->session_negotiate->ticket,
              tls->session_negotiate->ticket_len);
  free (tls->session_negotiate->ticket);
  tls->session_negotiate->ticket = NULL;
  tls->session_negotiate->ticket_len = 0;

  ticket = malloc (ticket_len);
  if (!ticket)
    {
      err = gpg_error_from_syserror ();
      debug_msg (1, "ticket malloc failed");
      return err;
    }

  memcpy (ticket, tls->in_msg + 10, ticket_len);

  tls->session_negotiate->ticket = ticket;
  tls->session_negotiate->ticket_len = ticket_len;
  tls->session_negotiate->ticket_lifetime = lifetime;

  /*
   * RFC 5077 section 3.4:
   * "If the client receives a session ticket from the server, then it
   * discards any Session ID that was sent in the ServerHello."
   */
  debug_msg (3, "ticket in use, discarding session id");
  tls->session_negotiate->length = 0;

  return 0;
}


/*
 * SSL handshake -- client side -- single step
 */
gpg_error_t
_ntbtls_handshake_client_step (ntbtls_t tls)
{
  gpg_error_t err;

  if (tls->state == TLS_HANDSHAKE_OVER)
    return gpg_error (GPG_ERR_INV_STATE);

  debug_msg (2, "client state: %d (%s)",
             tls->state, _ntbtls_state2str (tls->state));

  err = _ntbtls_flush_output (tls);
  if (err)
    return err;

  switch (tls->state)
    {
    case TLS_HELLO_REQUEST:
      tls->state = TLS_CLIENT_HELLO;
      break;

      /*
       *  ==>   ClientHello
       */
    case TLS_CLIENT_HELLO:
      err = write_client_hello (tls);
      break;

      /*
       *  <==   ServerHello
       *        Certificate
       *      ( ServerKeyExchange  )
       *      ( CertificateRequest )
       *        ServerHelloDone
       */
    case TLS_SERVER_HELLO:
      err = read_server_hello (tls);
      break;

    case TLS_SERVER_CERTIFICATE:
      err = _ntbtls_read_certificate (tls);
      break;

    case TLS_SERVER_KEY_EXCHANGE:
      err = read_server_key_exchange (tls);
      break;

    case TLS_CERTIFICATE_REQUEST:
      err = read_certificate_request (tls);
      break;

    case TLS_SERVER_HELLO_DONE:
      err = read_server_hello_done (tls);
      break;

      /*
       *  ==> ( Certificate/Alert  )
       *        ClientKeyExchange
       *      ( CertificateVerify  )
       *        ChangeCipherSpec
       *        Finished
       */
    case TLS_CLIENT_CERTIFICATE:
      err = _ntbtls_write_certificate (tls);
      break;

    case TLS_CLIENT_KEY_EXCHANGE:
      err = write_client_key_exchange (tls);
      break;

    case TLS_CERTIFICATE_VERIFY:
      err = write_certificate_verify (tls);
      break;

    case TLS_CLIENT_CHANGE_CIPHER_SPEC:
      err = _ntbtls_write_change_cipher_spec (tls);
      break;

    case TLS_CLIENT_FINISHED:
      err = _ntbtls_write_finished (tls);
      break;

      /*
       *  <==   ( NewSessionTicket )
       *        ChangeCipherSpec
       *        Finished
       */
    case TLS_SERVER_CHANGE_CIPHER_SPEC:
      if (tls->handshake->new_session_ticket)
        err = parse_new_session_ticket (tls);
      else
        err = _ntbtls_read_change_cipher_spec (tls);
      break;

    case TLS_SERVER_FINISHED:
      err = _ntbtls_read_finished (tls);
      break;

    case TLS_FLUSH_BUFFERS:
      debug_msg (2, "handshake: done");
      tls->state = TLS_HANDSHAKE_WRAPUP;
      break;

    case TLS_HANDSHAKE_WRAPUP:
      _ntbtls_handshake_wrapup (tls);
      break;

    default:
      debug_msg (1, "invalid state %d", tls->state);
      err = gpg_error (GPG_ERR_INV_STATE);
      break;
    }

  return err;
}
