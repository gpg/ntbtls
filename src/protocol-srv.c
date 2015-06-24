/* protocol-srv.c - TLS 1.2 server side protocol
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

#include "ntbtls-int.h"



/*
 * Serialize a session in the following format:
 *  0   .   n-1     session structure, n = sizeof(ssl_session)
 *  n   .   n+2     peer_cert length = m (0 if no certificate)
 *  n+3 .   n+2+m   peer cert ASN.1
 *
 *  Assumes ticket is NULL (always true on server side).
 */
static int
ssl_save_session (const session_t session,
                  unsigned char *buf, size_t buf_len, size_t * olen)
{
  unsigned char *p = buf;
  size_t left = buf_len;
  size_t cert_len;

  if (left < sizeof *session)
    return (-1);

  memcpy (p, session, sizeof *session));
  p += sizeof (ssl_session);
  left -= sizeof (ssl_session);

  if (session->peer_cert == NULL)
    cert_len = 0;
  else
    cert_len = session->peer_cert->raw.len;

  if (left < 3 + cert_len)
    return (-1);

  *p++ = (unsigned char) (cert_len >> 16 & 0xFF);
  *p++ = (unsigned char) (cert_len >> 8 & 0xFF);
  *p++ = (unsigned char) (cert_len & 0xFF);

  if (session->peer_cert != NULL)
    memcpy (p, session->peer_cert->raw.p, cert_len);

  p += cert_len;

  *olen = p - buf;

  return (0);
}

/*
 * Unserialise session, see ssl_save_session()
 */
static int
ssl_load_session (session_t session, const unsigned char *buf, size_t len)
{
  const unsigned char *p = buf;
  const unsigned char *const end = buf + len;
  size_t cert_len;

  if (p + sizeof *session > end)
    return gpg_error (GPG_ERR_INV_ARG);

  memcpy (session, p, sizeof *session);
  p += sizeof *session;

  if (p + 3 > end)
    return gpg_error (GPG_ERR_INV_ARG);

  cert_len = buf24_to_size_t (p);
  p += 3;

  if (cert_len == 0)
    {
      session->peer_cert = NULL;
    }
  else
    {
      int ret;

      if (p + cert_len > end)
        return gpg_error (GPG_ERR_INV_ARG);

      session->peer_cert = malloc (sizeof (x509_crt));
      if (!session->peer_cert)
        return gpg_error_from_syserror ();

      x509_crt_init (session->peer_cert);

      if ((ret = x509_crt_parse_der (session->peer_cert, p, cert_len)) != 0)
        {
          x509_crt_free (session->peer_cert);
          polarssl_free (session->peer_cert);
          session->peer_cert = NULL;
          return (ret);
        }

      p += cert_len;
    }

  if (p != end)
    return gpg_error (GPG_ERR_INV_ARG);

  return (0);
}


/*
 * Create session ticket, secured as recommended in RFC 5077 section 4:
 *
 *    struct {
 *        opaque key_name[16];
 *        opaque iv[16];
 *        opaque encrypted_state<0..2^16-1>;
 *        opaque mac[32];
 *    } ticket;
 *
 * (the internal state structure differs, however).
 */
static int
ssl_write_ticket (ntbtls_t ssl, size_t * tlen)
{
  int ret;
  unsigned char *const start = ssl->out_msg + 10;
  unsigned char *p = start;
  unsigned char *state;
  unsigned char iv[16];
  size_t clear_len, enc_len, pad_len, i;

  *tlen = 0;

  if (ssl->ticket_keys == NULL)
    return gpg_error (GPG_ERR_INV_ARG);

  /* Write key name */
  memcpy (p, ssl->ticket_keys->key_name, 16);
  p += 16;

  /* Generate and write IV (with a copy for aes_crypt) */
  if ((ret = ssl->f_rng (ssl->p_rng, p, 16)) != 0)
    return (ret);
  memcpy (iv, p, 16);
  p += 16;

  /*
   * Dump session state
   *
   * After the session state itself, we still need room for 16 bytes of
   * padding and 32 bytes of MAC, so there's only so much room left
   */
  state = p + 2;
  if (ssl_save_session (ssl->session_negotiate, state,
                        SSL_MAX_CONTENT_LEN - (state - ssl->out_ctr) - 48,
                        &clear_len) != 0)
    {
      return gpg_error (GPG_ERR_CERT_TOO_LARGE);
    }
  debug_buf (3, "session ticket cleartext", state, clear_len);

  /* Apply PKCS padding */
  pad_len = 16 - clear_len % 16;
  enc_len = clear_len + pad_len;
  for (i = clear_len; i < enc_len; i++)
    state[i] = (unsigned char) pad_len;

  /* Encrypt */
  if ((ret = aes_crypt_cbc (&ssl->ticket_keys->enc, AES_ENCRYPT,
                            enc_len, iv, state, state)) != 0)
    {
      return (ret);
    }

  /* Write length */
  *p++ = (unsigned char) ((enc_len >> 8) & 0xFF);
  *p++ = (unsigned char) ((enc_len) & 0xFF);
  p = state + enc_len;

  /* Compute and write MAC( key_name + iv + enc_state_len + enc_state ) */
  sha256_hmac (ssl->ticket_keys->mac_key, 16, start, p - start, p, 0);
  p += 32;

  *tlen = p - start;

  debug_buf (3, "session ticket structure", start, *tlen);

  return (0);
}


/*
 * Load session ticket (see ssl_write_ticket for structure)
 */
static int
ssl_parse_ticket (ntbtls_t ssl, unsigned char *buf, size_t len)
{
  int ret;
  struct _ntbtls_session_s sessionbuf;
  unsigned char *key_name = buf;
  unsigned char *iv = buf + 16;
  unsigned char *enc_len_p = iv + 16;
  unsigned char *ticket = enc_len_p + 2;
  unsigned char *mac;
  unsigned char computed_mac[32];
  size_t enc_len, clear_len, i;
  unsigned char pad_len, diff;

  debug_buf (3, "session ticket structure", buf, len);

  if (len < 34 || ssl->ticket_keys == NULL)
    return gpg_error (GPG_ERR_INV_ARG);

  enc_len = buf16_to_size_t (enc_len_p);
  mac = ticket + enc_len;

  if (len != enc_len + 66)
    return gpg_error (GPG_ERR_INV_ARG);

  /* Check name, in constant time though it's not a big secret */
  diff = 0;
  for (i = 0; i < 16; i++)
    diff |= key_name[i] ^ ssl->ticket_keys->key_name[i];
  /* don't return yet, check the MAC anyway */

  /* Check mac, with constant-time buffer comparison */
  sha256_hmac (ssl->ticket_keys->mac_key, 16, buf, len - 32, computed_mac, 0);

  for (i = 0; i < 32; i++)
    diff |= mac[i] ^ computed_mac[i];

  /* Now return if ticket is not authentic, since we want to avoid
   * decrypting arbitrary attacker-chosen data */
  if (diff != 0)
    return gpg_error (GPG_ERR_BAD_MAC);

  /* Decrypt */
  if ((ret = aes_crypt_cbc (&ssl->ticket_keys->dec, AES_DECRYPT,
                            enc_len, iv, ticket, ticket)) != 0)
    {
      return (ret);
    }

  /* Check PKCS padding */
  pad_len = ticket[enc_len - 1];

  ret = 0;
  for (i = 2; i < pad_len; i++)
    if (ticket[enc_len - i] != pad_len)
      ret = gpg_error (GPG_ERR_INV_ARG); /* FIXME: Better error message */
  if (ret != 0)
    return (ret);

  clear_len = enc_len - pad_len;

  debug_buf (3, "session ticket cleartext", ticket, clear_len);

  /* Actually load session */
  if ((ret = ssl_load_session (&sessionbuf, ticket, clear_len)) != 0)
    {
      debug_msg (1, "failed to parse ticket content");
      ssl_session_free (&sessionbuf);
      return (ret);
    }

  /* Check if still valid */
  if ((int) (time (NULL) - session.start) > ssl->ticket_lifetime)
    {
      debug_msg (1, "session ticket expired");
      ssl_session_free (&sessionbuf);
      return gpg_error (GPG_ERR_TICKET_EXPIRED);
    }

  /*
   * Keep the session ID sent by the client, since we MUST send it back to
   * inform him we're accepting the ticket  (RFC 5077 section 3.4)
   */
  sessionbuf.length = ssl->session_negotiate->length;
  memcpy (&sessionbuf.id, ssl->session_negotiate->id, sessionbuf.length);

  ssl_session_free (ssl->session_negotiate);
  memcpy (ssl->session_negotiate, &sessionbuf, sizeof sessionbuf);

  /* Zeroize instead of free as we copied the content */
  wipememory (&sessionbuf, sizeof sessionbuf);

  return 0;
}


/*
 * Wrapper around f_sni, allowing use of ssl_set_own_cert() but
 * making it act on ssl->hanshake->sni_key_cert instead.
 */
static int
ssl_sni_wrapper (ntbtls_t ssl, const unsigned char *name, size_t len)
{
  int ret;
  ssl_key_cert *key_cert_ori = ssl->key_cert;

  /* Fixme: Turn HOSTNAME into a C string and bail out if it has
     embedded nuls.  */
  ssl->key_cert = NULL;
  ret = ssl->f_sni (ssl->p_sni, ssl, name, len);
  ssl->handshake->sni_key_cert = ssl->key_cert;

  ssl->key_cert = key_cert_ori;

  return (ret);
}

static int
ssl_parse_servername_ext (ntbtls_t ssl,
                          const unsigned char *buf, size_t len)
{
  int ret;
  size_t servername_list_size, hostname_len;
  const unsigned char *p;

  debug_msg (3, "parse ServerName extension");

  servername_list_size = buf16_to_size_t (buf);
  if (servername_list_size + 2 != len)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  p = buf + 2;
  while (servername_list_size > 0)
    {
      hostname_len = buf16_to_size_t (p + 1);
      if (hostname_len + 3 > servername_list_size)
        {
          debug_msg (1, "bad client hello message");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
        }

      if (p[0] == TLS_EXT_SERVERNAME_HOSTNAME)
        {
          ret = ssl_sni_wrapper (ssl, p + 3, hostname_len);
          if (ret != 0)
            {
              debug_ret (1, "ssl_sni_wrapper", ret);
              _ntbtls_send_alert_message (ssl, TLS_ALERT_LEVEL_FATAL,
                                          TLS_ALERT_MSG_UNRECOGNIZED_NAME);
              return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
            }
          return (0);
        }

      servername_list_size -= hostname_len + 3;
      p += hostname_len + 3;
    }

  if (servername_list_size != 0)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  return (0);
}


static int
ssl_parse_renegotiation_info (ntbtls_t ssl,
                              const unsigned char *buf, size_t len)
{
  int ret;

  if (ssl->renegotiation == SSL_INITIAL_HANDSHAKE)
    {
      if (len != 1 || buf[0] != 0x0)
        {
          debug_msg (1, "non-zero length renegotiated connection field");

          if ((ret = ssl_send_fatal_handshake_failure (ssl)) != 0)
            return (ret);

          return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
        }

      ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
    }
  else
    {
      /* Check verify-data in constant-time. The length OTOH is no secret */
      if (len != 1 + ssl->verify_data_len ||
          buf[0] != ssl->verify_data_len ||
          memcmpct (buf + 1, ssl->peer_verify_data, ssl->verify_data_len))
        {
          debug_msg (1, "non-matching renegotiated connection field");

          if ((ret = ssl_send_fatal_handshake_failure (ssl)) != 0)
            return (ret);

          return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
        }
    }

  return (0);
}


static int
ssl_parse_signature_algorithms_ext (ntbtls_t ssl,
                                    const unsigned char *buf, size_t len)
{
  size_t sig_alg_list_size;
  const unsigned char *p;
  const unsigned char *end = buf + len;
  const md_algo_t *md_cur;


  sig_alg_list_size = buf16_to_size_t (buf);
  if (sig_alg_list_size + 2 != len || sig_alg_list_size % 2 != 0)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  /*
   * For now, ignore the SignatureAlgorithm part and rely on offered
   * ciphersuites only for that part. To be fixed later.
   *
   * So, just look at the HashAlgorithm part.
   */
  for (md_cur = md_list (); *md_cur; md_cur++)
    {
      for (p = buf + 2; p < end; p += 2)
        {
          if (*md_cur == (int) _ntbtls_md_alg_from_hash (p[0]))
            {
              ssl->handshake->sig_alg = p[0];
              break;
            }
        }
    }

  debug_msg (3, "client hello v3, signature_algorithm ext: %d",
             ssl->handshake->sig_alg);

  return (0);
}



static int
ssl_parse_supported_elliptic_curves (ntbtls_t ssl,
                                     const unsigned char *buf, size_t len)
{
  size_t list_size, our_size;
  const unsigned char *p;
  const ecp_curve_info *curve_info, **curves;

  list_size = buf16_to_size_t (buf);
  if (list_size + 2 != len || list_size % 2 != 0)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  /* Don't allow our peer to make us allocate too much memory,
   * and leave room for a final 0 */
  our_size = list_size / 2 + 1;
  if (our_size > POLARSSL_ECP_DP_MAX)
    our_size = POLARSSL_ECP_DP_MAX;

  curves = calloc (our_size, sizeof (*curves));
  if (!curves)
    return err = gpg_error_from_syserror ();

  ssl->handshake->curves = curves;

  p = buf + 2;
  while (list_size > 0 && our_size > 1)
    {
      curve_info = ecp_curve_info_from_tls_id ((p[0] << 8) | p[1]);

      if (curve_info != NULL)
        {
          *curves++ = curve_info;
          our_size--;
        }

      list_size -= 2;
      p += 2;
    }

  return (0);
}

static int
ssl_parse_supported_point_formats (ntbtls_t ssl,
                                   const unsigned char *buf, size_t len)
{
  size_t list_size;
  const unsigned char *p;

  list_size = buf[0];
  if (list_size + 1 != len)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  p = buf + 2;
  while (list_size > 0)
    {
      if (p[0] == POLARSSL_ECP_PF_UNCOMPRESSED ||
          p[0] == POLARSSL_ECP_PF_COMPRESSED)
        {
          ssl->handshake->ecdh_ctx.point_format = p[0];
          debug_msg (4, "point format selected: %d", p[0]);
          return (0);
        }

      list_size--;
      p++;
    }

  return (0);
}


static int
ssl_parse_max_fragment_length_ext (ntbtls_t ssl,
                                   const unsigned char *buf, size_t len)
{
  if (len != 1 || buf[0] >= SSL_MAX_FRAG_LEN_INVALID)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  ssl->session_negotiate->mfl_code = buf[0];

  return (0);
}


static int
ssl_parse_truncated_hmac_ext (ntbtls_t ssl,
                              const unsigned char *buf, size_t len)
{
  if (len != 0)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  ((void) buf);

  ssl->session_negotiate->use_trunc_hmac = 1;

  return (0);
}


static int
ssl_parse_session_ticket_ext (ntbtls_t ssl,
                              unsigned char *buf, size_t len)
{
  int ret;

  if (!ssl->use_session_tickets)
    return 0;

  /* Remember the client asked us to send a new ticket */
  ssl->handshake->new_session_ticket = 1;

  debug_msg (3, "ticket length: %zu", len);

  if (len == 0)
    return (0);

  if (ssl->renegotiation != SSL_INITIAL_HANDSHAKE)
    {
      debug_msg (3, "ticket rejected: renegotiating");
      return (0);
    }

  /*
   * Failures are ok: just ignore the ticket and proceed.
   */
  if ((ret = ssl_parse_ticket (ssl, buf, len)) != 0)
    {
      debug_ret (1, "ssl_parse_ticket", ret);
      return (0);
    }

  debug_msg (3, "session successfully restored from ticket");

  ssl->handshake->resume = 1;

  /* Don't send a new ticket after all, this one is OK */
  ssl->handshake->new_session_ticket = 0;

  return (0);
}


static int
ssl_parse_alpn_ext (ntbtls_t ssl, const unsigned char *buf, size_t len)
{
  size_t list_len, cur_len, ours_len;
  const unsigned char *theirs, *start, *end;
  const char **ours;

  /* If ALPN not configured, just ignore the extension */
  if (ssl->alpn_list == NULL)
    return (0);

  /*
   * opaque ProtocolName<1..2^8-1>;
   *
   * struct {
   *     ProtocolName protocol_name_list<2..2^16-1>
   * } ProtocolNameList;
   */

  /* Min length is 2 (list_len) + 1 (name_len) + 1 (name) */
  if (len < 4)
    return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);

  list_len = buf16_to_size_t (buf);
  if (list_len != len - 2)
    return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);

  /*
   * Use our order of preference
   */
  start = buf + 2;
  end = buf + len;
  for (ours = ssl->alpn_list; *ours != NULL; ours++)
    {
      ours_len = strlen (*ours);
      for (theirs = start; theirs != end; theirs += cur_len)
        {
          /* If the list is well formed, we should get equality first */
          if (theirs > end)
            return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);

          cur_len = *theirs++;

          /* Empty strings MUST NOT be included */
          if (cur_len == 0)
            return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);

          if (cur_len == ours_len && memcmp (theirs, *ours, cur_len) == 0)
            {
              ssl->alpn_chosen = *ours;
              return (0);
            }
        }
    }

  /* If we get there, no match was found */
  _ntbtls_send_alert_message (ssl, TLS_ALERT_LEVEL_FATAL,
                          TLS_ALERT_MSG_NO_APPLICATION_PROTOCOL);
  return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
}


/*
 * Auxiliary functions for ServerHello parsing and related actions
 */


/*
 * Return 1 if the given EC key uses the given curve, 0 otherwise
 */
static int
ssl_key_matches_curves (pk_context * pk, const ecp_curve_info ** curves)
{
  const ecp_curve_info **crv = curves;
  ecp_group_id grp_id = pk_ec (*pk)->grp.id;

  while (*crv != NULL)
    {
      if ((*crv)->grp_id == grp_id)
        return (1);
      crv++;
    }

  return (0);
}

/*
 * Try picking a certificate for this ciphersuite,
 * return 0 on success and -1 on failure.
 */
static int
ssl_pick_cert (ntbtls_t ssl, const ssl_ciphersuite_t * suite)
{
  ssl_key_cert *cur, *list;
  pk_algo_t pk_alg = ssl_get_ciphersuite_sig_pk_alg (suite);

  if (ssl->handshake->sni_key_cert != NULL)
    list = ssl->handshake->sni_key_cert;
  else
    list = ssl->handshake->key_cert;

  if (pk_alg == POLARSSL_PK_NONE)
    return (0);

  for (cur = list; cur != NULL; cur = cur->next)
    {
      if (!pk_can_do (cur->key, pk_alg))
        continue;

      /*
       * This avoids sending the client a cert it'll reject based on
       * keyUsage or other extensions.
       *
       * It also allows the user to provision different certificates for
       * different uses based on keyUsage, eg if they want to avoid signing
       * and decrypting with the same RSA key.
       */
      if (ssl_check_cert_usage (cur->cert, suite,
                                SSL_IS_SERVER) != 0)
        {
          continue;
        }

      if (pk_alg == POLARSSL_PK_ECDSA)
        {
          if (ssl_key_matches_curves (cur->key, ssl->handshake->curves))
            break;
        }
      else
        break;
    }

  if (cur == NULL)
    return (-1);

  ssl->handshake->key_cert = cur;
  return (0);
}


/*
 * Check if a given ciphersuite is suitable for use with our config/keys/etc
 * Sets suite only if the suite matches.
 */
static int
ssl_ciphersuite_match (ntbtls_t ssl, int suite_id,
                       const ssl_ciphersuite_t ** suite)
{
  const ssl_ciphersuite_t *suite_info;

  suite_info = ssl_ciphersuite_from_id (suite_id);
  if (suite_info == NULL)
    {
      debug_msg (1, "ciphersuite info for %04x not found", suite_id);
      return gpg_error (GPG_ERR_INV_ARG);
    }

  if (suite_info->min_minor_ver > ssl->minor_ver ||
      suite_info->max_minor_ver < ssl->minor_ver)
    return (0);

  if (ssl_ciphersuite_uses_ec (suite_info) &&
      (ssl->handshake->curves == NULL || ssl->handshake->curves[0] == NULL))
    return (0);

  /* If the ciphersuite requires a pre-shared key and we don't
   * have one, skip it now rather than failing later */
  if (ssl_ciphersuite_uses_psk (suite_info) &&
      ssl->f_psk == NULL &&
      (ssl->psk == NULL || ssl->psk_identity == NULL ||
       ssl->psk_identity_len == 0 || ssl->psk_len == 0))
    return (0);

  /*
   * Final check: if ciphersuite requires us to have a
   * certificate/key of a particular type:
   * - select the appropriate certificate if we have one, or
   * - try the next ciphersuite if we don't
   * This must be done last since we modify the key_cert list.
   */
  if (ssl_pick_cert (ssl, suite_info) != 0)
    return (0);

  *suite = suite_info;
  return (0);
}


static int
read_client_hello (ntbtls_t ssl)
{
  int ret;
  unsigned int i, j;
  size_t n;
  unsigned int ciph_len, sess_len;
  unsigned int comp_len;
  unsigned int ext_len = 0;
  unsigned char *buf, *p, *ext;
  int renegotiation_info_seen = 0;
  int handshake_failure = 0;
  const int *ciphersuites;
  const ssl_ciphersuite_t *suite;

  debug_msg (2, "=> parse client hello");

  if (ssl->renegotiation == SSL_INITIAL_HANDSHAKE &&
      (ret = _ntbtls_fetch_input (ssl, 5)) != 0)
    {
      debug_ret (1, "ssl_fetch_input", ret);
      return (ret);
    }

  buf = ssl->in_hdr;

  debug_buf (4, "record header", buf, 5);

  debug_msg (3, "client hello v3, message type: %d", buf[0]);
  debug_msg (3, "client hello v3, message len.: %d", (buf[3] << 8) | buf[4]);
  debug_msg (3, "client hello v3, protocol ver: [%d:%d]", buf[1], buf[2]);

  /*
   * SSLv3/TLS Client Hello
   *
   * Record layer:
   *     0  .   0   message type
   *     1  .   2   protocol version
   *     3  .   4   message length
   */

  /* According to RFC 5246 Appendix E.1, the version here is typically
   * "{03,00}, the lowest version number supported by the client, [or] the
   * value of ClientHello.client_version", so the only meaningful check here
   * is the major version shouldn't be less than 3 */
  if (buf[0] != TLS_MSG_HANDSHAKE || buf[1] < SSL_MAJOR_VERSION_3)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  n = buf16_to_size_t (buf + 3);

  if (n < 45 || n > SSL_MAX_CONTENT_LEN)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  if (ssl->renegotiation == SSL_INITIAL_HANDSHAKE &&
      (err = _ntbtls_fetch_input (ssl, 5 + n)) != 0)
    {
      debug_ret (1, "ssl_fetch_input", ret);
      return (ret);
    }

  buf = ssl->in_msg;
  if (!ssl->renegotiation)
    n = ssl->in_left - 5;
  else
    n = ssl->in_msglen;

  ssl->handshake->update_checksum (ssl, buf, n);

  /*
   * SSL layer:
   *     0  .   0   handshake type
   *     1  .   3   handshake length
   *     4  .   5   protocol version
   *     6  .   9   UNIX time()
   *    10  .  37   random bytes
   *    38  .  38   session id length
   *    39  . 38+x  session id
   *   39+x . 40+x  ciphersuitelist length
   *   41+x . 40+y  ciphersuitelist
   *   41+y . 41+y  compression alg length
   *   42+y . 41+z  compression algs
   *    ..  .  ..   extensions
   */
  debug_buf (4, "record contents", buf, n);

  debug_msg (3, "client hello v3, handshake type: %d", buf[0]);
  debug_msg (3, "client hello v3, handshake len.: %d",
             (buf[1] << 16) | (buf[2] << 8) | buf[3]));
  debug_msg (3, "client hello v3, max. version: [%d:%d]", buf[4], buf[5]);

  /*
   * Check the handshake type and protocol version
   */
  if (buf[0] != TLS_HS_CLIENT_HELLO)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  ssl->major_ver = buf[4];
  ssl->minor_ver = buf[5];

  ssl->handshake->max_major_ver = ssl->major_ver;
  ssl->handshake->max_minor_ver = ssl->minor_ver;

  if (ssl->major_ver < ssl->min_major_ver ||
      ssl->minor_ver < ssl->min_minor_ver)
    {
      debug_msg (1, "client only supports ssl smaller than minimum"
                 " [%d:%d] < [%d:%d]",
                 ssl->major_ver, ssl->minor_ver,
                 ssl->min_major_ver, ssl->min_minor_ver);

      ntbtls_send_alert_message (ssl, TLS_ALERT_LEVEL_FATAL,
                              TLS_ALERT_MSG_PROTOCOL_VERSION);

      return gpg_error (GPG_ERR_UNSUPPORTED_PROTOCOL);
    }

  if (ssl->major_ver > ssl->max_major_ver)
    {
      ssl->major_ver = ssl->max_major_ver;
      ssl->minor_ver = ssl->max_minor_ver;
    }
  else if (ssl->minor_ver > ssl->max_minor_ver)
    ssl->minor_ver = ssl->max_minor_ver;

  memcpy (ssl->handshake->randbytes, buf + 6, 32);

  /*
   * Check the handshake message length
   */
  if (buf[1] != 0 || n != (unsigned int) 4 + buf16_to_uint (buf+2))
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  /*
   * Check the session length
   */
  sess_len = buf[38];

  if (sess_len > 32 || sess_len > n - 42)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  ssl->session_negotiate->length = sess_len;
  memset (ssl->session_negotiate->id, 0, sizeof (ssl->session_negotiate->id));
  memcpy (ssl->session_negotiate->id, buf + 39,
          ssl->session_negotiate->length);

  /*
   * Check the ciphersuitelist length
   */
  ciph_len = buf16_to_uint (buf + 39);

  if (ciph_len < 2 || (ciph_len % 2) != 0 || ciph_len > n - 42 - sess_len)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  /*
   * Check the compression algorithms length
   */
  comp_len = buf[41 + sess_len + ciph_len];

  if (comp_len < 1 || comp_len > 16 ||
      comp_len > n - 42 - sess_len - ciph_len)
    {
      debug_msg (1, "bad client hello message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  /*
   * Check the extension length
   */
  if (n > 42 + sess_len + ciph_len + comp_len)
    {
      ext_len = buf16_to_uint (buf + 42 + sess_len + ciph_len + comp_len);
      if ((ext_len > 0 && ext_len < 4)
          || n != 44 + sess_len + ciph_len + comp_len + ext_len)
        {
          debug_msg (1, "bad client hello message");
          debug_buf (3, "Ext",
                     buf + 44 + sess_len + ciph_len + comp_len, ext_len);
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
        }
    }

  ssl->session_negotiate->compression = SSL_COMPRESS_NULL;
  for (i = 0; i < comp_len; ++i)
    {
      if (buf[42 + sess_len + ciph_len + i] == SSL_COMPRESS_DEFLATE)
        {
          ssl->session_negotiate->compression = SSL_COMPRESS_DEFLATE;
          break;
        }
    }

  debug_buf (3, "client hello, random bytes", buf + 6, 32);
  debug_buf (3, "client hello, session id", buf + 38, sess_len);
  debug_buf (3, "client hello, ciphersuitelist", buf + 41 + sess_len, ciph_len);
  debug_buf (3, "client hello, compression",
             buf + 42 + sess_len + ciph_len, comp_len);

  /*
   * Check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
   */
  for (i = 0, p = buf + 41 + sess_len; i < ciph_len; i += 2, p += 2)
    {
      if (p[0] == 0 && p[1] == SSL_EMPTY_RENEGOTIATION_INFO)
        {
          debug_msg (3, "received TLS_EMPTY_RENEGOTIATION_INFO ");
          if (ssl->renegotiation == SSL_RENEGOTIATION)
            {
              debug_msg (1, "received RENEGOTIATION SCSV during renegotiation");

              if ((ret = ssl_send_fatal_handshake_failure (ssl)) != 0)
                return (ret);

              return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
            }
          ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
          break;
        }
    }

  ext = buf + 44 + sess_len + ciph_len + comp_len;

  while (ext_len)
    {
      unsigned int ext_id = buf16_to_uint (ext);
      unsigned int ext_size = buf16_to_uint (ext + 2);

      if (ext_size + 4 > ext_len)
        {
          debug_msg (1, "bad client hello message");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
        }
      switch (ext_id)
        {
        case TLS_EXT_SERVERNAME:
          debug_msg (3, "found ServerName extension");
          if (ssl->f_sni == NULL)
            break;

          ret = ssl_parse_servername_ext (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_RENEGOTIATION_INFO:
          debug_msg (3, "found renegotiation extension");
          renegotiation_info_seen = 1;

          ret = ssl_parse_renegotiation_info (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_SIG_ALG:
          debug_msg (3, "found signature_algorithms extension");
          if (ssl->renegotiation == SSL_RENEGOTIATION)
            break;

          ret = ssl_parse_signature_algorithms_ext (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_SUPPORTED_ELLIPTIC_CURVES:
          debug_msg (3, "found supported elliptic curves extension");

          ret = ssl_parse_supported_elliptic_curves (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_SUPPORTED_POINT_FORMATS:
          debug_msg (3, "found supported point formats extension");
          ssl->handshake->cli_exts |= TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT;

          ret = ssl_parse_supported_point_formats (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_MAX_FRAGMENT_LENGTH:
          debug_msg (3, "found max fragment length extension");

          ret = ssl_parse_max_fragment_length_ext (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_TRUNCATED_HMAC:
          debug_msg (3, "found truncated hmac extension");

          ret = ssl_parse_truncated_hmac_ext (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_SESSION_TICKET:
          debug_msg (3, "found session ticket extension");

          ret = ssl_parse_session_ticket_ext (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        case TLS_EXT_ALPN:
          debug_msg (3, "found alpn extension");

          ret = ssl_parse_alpn_ext (ssl, ext + 4, ext_size);
          if (ret != 0)
            return (ret);
          break;

        default:
          debug_msg (3, "unknown extension found: %d (ignoring)", ext_id);
          break;
        }

      ext_len -= 4 + ext_size;
      ext += 4 + ext_size;

      if (ext_len > 0 && ext_len < 4)
        {
          debug_msg (1, "bad client hello message");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
        }
    }

  /*
   * Renegotiation security checks
   */
  if (ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
      ssl->allow_legacy_renegotiation == SSL_LEGACY_BREAK_HANDSHAKE)
    {
      debug_msg (1, "legacy renegotiation, breaking off handshake");
      handshake_failure = 1;
    }
  else if (ssl->renegotiation == SSL_RENEGOTIATION &&
           ssl->secure_renegotiation == SSL_SECURE_RENEGOTIATION &&
           renegotiation_info_seen == 0)
    {
      debug_msg (1, "renegotiation_info extension missing (secure)");
      handshake_failure = 1;
    }
  else if (ssl->renegotiation == SSL_RENEGOTIATION &&
           ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
           ssl->allow_legacy_renegotiation == SSL_LEGACY_NO_RENEGOTIATION)
    {
      debug_msg (1, "legacy renegotiation not allowed");
      handshake_failure = 1;
    }
  else if (ssl->renegotiation == SSL_RENEGOTIATION &&
           ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
           renegotiation_info_seen == 1)
    {
      debug_msg (1, "renegotiation_info extension present (legacy)");
      handshake_failure = 1;
    }

  if (handshake_failure == 1)
    {
      if ((ret = ssl_send_fatal_handshake_failure (ssl)) != 0)
        return (ret);

      return gpg_error (GPG_ERR_BAD_HS_CLIENT_HELLO);
    }

  /*
   * Search for a matching ciphersuite
   * (At the end because we need information from the EC-based extensions
   * and certificate from the SNI callback triggered by the SNI extension.)
   */
  ciphersuites = ssl->ciphersuite_list[ssl->minor_ver];
  suite = NULL;
  for (j = 0, p = buf + 41 + sess_len; j < ciph_len; j += 2, p += 2)
    {
      for (i = 0; ciphersuites[i] != 0; i++)
        {
          if (p[0] != ((ciphersuites[i] >> 8) & 0xFF) ||
              p[1] != ((ciphersuites[i]) & 0xFF))
            continue;

          if ((ret = ssl_ciphersuite_match (ssl, ciphersuites[i],
                                            &suite)) != 0)
            return (ret);

          if (suite != NULL)
            goto have_ciphersuite;
        }
    }

  debug_msg (1, "got no ciphersuites in common");

  if ((ret = ssl_send_fatal_handshake_failure (ssl)) != 0)
    return (ret);

return gpg_error (GPG_ERR_NO_CIPHER);

have_ciphersuite:
  ssl->session_negotiate->ciphersuite = ciphersuites[i];
  ssl->transform_negotiate->ciphersuite = suite;
  _ntbtls_optimize_checksum (ssl, ssl->transform_negotiate->ciphersuite);

  ssl->in_left = 0;
  ssl->state++;

  debug_msg (2, "<= parse client hello");

  return (0);
}


static void
write_srv_truncated_hmac_ext (ntbtls_t ssl,
                              unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;

  if (!ssl->session_negotiate->use_trunc_hmac)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "server hello, adding truncated hmac extension");

  *p++ = (unsigned char) ((TLS_EXT_TRUNCATED_HMAC >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_TRUNCATED_HMAC) & 0xFF);

  *p++ = 0x00;
  *p++ = 0x00;

  *olen = 4;
}



static void
write_srv_session_ticket_ext (ntbtls_t ssl,
                              unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;

  if (ssl->handshake->new_session_ticket == 0)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "server hello, adding session ticket extension");

  *p++ = (unsigned char) ((TLS_EXT_SESSION_TICKET >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SESSION_TICKET) & 0xFF);

  *p++ = 0x00;
  *p++ = 0x00;

  *olen = 4;
}


static void
write_srv_renegotiation_ext (ntbtls_t ssl,
                             unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;

  if (ssl->secure_renegotiation != SSL_SECURE_RENEGOTIATION)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "server hello, secure renegotiation extension");

  *p++ = (unsigned char) ((TLS_EXT_RENEGOTIATION_INFO >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_RENEGOTIATION_INFO) & 0xFF);

  *p++ = 0x00;
  *p++ = (ssl->verify_data_len * 2 + 1) & 0xFF;
  *p++ = ssl->verify_data_len * 2 & 0xFF;

  memcpy (p, ssl->peer_verify_data, ssl->verify_data_len);
  p += ssl->verify_data_len;
  memcpy (p, ssl->own_verify_data, ssl->verify_data_len);
  p += ssl->verify_data_len;

  *olen = 5 + ssl->verify_data_len * 2;
}


static void
write_srv_max_fragment_length_ext (ntbtls_t ssl,
                                   unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;

  if (ssl->session_negotiate->mfl_code == SSL_MAX_FRAG_LEN_NONE)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "server hello, max_fragment_length extension");

  *p++ = (unsigned char) ((TLS_EXT_MAX_FRAGMENT_LENGTH >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_MAX_FRAGMENT_LENGTH) & 0xFF);

  *p++ = 0x00;
  *p++ = 1;

  *p++ = ssl->session_negotiate->mfl_code;

  *olen = 5;
}


static void
write_srv_supported_point_formats_ext (ntbtls_t ssl,
                                       unsigned char *buf, size_t * olen)
{
  unsigned char *p = buf;
  ((void) ssl);

  if ((ssl->handshake->cli_exts &
       TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT) == 0)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "server hello, supported_point_formats extension");

  *p++ = (unsigned char) ((TLS_EXT_SUPPORTED_POINT_FORMATS >> 8) & 0xFF);
  *p++ = (unsigned char) ((TLS_EXT_SUPPORTED_POINT_FORMATS) & 0xFF);

  *p++ = 0x00;
  *p++ = 2;

  *p++ = 1;
  *p++ = POLARSSL_ECP_PF_UNCOMPRESSED;

  *olen = 6;
}


static void
write_srv_alpn_ext (ntbtls_t ssl, unsigned char *buf, size_t * olen)
{
  if (ssl->alpn_chosen == NULL)
    {
      *olen = 0;
      return;
    }

  debug_msg (3, "server hello, adding alpn extension");

  /*
   * 0 . 1    ext identifier
   * 2 . 3    ext length
   * 4 . 5    protocol list length
   * 6 . 6    protocol name length
   * 7 . 7+n  protocol name
   */
  buf[0] = (unsigned char) ((TLS_EXT_ALPN >> 8) & 0xFF);
  buf[1] = (unsigned char) ((TLS_EXT_ALPN) & 0xFF);

  *olen = 7 + strlen (ssl->alpn_chosen);

  buf[2] = (unsigned char) (((*olen - 4) >> 8) & 0xFF);
  buf[3] = (unsigned char) (((*olen - 4)) & 0xFF);

  buf[4] = (unsigned char) (((*olen - 6) >> 8) & 0xFF);
  buf[5] = (unsigned char) (((*olen - 6)) & 0xFF);

  buf[6] = (unsigned char) (((*olen - 7)) & 0xFF);

  memcpy (buf + 7, ssl->alpn_chosen, *olen - 7);
}


static int
write_server_hello (ntbtls_t ssl)
{
  time_t t;
  int ret;
  size_t olen, ext_len = 0, n;
  unsigned char *buf, *p;

  debug_msg (2, "=> write server hello");

  /*
   *     0  .   0   handshake type
   *     1  .   3   handshake length
   *     4  .   5   protocol version
   *     6  .   9   UNIX time()
   *    10  .  37   random bytes
   */
  buf = ssl->out_msg;
  p = buf + 4;

  *p++ = (unsigned char) ssl->major_ver;
  *p++ = (unsigned char) ssl->minor_ver;

  debug_msg (3, "server hello, chosen version: [%d:%d]", buf[4], buf[5]);

  t = time (NULL);
  *p++ = (unsigned char) (t >> 24);
  *p++ = (unsigned char) (t >> 16);
  *p++ = (unsigned char) (t >> 8);
  *p++ = (unsigned char) (t);

  debug_msg (3, "server hello, current time: %lu", t);

  if ((ret = ssl->f_rng (ssl->p_rng, p, 28)) != 0)
    return (ret);

  p += 28;

  memcpy (ssl->handshake->randbytes + 32, buf + 6, 32);

  debug_buf (3, "server hello, random bytes", buf + 6, 32);

  /*
   * Resume is 0  by default, see handshake_init().
   * It may be already set to 1 by ssl_parse_session_ticket_ext().
   * If not, try looking up session ID in our cache.
   */
  if (ssl->handshake->resume == 0 &&
      ssl->renegotiation == SSL_INITIAL_HANDSHAKE &&
      ssl->session_negotiate->length != 0 &&
      ssl->f_get_cache != NULL &&
      ssl->f_get_cache (ssl->p_get_cache, ssl->session_negotiate) == 0)
    {
      debug_msg (3, "session successfully restored from cache");
      ssl->handshake->resume = 1;
    }

  if (ssl->handshake->resume == 0)
    {
      /*
       * New session, create a new session id,
       * unless we're about to issue a session ticket
       */
      ssl->state++;

      ssl->session_negotiate->start = time (NULL);

      if (ssl->handshake->new_session_ticket != 0)
        {
          ssl->session_negotiate->length = n = 0;
          memset (ssl->session_negotiate->id, 0, 32);
        }
      else
        {
          ssl->session_negotiate->length = n = 32;
          if ((ret = ssl->f_rng (ssl->p_rng, ssl->session_negotiate->id,
                                 n)) != 0)
            return (ret);
        }
    }
  else
    {
      /*
       * Resuming a session
       */
      n = ssl->session_negotiate->length;
      ssl->state = SSL_SERVER_CHANGE_CIPHER_SPEC;

      if ((ret = _ntbtls_derive_keys (ssl)) != 0)
        {
          debug_ret (1, "ssl_derive_keys", ret);
          return (ret);
        }
    }

  /*
   *    38  .  38     session id length
   *    39  . 38+n    session id
   *   39+n . 40+n    chosen ciphersuite
   *   41+n . 41+n    chosen compression alg.
   *   42+n . 43+n    extensions length
   *   44+n . 43+n+m  extensions
   */
  *p++ = (unsigned char) ssl->session_negotiate->length;
  memcpy (p, ssl->session_negotiate->id, ssl->session_negotiate->length);
  p += ssl->session_negotiate->length;

  debug_msg (3, "server hello, session id len.: %d", n);
  debug_buf (3, "server hello, session id", buf + 39, n);
  debug_msg (3, "%s session has been resumed",
             ssl->handshake->resume ? "a" : "no");

  *p++ = (unsigned char) (ssl->session_negotiate->ciphersuite >> 8);
  *p++ = (unsigned char) (ssl->session_negotiate->ciphersuite);
  *p++ = (unsigned char) (ssl->session_negotiate->compression);

  debug_msg (3, "server hello, chosen ciphersuite: %s",
             ssl_get_ciphersuite_name (ssl->session_negotiate->ciphersuite));
  debug_msg (3, "server hello, compress alg.: 0x%02X",
             ssl->session_negotiate->compression);

  /*
   *  First write extensions, then the total length
   */
  write_srv_renegotiation_ext (ssl, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_srv_max_fragment_length_ext (ssl, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_srv_truncated_hmac_ext (ssl, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_srv_session_ticket_ext (ssl, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_srv_supported_point_formats_ext (ssl, p + 2 + ext_len, &olen);
  ext_len += olen;

  write_srv_alpn_ext (ssl, p + 2 + ext_len, &olen);
  ext_len += olen;

  debug_msg (3, "server hello, total extension length: %d", ext_len);

  if (ext_len > 0)
    {
      *p++ = (unsigned char) ((ext_len >> 8) & 0xFF);
      *p++ = (unsigned char) ((ext_len) & 0xFF);
      p += ext_len;
    }

  ssl->out_msglen = p - buf;
  ssl->out_msgtype = TLS_MSG_HANDSHAKE;
  ssl->out_msg[0] = TLS_HS_SERVER_HELLO;

  ret = ssl_write_record (ssl);

  debug_msg (2, "<= write server hello");

  return (ret);
}


static int
write_certificate_request (ntbtls_t ssl)
{
  int ret = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  const ssl_ciphersuite_t *suite =
    ssl->transform_negotiate->ciphersuite;
  size_t dn_size, total_dn_size;        /* excluding length bytes */
  size_t ct_len, sa_len;        /* including length bytes */
  unsigned char *buf, *p;
  const x509_crt *crt;

  debug_msg (2, "=> write certificate request");

  ssl->state++;

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_RSA_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_PSK ||
      ssl->authmode == SSL_VERIFY_NONE)
    {
      debug_msg (2, "<= skip write certificate request");
      return (0);
    }

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
  buf = ssl->out_msg;
  p = buf + 4;

  /*
   * Supported certificate types
   *
   *     ClientCertificateType certificate_types<1..2^8-1>;
   *     enum { (255) } ClientCertificateType;
   */
  ct_len = 0;

  p[1 + ct_len++] = SSL_CERT_TYPE_RSA_SIGN;
  p[1 + ct_len++] = SSL_CERT_TYPE_ECDSA_SIGN;

  p[0] = (unsigned char) ct_len++;
  p += ct_len;

  sa_len = 0;
  /*
   * Add signature_algorithms for verify (TLS 1.2)
   *
   *     SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
   *
   *     struct {
   *           HashAlgorithm hash;
   *           SignatureAlgorithm signature;
   *     } SignatureAndHashAlgorithm;
   *
   *     enum { (255) } HashAlgorithm;
   *     enum { (255) } SignatureAlgorithm;
   */
  if (ssl->minor_ver == SSL_MINOR_VERSION_3)
    {
      /*
       * Only use current running hash algorithm that is already required
       * for requested ciphersuite.
       */
      ssl->handshake->verify_sig_alg = SSL_HASH_SHA256;

      if (ssl->transform_negotiate->ciphersuite->mac ==
          POLARSSL_MD_SHA384)
        {
          ssl->handshake->verify_sig_alg = SSL_HASH_SHA384;
        }

      /*
       * Supported signature algorithms
       */
      p[2 + sa_len++] = ssl->handshake->verify_sig_alg;
      p[2 + sa_len++] = SSL_SIG_RSA;
      p[2 + sa_len++] = ssl->handshake->verify_sig_alg;
      p[2 + sa_len++] = SSL_SIG_ECDSA;

      p[0] = (unsigned char) (sa_len >> 8);
      p[1] = (unsigned char) (sa_len);
      sa_len += 2;
      p += sa_len;
    }

  /*
   * DistinguishedName certificate_authorities<0..2^16-1>;
   * opaque DistinguishedName<1..2^16-1>;
   */
  p += 2;
  crt = ssl->ca_chain;

  total_dn_size = 0;
  while (crt != NULL && crt->version != 0)
    {
      if (p - buf > 4096)
        break;

      dn_size = crt->subject_raw.len;
      *p++ = (unsigned char) (dn_size >> 8);
      *p++ = (unsigned char) (dn_size);
      memcpy (p, crt->subject_raw.p, dn_size);
      p += dn_size;

      debug_buf (3, "requested DN", p, dn_size);

      total_dn_size += 2 + dn_size;
      crt = crt->next;
    }

  ssl->out_msglen = p - buf;
  ssl->out_msgtype = TLS_MSG_HANDSHAKE;
  ssl->out_msg[0] = TLS_HS_CERTIFICATE_REQUEST;
  ssl->out_msg[4 + ct_len + sa_len] = (unsigned char) (total_dn_size >> 8);
  ssl->out_msg[5 + ct_len + sa_len] = (unsigned char) (total_dn_size);

  ret = ssl_write_record (ssl);

  debug_msg (2, "<= write certificate request");

  return (ret);
}


static int
ssl_get_ecdh_params_from_cert (ntbtls_t ssl)
{
  int ret;

  if (!pk_can_do (ssl_own_key (ssl), POLARSSL_PK_ECKEY))
    {
      debug_msg (1, "server key not ECDH capable");
      return gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);
    }

  if ((ret = ecdh_get_params (&ssl->handshake->ecdh_ctx,
                              pk_ec (*ssl_own_key (ssl)),
                              POLARSSL_ECDH_OURS)) != 0)
    {
      debug_ret (1, ("ecdh_get_params"), ret);
      return (ret);
    }

  return (0);
}


static int
write_server_key_exchange (ntbtls_t ssl)
{
  int ret;
  size_t n = 0;
  const ssl_ciphersuite_t *suite =
    ssl->transform_negotiate->ciphersuite;
  unsigned char *p = ssl->out_msg + 4;
  unsigned char *dig_signed = p;
  size_t dig_signed_len = 0, len;
  ((void) dig_signed);
  ((void) dig_signed_len);


  debug_msg (2, "=> write server key exchange");

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_RSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_RSA_PSK)
    {
      debug_msg (2, "<= skip write server key exchange");
      ssl->state++;
      return (0);
    }

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDH_RSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDH_ECDSA)
    {
      ssl_get_ecdh_params_from_cert (ssl);

      debug_msg (2, "<= skip write server key exchange");
      ssl->state++;
      return (0);
    }

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_PSK)
    {
      /* TODO: Support identity hints */
      *(p++) = 0x00;
      *(p++) = 0x00;

      n += 2;
    }

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_RSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK)
    {
      /*
       * Ephemeral DH parameters:
       *
       * struct {
       *     opaque dh_p<1..2^16-1>;
       *     opaque dh_g<1..2^16-1>;
       *     opaque dh_Ys<1..2^16-1>;
       * } ServerDHParams;
       */
      if ((ret = mpi_copy (&ssl->handshake->dhm_ctx.P, &ssl->dhm_P)) != 0 ||
          (ret = mpi_copy (&ssl->handshake->dhm_ctx.G, &ssl->dhm_G)) != 0)
        {
          debug_ret (1, "mpi_copy", ret);
          return (ret);
        }

      if ((ret = dhm_make_params (&ssl->handshake->dhm_ctx,
                                  (int) mpi_size (&ssl->handshake->dhm_ctx.P),
                                  p, &len, ssl->f_rng, ssl->p_rng)) != 0)
        {
          debug_ret (1, "dhm_make_params", ret);
          return (ret);
        }

      dig_signed = p;
      dig_signed_len = len;

      p += len;
      n += len;

      SSL_DEBUG_MPI (3, "DHM: X ", &ssl->handshake->dhm_ctx.X);
      SSL_DEBUG_MPI (3, "DHM: P ", &ssl->handshake->dhm_ctx.P);
      SSL_DEBUG_MPI (3, "DHM: G ", &ssl->handshake->dhm_ctx.G);
      SSL_DEBUG_MPI (3, "DHM: GX", &ssl->handshake->dhm_ctx.GX);
    }

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_PSK)
    {
      /*
       * Ephemeral ECDH parameters:
       *
       * struct {
       *     ECParameters curve_params;
       *     ECPoint      public;
       * } ServerECDHParams;
       */
      const ecp_curve_info **curve = NULL;
      const ecp_group_id *gid;

      /* Match our preference list against the offered curves */
      for (gid = ssl->curve_list; *gid != POLARSSL_ECP_DP_NONE; gid++)
        for (curve = ssl->handshake->curves; *curve != NULL; curve++)
          if ((*curve)->grp_id == *gid)
            goto curve_matching_done;

    curve_matching_done:
      if (*curve == NULL)
        {
          debug_msg (1, "no matching curve for ECDHE");
          return gpg_error (GPG_ERR_NO_CIPHER)
        }

      debug_msg (2, "ECDHE curve: %s", (*curve)->name);

      if ((ret = ecp_use_known_dp (&ssl->handshake->ecdh_ctx.grp,
                                   (*curve)->grp_id)) != 0)
        {
          debug_ret (1, "ecp_use_known_dp", ret);
          return (ret);
        }

      // FIXME:
      /* assert (n <= TLS_MAX_CONTENT_LEN); */
      /* if ((ret = ecdh_make_params (&ssl->handshake->ecdh_ctx, &len, */
      /*                              p, TLS_MAX_CONTENT_LEN - n, */
      /*                              ssl->f_rng, ssl->p_rng)) != 0) */
      /*   { */
      /*     debug_ret (1, "ecdh_make_params", ret); */
      /*     return (ret); */
      /*   } */

      dig_signed = p;
      dig_signed_len = len;

      p += len;
      n += len;

      SSL_DEBUG_ECP (3, "ECDH: Q ", &ssl->handshake->ecdh_ctx.Q);
    }

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_RSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA)
    {
      size_t signature_len = 0;
      unsigned int hashlen = 0;
      unsigned char hash[64];
      md_algo_t md_alg = 0;

      /*
       * Choose hash algorithm. NONE means MD5 + SHA1 here.
       */
      if (ssl->minor_ver == SSL_MINOR_VERSION_3)
        {
          md_alg = _ntbtls_md_alg_from_hash (ssl->handshake->sig_alg);
          if (!md_alg)
            {
              debug_bug ();
              return gpg_error (GPG_ERR_INTERNAL);
            }
        }
      else
        {
          md_alg = POLARSSL_MD_NONE;
        }

      /*
       * Compute the hash to be signed
       */
      if (md_alg != POLARSSL_MD_NONE)
        {
          md_context_t ctx;
          const md_info_t *md_info = md_info_from_type (md_alg);

          md_init (&ctx);

          /* Info from md_alg will be used instead */
          hashlen = 0;

          /*
           * digitally-signed struct {
           *     opaque client_random[32];
           *     opaque server_random[32];
           *     ServerDHParams params;
           * };
           */
          if ((ret = md_init_ctx (&ctx, md_info)) != 0)
            {
              debug_ret (1, "md_init_ctx", ret);
              return (ret);
            }

          md_starts (&ctx);
          md_update (&ctx, ssl->handshake->randbytes, 64);
          md_update (&ctx, dig_signed, dig_signed_len);
          md_finish (&ctx, hash);
          md_free (&ctx);
        }
      else
        {
          debug_bug ();
          return gpg_error (GPG_ERR_INTERNAL);
        }

      debug_buf (3, "parameters hash", hash, hashlen != 0 ? hashlen :
                 (unsigned int) (md_info_from_type (md_alg))->size);

      /*
       * Make the signature
       */
      if (ssl_own_key (ssl) == NULL)
        {
          debug_msg (1, "got no private key");
          return gpg_error (GPG_ERR_NO_SECKEY);
        }

      if (ssl->minor_ver == SSL_MINOR_VERSION_3)
        {
          *(p++) = ssl->handshake->sig_alg;
          *(p++) = 0;//FIXME: ssl_sig_from_pk (ssl_own_key (ssl));

          n += 2;
        }

      if ((ret = pk_sign (ssl_own_key (ssl), md_alg, hash, hashlen,
                          p + 2, &signature_len,
                          ssl->f_rng, ssl->p_rng)) != 0)
        {
          debug_ret (1, "pk_sign", ret);
          return (ret);
        }

      *(p++) = (unsigned char) (signature_len >> 8);
      *(p++) = (unsigned char) (signature_len);
      n += 2;

      debug_buf (3, "my signature", p, signature_len);

      p += signature_len;
      n += signature_len;
    }

  ssl->out_msglen = 4 + n;
  ssl->out_msgtype = TLS_MSG_HANDSHAKE;
  ssl->out_msg[0] = TLS_HS_SERVER_KEY_EXCHANGE;

  ssl->state++;

  if ((ret = ssl_write_record (ssl)) != 0)
    {
      debug_ret (1, "ssl_write_record", ret);
      return (ret);
    }

  debug_msg (2, "<= write server key exchange");

  return (0);
}

static int
write_server_hello_done (ntbtls_t ssl)
{
  int ret;

  debug_msg (2, "=> write server hello done");

  ssl->out_msglen = 4;
  ssl->out_msgtype = TLS_MSG_HANDSHAKE;
  ssl->out_msg[0] = TLS_HS_SERVER_HELLO_DONE;

  ssl->state++;

  if ((ret = ssl_write_record (ssl)) != 0)
    {
      debug_ret (1, "ssl_write_record", ret);
      return (ret);
    }

  debug_msg (2, "<= write server hello done");

  return (0);
}


static int
ssl_parse_client_dh_public (ntbtls_t ssl, unsigned char **p,
                            const unsigned char *end)
{
  int ret = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  size_t n;

  /*
   * Receive G^Y mod P, premaster = (G^Y)^X mod P
   */
  if (*p + 2 > end)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  n = buf16_to_size_t (*p);
  *p += 2;

  if (*p + n > end)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  if ((ret = dhm_read_public (&ssl->handshake->dhm_ctx, *p, n)) != 0)
    {
      debug_ret (1, "dhm_read_public", ret);
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  *p += n;

  SSL_DEBUG_MPI (3, "DHM: GY", &ssl->handshake->dhm_ctx.GY);

  return (ret);
}


static int
ssl_parse_encrypted_pms (ntbtls_t ssl,
                         const unsigned char *p,
                         const unsigned char *end, size_t pms_offset)
{
  int ret;
  size_t len = pk_get_len (ssl_own_key (ssl));
  unsigned char *pms = ssl->handshake->premaster + pms_offset;

  if (!pk_can_do (ssl_own_key (ssl), POLARSSL_PK_RSA))
    {
      debug_msg (1, "got no RSA private key");
      return gpg_error (GPG_ERR_NO_SECKEY);
    }

  /*
   * Decrypt the premaster using own private RSA key
   */
  if (ssl->minor_ver != SSL_MINOR_VERSION_0)
    {
      if (*p++ != ((len >> 8) & 0xFF) || *p++ != ((len) & 0xFF))
        {
          debug_msg (1, "bad client key exchange message");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }
    }

  if (p + len != end)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  ret = pk_decrypt (ssl_own_key (ssl), p, len,
                    pms, &ssl->handshake->pmslen,
                    sizeof (ssl->handshake->premaster) - pms_offset,
                    ssl->f_rng, ssl->p_rng);

  if (ret != 0 || ssl->handshake->pmslen != 48 ||
      pms[0] != ssl->handshake->max_major_ver ||
      pms[1] != ssl->handshake->max_minor_ver)
    {
      debug_msg (1, "bad client key exchange message");

      /*
       * Protection against Bleichenbacher's attack:
       * invalid PKCS#1 v1.5 padding must not cause
       * the connection to end immediately; instead,
       * send a bad_record_mac later in the handshake.
       */
      ssl->handshake->pmslen = 48;

      ret = ssl->f_rng (ssl->p_rng, pms, ssl->handshake->pmslen);
      if (ret != 0)
        return (ret);
    }

  return (ret);
}


static int
ssl_parse_client_psk_identity (ntbtls_t ssl, unsigned char **p,
                               const unsigned char *end)
{
  int ret = 0;
  size_t n;

  if (ssl->f_psk == NULL &&
      (ssl->psk == NULL || ssl->psk_identity == NULL ||
       ssl->psk_identity_len == 0 || ssl->psk_len == 0))
    {
      debug_msg (1, "got no pre-shared key");
      return gpg_error (GPG_ERR_NO_SECKEY);
    }

  /*
   * Receive client pre-shared key identity name
   */
  if (*p + 2 > end)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  n = buf16_to_size_t (*p);
  *p += 2;

  if (n < 1 || n > 65535 || *p + n > end)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  if (ssl->f_psk != NULL)
    {
      if (ssl->f_psk (ssl->p_psk, ssl, *p, n) != 0)
        ret = gpg_error (GPG_ERR_UNKNOWN_IDENTITY);
    }
  else
    {
      /* Identity is not a big secret since clients send it in the clear,
       * but treat it carefully anyway, just in case */
      if (n != ssl->psk_identity_len ||
          memcmpct (ssl->psk_identity, *p, n))
        {
          ret = gpg_error (GPG_ERR_UNKNOWN_IDENTITY);
        }
    }

  if (gpg_err_code (ret) == GPG_ERR_UNKNOWN_IDENTITY)
    {
      debug_buf (3, "Unknown PSK identity", *p, n);
      if ((ret = ntbtls_send_alert_message (ssl,
                                         TLS_ALERT_LEVEL_FATAL,
                                         TLS_ALERT_MSG_UNKNOWN_PSK_IDENTITY))
          != 0)
        {
          return (ret);
        }

      return gpg_error (GPG_ERR_UNKNOWN_IDENTITY);
    }

  *p += n;

  return (0);
}


static int
read_client_key_exchange (ntbtls_t ssl)
{
  int ret;
  const ssl_ciphersuite_t *suite;

  suite = ssl->transform_negotiate->ciphersuite;

  debug_msg (2, "=> parse client key exchange");

  if ((ret = _ntbtls_read_record (ssl)) != 0)
    {
      debug_ret (1, "read_record", ret);
      return (ret);
    }

  if (ssl->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  if (ssl->in_msg[0] != TLS_HS_CLIENT_KEY_EXCHANGE)
    {
      debug_msg (1, "bad client key exchange message");
      return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
    }

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_RSA)
    {
      unsigned char *p = ssl->in_msg + 4;
      unsigned char *end = ssl->in_msg + ssl->in_hslen;

      if ((ret = ssl_parse_client_dh_public (ssl, &p, end)) != 0)
        {
          debug_ret (1, ("ssl_parse_client_dh_public"), ret);
          return (ret);
        }

      if (p != end)
        {
          debug_msg (1, "bad client key exchange");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      ssl->handshake->pmslen = POLARSSL_PREMASTER_SIZE;

      if ((ret = dhm_calc_secret (&ssl->handshake->dhm_ctx,
                                  ssl->handshake->premaster,
                                  &ssl->handshake->pmslen,
                                  ssl->f_rng, ssl->p_rng)) != 0)
        {
          debug_ret (1, "dhm_calc_secret", ret);
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      SSL_DEBUG_MPI (3, "DHM: K ", &ssl->handshake->dhm_ctx.K);
    }
  else if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA
        || suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA
        || suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDH_RSA
        || suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDH_ECDSA)
    {
      if ((ret = ecdh_read_public (&ssl->handshake->ecdh_ctx,
                                   ssl->in_msg + 4, ssl->in_hslen - 4)) != 0)
        {
          debug_ret (1, "ecdh_read_public", ret);
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      SSL_DEBUG_ECP (3, "ECDH: Qp ", &ssl->handshake->ecdh_ctx.Qp);

      if ((ret = ecdh_calc_secret (&ssl->handshake->ecdh_ctx,
                                   &ssl->handshake->pmslen,
                                   ssl->handshake->premaster,
                                   POLARSSL_MPI_MAX_SIZE,
                                   ssl->f_rng, ssl->p_rng)) != 0)
        {
          debug_ret (1, "ecdh_calc_secret", ret);
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      SSL_DEBUG_MPI (3, "ECDH: z  ", &ssl->handshake->ecdh_ctx.z);
    }
  else if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_PSK)
    {
      unsigned char *p = ssl->in_msg + 4;
      unsigned char *end = ssl->in_msg + ssl->in_hslen;

      if ((ret = ssl_parse_client_psk_identity (ssl, &p, end)) != 0)
        {
          debug_ret (1, ("ssl_parse_client_psk_identity"), ret);
          return (ret);
        }

      if (p != end)
        {
          debug_msg (1, "bad client key exchange");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      if ((ret = ssl_psk_derive_premaster (ssl,
                                           suite->key_exchange)) !=
          0)
        {
          debug_ret (1, "ssl_psk_derive_premaster", ret);
          return (ret);
        }
    }
  else if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_RSA_PSK)
    {
      unsigned char *p = ssl->in_msg + 4;
      unsigned char *end = ssl->in_msg + ssl->in_hslen;

      if ((ret = ssl_parse_client_psk_identity (ssl, &p, end)) != 0)
        {
          debug_ret (1, ("ssl_parse_client_psk_identity"), ret);
          return (ret);
        }

      if ((ret = ssl_parse_encrypted_pms (ssl, p, end, 2)) != 0)
        {
          debug_ret (1, ("ssl_parse_encrypted_pms"), ret);
          return (ret);
        }

      if ((ret = ssl_psk_derive_premaster (ssl,
                                           suite->key_exchange)) !=
          0)
        {
          debug_ret (1, "ssl_psk_derive_premaster", ret);
          return (ret);
        }
    }
  else if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK)
    {
      unsigned char *p = ssl->in_msg + 4;
      unsigned char *end = ssl->in_msg + ssl->in_hslen;

      if ((ret = ssl_parse_client_psk_identity (ssl, &p, end)) != 0)
        {
          debug_ret (1, ("ssl_parse_client_psk_identity"), ret);
          return (ret);
        }
      if ((ret = ssl_parse_client_dh_public (ssl, &p, end)) != 0)
        {
          debug_ret (1, ("ssl_parse_client_dh_public"), ret);
          return (ret);
        }

      if (p != end)
        {
          debug_msg (1, "bad client key exchange");
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      if ((ret = ssl_psk_derive_premaster (ssl,
                                           suite->key_exchange)) !=
          0)
        {
          debug_ret (1, "ssl_psk_derive_premaster", ret);
          return (ret);
        }
    }
  else if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_PSK)
    {
      unsigned char *p = ssl->in_msg + 4;
      unsigned char *end = ssl->in_msg + ssl->in_hslen;

      if ((ret = ssl_parse_client_psk_identity (ssl, &p, end)) != 0)
        {
          debug_ret (1, ("ssl_parse_client_psk_identity"), ret);
          return (ret);
        }

      if ((ret = ecdh_read_public (&ssl->handshake->ecdh_ctx,
                                   p, end - p)) != 0)
        {
          debug_ret (1, "ecdh_read_public", ret);
          return gpg_error (GPG_ERR_BAD_HS_CLIENT_KEX);
        }

      SSL_DEBUG_ECP (3, "ECDH: Qp ", &ssl->handshake->ecdh_ctx.Qp);

      if ((ret = ssl_psk_derive_premaster (ssl,
                                           suite->key_exchange)) !=
          0)
        {
          debug_ret (1, "ssl_psk_derive_premaster", ret);
          return (ret);
        }
    }
  else if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_RSA)
    {
      if ((ret = ssl_parse_encrypted_pms (ssl,
                                          ssl->in_msg + 4,
                                          ssl->in_msg + ssl->in_hslen,
                                          0)) != 0)
        {
          debug_ret (1, ("ssl_parse_parse_encrypted_pms_secret"), ret);
          return (ret);
        }
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  if ((ret = _ntbtls_derive_keys (ssl)) != 0)
    {
      debug_ret (1, "ssl_derive_keys", ret);
      return (ret);
    }

  ssl->state++;

  debug_msg (2, "<= parse client key exchange");

  return (0);
}


static int
read_certificate_verify (ntbtls_t ssl)
{
  int ret = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  size_t sa_len, sig_len;
  unsigned char hash[48];
  unsigned char *hash_start = hash;
  size_t hashlen;
  pk_algo_t pk_alg;
  md_algo_t md_alg;
  const ssl_ciphersuite_t *suite =
    ssl->transform_negotiate->ciphersuite;

  debug_msg (2, "=> parse certificate verify");

  if (suite->key_exchange == POLARSSL_KEY_EXCHANGE_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_RSA_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_PSK ||
      suite->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK)
    {
      debug_msg (2, "<= skip parse certificate verify");
      ssl->state++;
      return (0);
    }

  if (ssl->session_negotiate->peer_cert == NULL)
    {
      debug_msg (2, "<= skip parse certificate verify");
      ssl->state++;
      return (0);
    }

  ssl->handshake->calc_verify (ssl, hash);

  if ((ret = _ntbtls_read_record (ssl)) != 0)
    {
      debug_ret (1, "read_record", ret);
      return (ret);
    }

  ssl->state++;

  if (ssl->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad certificate verify message");
      return gpg_error (GPG_ERR_BAD_HS_CERT_VER);
    }

  if (ssl->in_msg[0] != TLS_HS_CERTIFICATE_VERIFY)
    {
      debug_msg (1, "bad certificate verify message");
      return gpg_error (GPG_ERR_BAD_HS_CERT_VER);
    }

  /*
   *     0  .   0   handshake type
   *     1  .   3   handshake length
   *     4  .   5   sig alg (TLS 1.2 only)
   *    4+n .  5+n  signature length (n = sa_len)
   *    6+n . 6+n+m signature (m = sig_len)
   */

  if (ssl->minor_ver == SSL_MINOR_VERSION_3)
    {
      sa_len = 2;

      /*
       * Hash
       */
      if (ssl->in_msg[4] != ssl->handshake->verify_sig_alg)
        {
          debug_msg (1, "peer not adhering to requested sig_alg"
                     " for verify message");
          return gpg_error (GPG_ERR_BAD_HS_CERT_VER);
        }

      md_alg = ssl_md_alg_from_hash (ssl->handshake->verify_sig_alg);

      /* Info from md_alg will be used instead */
      hashlen = 0;

      /*
       * Signature
       */
      pk_alg = _ntbtls_pk_alg_from_sig (ssl->in_msg[5]);
      if (!pk_alg)
        {
          debug_msg (1, "peer not adhering to requested sig_alg"
                     " for verify message");
          return gpg_error (GPG_ERR_BAD_HS_CERT_VER);
        }

      /*
       * Check the certificate's key type matches the signature alg
       */
      if (!pk_can_do (&ssl->session_negotiate->peer_cert->pk, pk_alg))
        {
          debug_msg (1, "sig_alg doesn't match cert key");
          return gpg_error (GPG_ERR_BAD_HS_CERT_VER);
        }
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  sig_len = buf16_to_size_t (ssl->in_msg + 4 + sa_len);

  if (sa_len + sig_len + 6 != ssl->in_hslen)
    {
      debug_msg (1, "bad certificate verify message");
      return gpg_error (GPG_ERR_BAD_HS_CERT_VER);
    }

  if ((ret = pk_verify (&ssl->session_negotiate->peer_cert->pk,
                        md_alg, hash_start, hashlen,
                        ssl->in_msg + 6 + sa_len, sig_len)) != 0)
    {
      debug_ret (1, "pk_verify", ret);
      return (ret);
    }

  debug_msg (2, "<= parse certificate verify");

  return (ret);
}


static int
write_new_session_ticket (ntbtls_t ssl)
{
  int ret;
  size_t tlen;
  uint32_t lifetime = (uint32_t) ssl->ticket_lifetime;

  debug_msg (2, "=> write new session ticket");

  ssl->out_msgtype = TLS_MSG_HANDSHAKE;
  ssl->out_msg[0] = TLS_HS_NEW_SESSION_TICKET;

  /*
   * struct {
   *     uint32 ticket_lifetime_hint;
   *     opaque ticket<0..2^16-1>;
   * } NewSessionTicket;
   *
   * 4  .  7   ticket_lifetime_hint (0 = unspecified)
   * 8  .  9   ticket_len (n)
   * 10 .  9+n ticket content
   */

  ssl->out_msg[4] = (lifetime >> 24) & 0xFF;
  ssl->out_msg[5] = (lifetime >> 16) & 0xFF;
  ssl->out_msg[6] = (lifetime >> 8) & 0xFF;
  ssl->out_msg[7] = (lifetime) & 0xFF;

  if ((ret = ssl_write_ticket (ssl, &tlen)) != 0)
    {
      debug_ret (1, "ssl_write_ticket", ret);
      tlen = 0;
    }

  ssl->out_msg[8] = (unsigned char) ((tlen >> 8) & 0xFF);
  ssl->out_msg[9] = (unsigned char) ((tlen) & 0xFF);

  ssl->out_msglen = 10 + tlen;

  /*
   * Morally equivalent to updating ssl->state, but NewSessionTicket and
   * ChangeCipherSpec share the same state.
   */
  ssl->handshake->new_session_ticket = 0;

  if ((ret = ssl_write_record (ssl)) != 0)
    {
      debug_ret (1, "ssl_write_record", ret);
      return (ret);
    }

  debug_msg (2, "<= write new session ticket");

  return (0);
}


/*
 * SSL handshake -- server side -- single step
 */
gpg_error_t
_ntbtls_handshake_server_step (ntbtls_t tls)
{
  gpg_error_t err;

  if (tls->state == TLS_HANDSHAKE_OVER)
    return gpg_error (GPG_ERR_INV_STATE)

  debug_msg (2, "server state: %d (%s)",
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
       *  <==   ClientHello
       */
    case TLS_CLIENT_HELLO:
      err = read_client_hello (tls);
      break;

      /*
       *  ==>   ServerHello
       *        Certificate
       *      ( ServerKeyExchange  )
       *      ( CertificateRequest )
       *        ServerHelloDone
       */
    case TLS_SERVER_HELLO:
      err = write_server_hello (tls);
      break;

    case TLS_SERVER_CERTIFICATE:
      err = _ntbtls_write_certificate (tls);
      break;

    case TLS_SERVER_KEY_EXCHANGE:
      err = write_server_key_exchange (tls);
      break;

    case TLS_CERTIFICATE_REQUEST:
      err = write_certificate_request (tls);
      break;

    case TLS_SERVER_HELLO_DONE:
      err = write_server_hello_done (tls);
      break;

      /*
       *  <== ( Certificate/Alert  )
       *        ClientKeyExchange
       *      ( CertificateVerify  )
       *        ChangeCipherSpec
       *        Finished
       */
    case TLS_CLIENT_CERTIFICATE:
      err = _ntbtls_read_certificate (tls);
      break;

    case TLS_CLIENT_KEY_EXCHANGE:
      err = read_client_key_exchange (tls);
      break;

    case TLS_CERTIFICATE_VERIFY:
      err = read_certificate_verify (tls);
      break;

    case TLS_CLIENT_CHANGE_CIPHER_SPEC:
      err = _ntbtls_read_change_cipher_spec (tls);
      break;

    case TLS_CLIENT_FINISHED:
      err = _ntbtls_read_finished (tls);
      break;

      /*
       *  ==> ( NewSessionTicket )
       *        ChangeCipherSpec
       *        Finished
       */
    case TLS_SERVER_CHANGE_CIPHER_SPEC:
      if (tls->handshake->new_session_ticket)
        err = write_new_session_ticket (tls);
      else
        err = _ntbtls_write_change_cipher_spec (tls);
      break;

    case TLS_SERVER_FINISHED:
      err = _ntbtls_write_finished (tls);
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
