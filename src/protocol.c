/* protocol.c - TLS 1.2 protocol implementation
 * Copyright (C) 2006-2014, Brainspark B.V.
 * Copyright (C) 2014, 2017 g10 code GmbH
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
#include <errno.h>

#include "ntbtls-int.h"
#include "ciphersuites.h"



static void transform_deinit (transform_t transform);
static void session_deinit (session_t session);
static void handshake_params_deinit (handshake_params_t handshake);
static void ticket_keys_deinit (ticket_keys_t tkeys);

static void update_checksum_sha256 (ntbtls_t, const unsigned char *, size_t);
static void calc_verify_tls_sha256 (ntbtls_t, unsigned char *);
static void calc_finished_tls_sha256 (ntbtls_t, unsigned char *, int);
static void calc_verify_tls_sha384 (ntbtls_t, unsigned char *);
static void calc_finished_tls_sha384 (ntbtls_t, unsigned char *, int);


static const char *
alert_msg_to_string (int msgno)
{
  switch (msgno)
    {
    case TLS_ALERT_MSG_CLOSE_NOTIFY:       return "close notify";
    case TLS_ALERT_MSG_UNEXPECTED_MESSAGE: return "unexpected msg";
    case TLS_ALERT_MSG_BAD_RECORD_MAC:     return "bad record mac ";
    case TLS_ALERT_MSG_DECRYPTION_FAILED:  return "decryption failed";
    case TLS_ALERT_MSG_RECORD_OVERFLOW:    return "record overflow";
    case TLS_ALERT_MSG_DECOMPRESSION_FAILURE:return "decompression failure";
    case TLS_ALERT_MSG_HANDSHAKE_FAILURE:  return "handshake failure";
    case TLS_ALERT_MSG_NO_CERT:            return "no cert";
    case TLS_ALERT_MSG_BAD_CERT:           return "bad cert";
    case TLS_ALERT_MSG_UNSUPPORTED_CERT:   return "unsupported cert";
    case TLS_ALERT_MSG_CERT_REVOKED:       return "cert revoked";
    case TLS_ALERT_MSG_CERT_EXPIRED:       return "cert expired";
    case TLS_ALERT_MSG_CERT_UNKNOWN:       return "cert unknown";
    case TLS_ALERT_MSG_ILLEGAL_PARAMETER:  return "illegal param";
    case TLS_ALERT_MSG_UNKNOWN_CA:         return "unknown CA";
    case TLS_ALERT_MSG_ACCESS_DENIED:      return "access denied";
    case TLS_ALERT_MSG_DECODE_ERROR:       return "decode error";
    case TLS_ALERT_MSG_DECRYPT_ERROR:      return "decrypt error";
    case TLS_ALERT_MSG_EXPORT_RESTRICTION: return "export restriction";
    case TLS_ALERT_MSG_PROTOCOL_VERSION:   return "protocol version";
    case TLS_ALERT_MSG_INSUFFICIENT_SECURITY:return "insufficient security";
    case TLS_ALERT_MSG_INTERNAL_ERROR:     return "internal error";
    case TLS_ALERT_MSG_USER_CANCELED:      return "user canceled";
    case TLS_ALERT_MSG_NO_RENEGOTIATION:   return "no renegotiation";
    case TLS_ALERT_MSG_UNSUPPORTED_EXT:    return "unsupported extenstion";
    case TLS_ALERT_MSG_UNRECOGNIZED_NAME:  return "unsupported name";
    case TLS_ALERT_MSG_UNKNOWN_PSK_IDENTITY:   return "unknown PSK identify";
    case TLS_ALERT_MSG_NO_APPLICATION_PROTOCOL:return "no application protocol";
    default: return "[?]";
    }
}



/*
 * Convert max_fragment_length codes to length.
 * RFC 6066 says:
 *    enum{
 *        2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
 *    } MaxFragmentLength;
 * and we add 0 -> extension unused
 */
static unsigned int mfl_code_to_length[] =
  {
    TLS_MAX_CONTENT_LEN,          /* TLS_MAX_FRAG_LEN_NONE */
    512,                          /* TLS_MAX_FRAG_LEN_512  */
    1024,                         /* TLS_MAX_FRAG_LEN_1024 */
    2048,                         /* TLS_MAX_FRAG_LEN_2048 */
    4096                          /* TLS_MAX_FRAG_LEN_4096 */
  };


/* Return true is MODE is an AEAD mode.  */
static int
is_aead_mode (cipher_mode_t mode)
{
  switch (mode)
    {
    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_CCM:
      return 1;
    default:
      return 0;
    }
}


const char *
_ntbtls_state2str (tls_state_t state)
{
  const char *s = "?";

  switch (state)
    {
    case TLS_HELLO_REQUEST:             s = "hello_request"; break;
    case TLS_CLIENT_HELLO:              s = "client_hello"; break;
    case TLS_SERVER_HELLO:              s = "server_hello"; break;
    case TLS_SERVER_CERTIFICATE:        s = "server_certificate"; break;
    case TLS_SERVER_KEY_EXCHANGE:       s = "server_key_exchange"; break;
    case TLS_CERTIFICATE_REQUEST:       s = "certificate_request"; break;
    case TLS_SERVER_HELLO_DONE:         s = "server_hello_done"; break;
    case TLS_CLIENT_CERTIFICATE:        s = "client_certificate"; break;
    case TLS_CLIENT_KEY_EXCHANGE:       s = "client_key_exchange"; break;
    case TLS_CERTIFICATE_VERIFY:        s = "certificate_verify"; break;
    case TLS_CLIENT_CHANGE_CIPHER_SPEC: s = "client_change_cipher_spec"; break;
    case TLS_CLIENT_FINISHED:           s = "client_finished"; break;
    case TLS_SERVER_CHANGE_CIPHER_SPEC: s = "server_change_cipher_spec"; break;
    case TLS_SERVER_FINISHED:           s = "server_finished"; break;
    case TLS_FLUSH_BUFFERS:             s = "flush_buffers"; break;
    case TLS_HANDSHAKE_WRAPUP:          s = "handshake_wrapup"; break;
    case TLS_HANDSHAKE_OVER:            s = "handshake_over"; break;
    case TLS_SERVER_NEW_SESSION_TICKET: s = "server_new_session_tickets"; break;
    }
  return s;
}



static gpg_error_t
session_copy (session_t dst, const session_t src)
{
  session_deinit (dst);
  memcpy (dst, src, sizeof *src);

  if (src->peer_chain)
    {
      /* int ret; */

      //FIXME: Use libksba
      /* dst->peer_cert = malloc (sizeof *dst->peer_cert); */
      /* if (!dst->peer_cert) */
      /*   return gpg_error_from_syserror (); */

      /* x509_crt_init (dst->peer_cert); */

      /* if ((ret = x509_crt_parse_der (dst->peer_cert, src->peer_cert->raw.p, */
      /*                                src->peer_cert->raw.len)) != 0) */
      /*   { */
      /*     free (dst->peer_cert); */
      /*     dst->peer_cert = NULL; */
      /*     return (ret); */
      /*   } */
    }

  if (src->ticket)
    {
      dst->ticket = malloc (src->ticket_len);
      if (!dst->ticket)
        return gpg_error_from_syserror ();

      memcpy (dst->ticket, src->ticket, src->ticket_len);
    }

  return 0;
}


/*
 * output = HMAC-SHA-NNN( hmac key, input buffer )
 *
 * The used algorithm depends on OUTPUTSIZE which is expected in bytes.
 */
static gpg_error_t
sha_hmac (const unsigned char *key, size_t keylen,
          const unsigned char *input, size_t inputlen,
          unsigned char *output, int outputsize)
{
  gpg_error_t err;
  gcry_mac_hd_t hd;
  size_t macoutlen;
  int algo;

  switch (outputsize)
    {
    case 32: algo = GCRY_MAC_HMAC_SHA256; break;
    case 48: algo = GCRY_MAC_HMAC_SHA384; break;
    case 64: algo = GCRY_MAC_HMAC_SHA512; break;
    default: return gpg_error (GPG_ERR_MAC_ALGO);
    }

  err = gcry_mac_open (&hd, algo, 0, NULL);
  if (!err)
    {
      err = gcry_mac_setkey (hd, key, keylen);
      if (!err)
        {
          err = gcry_mac_write (hd, input, inputlen);
          if (!err)
            {
              macoutlen = outputsize;
              err = gcry_mac_read (hd, output, &macoutlen);
            }
        }
      gcry_mac_close (hd);
    }
  return err;
}


/*
 * Key material generation
 */

static gpg_error_t
do_tls_prf (const unsigned char *secret, size_t slen,
            const char *label,
            const unsigned char *random, size_t rlen,
            unsigned char *dstbuf, size_t dlen,
            size_t hashlen)
{
  gpg_error_t err;
  size_t nb;
  size_t i, j, k;
  unsigned char tmp[128];
  unsigned char h_i[64];

  if (sizeof (tmp) < hashlen + strlen (label) + rlen)
    return gpg_error (GPG_ERR_INV_ARG);

  nb = strlen (label);
  memcpy (tmp + hashlen, label, nb);
  memcpy (tmp + hashlen + nb, random, rlen);
  nb += rlen;

  /*
   * Compute P_<hash>(secret, label + random)[0..dlen]
   */
  err = sha_hmac (secret, slen, tmp + hashlen, nb, tmp, hashlen);
  if (err)
    return err;

  for (i = 0; i < dlen; i += hashlen)
    {
      err = sha_hmac (secret, slen, tmp, hashlen + nb, h_i, hashlen);
      if (err)
        return err;
      err = sha_hmac (secret, slen, tmp, hashlen, tmp, hashlen);
      if (err)
        return err;

      k = (i + hashlen > dlen) ? dlen % hashlen : hashlen;

      for (j = 0; j < k; j++)
        dstbuf[i + j] = h_i[j];
    }

  wipememory (tmp, sizeof (tmp));
  wipememory (h_i, hashlen);

  return 0;
}


static gpg_error_t
tls_prf_sha256 (const unsigned char *secret, size_t slen,
                const char *label,
                const unsigned char *random, size_t rlen,
                unsigned char *dstbuf, size_t dlen)
{
  return do_tls_prf (secret, slen, label, random, rlen, dstbuf, dlen, 32);
}


static gpg_error_t
tls_prf_sha384 (const unsigned char *secret, size_t slen,
                const char *label,
                const unsigned char *random, size_t rlen,
                unsigned char *dstbuf, size_t dlen)
{
  return do_tls_prf (secret, slen, label, random, rlen, dstbuf, dlen, 48);
}


gpg_error_t
_ntbtls_derive_keys (ntbtls_t tls)
{
  gpg_error_t err;
  unsigned char tmp[64];
  unsigned char keyblk[256];
  unsigned char *key1;
  unsigned char *key2;
  unsigned char *mac_enc;
  unsigned char *mac_dec;
  size_t iv_copy_len;
  cipher_algo_t cipher;
  cipher_mode_t ciphermode;
  mac_algo_t mac;
  session_t session = tls->session_negotiate;
  transform_t transform = tls->transform_negotiate;
  handshake_params_t handshake = tls->handshake;

  debug_msg (2, "derive keys");

  if (tls->minor_ver != TLS_MINOR_VERSION_3)
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  cipher = _ntbtls_ciphersuite_get_cipher (transform->ciphersuite,
                                           &ciphermode);
  if (!cipher || !ciphermode)
    {
      debug_msg (1, "cipher algo not found");
      return gpg_error (GPG_ERR_INV_ARG);
    }

  mac = _ntbtls_ciphersuite_get_mac (transform->ciphersuite);
  if (!mac)
    {
      debug_msg (1, "mac algo not found");
      return gpg_error (GPG_ERR_INV_ARG);
    }

  /*
   * Set appropriate PRF function and other TLS functions
   */
  if (mac == GCRY_MAC_HMAC_SHA384)
    {
      handshake->tls_prf = tls_prf_sha384;
      handshake->calc_verify = calc_verify_tls_sha384;
      handshake->calc_finished = calc_finished_tls_sha384;
    }
  else
    {
      handshake->tls_prf = tls_prf_sha256;
      handshake->calc_verify = calc_verify_tls_sha256;
      handshake->calc_finished = calc_finished_tls_sha256;
    }

  /*
   * TLSv1+:
   *   master = PRF( premaster, "master secret", randbytes )[0..47]
   */
  if (!handshake->resume)
    {
      debug_buf (3, "premaster secret",
                 handshake->premaster, handshake->pmslen);

      handshake->tls_prf (handshake->premaster, handshake->pmslen,
                          "master secret",
                          handshake->randbytes, 64, session->master, 48);

      wipememory (handshake->premaster, sizeof (handshake->premaster));
    }
  else
    debug_msg (3, "no premaster (session resumed)");

  /*
   * Swap the client and server random values.
   */
  memcpy (tmp, handshake->randbytes, 64);
  memcpy (handshake->randbytes, tmp + 32, 32);
  memcpy (handshake->randbytes + 32, tmp, 32);
  wipememory (tmp, sizeof (tmp));

  /*
   *  TLSv1:
   *    key block = PRF( master, "key expansion", randbytes )
   */
  handshake->tls_prf (session->master, 48,
                      "key expansion",
                      handshake->randbytes, 64, keyblk, 256);

  debug_msg (3, "ciphersuite = %s",
             _ntbtls_ciphersuite_get_name (session->ciphersuite));
  debug_buf (3, "master secret", session->master, 48);
  debug_buf (4, "random bytes", handshake->randbytes, 64);
  debug_buf (4, "key block", keyblk, 256);

  wipememory (handshake->randbytes, sizeof (handshake->randbytes));

  /*
   * Determine the appropriate key, IV and MAC length.
   */

  transform->keylen = gcry_cipher_get_algo_keylen (cipher);
  /* FIXME: Check that KEYLEN has an upper bound.
            2015-06-23 wk: Why? */

  if (is_aead_mode (ciphermode))
    {
      transform->maclen = 0;

      transform->ivlen = 12;
      transform->fixed_ivlen = 4;

      /* Minimum length is expicit IV + tag */
      transform->minlen =
        (transform->ivlen
         - transform->fixed_ivlen
         + ((_ntbtls_ciphersuite_get_flags (transform->ciphersuite)
             & CIPHERSUITE_FLAG_SHORT_TAG)? 8 : 16));
    }
  else
    {
      size_t blklen = gcry_cipher_get_algo_blklen (cipher);

      /* Initialize HMAC contexts */
      /* Fixme: Check whether the context may really be open.  */
      gcry_mac_close (transform->mac_ctx_enc);
      err = gcry_mac_open (&transform->mac_ctx_enc, mac, 0, NULL);
      if (!err)
        {
          gcry_mac_close (transform->mac_ctx_dec);
          err = gcry_mac_open (&transform->mac_ctx_dec, mac, 0, NULL);
        }
      if (err)
        {
          debug_ret (1, "gcry_mac_open", err);
          return err;
        }

      /* Get MAC length */
      transform->maclen = gcry_mac_get_algo_maclen (mac);
      if (transform->maclen < TLS_TRUNCATED_HMAC_LEN)
        {
          debug_bug ();
          return gpg_error (GPG_ERR_BUG);
        }

      /*
       * If HMAC is to be truncated, we shall keep the leftmost bytes,
       * (rfc 6066 page 13 or rfc 2104 section 4),
       * so we only need to adjust the length here.
       */
      if (session->use_trunc_hmac)
        transform->maclen = TLS_TRUNCATED_HMAC_LEN;

      /* IV length.  According to RFC-5246, Appendix C, we shall use
         the block length of the IV length.  */
      transform->ivlen = blklen;

      /* Minimum length for GenericBlockCipher:
       * First multiple of blocklen greater than maclen + IV.  */
      transform->minlen = (transform->maclen
                           + blklen
                           - (transform->maclen % blklen)
                           + transform->ivlen);
    }

  debug_msg (3, "keylen: %d, minlen: %zu, ivlen: %zu, maclen: %zu",
             transform->keylen, transform->minlen, transform->ivlen,
             transform->maclen);

  /*
   * Finally setup the cipher contexts, IVs and MAC secrets.
   */
  if (tls->is_client)
    {
      key1 = keyblk + transform->maclen * 2;
      key2 = keyblk + transform->maclen * 2 + transform->keylen;

      mac_enc = keyblk;
      mac_dec = keyblk + transform->maclen;

      /*
       * This is not used in TLS v1.1.  FIXME: Check and remove.
       */
      iv_copy_len = (transform->fixed_ivlen ?
                     transform->fixed_ivlen : transform->ivlen);
      memcpy (transform->iv_enc, key2 + transform->keylen, iv_copy_len);
      memcpy (transform->iv_dec, key2 + transform->keylen + iv_copy_len,
              iv_copy_len);
    }
  else
    {
      key1 = keyblk + transform->maclen * 2 + transform->keylen;
      key2 = keyblk + transform->maclen * 2;

      mac_enc = keyblk + transform->maclen;
      mac_dec = keyblk;

      /*
       * This is not used in TLS v1.1.  FIXME: Check and remove
       */
      iv_copy_len = (transform->fixed_ivlen ?
                     transform->fixed_ivlen : transform->ivlen);
      memcpy (transform->iv_dec, key1 + transform->keylen, iv_copy_len);
      memcpy (transform->iv_enc, key1 + transform->keylen + iv_copy_len,
              iv_copy_len);
    }


  if (!is_aead_mode (ciphermode))
    {
      err = gcry_mac_setkey (transform->mac_ctx_enc,
                             mac_enc, transform->maclen);
      if (!err)
        err = gcry_mac_setkey (transform->mac_ctx_dec,
                               mac_dec, transform->maclen);
      if (err)
        {
          debug_ret (1, "gcry_mac_setkey", err);
          return err;
        }
    }

  gcry_cipher_close (transform->cipher_ctx_enc);
  err = gcry_cipher_open (&transform->cipher_ctx_enc, cipher, ciphermode, 0);
  if (!err)
    {
      gcry_cipher_close (transform->cipher_ctx_dec);
      err = gcry_cipher_open (&transform->cipher_ctx_dec, cipher, ciphermode,0);
    }
  if (err)
    {
      debug_ret (1, "gcry_cipher_open", err);
      return err;
    }
  transform->cipher_mode_enc = ciphermode;
  transform->cipher_mode_dec = ciphermode;

  err = gcry_cipher_setkey (transform->cipher_ctx_enc,
                            key1, transform->keylen);
  if (!err)
    err = gcry_cipher_setkey (transform->cipher_ctx_dec,
                              key2, transform->keylen);
  if (err)
    {
      debug_ret (1, "cipher_setkey", err);
      return err;
    }

  wipememory (keyblk, sizeof (keyblk));

  /* Initialize compression.  */
  if (session->compression == TLS_COMPRESS_DEFLATE)
    {
      /* if (tls->compress_buf == NULL) */
      /*   { */
      /*     deboug_msg (3, "Allocating compression buffer"); */
      /*     ssl->compress_buf = malloc (SSL_BUFFER_LEN); */
      /*     if (!ssl->compress_buf) */
      /*       { */
      /*         err = gpg_error_from_syserror (); */
      /*         debug_msg (1, "malloc(%d bytes) failed", SSL_BUFFER_LEN); */
      /*         return err; */
      /*       } */
      /*   } */

      /* debug_msg (3, "Initializing zlib states"); */

      /* memset (&transform->ctx_deflate, 0, sizeof (transform->ctx_deflate));*/
      /* memset (&transform->ctx_inflate, 0, sizeof (transform->ctx_inflate));*/

      /* if (deflateInit (&transform->ctx_deflate, */
      /*                  Z_DEFAULT_COMPRESSION) != Z_OK || */
      /*     inflateInit (&transform->ctx_inflate) != Z_OK) */
        {
          debug_msg (1, "Failed to initialize compression");
          return gpg_error (GPG_ERR_COMPR_FAILED);
        }
    }

  return 0;
}


static void
calc_verify_tls (gcry_md_hd_t md_input, md_algo_t md_alg,
                 unsigned char *hash, size_t hashlen)
{
  gpg_error_t err;
  gcry_md_hd_t md;
  char *p;

  debug_msg (2, "calc_verify_tls sha%zu", hashlen*8);

  err = gcry_md_copy (&md, md_input);
  if (err)
    {
      debug_ret (1, "calc_verify_tls", err);
      memset (hash, 0, hashlen);
      return;
    }
  p = gcry_md_read (md, md_alg);
  if (!p)
    {
      debug_bug ();
      memset (hash, 0, hashlen);
      gcry_md_close (md);
      return;
    }
  memcpy (hash, p, hashlen);
  gcry_md_close (md);

  debug_buf (3, "calculated verify result", hash, hashlen);
  debug_msg (3, "calc_verify_tls sha%zu", hashlen*8);
}


static void
calc_verify_tls_sha256 (ntbtls_t tls, unsigned char *hash)
{
  calc_verify_tls (tls->handshake->fin_sha256, GCRY_MD_SHA256, hash, 32);
}

static void
calc_verify_tls_sha384 (ntbtls_t tls, unsigned char *hash)
{
  calc_verify_tls (tls->handshake->fin_sha512, GCRY_MD_SHA384, hash, 48);
}


gpg_error_t
_ntbtls_psk_derive_premaster (ntbtls_t tls, key_exchange_type_t kex)
{
  gpg_error_t err;
  unsigned char *p = tls->handshake->premaster;
  unsigned char *end = p + sizeof (tls->handshake->premaster);

  /*
   * PMS = struct {
   *     opaque other_secret<0..2^16-1>;
   *     opaque psk<0..2^16-1>;
   * };
   * with "other_secret" depending on the particular key exchange
   */
  if (kex == KEY_EXCHANGE_PSK)
    {
      if (end - p < 2 + (int) tls->psk_len)
        return gpg_error (GPG_ERR_INV_ARG);

      *(p++) = (unsigned char) (tls->psk_len >> 8);
      *(p++) = (unsigned char) (tls->psk_len);
      p += tls->psk_len;
    }
  else if (kex == KEY_EXCHANGE_RSA_PSK)
    {
      /*
       * other_secret already set by the ClientKeyExchange message,
       * and is 48 bytes long
       */
      *p++ = 0;
      *p++ = 48;
      p += 48;
    }
  else if (kex == KEY_EXCHANGE_DHE_PSK)
    {
      size_t len = end - (p + 2);

      /* Write length only when we know the actual value.  */
      /* err = dhm_calc_secret (&tls->handshake->dhm_ctx, p + 2, &len); */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      if (err)
        {
          debug_ret (1, "dhm_calc_secret", err);
          return err;
        }
      *(p++) = (unsigned char) (len >> 8);
      *(p++) = (unsigned char) (len);
      p += len;

      /* SSL_DEBUG_MPI (3, "DHM: K ", &tls->handshake->dhm_ctx.K); */
    }
  else if (kex == KEY_EXCHANGE_ECDHE_PSK)
    {
      size_t zlen = 0;

      /* err = ecdh_calc_secret (&tls->handshake->ecdh_ctx, &zlen, */
      /*                         p + 2, end - (p + 2)); */
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      if (err)
        {
          debug_ret (1, "ecdh_calc_secret", err);
          return err;
        }

      *(p++) = (unsigned char) (zlen >> 8);
      *(p++) = (unsigned char) (zlen);
      p += zlen;

      /* SSL_DEBUG_MPI (3, "ECDH: z", &tls->handshake->ecdh_ctx.z); */
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  /* opaque psk<0..2^16-1>; */
  if (end - p < 2 + (int) tls->psk_len)
    return gpg_error (GPG_ERR_INV_ARG);

  *(p++) = (unsigned char) (tls->psk_len >> 8);
  *(p++) = (unsigned char) (tls->psk_len);
  memcpy (p, tls->psk, tls->psk_len);
  p += tls->psk_len;

  tls->handshake->pmslen = p - tls->handshake->premaster;

  return 0;
}


/*
 * Encryption/decryption functions
 */
static gpg_error_t
encrypt_buf (ntbtls_t tls)
{
  gpg_error_t err;
  size_t tmplen, i;
  cipher_mode_t mode = tls->transform_out->cipher_mode_enc;

  debug_msg (2, "encrypt buf");

  if (tls->minor_ver < TLS_MINOR_VERSION_3)
    {
      debug_bug ();
      return gpg_error (GPG_ERR_BUG);
    }


  /*
   * Add MAC before encrypt, except for AEAD modes
   */
  if (!is_aead_mode (mode))
    {
      err = gcry_mac_write (tls->transform_out->mac_ctx_enc,
                            tls->out_ctr, 13);
      if (!err)
        err = gcry_mac_write (tls->transform_out->mac_ctx_enc,
                              tls->out_msg, tls->out_msglen);
      tmplen = tls->transform_out->maclen;

      if (!err)
        err = gcry_mac_read (tls->transform_out->mac_ctx_enc,
                             tls->out_msg + tls->out_msglen, &tmplen);
      if (!err)
        err = gcry_mac_reset (tls->transform_out->mac_ctx_enc);

      if (err)
        {
          debug_ret (1, "encrypt_buf: MACing failed", err);
          return err;
        }

      debug_buf (4, "computed mac",
                 tls->out_msg + tls->out_msglen,
                 tls->transform_out->maclen);

      tls->out_msglen += tls->transform_out->maclen;
    }

  /*
   * Encrypt
   */
  if (is_aead_mode (mode))
    {
      size_t enc_msglen;
      unsigned char *enc_msg;
      unsigned char add_data[13];
      unsigned char taglen;
      unsigned char iv[12];


      taglen = (_ntbtls_ciphersuite_get_flags (tls->transform_out->ciphersuite)
                & CIPHERSUITE_FLAG_SHORT_TAG)? 8 : 16;

      memcpy (add_data, tls->out_ctr, 8);
      add_data[8] = tls->out_msgtype;
      add_data[9] = tls->major_ver;
      add_data[10] = tls->minor_ver;
      add_data[11] = (tls->out_msglen >> 8) & 0xFF;
      add_data[12] = tls->out_msglen & 0xFF;

      debug_buf (4, "additional data used for AEAD", add_data, 13);

      /*
       * Generate IV
       */
      memcpy (iv, tls->transform_out->iv_enc, tls->transform_out->fixed_ivlen);
      memcpy (iv + tls->transform_out->fixed_ivlen, tls->out_ctr, 8);
      memcpy (tls->out_iv, tls->out_ctr, 8);

      debug_buf (4, "IV used (internal)", iv, tls->transform_out->ivlen);
      debug_buf (4, "IV used (transmitted)", tls->out_iv,
                 tls->transform_out->ivlen - tls->transform_out->fixed_ivlen);

      /*
       * Fix pointer positions and message length with added IV
       */
      enc_msg = tls->out_msg;
      enc_msglen = tls->out_msglen;
      tls->out_msglen += (tls->transform_out->ivlen
                          - tls->transform_out->fixed_ivlen);

      debug_msg (3, "before encrypt: msglen = %zu, "
                 "including %d bytes of padding", enc_msglen, 0);
      debug_buf (4, "before encrypt: output payload",
                 tls->out_msg, enc_msglen);

      err = gcry_cipher_reset (tls->transform_out->cipher_ctx_enc);
      if (err)
        {
          debug_ret (1, "cipher_reset", err);
          return err;
        }
      err = gcry_cipher_setiv (tls->transform_out->cipher_ctx_enc, iv,
                               tls->transform_out->ivlen);
      if (err)
        {
          debug_ret (1, "cipher_setiv", err);
          return err;
        }

      /*
       * Encrypt and authenticate
       */
      err = gcry_cipher_authenticate (tls->transform_out->cipher_ctx_enc,
                                      add_data, 13);
      if (err)
        {
          debug_ret (1, "cipher_authenticate", err);
          return err;
        }

      err = gcry_cipher_encrypt (tls->transform_out->cipher_ctx_enc,
                                 enc_msg, enc_msglen, NULL, 0);
      if (err)
        {
          debug_ret (1, "cipher_encrypt", err);
          return err;
        }

      err = gcry_cipher_gettag (tls->transform_out->cipher_ctx_enc,
                                enc_msg + enc_msglen, taglen);
      if (err)
        {
          debug_ret (1, "cipher_gettag", err);
          return err;
        }

      tls->out_msglen += taglen;

      debug_buf (4, "after encrypt: payload", enc_msg, enc_msglen);
      debug_buf (4, "after encrypt: tag", enc_msg + enc_msglen, taglen);
    }
  else if (mode == GCRY_CIPHER_MODE_CBC)
    {
      unsigned char *enc_msg;
      size_t enc_msglen, padlen;

      padlen = (tls->transform_out->ivlen
                - ((tls->out_msglen + 1) % tls->transform_out->ivlen));
      if (padlen == tls->transform_out->ivlen)
        padlen = 0;

      for (i = 0; i <= padlen; i++)
        tls->out_msg[tls->out_msglen + i] = (unsigned char) padlen;

      tls->out_msglen += padlen + 1;

      enc_msglen = tls->out_msglen;
      enc_msg = tls->out_msg;

      /*
       * Prepend per-record IV for block cipher in TLS v1.1 and up as per
       * Method 1 (RFC-5246, 6.2.3.2)
       */

      /* Generate IV.  */
      gcry_create_nonce (tls->transform_out->iv_enc, tls->transform_out->ivlen);

      memcpy (tls->out_iv, tls->transform_out->iv_enc,
              tls->transform_out->ivlen);

      /* Fix pointer positions and message length with added IV.  */
      enc_msg = tls->out_msg;
      enc_msglen = tls->out_msglen;
      tls->out_msglen += tls->transform_out->ivlen;

      debug_msg (3, "before encrypt: msglen = %zu, "
                 "including %zu bytes of IV and %zu bytes of padding",
                 tls->out_msglen, tls->transform_out->ivlen, padlen + 1);
      debug_buf (4, "before encrypt: output payload",
                 tls->out_iv, tls->out_msglen);

      err = gcry_cipher_reset (tls->transform_out->cipher_ctx_enc);
      if (err)
        {
          debug_ret (1, "cipher_reset", err);
          return err;
        }
      err = gcry_cipher_setiv (tls->transform_out->cipher_ctx_enc,
                               tls->transform_out->iv_enc,
                               tls->transform_out->ivlen);
      if (err)
        {
          debug_ret (1, "cipher_setiv", err);
          return err;
        }

      err = gcry_cipher_encrypt (tls->transform_out->cipher_ctx_enc,
                                 enc_msg, enc_msglen, NULL, 0);
      if (err)
        {
          debug_ret (1, "cipher_encrypt", err);
          return err;
        }
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  for (i = 8; i > 0; i--)
    if (++tls->out_ctr[i - 1] != 0)
      break;

  /* The loops goes to its end iff the counter is wrapping */
  if (!i)
    {
      debug_msg (1, "outgoing message counter would wrap");
      return gpg_error (GPG_ERR_WOULD_WRAP);
    }

  return 0;
}


static int
decrypt_buf (ntbtls_t tls)
{
  gpg_error_t err;
  cipher_mode_t mode = tls->transform_out->cipher_mode_dec;
  size_t padlen = 0;
  size_t correct = 1;
  size_t tmplen, i;

  debug_msg (2, "decrypt buf");

  if (tls->minor_ver < TLS_MINOR_VERSION_3)
    {
      debug_bug ();
      return gpg_error (GPG_ERR_BUG);
    }

  if (tls->in_msglen < tls->transform_in->minlen)
    {
      debug_msg (1, "in_msglen (%zu) < minlen (%zu)",
                 tls->in_msglen, tls->transform_in->minlen);
      return gpg_error (GPG_ERR_INV_MAC);
    }

  if (is_aead_mode (mode))
    {
      size_t dec_msglen;
      unsigned char *dec_msg;
      unsigned char add_data[13];
      unsigned char taglen, explicit_iv_len;
      unsigned char iv[12];

      taglen = (_ntbtls_ciphersuite_get_flags (tls->transform_in->ciphersuite)
                & CIPHERSUITE_FLAG_SHORT_TAG)? 8 : 16;
      explicit_iv_len = (tls->transform_in->ivlen
                         - tls->transform_in->fixed_ivlen);

      if (tls->in_msglen < explicit_iv_len + taglen)
        {
          debug_msg (1, "msglen (%zud) < explicit_iv_len (%d) "
                     "+ taglen (%d)", tls->in_msglen,
                     explicit_iv_len, taglen);
          return gpg_error (GPG_ERR_INV_MAC);
         }
      dec_msglen = tls->in_msglen - explicit_iv_len - taglen;

      dec_msg = tls->in_msg;
      tls->in_msglen = dec_msglen;

      memcpy (add_data, tls->in_ctr, 8);
      add_data[8] = tls->in_msgtype;
      add_data[9] = tls->major_ver;
      add_data[10] = tls->minor_ver;
      add_data[11] = (tls->in_msglen >> 8) & 0xFF;
      add_data[12] = tls->in_msglen & 0xFF;

      debug_buf (4, "additional data used for AEAD", add_data, 13);

      memcpy (iv, tls->transform_in->iv_dec, tls->transform_in->fixed_ivlen);
      memcpy (iv + tls->transform_in->fixed_ivlen, tls->in_iv, 8);

      debug_buf (4, "IV used", iv, 12);
      debug_buf (4, "TAG used", dec_msg + dec_msglen, taglen);

      /*
       * Decrypt and authenticate
       */
      err = gcry_cipher_reset (tls->transform_in->cipher_ctx_dec);
      if (err)
        {
          debug_ret (1, "cipher_reset", err);
          return err;
        }
      err = gcry_cipher_setiv (tls->transform_in->cipher_ctx_dec, iv,
                               tls->transform_in->ivlen);
      if (err)
        {
          debug_ret (1, "cipher_setiv", err);
          return err;
        }

      err = gcry_cipher_authenticate (tls->transform_in->cipher_ctx_dec,
                                      add_data, 13);
      if (err)
        {
          debug_ret (1, "cipher_authenticate", err);
          return err;
        }

      err = gcry_cipher_decrypt (tls->transform_in->cipher_ctx_dec,
                                 dec_msg, dec_msglen, NULL, 0);
      if (err)
        {
          debug_ret (1, "cipher_decrypt", err);
          return err;
        }

      err = gcry_cipher_checktag (tls->transform_in->cipher_ctx_dec,
                                  dec_msg + dec_msglen, taglen);
      if (err)
        {
          debug_ret (1, "cipher_checktag", err);
          return err;
        }
    }
  else if (mode == GCRY_CIPHER_MODE_CBC)
    {
      /*
       * Decrypt and check the padding
       */
      unsigned char *dec_msg;
      size_t pad_count, real_count, padding_idx;
      size_t dec_msglen;
      size_t minlen = 0;

      /*
       * Check immediate ciphertext sanity
       */
      if ((tls->in_msglen % tls->transform_in->ivlen))
        {
          debug_msg (1, "msglen (%zu) %% ivlen (%zu) != 0",
                     tls->in_msglen, tls->transform_in->ivlen);
          return gpg_error (GPG_ERR_INV_MAC);
        }

      minlen += tls->transform_in->ivlen;

      if (tls->in_msglen < minlen + tls->transform_in->ivlen
          || tls->in_msglen < minlen + tls->transform_in->maclen + 1)
        {
          debug_msg (1, "msglen (%zu) < max( ivlen(%zu), maclen (%zu) "
                     "+ 1 ) ( + expl IV )",
                     tls->in_msglen,
                     tls->transform_in->ivlen,
                     tls->transform_in->maclen);
          return gpg_error (GPG_ERR_INV_MAC);
        }

      dec_msglen = tls->in_msglen;
      dec_msg = tls->in_msg;

      /*
       * Initialize for prepended IV.
       */
      dec_msglen -= tls->transform_in->ivlen;
      tls->in_msglen -= tls->transform_in->ivlen;

      for (i = 0; i < tls->transform_in->ivlen; i++)
        tls->transform_in->iv_dec[i] = tls->in_iv[i];

      err = gcry_cipher_reset (tls->transform_out->cipher_ctx_dec);
      if (err)
        {
          debug_ret (1, "cipher_reset", err);
          return err;
        }
      err = gcry_cipher_setiv (tls->transform_out->cipher_ctx_dec,
                               tls->transform_out->iv_dec,
                               tls->transform_out->ivlen);
      if (err)
        {
          debug_ret (1, "cipher_setiv", err);
          return err;
        }

      err = gcry_cipher_decrypt (tls->transform_out->cipher_ctx_dec,
                                 dec_msg, dec_msglen, NULL, 0);
      if (err)
        {
          debug_ret (1, "cipher_decrypt", err);
          return err;
        }

      padlen = 1 + tls->in_msg[tls->in_msglen - 1];

      if (tls->in_msglen < tls->transform_in->maclen + padlen)
        {
          debug_msg (1, "msglen (%zu) < maclen (%zu) + padlen (%zu)",
                     tls->in_msglen, tls->transform_in->maclen, padlen);
          padlen = 0;
          correct = 0;
        }

      /*
       * Always check the padding up to the first failure and fake
       * check up to 256 bytes of padding
       */
      pad_count = 0;
      real_count = 1;
      padding_idx = tls->in_msglen - padlen - 1;

      /*
       * Padding is guaranteed to be incorrect if:
       *   1. padlen >= tls->in_msglen
       *
       *   2. padding_idx >= TLS_MAX_CONTENT_LEN +
       *                     tls->transform_in->maclen
       *
       * In both cases we reset padding_idx to a safe value (0) to
       * prevent out-of-buffer reads.
       */
      correct &= (tls->in_msglen >= padlen + 1);
      correct &= (padding_idx < TLS_MAX_CONTENT_LEN
                  + tls->transform_in->maclen);
      padding_idx *= correct;

      for (i = 1; i <= 256; i++)
        {
          real_count &= (i <= padlen);
          pad_count += real_count * (tls->in_msg[padding_idx + i] == padlen-1);
        }

      correct &= (pad_count == padlen);     /* Only 1 on correct padding */

      if (padlen > 0 && !correct)
        debug_msg (1, "bad padding byte detected");

      padlen &= correct * 0x1FF;
    }
  else
    {
      debug_bug ();
      return gpg_error (GPG_ERR_INTERNAL);
    }

  debug_buf (4, "raw buffer after decryption", tls->in_msg, tls->in_msglen);

  /*
   * Always compute the MAC (RFC4346, CBCTIME), except for AEAD of course
   */
  if (!is_aead_mode (mode))
    {
      unsigned char tmp[TLS_MAX_MAC_SIZE];
      size_t  extra_run;

      tls->in_msglen -= (tls->transform_in->maclen + padlen);

      tls->in_hdr[3] = (unsigned char) (tls->in_msglen >> 8);
      tls->in_hdr[4] = (unsigned char) (tls->in_msglen);

      memcpy (tmp, tls->in_msg + tls->in_msglen, tls->transform_in->maclen);

      /*
       * Process MAC and always update for padlen afterwards to make
       * total time independent of padlen
       *
       * extra_run compensates MAC check for padlen
       *
       * Known timing attacks:
       *  - Lucky Thirteen (http://www.isg.rhul.ac.uk/tls/TLStiming.pdf)
       *
       * We use ( ( Lx + 8 ) / 64 ) to handle 'negative Lx' values
       * correctly. (We round down instead of up, so -56 is the correct
       * value for our calculations instead of -55).
       *
       * Fixme: Get the transform block size from Libgcrypt instead of
       * assuming 64.
       */
      extra_run = ((13 + tls->in_msglen + padlen + 8) / 64
                   - (13 + tls->in_msglen + 8) / 64);

      extra_run &= correct * 0xFF;

      err = gcry_mac_write (tls->transform_in->mac_ctx_dec,
                            tls->in_ctr, 13);
      if (!err)
        err = gcry_mac_write (tls->transform_in->mac_ctx_dec,
                              tls->in_msg, tls->in_msglen);
      tmplen = tls->transform_in->maclen;
      if (!err)
        err = gcry_mac_read (tls->transform_in->mac_ctx_dec,
                             tls->in_msg + tls->in_msglen, &tmplen);
      /* Keep on hashing dummy blocks if needed.  gcry_mac_write
         explictly declares this as a valid modus operandi. */
      if (!err && extra_run)
        {
          int j;

          for (j = 0; j < extra_run && !err; j++)
            err = gcry_mac_write (tls->transform_in->mac_ctx_dec,
                                  tls->in_msg, 64);
          if (!err)
            err = gcry_mac_write (tls->transform_in->mac_ctx_dec, NULL, 0);
        }

      if (!err)
        err = gcry_mac_reset (tls->transform_in->mac_ctx_dec);

      if (err)
        {
          /* Note that such an error is due to a bug in the code, a
             missing algorithm, or an out of core case.  It is highly
             unlikely that a side channel attack can be constructed
             based on such an error.  In any case, with failing MAC
             functions we are anyway not able to guarantee a constant
             time behavior.  */
          debug_ret (1, "decrypt_buf: MACing failed", err);
          return err;
        }

      debug_buf (4, "message  mac", tmp, tls->transform_in->maclen);
      debug_buf (4, "computed mac",
                 tls->in_msg + tls->in_msglen, tls->transform_in->maclen);

      if (memcmpct (tmp, tls->in_msg + tls->in_msglen,
                    tls->transform_in->maclen))
        {
          debug_msg (1, "message mac does not match");
          correct = 0;
        }

      /*
       * Finally check the correct flag
       */
      if (!correct)
        return gpg_error (GPG_ERR_BAD_MAC);
    }

  if (!tls->in_msglen)
    {
      tls->nb_zero++;

      /*
       * Three or more empty messages may be a DoS attack
       * (excessive CPU consumption).
       */
      if (tls->nb_zero > 3)
        {
          debug_msg (1, "received four consecutive empty "
                     "messages, possible DoS attack");
          return gpg_error (GPG_ERR_INV_MAC);
        }
    }
  else
    tls->nb_zero = 0;

  for (i = 8; i > 0; i--)
    if (++tls->in_ctr[i - 1] != 0)
      break;

  /* The loops goes to its end iff the counter is wrapping */
  if (!i)
    {
      debug_msg (1, "incoming message counter would wrap");
      return gpg_error (GPG_ERR_WOULD_WRAP);
    }

  return 0;
}


/*
 * Compression/decompression functions
 */
static int
ssl_compress_buf (ntbtls_t ssl)
{
  int ret;
  unsigned char *msg_post = ssl->out_msg;
  size_t len_pre = ssl->out_msglen;
  unsigned char *msg_pre = ssl->compress_buf;

  debug_msg (2, "compress buf");

  if (len_pre == 0)
    return (0);

  memcpy (msg_pre, ssl->out_msg, len_pre);

  debug_msg (3, "before compression: msglen = %zu, ", ssl->out_msglen);

  debug_buf (4, "before compression: output payload",
             ssl->out_msg, ssl->out_msglen);

  ssl->transform_out->ctx_deflate.next_in = msg_pre;
  ssl->transform_out->ctx_deflate.avail_in = len_pre;
  ssl->transform_out->ctx_deflate.next_out = msg_post;
  ssl->transform_out->ctx_deflate.avail_out = TLS_BUFFER_LEN;

  /* ret = deflate (&ssl->transform_out->ctx_deflate, Z_SYNC_FLUSH); */
  ret = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  if (ret != Z_OK)
    {
      debug_msg (1, "failed to perform compression (%d)", ret);
      return gpg_error (GPG_ERR_COMPR_FAILED);
    }

  ssl->out_msglen = (TLS_BUFFER_LEN
                     - ssl->transform_out->ctx_deflate.avail_out);

  debug_msg (3, "after compression: msglen = %zu, ", ssl->out_msglen);

  debug_buf (4, "after compression: output payload",
             ssl->out_msg, ssl->out_msglen);

  return (0);
}

static int
ssl_decompress_buf (ntbtls_t ssl)
{
  int ret;
  unsigned char *msg_post = ssl->in_msg;
  size_t len_pre = ssl->in_msglen;
  unsigned char *msg_pre = ssl->compress_buf;

  debug_msg (2, "decompress buf");

  if (len_pre == 0)
    return (0);

  memcpy (msg_pre, ssl->in_msg, len_pre);

  debug_msg (3, "before decompression: msglen = %zu, ", ssl->in_msglen);

  debug_buf (4, "before decompression: input payload",
             ssl->in_msg, ssl->in_msglen);

  ssl->transform_in->ctx_inflate.next_in = msg_pre;
  ssl->transform_in->ctx_inflate.avail_in = len_pre;
  ssl->transform_in->ctx_inflate.next_out = msg_post;
  ssl->transform_in->ctx_inflate.avail_out = TLS_MAX_CONTENT_LEN;

  /* ret = inflate (&ssl->transform_in->ctx_inflate, Z_SYNC_FLUSH); */
  ret = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
  if (ret != Z_OK)
    {
      debug_msg (1, "failed to perform decompression (%d)", ret);
      return gpg_error (GPG_ERR_COMPR_FAILED);
    }

  ssl->in_msglen = (TLS_MAX_CONTENT_LEN
                    - ssl->transform_in->ctx_inflate.avail_out);

  debug_msg (3, "after decompression: msglen = %zu, ", ssl->in_msglen);

  debug_buf (4, "after decompression: input payload",
             ssl->in_msg, ssl->in_msglen);

  return (0);
}


/* Fill the input message buffer with NB_WANT bytes.  The function
 * returns an error if the numer of requested bytes do not fit into
 * the record buffer, there is a read problem, or on EOF.  */
gpg_error_t
_ntbtls_fetch_input (ntbtls_t tls, size_t nb_want)
{
  gpg_error_t err;
  size_t len, nread;

  debug_msg (3, "fetch input");

  if (!tls->inbound)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  if (nb_want > TLS_BUFFER_LEN - 8)
    {
      debug_msg (1, "requesting more data than fits");
      return gpg_error (GPG_ERR_REQUEST_TOO_LONG);
    }

  err = 0;
  while (tls->in_left < nb_want)
    {
      len = nb_want - tls->in_left;
      if (es_read (tls->inbound, tls->in_hdr + tls->in_left, len, &nread))
        err = gpg_error_from_syserror ();
      else if (!nread) /*ie. EOF*/
        err = gpg_error (GPG_ERR_EOF);

      debug_msg (3, "in_left: %zu, nb_want: %zu", tls->in_left, nb_want);
      debug_ret (3, "es_read", err);

      if (err)
        break;

      tls->in_left += nread;
    }

  return err;
}


/*
 * Flush any data not yet written
 */
gpg_error_t
_ntbtls_flush_output (ntbtls_t tls)
{
  gpg_error_t err;
  unsigned char *buf;
  size_t nwritten;

  debug_msg (3, "flush output");

  if (!tls->outbound)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  err = 0;
  while (tls->out_left > 0)
    {
      debug_msg (3, "message length: %zu, out_left: %zu",
                 5 + tls->out_msglen, tls->out_left);

      buf = tls->out_hdr + 5 + tls->out_msglen - tls->out_left;
      if (es_write (tls->outbound, buf, tls->out_left, &nwritten))
        err = gpg_error_from_syserror ();

      debug_ret (3, "es_write", err);

      if (err)
        break;

      tls->out_left -= nwritten;
    }

  return err;
}


/*
 * Record layer functions
 */
gpg_error_t
_ntbtls_write_record (ntbtls_t tls)
{
  gpg_error_t err;
  int done = 0;
  size_t len = tls->out_msglen;

  debug_msg (3, "write record");

  if (tls->out_msgtype == TLS_MSG_HANDSHAKE)
    {
      tls->out_msg[1] = (unsigned char) ((len - 4) >> 16);
      tls->out_msg[2] = (unsigned char) ((len - 4) >> 8);
      tls->out_msg[3] = (unsigned char) ((len - 4));

      if (tls->out_msg[0] != TLS_HS_HELLO_REQUEST)
        tls->handshake->update_checksum (tls, tls->out_msg, len);
    }

  if (tls->transform_out
      && tls->session_out->compression == TLS_COMPRESS_DEFLATE)
    {
      err = ssl_compress_buf (tls);
      if (err)
        {
          debug_ret (1, "ssl_compress_buf", err);
          return err;
        }

      len = tls->out_msglen;
    }

  if (!done)
    {
      tls->out_hdr[0] = (unsigned char) tls->out_msgtype;
      tls->out_hdr[1] = (unsigned char) tls->major_ver;
      tls->out_hdr[2] = (unsigned char) tls->minor_ver;
      tls->out_hdr[3] = (unsigned char) (len >> 8);
      tls->out_hdr[4] = (unsigned char) (len);

      if (tls->transform_out)
        {
          err = encrypt_buf (tls);
          if (err)
            {
              debug_ret (1, "encrypt_buf", err);
              return err;
            }

          len = tls->out_msglen;
          tls->out_hdr[3] = (unsigned char) (len >> 8);
          tls->out_hdr[4] = (unsigned char) (len);
        }

      tls->out_left = 5 + tls->out_msglen;

      debug_msg (3, "output record: msgtype = %d, "
                 "version = [%d:%d], msglen = %u",
                 tls->out_hdr[0], tls->out_hdr[1], tls->out_hdr[2],
                 buf16_to_uint (tls->out_hdr + 3));

      debug_buf (4, "output record sent to network",
                 tls->out_hdr, 5 + tls->out_msglen);
    }

  err = _ntbtls_flush_output (tls);
  if (err)
    debug_ret (1, "_ntbtls_flush_output", err);

  return err;
}


gpg_error_t
_ntbtls_read_record (ntbtls_t tls)
{
  gpg_error_t err;
  int done = 0;

  debug_msg (3, "read record");

  if (tls->in_hslen != 0 && tls->in_hslen < tls->in_msglen)
    {
      /*
       * Get next Handshake message in the current record
       */
      tls->in_msglen -= tls->in_hslen;

      memmove (tls->in_msg, tls->in_msg + tls->in_hslen, tls->in_msglen);

      tls->in_hslen = 4;
      tls->in_hslen += buf16_to_size_t (tls->in_msg + 2);

      debug_msg (3, "handshake message: msglen ="
                 " %zu, type = %u, hslen = %zu",
                 tls->in_msglen, tls->in_msg[0], tls->in_hslen);

      if (tls->in_msglen < 4 || tls->in_msg[1] != 0)
        {
          debug_msg (1, "bad handshake length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }

      if (tls->in_msglen < tls->in_hslen)
        {
          debug_msg (1, "bad handshake length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }

      if (tls->state != TLS_HANDSHAKE_OVER)
        tls->handshake->update_checksum (tls, tls->in_msg, tls->in_hslen);

      return 0;
    }

  tls->in_hslen = 0;

 read_record_header:
  /*
   * Read the record header and validate it
   */
  err = _ntbtls_fetch_input (tls, 5);
  if (err)
    {
      debug_ret (1, "fetch_input", err);
      return err;
    }
  //FIXME: Handle EOF

  tls->in_msgtype = tls->in_hdr[0];
  tls->in_msglen = buf16_to_size_t (tls->in_hdr + 3);

  debug_msg (3, "input record: msgtype = %d, "
             "version = [%d:%d], msglen = %u",
             tls->in_hdr[0], tls->in_hdr[1], tls->in_hdr[2],
             buf16_to_uint (tls->in_hdr + 3));

  if (tls->in_hdr[1] != tls->major_ver)
    {
      debug_msg (1, "major version mismatch");
      return gpg_error (GPG_ERR_INV_RECORD);
    }

  if (tls->in_hdr[2] > tls->max_minor_ver)
    {
      debug_msg (1, "minor version mismatch");
      return gpg_error (GPG_ERR_INV_RECORD);
    }

  /* Sanity check (outer boundaries) */
  if (tls->in_msglen < 1 || tls->in_msglen > TLS_BUFFER_LEN - 13)
    {
      debug_msg (1, "bad message length");
      return gpg_error (GPG_ERR_INV_RECORD);
    }

  /*
   * Make sure the message length is acceptable for the current transform
   * and protocol version.
   */
  if (!tls->transform_in)
    {
      if (tls->in_msglen > TLS_MAX_CONTENT_LEN)
        {
          debug_msg (1, "bad message length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }
    }
  else
    {
      if (tls->in_msglen < tls->transform_in->minlen)
        {
          debug_msg (1, "bad message length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }

      /*
       * TLS encrypted messages can have up to 256 bytes of padding
       */
      if (tls->minor_ver >= TLS_MINOR_VERSION_1
          && tls->in_msglen > (tls->transform_in->minlen
                               + TLS_MAX_CONTENT_LEN + 256))
        {
          debug_msg (1, "bad message length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }
    }

  /*
   * Read and optionally decrypt the message contents
   */
  err = _ntbtls_fetch_input (tls, 5 + tls->in_msglen);
  if (err)
    {
      debug_ret (1, "fetch_input", err);
      return err;
    }
  //FIXME: Handle EOF

  debug_buf (4, "input record from network", tls->in_hdr, 5 + tls->in_msglen);

  if (!done && tls->transform_in)
    {
      err = decrypt_buf (tls);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_INV_MAC
              || gpg_err_code (err) == GPG_ERR_BAD_MAC
              || gpg_err_code (err) == GPG_ERR_CHECKSUM)
            {
              _ntbtls_send_alert_message (tls,
                                          TLS_ALERT_LEVEL_FATAL,
                                          TLS_ALERT_MSG_BAD_RECORD_MAC);
            }
          debug_ret (1, "decrypt_buf", err);
          return err;
        }

      debug_buf (4, "input payload after decrypt", tls->in_msg, tls->in_msglen);

      if (tls->in_msglen > TLS_MAX_CONTENT_LEN)
        {
          debug_msg (1, "bad message length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }
    }

  if (tls->transform_in && tls->session_in->compression == TLS_COMPRESS_DEFLATE)
    {
      err = ssl_decompress_buf (tls);
      if (err)
        {
          debug_ret (1, "decompress_buf", err);
          return err;
        }

      tls->in_hdr[3] = (unsigned char) (tls->in_msglen >> 8);
      tls->in_hdr[4] = (unsigned char) (tls->in_msglen);
    }

  if (   tls->in_msgtype != TLS_MSG_HANDSHAKE
      && tls->in_msgtype != TLS_MSG_ALERT
      && tls->in_msgtype != TLS_MSG_CHANGE_CIPHER_SPEC
      && tls->in_msgtype != TLS_MSG_APPLICATION_DATA)
    {
      debug_msg (1, "unknown record type");

      err = _ntbtls_send_alert_message (tls, TLS_ALERT_LEVEL_FATAL,
                                        TLS_ALERT_MSG_UNEXPECTED_MESSAGE);
      if (!err)
        err = gpg_error (GPG_ERR_INV_RECORD);

      return err;
    }

  if (tls->in_msgtype == TLS_MSG_HANDSHAKE)
    {
      tls->in_hslen = 4;
      tls->in_hslen += buf16_to_size_t (tls->in_msg + 2);

      debug_msg (3, "handshake message: msglen ="
                 " %zu, type = %u, hslen = %zu",
                 tls->in_msglen, tls->in_msg[0], tls->in_hslen);

      /*
       * Additional checks to validate the handshake header
       */
      if (tls->in_msglen < 4 || tls->in_msg[1] != 0)
        {
          debug_msg (1, "bad handshake length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }

      if (tls->in_msglen < tls->in_hslen)
        {
          debug_msg (1, "bad handshake length");
          return gpg_error (GPG_ERR_INV_RECORD);
        }

      if (tls->state != TLS_HANDSHAKE_OVER)
        tls->handshake->update_checksum (tls, tls->in_msg, tls->in_hslen);
    }

  if (tls->in_msgtype == TLS_MSG_ALERT)
    {
      tls->last_alert.any = 1;
      tls->last_alert.level = tls->in_msg[0];
      tls->last_alert.type = tls->in_msg[1];

      if (tls->in_msg[0] == TLS_ALERT_LEVEL_FATAL)
        debug_msg (1, "got fatal alert message %d: %s",
                   tls->in_msg[1], alert_msg_to_string (tls->in_msg[1]));

      else if (tls->in_msg[0] == TLS_ALERT_LEVEL_WARNING)
        debug_msg (2, "got warning alert message %d: %s",
                   tls->in_msg[1], alert_msg_to_string (tls->in_msg[1]));
      else
        debug_msg (2, "got alert message of unknown level %d type %d: %s",
                   tls->in_msg[0], tls->in_msg[1],
                   alert_msg_to_string (tls->in_msg[1]));

      /*
       * Ignore non-fatal alerts, except close_notify
       */
      if (tls->in_msg[0] == TLS_ALERT_LEVEL_FATAL)
        {
          return gpg_error (GPG_ERR_FATAL_ALERT);
        }

      if (tls->in_msg[0] == TLS_ALERT_LEVEL_WARNING &&
          tls->in_msg[1] == TLS_ALERT_MSG_CLOSE_NOTIFY)
        {
          return gpg_error (GPG_ERR_CLOSE_NOTIFY);
        }

      tls->in_left = 0;
      goto read_record_header;
    }

  tls->in_left = 0;

  return (0);
}


gpg_error_t
_ntbtls_send_fatal_handshake_failure (ntbtls_t tls)
{
  return _ntbtls_send_alert_message (tls, TLS_ALERT_LEVEL_FATAL,
                                     TLS_ALERT_MSG_HANDSHAKE_FAILURE);
}


gpg_error_t
_ntbtls_send_alert_message (ntbtls_t tls,
                            unsigned char level, unsigned char message)
{
  gpg_error_t err;

  debug_msg (2, "send alert message");

  tls->out_msgtype = TLS_MSG_ALERT;
  tls->out_msglen = 2;
  tls->out_msg[0] = level;
  tls->out_msg[1] = message;

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return 0;
}


/*
 * Handshake functions
 */


gpg_error_t
_ntbtls_write_certificate (ntbtls_t tls)
{
  gpg_error_t err;
  const ciphersuite_t suite = tls->transform_negotiate->ciphersuite;
  key_exchange_type_t kex = _ntbtls_ciphersuite_get_kex (suite);
  x509_cert_t cert;
  int idx;
  const unsigned char *der;
  size_t derlen;
  size_t i;

  if (kex == KEY_EXCHANGE_PSK
      || kex == KEY_EXCHANGE_DHE_PSK
      || kex == KEY_EXCHANGE_ECDHE_PSK
      || (tls->is_client && !tls->client_auth))
    {
      debug_msg (2, "skipping write certificate");
      tls->state++;
      return 0;
    }

  debug_msg (2, "write certificate");

  if (!tls->is_client && !tls_own_cert (tls))
    {
      debug_msg (1, "got no certificate to send");
      return gpg_error (GPG_ERR_MISSING_CERT);
    }

  /* SSL_DEBUG_CRT (3, "own certificate", tls_own_cert (tls)); */

  /*
   *     0  .  0    handshake type
   *     1  .  3    handshake length
   *     4  .  6    length of all certs
   *     7  .  9    length of cert. 1
   *    10  . n-1   peer certificate
   *     n  . n+2   length of cert. 2
   *    n+3 . ...   upper level cert, etc.
   */
  i = 7;
  cert = tls_own_cert (tls);
  for (idx = 0; (der = _ntbtls_x509_get_cert (cert, idx, &derlen)); idx++)
    {
      if (derlen > TLS_MAX_CONTENT_LEN - 3 - i)
        {
          debug_msg (1, "certificate too large, %zu > %d",
                     i + 3 + derlen, TLS_MAX_CONTENT_LEN);
          return gpg_error (GPG_ERR_CERT_TOO_LARGE);
        }

      tls->out_msg[i]     = (unsigned char) (derlen >> 16);
      tls->out_msg[i + 1] = (unsigned char) (derlen >> 8);
      tls->out_msg[i + 2] = (unsigned char) (derlen);
      i += 3;
      memcpy (tls->out_msg + i, der, derlen);
      i += derlen;
    }

  tls->out_msg[4] = (unsigned char) ((i - 7) >> 16);
  tls->out_msg[5] = (unsigned char) ((i - 7) >> 8);
  tls->out_msg[6] = (unsigned char) ((i - 7));

  tls->out_msglen = i;
  tls->out_msgtype = TLS_MSG_HANDSHAKE;
  tls->out_msg[0] = TLS_HS_CERTIFICATE;

  tls->state++;

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return err;
}


gpg_error_t
_ntbtls_read_certificate (ntbtls_t tls)
{
  gpg_error_t err;
  size_t i, n;
  const ciphersuite_t suite = tls->transform_negotiate->ciphersuite;
  key_exchange_type_t kex = _ntbtls_ciphersuite_get_kex (suite);

  if (kex == KEY_EXCHANGE_PSK
      || kex == KEY_EXCHANGE_DHE_PSK
      || kex == KEY_EXCHANGE_ECDHE_PSK)
    {
      debug_msg (2, "skipping read certificate");
      tls->state++;
      return 0;
    }

  if (!tls->is_client
      && (tls->authmode == TLS_VERIFY_NONE || kex == KEY_EXCHANGE_RSA_PSK))
    {
      tls->session_negotiate->verify_result = BADCERT_SKIP_VERIFY;
      debug_msg (2, "skipping read certificate");
      tls->state++;
      return 0;
    }

  debug_msg (3, "read certificate");

  err = _ntbtls_read_record (tls);
  if (err)
    {
      debug_ret (1, "read_record", err);
      return err;
    }

  tls->state++;

  if (!tls->is_client && tls->minor_ver != TLS_MINOR_VERSION_0)
    {
      if (tls->in_hslen == 7 &&
          tls->in_msgtype == TLS_MSG_HANDSHAKE &&
          tls->in_msg[0] == TLS_HS_CERTIFICATE &&
          !memcmp (tls->in_msg + 4, "\0\0\0", 3))
        {
          debug_msg (1, "TLSv1 client has no certificate");

          tls->session_negotiate->verify_result = BADCERT_MISSING;
          if (tls->authmode == TLS_VERIFY_REQUIRED)
            return gpg_error (GPG_ERR_MISSING_CLIENT_CERT);
          else
            return 0;
        }
    }

  if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad certificate message");
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  if (tls->in_msg[0] != TLS_HS_CERTIFICATE || tls->in_hslen < 10)
    {
      debug_msg (1, "bad certificate message");
      return gpg_error (GPG_ERR_BAD_HS_CERT);
    }

  /*
   * Same message structure as in _ntbtls_write_certificate()
   */
  n = buf16_to_size_t (tls->in_msg + 5);

  if (tls->in_msg[4] != 0 || tls->in_hslen != 7 + n)
    {
      debug_msg (1, "bad certificate message");
      return gpg_error (GPG_ERR_BAD_HS_CERT);
    }

  /* In case we tried to reuse a session but it failed. */
  if (tls->session_negotiate->peer_chain)
    {
      _ntbtls_x509_cert_release (tls->session_negotiate->peer_chain);
      tls->session_negotiate->peer_chain = NULL;
    }

  err = _ntbtls_x509_cert_new (&tls->session_negotiate->peer_chain);
  if (err)
    {
      debug_msg (1, "allocating X.509 cert object failed");
      return err;
    }

  for (i = 7; i < tls->in_hslen; )
    {
      if (tls->in_msg[i] != 0)
        {
          debug_msg (1, "bad certificate message");
          return gpg_error (GPG_ERR_BAD_HS_CERT);
        }

      n = buf16_to_size_t (tls->in_msg + i + 1);
      i += 3;

      if (n < 128 || i + n > tls->in_hslen)
        {
          debug_msg (1, "bad certificate message");
          return gpg_error (GPG_ERR_BAD_HS_CERT);
        }

      err = _ntbtls_x509_append_cert (tls->session_negotiate->peer_chain,
                                      tls->in_msg + i, n);
      if (err)
        {
          debug_ret (1, "x509_append_cert", err);
          return err;
        }
      i += n;
    }

  debug_crt (1, "peer certificate", tls->session_negotiate->peer_chain);

  /*
   * On client, make sure the server cert doesn't change during renego to
   * avoid "triple handshake" attack: https://secure-resumption.com/
   */
  if (tls->is_client && tls->renegotiation == TLS_RENEGOTIATION)
    {
      if (!tls->session->peer_chain)
        {
          debug_msg (1, "new server cert during renegotiation");
          return gpg_error (GPG_ERR_BAD_HS_CERT);
        }

      //FIXME:  Need to implement this in x509.c  IMPORTANT!
      /* if (tls->session->peer_chain->raw.len != */
      /*     tls->session_negotiate->peer_chain->raw.len */
      /*     ||  memcmp (tls->session->peer_chain->raw.p, */
      /*                 tls->session_negotiate->peer_chain->raw.p, */
      /*                 tls->session->peer_chain->raw.len)) */
      /*   { */
      /*     debug_msg (1, "server cert changed during renegotiation"); */
      /*     return gpg_error (GPG_ERR_BAD_HS_CERT); */
      /*   } */
    }

  if (tls->authmode != TLS_VERIFY_NONE)
    {
      /*
       * Verify hostname
       */
      if (tls->hostname)
        {
          if (!tls->session_negotiate)
            err = gpg_error (GPG_ERR_MISSING_CERT);
          else
            err = _ntbtls_x509_check_hostname
              (tls->session_negotiate->peer_chain, tls->hostname);
          if (err)
            {
              debug_ret (1, "x509_check_hostname", err);
            }
        }
      else
        err = 0;

      /*
       * Verify certificate.  We don't do this if the hostname check
       * already failed.
       */
      if (!err)
        {
          if (!tls->verify_cb)
            {
              debug_msg (1, "verify callback not set");
              return gpg_error (GPG_ERR_NOT_INITIALIZED);
            }
          err = tls->verify_cb (tls->verify_cb_value, tls, 0);
          if (err)
            {
              debug_ret (1, "error from the verify callback", err);
            }

          if (tls->authmode != TLS_VERIFY_REQUIRED)
            err = 0;
        }
    }

  return err;
}


gpg_error_t
_ntbtls_write_change_cipher_spec (ntbtls_t tls)
{
  gpg_error_t err;

  debug_msg (2, "write change cipher spec");

  tls->out_msgtype = TLS_MSG_CHANGE_CIPHER_SPEC;
  tls->out_msglen = 1;
  tls->out_msg[0] = 1;

  tls->state++;

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return 0;
}


gpg_error_t
_ntbtls_read_change_cipher_spec (ntbtls_t tls)
{
  gpg_error_t err;

  debug_msg (2, "read change_cipher_spec");

  err = _ntbtls_read_record (tls);
  if (err)
    {
      debug_ret (1, "read_record", err);
      return err;
    }

  if (tls->in_msgtype != TLS_MSG_CHANGE_CIPHER_SPEC)
    {
      debug_msg (1, "bad change_cipher_spec message");
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  if (tls->in_msglen != 1 || tls->in_msg[0] != 1)
    {
      debug_msg (1, "bad change_cipher_spec message");
      return gpg_error (GPG_ERR_BAD_HS_CHANGE_CIPHER);
    }

  tls->state++;

  return 0;
}


static void
update_checksum_sha256 (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  gcry_md_write (tls->handshake->fin_sha256, buf, len);
}


static void
update_checksum_sha384 (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  gcry_md_write (tls->handshake->fin_sha512, buf, len);
}


void
_ntbtls_optimize_checksum (ntbtls_t tls, const ciphersuite_t suite)
{
  if (_ntbtls_ciphersuite_get_mac (suite) == GCRY_MAC_HMAC_SHA384)
    tls->handshake->update_checksum = update_checksum_sha384;
  else if (_ntbtls_ciphersuite_get_mac (suite) != GCRY_MAC_HMAC_SHA384)
    tls->handshake->update_checksum = update_checksum_sha256;
  else
    {
      debug_bug ();
      return;
    }
}


static void
update_checksum_start (ntbtls_t tls, const unsigned char *buf, size_t len)
{
  gcry_md_write (tls->handshake->fin_sha256, buf, len);
  gcry_md_write (tls->handshake->fin_sha512, buf, len);
}



static void
calc_finished_tls (ntbtls_t tls, int is_sha384,
                   unsigned char *buf, int is_client)
{
  gpg_error_t err;
  gcry_md_hd_t md;
  int len = 12;
  const char *sender;
  unsigned char padbuf[48];
  size_t hashlen = is_sha384? 48 : 32;
  session_t session;
  char *p;

  session = tls->session_negotiate;
  if (!session)
    session = tls->session;

  debug_msg (2, "calc finished tls sha%d", is_sha384? 384 : 256);

  err = gcry_md_copy (&md, (is_sha384 ? tls->handshake->fin_sha512
                            /*     */ : tls->handshake->fin_sha256));
  if (err)
    {
      debug_ret (1, "calc_finished_tls", err);
      memset (buf, 0, len);
      return;
    }

  /*
   * TLSv1.2:
   *   hash = PRF( master, finished_label,
   *               Hash( handshake ) )[0.11]
   */
  sender = is_client ? "client finished" : "server finished";

  p = gcry_md_read (md, is_sha384? GCRY_MD_SHA384 : GCRY_MD_SHA256);
  if (p)
    memcpy (padbuf, p, hashlen);
  gcry_md_close (md);
  if (!p)
    {
      debug_bug ();
      memset (buf, 0, len);
      return;
    }

  tls->handshake->tls_prf (session->master, 48, sender,
                           padbuf, hashlen, buf, len);

  debug_buf (3, "calc finished result", buf, len);

  wipememory (padbuf, hashlen);
}


static void
calc_finished_tls_sha256 (ntbtls_t tls, unsigned char *buf, int is_client)
{
  calc_finished_tls (tls, 0, buf, is_client);
}

static void
calc_finished_tls_sha384 (ntbtls_t tls, unsigned char *buf, int is_client)
{
  calc_finished_tls (tls, 1, buf, is_client);
}


void
_ntbtls_handshake_wrapup (ntbtls_t tls)
{
  int resume = tls->handshake->resume;

  debug_msg (3, "handshake wrapup");

  /*
   * Free our handshake params
   */
  handshake_params_deinit (tls->handshake);
  free (tls->handshake);
  tls->handshake = NULL;

  if (tls->renegotiation == TLS_RENEGOTIATION)
    {
      tls->renegotiation = TLS_RENEGOTIATION_DONE;
      tls->renego_records_seen = 0;
    }

  /*
   * Switch in our now active transform context
   */
  if (tls->transform)
    {
      transform_deinit (tls->transform);
      free (tls->transform);
    }
  tls->transform = tls->transform_negotiate;
  tls->transform_negotiate = NULL;

  if (tls->session)
    {
      session_deinit (tls->session);
      free (tls->session);
    }
  tls->session = tls->session_negotiate;
  tls->session_negotiate = NULL;

  /*
   * Add cache entry
   */
  if (tls->f_set_cache && tls->session->length && !resume)
    {
      if (tls->f_set_cache (tls->p_set_cache, tls->session))
        debug_msg (1, "cache did not store session");
    }

  tls->state++;

  debug_msg (3, "handshake wrapup ready ");
}


gpg_error_t
_ntbtls_write_finished (ntbtls_t tls)
{
  gpg_error_t err;
  int hashlen;

  debug_msg (2, "write finished");

  /*
   * Set the out_msg pointer to the correct location based on IV length
   */
  if (tls->minor_ver >= TLS_MINOR_VERSION_2)
    {
      tls->out_msg = (tls->out_iv
                      + tls->transform_negotiate->ivlen
                      - tls->transform_negotiate->fixed_ivlen);
    }
  else
    tls->out_msg = tls->out_iv;

  tls->handshake->calc_finished (tls, tls->out_msg + 4, tls->is_client);

  /* TODO TLS/1.2 Hash length is determined by cipher suite (Page 63)
     but all currently defined cipher suite keep it at 12.  */
  hashlen = 12;

  tls->verify_data_len = hashlen;
  memcpy (tls->own_verify_data, tls->out_msg + 4, hashlen);

  tls->out_msglen = 4 + hashlen;
  tls->out_msgtype = TLS_MSG_HANDSHAKE;
  tls->out_msg[0] = TLS_HS_FINISHED;

  /*
   * In case of session resuming, invert the client and server
   * ChangeCipherSpec messages order.
   */
  if (tls->handshake->resume)
    {
      if (tls->is_client)
        tls->state = TLS_HANDSHAKE_WRAPUP;
      else
        tls->state = TLS_CLIENT_CHANGE_CIPHER_SPEC;
    }
  else
    tls->state++;

  /*
   * Switch to our negotiated transform and session parameters for outbound
   * data.
   */
  debug_msg (3, "switching to new transform spec for outbound data");
  tls->transform_out = tls->transform_negotiate;
  tls->session_out = tls->session_negotiate;
  memset (tls->out_ctr, 0, 8);

  err = _ntbtls_write_record (tls);
  if (err)
    {
      debug_ret (1, "write_record", err);
      return err;
    }

  return 0;
}


gpg_error_t
_ntbtls_read_finished (ntbtls_t tls)
{
  gpg_error_t err;
  unsigned int hashlen;
  unsigned char buf[36];

  debug_msg (2, "read finished");

  tls->handshake->calc_finished (tls, buf, !tls->is_client);

  /*
   * Switch to our negotiated transform and session parameters for inbound
   * data.
   */
  debug_msg (3, "switching to new transform spec for inbound data");
  tls->transform_in = tls->transform_negotiate;
  tls->session_in = tls->session_negotiate;
  memset (tls->in_ctr, 0, 8);

  /*
   * Set the in_msg pointer to the correct location based on IV length
   */
  if (tls->minor_ver >= TLS_MINOR_VERSION_2)
    {
      tls->in_msg = (tls->in_iv
                     + tls->transform_negotiate->ivlen
                     - tls->transform_negotiate->fixed_ivlen);
    }
  else
    tls->in_msg = tls->in_iv;

  err = _ntbtls_read_record (tls);
  if (err)
    {
      debug_ret (1, "read_record", err);
      return err;
    }

  if (tls->in_msgtype != TLS_MSG_HANDSHAKE)
    {
      debug_msg (1, "bad finished message");
      return gpg_error (GPG_ERR_UNEXPECTED_MSG);
    }

  /* TODO TLS/1.2 Hash length is determined by cipher suite (Page 63).  */
  hashlen = 12;

  if (tls->in_msg[0] != TLS_HS_FINISHED || tls->in_hslen != 4 + hashlen)
    {
      debug_msg (1, "bad finished message");
      return gpg_error (GPG_ERR_BAD_HS_FINISHED);
    }

  if (memcmpct (tls->in_msg + 4, buf, hashlen))
    {
      debug_msg (1, "bad finished message");
      debug_buf (2, "want", buf, hashlen);
      debug_buf (2, " got", tls->in_msg+4, hashlen);
      return gpg_error (GPG_ERR_BAD_HS_FINISHED);
    }

  tls->verify_data_len = hashlen;
  memcpy (tls->peer_verify_data, buf, hashlen);

  if (tls->handshake->resume)
    {
      if (tls->is_client)
        tls->state = TLS_CLIENT_CHANGE_CIPHER_SPEC;
      else
        tls->state = TLS_HANDSHAKE_WRAPUP;
    }
  else
    tls->state++;

  return 0;
}


static gpg_error_t
transform_init (transform_t transform)
{
  gpg_error_t err = 0;

  (void)transform;
  //FIXME:
  /* cipher_init (&transform->cipher_ctx_enc); */
  /* cipher_init (&transform->cipher_ctx_dec); */

  /* md_init (&transform->mac_ctx_enc); */
  /* md_init (&transform->mac_ctx_dec); */
  return err;
}


static void
transform_deinit (transform_t transform)
{
  if (!transform)
    return;

  //FIXME:
  /* deflateEnd (&transform->ctx_deflate); */
  /* inflateEnd (&transform->ctx_inflate); */

  /* cipher_free (&transform->cipher_ctx_enc); */
  /* cipher_free (&transform->cipher_ctx_dec); */

  /* md_free (&transform->mac_ctx_enc); */
  /* md_free (&transform->mac_ctx_dec); */

  wipememory (transform, sizeof *transform);
}


static gpg_error_t
session_init (session_t session)
{
  (void)session;
  return 0;
}


static void
session_deinit (session_t session)
{
  if (!session)
    return;

  _ntbtls_x509_cert_release (session->peer_chain);

  free (session->ticket);
  wipememory (session, sizeof *session);
}


static gpg_error_t
handshake_params_init (handshake_params_t handshake)
{
  gpg_error_t err;

  err = gcry_md_open (&handshake->fin_sha256, GCRY_MD_SHA256, 0);
  if (err)
    return err;

  err = gcry_md_open (&handshake->fin_sha512, GCRY_MD_SHA384, 0);
  if (err)
    {
      gcry_md_close (handshake->fin_sha256);
      handshake->fin_sha256 = NULL;
      return err;
    }

  err = _ntbtls_dhm_new (&handshake->dhm_ctx);
  if (err)
    {
      gcry_md_close (handshake->fin_sha256);
      handshake->fin_sha256 = NULL;
      gcry_md_close (handshake->fin_sha512);
      handshake->fin_sha512 = NULL;
      return err;
    }

  err = _ntbtls_ecdh_new (&handshake->ecdh_ctx);
  if (err)
    {
      _ntbtls_dhm_release (handshake->dhm_ctx);
      handshake->dhm_ctx = NULL;
      gcry_md_close (handshake->fin_sha256);
      handshake->fin_sha256 = NULL;
      gcry_md_close (handshake->fin_sha512);
      handshake->fin_sha512 = NULL;
      return err;
    }

  handshake->update_checksum = update_checksum_start;
  handshake->sig_alg = TLS_HASH_SHA256;

  return 0;
}


static void
handshake_params_deinit (handshake_params_t handshake)
{
  if (!handshake)
    return;

  _ntbtls_dhm_release (handshake->dhm_ctx);
  handshake->dhm_ctx = NULL;
  _ntbtls_ecdh_release (handshake->ecdh_ctx);
  handshake->ecdh_ctx = NULL;

  free (handshake->curves);

  /* Free only the linked list wrapper, not the keys themselves since
     the belong to the SNI callback. */
  if (handshake->sni_key_cert)
    {
      //FIXME:
      /* ssl_key_cert *cur, *next; */

      /* cur = handshake->sni_key_cert; */
      /* while (cur) */
      /*   { */
      /*     next = cur->next; */
      /*     free (cur); */
      /*     cur = next; */
      /*   } */
    }

  wipememory (handshake, sizeof *handshake);
}


static gpg_error_t
handshake_init (ntbtls_t tls)
{
  gpg_error_t err;

  /* Clear old handshake information if present.  */
  transform_deinit (tls->transform_negotiate);
  session_deinit (tls->session_negotiate);
  handshake_params_deinit (tls->handshake);

  /*
   * Either the pointers are now NULL or cleared properly and can be freed.
   * Now allocate missing structures.
   */
  if (!tls->transform_negotiate)
    {
      tls->transform_negotiate = calloc (1, sizeof *tls->transform_negotiate);
      if (!tls->transform_negotiate)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  if (!tls->session_negotiate)
    {
      tls->session_negotiate = calloc (1, sizeof *tls->session_negotiate);
      if (!tls->session_negotiate)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }
  if (!tls->handshake)
    {
      tls->handshake = calloc (1, sizeof *tls->handshake);
      if (!tls->handshake)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }
    }

  /* Initialize structures */
  err = transform_init (tls->transform_negotiate);
  if (err)
    goto leave;
  err = session_init (tls->session_negotiate);
  if (err)
    goto leave;
  err = handshake_params_init (tls->handshake);
  if (err)
    goto leave;

  /* Fixme: Document the owner of KEY_CERT or use a ref counter.  */
  tls->handshake->key_cert = tls->key_cert;

 leave:
  if (err)
    {
      transform_deinit (tls->transform_negotiate);
      free (tls->transform_negotiate);
      tls->transform_negotiate = NULL;

      session_deinit (tls->session_negotiate);
      free (tls->session_negotiate);
      tls->session_negotiate = NULL;

      handshake_params_deinit (tls->handshake);
      free (tls->handshake);
      tls->handshake = NULL;
    }
  return err;
}


/*
 * Create a new TLS context.  Valid values for FLAGS are:
 *
 *   NTBTLS_SERVER  - This endpoint is a server (default).
 *   NTBTLS_CLIENT  - This endpoint is a client.
 *
 * On success a context object is returned at R_TLS.  One error NULL
 * is stored at R_TLS and an error code is returned.
 */
gpg_error_t
_ntbtls_new (ntbtls_t *r_tls, unsigned int flags)
{
  gpg_error_t err;
  ntbtls_t tls;
  int buffer_len = TLS_BUFFER_LEN;

  *r_tls = NULL;

  /* Note: NTBTLS_SERVER has value 0, thus we can't check for it. */
  if ((flags & ~(NTBTLS_CLIENT|NTBTLS_SAMETRHEAD)))
    return gpg_error (GPG_ERR_EINVAL);

  tls = calloc (1, sizeof *tls);
  if (!tls)
    return gpg_error_from_syserror ();  /* Return immediately.  */

  tls->magic = NTBTLS_CONTEXT_MAGIC;

  tls->min_major_ver = TLS_MIN_MAJOR_VERSION;
  tls->min_minor_ver = TLS_MIN_MINOR_VERSION;
  tls->max_major_ver = TLS_MAX_MAJOR_VERSION;
  tls->max_minor_ver = TLS_MAX_MINOR_VERSION;

  tls->flags = flags;
  if ((flags & NTBTLS_CLIENT))
    {
      tls->is_client = 1;
      tls->use_session_tickets = 1;
    }

  /* We only support TLS 1.2 and thus we set the list for the other
     TLS versions to NULL.  */
  tls->ciphersuite_list[TLS_MINOR_VERSION_0] = NULL;
  tls->ciphersuite_list[TLS_MINOR_VERSION_1] = NULL;
  tls->ciphersuite_list[TLS_MINOR_VERSION_2] = NULL;
  tls->ciphersuite_list[TLS_MINOR_VERSION_3] = _ntbtls_ciphersuite_list ();


  tls->renego_max_records = TLS_RENEGO_MAX_RECORDS_DEFAULT;

  /* FIXME */
  /* if ((ret = mpi_read_string (&tls->dhm_P, 16, */
  /*                             POLARSSL_DHM_RFC5114_MODP_1024_P)) != 0 || */
  /*     (ret = mpi_read_string (&tls->dhm_G, 16, */
  /*                             POLARSSL_DHM_RFC5114_MODP_1024_G)) != 0) */
  /*   { */
  /*     debug_ret (1, "mpi_read_string", ret); */
  /*     return (ret); */
  /*   } */

  /*
   * Prepare base structures
   */
  tls->in_ctr = malloc (buffer_len);
  if (!tls->in_ctr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  tls->in_hdr = tls->in_ctr + 8;
  tls->in_iv  = tls->in_ctr + 13;
  tls->in_msg = tls->in_ctr + 13;

  tls->out_ctr = malloc (buffer_len);
  if (!tls->out_ctr)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  tls->out_hdr = tls->out_ctr + 8;
  tls->out_iv  = tls->out_ctr + 13;
  tls->out_msg = tls->out_ctr + 13;

  memset (tls->in_ctr, 0, buffer_len);
  memset (tls->out_ctr, 0, buffer_len);

  tls->ticket_lifetime = TLS_DEFAULT_TICKET_LIFETIME;

  // FIXME: tls->curve_list = ecp_grp_id_list ();

  err = handshake_init (tls);
  if (err)
    goto leave;

  if (tls->is_client)
    tls->use_session_tickets = 1;


 leave:
  if (err)
    {
      free (tls->in_ctr);
      free (tls);
    }
  else
    *r_tls = tls;
  return err;
}


/*
 * Release an TLS context.
 */
void
_ntbtls_release (ntbtls_t tls)
{
  if (!tls)
    return;

  debug_msg (2, "release");
  if (tls->magic != NTBTLS_CONTEXT_MAGIC)
    debug_bug ();

  if (tls->out_ctr)
    {
      /* FIXME: At some points we are using a variable for the length.
         Either do that always or use always this constant. */
      wipememory (tls->out_ctr, TLS_BUFFER_LEN);
      free (tls->out_ctr);
    }

  if (tls->in_ctr)
    {
      wipememory (tls->in_ctr, TLS_BUFFER_LEN);
      free (tls->in_ctr);
    }

  if (tls->compress_buf)
    {
      wipememory (tls->compress_buf, TLS_BUFFER_LEN);
      free (tls->compress_buf);
    }

  //FIXME:
  /* mpi_free (&tls->dhm_P); */
  /* mpi_free (&tls->dhm_G); */

  if (tls->transform)
    {
      transform_deinit (tls->transform);
      free (tls->transform);
    }

  if (tls->handshake)
    {
      handshake_params_deinit (tls->handshake);
      free (tls->handshake);
      transform_deinit (tls->transform_negotiate);
      free (tls->transform_negotiate);
      session_deinit (tls->session_negotiate);
      free (tls->session_negotiate);
    }

  if (tls->session)
    {
      session_deinit (tls->session);
      free (tls->session);
    }

  if (tls->ticket_keys)
    {
      ticket_keys_deinit (tls->ticket_keys);
      free (tls->ticket_keys);
    }

  free (tls->hostname);

  if (tls->psk)
    {
      wipememory (tls->psk, tls->psk_len);
      wipememory (tls->psk_identity, tls->psk_identity_len);
      free (tls->psk);
      free (tls->psk_identity);
      tls->psk_len = 0;
      tls->psk_identity_len = 0;
    }


  //FIXME:
  /* ssl_key_cert_free (tls->key_cert); */

  /* Actually clear after last debug message */
  wipememory (tls, sizeof *tls);
  free (tls);
}


/* Return info about the last rceeived alert.  */
const char *
_ntbtls_get_last_alert (ntbtls_t tls,
                        unsigned int *r_level, unsigned int *r_type)
{
  if (!tls || !tls->last_alert.any)
    {
      if (r_level)
        *r_level = 0;
      if (r_type)
        *r_type = 0;
      return NULL;
    }

  if (r_level)
    *r_level = tls->last_alert.level;
  if (r_type)
    *r_type = tls->last_alert.type;
  return alert_msg_to_string (tls->last_alert.type);
}


/* Set the transport stream for the context TLS.  This needs to be
   called right after init and may not be changed later.  INBOUND and
   OUTBOUND are usually connected to the same socket.  The caller
   must ensure that the streams are not closed as long as the context
   TLS is valid.  However, after destroying the context the streams
   may be closed.  This behavior allows to setup a TLS connection on
   an existing stream, shutdown the TLS and continue unencrypted.
   Whether the latter is of any real use in practice is a different
   question.  Using separate streams allow to run TLS over a pair of
   half-duplex connections.  */
gpg_error_t
_ntbtls_set_transport (ntbtls_t tls, estream_t inbound, estream_t outbound)
{
  if (!tls || !inbound || !outbound)
    return gpg_error (GPG_ERR_INV_ARG);
  if (tls->inbound || tls->outbound)
    return gpg_error (GPG_ERR_CONFLICT);

  /* We do our own buffering thus we disable buffer of the transport
     streams.  */
  if (es_setvbuf (inbound, NULL, _IONBF, 0))
    return gpg_error_from_syserror ();
  if (es_setvbuf (outbound, NULL, _IONBF, 0))
    return gpg_error_from_syserror ();

  tls->inbound = inbound;
  tls->outbound = outbound;
  return 0;
}


/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 */
int
ssl_session_reset (ntbtls_t ssl)
{
  int ret;

  ssl->state = TLS_HELLO_REQUEST;
  ssl->renegotiation = TLS_INITIAL_HANDSHAKE;
  ssl->secure_renegotiation = TLS_LEGACY_RENEGOTIATION;

  ssl->verify_data_len = 0;
  memset (ssl->own_verify_data, 0, 36);
  memset (ssl->peer_verify_data, 0, 36);

  ssl->in_offt = NULL;

  ssl->in_msg = ssl->in_ctr + 13;
  ssl->in_msgtype = 0;
  ssl->in_msglen = 0;
  ssl->in_left = 0;

  ssl->in_hslen = 0;
  ssl->nb_zero = 0;
  ssl->record_read = 0;

  ssl->out_msg = ssl->out_ctr + 13;
  ssl->out_msgtype = 0;
  ssl->out_msglen = 0;
  ssl->out_left = 0;

  ssl->transform_in = NULL;
  ssl->transform_out = NULL;

  ssl->renego_records_seen = 0;

  memset (ssl->out_ctr, 0, TLS_BUFFER_LEN);
  memset (ssl->in_ctr, 0, TLS_BUFFER_LEN);

  if (ssl->transform)
    {
      transform_deinit (ssl->transform);
      free (ssl->transform);
      ssl->transform = NULL;
    }

  if (ssl->session)
    {
      session_deinit (ssl->session);
      free (ssl->session);
      ssl->session = NULL;
    }

  ssl->alpn_chosen = NULL;

  if ((ret = handshake_init (ssl)) != 0)
    return (ret);

  return (0);
}


static void
ticket_keys_deinit (ticket_keys_t tkeys)
{
  //FIXME:
  /* aes_free (&tkeys->enc); */
  /* aes_free (&tkeys->dec); */

  wipememory (tkeys, sizeof *tkeys);
}


/*
 * Allocate and initialize ticket keys in TLS if not yet done.
 */
static gpg_error_t
ticket_keys_setup (ntbtls_t tls)
{
  ticket_keys_t tkeys;
  unsigned char buf[16];

  if (tls->ticket_keys)
    return 0;

  tkeys = malloc (sizeof *tkeys);
  if (!tkeys)
    return gpg_error_from_syserror ();

  //FIXME:
  /* aes_init (&tkeys->enc); */
  /* aes_init (&tkeys->dec); */

  gcry_randomize (tkeys->key_name, 16, GCRY_STRONG_RANDOM);
  gcry_randomize (buf, 16, GCRY_STRONG_RANDOM);

  //FIXME:
  /* if ((ret = aes_setkey_enc (&tkeys->enc, buf, 128)) != 0 || */
  /*     (ret = aes_setkey_dec (&tkeys->dec, buf, 128)) != 0) */
  /*   { */
  /*     ssl_ticket_keys_free (tkeys); */
  /*     polarssl_free (tkeys); */
  /*     return (ret); */
  /*   } */

  gcry_randomize (tkeys->mac_key, 16, GCRY_STRONG_RANDOM);

  tls->ticket_keys = tkeys;

  return 0;
}


/*
 * SSL set accessors
 */

void
ssl_set_authmode (ntbtls_t ssl, int authmode)
{
  ssl->authmode = authmode;
}

#if defined(POLARSSL_X509_CRT_PARSE_C)
void
ssl_set_verify (ntbtls_t ssl,
                int (*f_vrfy) (void *, x509_crt *, int, int *), void *p_vrfy)
{
  ssl->f_vrfy = f_vrfy;
  ssl->p_vrfy = p_vrfy;
}
#endif /* POLARSSL_X509_CRT_PARSE_C */


void
ssl_set_session_cache (ntbtls_t ssl,
                       int (*f_get_cache) (void *, session_t),
                       void *p_get_cache, int (*f_set_cache) (void *,
                                                              const
                                                              session_t),
                       void *p_set_cache)
{
  ssl->f_get_cache = f_get_cache;
  ssl->p_get_cache = p_get_cache;
  ssl->f_set_cache = f_set_cache;
  ssl->p_set_cache = p_set_cache;
}


/* Request resumption of session (client-side only).
   Session data is copied from presented session structure. */
gpg_error_t
_ntbtls_set_session (ntbtls_t tls, const session_t session)
{
  gpg_error_t err;

  if (!tls || !session || !tls->session_negotiate || !tls->is_client)
    return gpg_error (GPG_ERR_INV_ARG);

  err = session_copy (tls->session_negotiate, session);
  if (err)
    return err;

  tls->handshake->resume = 1;

  return 0;
}



/* Add a new (empty) key_cert entry an return a pointer to it */
/* static ssl_key_cert * */
/* ssl_add_key_cert (ntbtls_t ssl) */
/* { */
/*   ssl_key_cert *key_cert, *last; */

/*   key_cert = calloc (1, sizeof *key_cert); */
/*   if (!key_cert) */
/*     return NULL; */

/*   /\* Append the new key_cert to the (possibly empty) current list *\/ */
/*   if (ssl->key_cert == NULL) */
/*     { */
/*       ssl->key_cert = key_cert; */
/*       if (ssl->handshake != NULL) */
/*         ssl->handshake->key_cert = key_cert; */
/*     } */
/*   else */
/*     { */
/*       last = ssl->key_cert; */
/*       while (last->next != NULL) */
/*         last = last->next; */
/*       last->next = key_cert; */
/*     } */

/*   return (key_cert); */
/* } */


/* Set a certificate verify callback for the session TLS.  */
gpg_error_t
_ntbtls_set_verify_cb (ntbtls_t tls, ntbtls_verify_cb_t cb, void *cb_value)
{
  if (!tls)
    return gpg_error (GPG_ERR_INV_ARG);

  tls->verify_cb = cb;
  tls->verify_cb_value = cb_value;

  /* Make sure we have an authmode set.  Right now, there is no API to
   * change thye authmode.  */
  tls->authmode = cb ? TLS_VERIFY_REQUIRED : TLS_VERIFY_NONE;

  return 0;
}


/* int */
/* ssl_set_own_cert (ntbtls_t ssl, x509_crt * own_cert, pk_context * pk_key) */
/* { */
/*   ssl_key_cert *key_cert; */

/*   key_cert = ssl_add_key_cert (ssl); */
/*   if (!key_cert) */
/*     return gpg_error_from_syserror (); */

/*   key_cert->cert = own_cert; */
/*   key_cert->key = pk_key; */

/*   return 0; */
/* } */


/* int */
/* ssl_set_own_cert_rsa (ntbtls_t ssl, x509_crt * own_cert, */
/*                       rsa_context * rsa_key) */
/* { */
/*   int ret; */
/*   ssl_key_cert *key_cert; */


/*   key_cert = ssl_add_key_cert (ssl); */
/*   if (!key_cert) */
/*     return gpg_error_from_syserror (); */

/*   key_cert->key = malloc (sizeof (pk_context)); */
/*   if (!key_cert->key) */
/*     return gpg_error_from_syserror (); */

/*   pk_init (key_cert->key); */

/*   ret = pk_init_ctx (key_cert->key, pk_info_from_type (POLARSSL_PK_RSA)); */
/*   if (ret != 0) */
/*     return (ret); */

/*   if ((ret = rsa_copy (pk_rsa (*key_cert->key), rsa_key)) != 0) */
/*     return (ret); */

/*   key_cert->cert = own_cert; */
/*   key_cert->key_own_alloc = 1; */

/*   return (0); */
/* } */


/* int */
/* ssl_set_own_cert_alt (ntbtls_t ssl, x509_crt * own_cert, */
/*                       void *rsa_key, */
/*                       rsa_decrypt_func rsa_decrypt, */
/*                       rsa_sign_func rsa_sign, rsa_key_len_func rsa_key_len) */
/* { */
/*   int ret; */
/*   ssl_key_cert *key_cert; */

/*   key_cert = ssl_add_key_cert (ssl); */
/*   if (!key_cert) */
/*     return gpg_error_from_syserror (); */

/*   key_cert->key = malloc (sizeof (pk_context)); */
/*   if (!key_cert->key) */
/*     { */
/*       err = gpg_error_from_syserror (); */
/*       free (key_cert); */
/*       return err; */
/*     } */

/*   pk_init (key_cert->key); */

/*   if ((ret = pk_init_ctx_rsa_alt (key_cert->key, rsa_key, */
/*                                   rsa_decrypt, rsa_sign, rsa_key_len)) != 0) */
/*     return (ret); */

/*   key_cert->cert = own_cert; */
/*   key_cert->key_own_alloc = 1; */

/*   return 0; */
/* } */


/* int */
/* ssl_set_psk (ntbtls_t ssl, const unsigned char *psk, size_t psk_len, */
/*              const unsigned char *psk_identity, size_t psk_identity_len) */
/* { */
/*   if (psk == NULL || psk_identity == NULL) */
/*     return gpg_error (GPG_ERR_INV_ARG); */

/*   if (psk_len > POLARSSL_PSK_MAX_LEN) */
/*     return gpg_error (GPG_ERR_INV_ARG); */

/*   if (ssl->psk != NULL) */
/*     { */
/*       free (ssl->psk); */
/*       ssl->psk = NULL; */
/*       free (ssl->psk_identity); */
/*       ssl->psk_identity = NULL; */
/*     } */

/*   ssl->psk_len = psk_len; */
/*   ssl->psk_identity_len = psk_identity_len; */

/*   ssl->psk = malloc (ssl->psk_len); */
/*   if (!ssl->psk) */
/*     return gpg_error_from_syserror (); */

/*   ssl->psk_identity = malloc (ssl->psk_identity_len); */
/*   if (!ssl->psk_identity) */
/*     { */
/*       err = gpg_error_from_syserror (); */
/*       free (ssl->psk); */
/*       ssl->psk = NULL; */
/*       return err; */
/*     } */

/*   memcpy (ssl->psk, psk, ssl->psk_len); */
/*   memcpy (ssl->psk_identity, psk_identity, ssl->psk_identity_len); */

/*   return (0); */
/* } */

/* void */
/* ssl_set_psk_cb (ntbtls_t ssl, */
/*                 int (*f_psk) (void *, ssl_context *, const unsigned char *, */
/*                               size_t), void *p_psk) */
/* { */
/*   ssl->f_psk = f_psk; */
/*   ssl->p_psk = p_psk; */
/* } */


/* int */
/* ssl_set_dh_param (ntbtls_t ssl, const char *dhm_P, const char *dhm_G) */
/* { */
/*   int ret; */

/*   if ((ret = mpi_read_string (&ssl->dhm_P, 16, dhm_P)) != 0) */
/*     { */
/*       debug_ret (1, "mpi_read_string", ret); */
/*       return (ret); */
/*     } */

/*   if ((ret = mpi_read_string (&ssl->dhm_G, 16, dhm_G)) != 0) */
/*     { */
/*       debug_ret (1, "mpi_read_string", ret); */
/*       return (ret); */
/*     } */

/*   return (0); */
/* } */

/* int */
/* ssl_set_dh_param_ctx (ntbtls_t ssl, dhm_context * dhm_ctx) */
/* { */
/*   int ret; */

/*   if ((ret = mpi_copy (&ssl->dhm_P, &dhm_ctx->P)) != 0) */
/*     { */
/*       debug_ret (1, "mpi_copy", ret); */
/*       return (ret); */
/*     } */

/*   if ((ret = mpi_copy (&ssl->dhm_G, &dhm_ctx->G)) != 0) */
/*     { */
/*       debug_ret (1, "mpi_copy", ret); */
/*       return (ret); */
/*     } */

/*   return (0); */
/* } */


/*
 * Set the allowed elliptic curves
 */
/* void */
/* ssl_set_curves (ntbtls_t ssl, const ecp_group_id * curve_list) */
/* { */
/*   ssl->curve_list = curve_list; */
/* } */


gpg_error_t
_ntbtls_set_hostname (ntbtls_t tls, const char *hostname)
{
  size_t len;

  if (!tls)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!hostname)
    {
      free (tls->hostname);
      tls->hostname = NULL;
    }

  len = strlen (hostname);
  if ( len + 1 < len )
    return gpg_error (GPG_ERR_EOVERFLOW);

  tls->hostname = malloc (len + 1);
  if (!tls->hostname)
    return gpg_error_from_syserror ();
  strcpy (tls->hostname, hostname);

  return 0;
}


/* Return the hostname which has been set with ntbtls_set_hostname.
 * The returned value is valid as long as TLS is valid and
 * ntbtls_set_hostname has not been used again.  */
const char *
_ntbtls_get_hostname (ntbtls_t tls)
{
  return tls ? tls->hostname : NULL;
}


/* void */
/* ssl_set_sni (ntbtls_t ssl, */
/*              int (*f_sni) (void *, ntbtls_t, */
/*                            const unsigned char *, size_t), void *p_sni) */
/* { */
/*   ssl->f_sni = f_sni; */
/*   ssl->p_sni = p_sni; */
/* } */


/* int */
/* ssl_set_alpn_protocols (ntbtls_t ssl, const char **protos) */
/* { */
/*   size_t cur_len, tot_len; */
/*   const char **p; */

/*   /\* */
/*    * "Empty strings MUST NOT be included and byte strings MUST NOT be */
/*    * truncated". Check lengths now rather than later. */
/*    *\/ */
/*   tot_len = 0; */
/*   for (p = protos; *p != NULL; p++) */
/*     { */
/*       cur_len = strlen (*p); */
/*       tot_len += cur_len; */

/*       if (cur_len == 0 || cur_len > 255 || tot_len > 65535) */
/*         return gpg_error (GPG_ERR_INV_ARG); */
/*     } */

/*   ssl->alpn_list = protos; */

/*   return (0); */
/* } */

/* const char * */
/* ssl_get_alpn_protocol (const ntbtls_t ssl) */
/* { */
/*   return (ssl->alpn_chosen); */
/* } */


/* void */
/* ssl_set_max_version (ntbtls_t ssl, int major, int minor) */
/* { */
/*   if (   major >= TLS_MIN_MAJOR_VERSION && major <= TLS_MAX_MAJOR_VERSION */
/*       && minor >= TLS_MIN_MINOR_VERSION && minor <= TLS_MAX_MINOR_VERSION) */
/*     { */
/*       ssl->max_major_ver = major; */
/*       ssl->max_minor_ver = minor; */
/*     } */
/* } */


/* void */
/* ssl_set_min_version (ntbtls_t ssl, int major, int minor) */
/* { */
/*   if (   major >= TLS_MIN_MAJOR_VERSION && major <= TLS_MAX_MAJOR_VERSION */
/*       && minor >= TLS_MIN_MINOR_VERSION && minor <= TLS_MAX_MINOR_VERSION) */
/*     { */
/*       ssl->min_major_ver = major; */
/*       ssl->min_minor_ver = minor; */
/*     } */
/* } */


int
ssl_set_max_frag_len (ntbtls_t ssl, unsigned char mfl_code)
{
  if (mfl_code >= DIM(mfl_code_to_length)
      || mfl_code_to_length[mfl_code] > TLS_MAX_CONTENT_LEN)
    {
      return gpg_error (GPG_ERR_INV_ARG);
    }

  ssl->mfl_code = mfl_code;

  return (0);
}


int
ssl_set_truncated_hmac (ntbtls_t ssl, int truncate)
{
  if (!ssl->is_client)
    return gpg_error (GPG_ERR_INV_ARG);

  ssl->use_trunc_hmac = !!truncate;

  return 0;
}


void
ssl_set_renegotiation (ntbtls_t ssl, int renegotiation)
{
  ssl->disable_renegotiation = renegotiation;
}

void
ssl_legacy_renegotiation (ntbtls_t ssl, int allow_legacy)
{
  ssl->allow_legacy_renegotiation = allow_legacy;
}

void
ssl_set_renegotiation_enforced (ntbtls_t ssl, int max_records)
{
  ssl->renego_max_records = max_records;
}


int
_ntbtls_set_session_tickets (ntbtls_t tls, int use_tickets)
{
  tls->use_session_tickets = !!use_tickets;

  if (tls->is_client)
    return 0;

  return ticket_keys_setup (tls);
}

void
ssl_set_session_ticket_lifetime (ntbtls_t ssl, int lifetime)
{
  ssl->ticket_lifetime = lifetime;
}


/*
 * SSL get accessors
 */
size_t
ssl_get_bytes_avail (const ntbtls_t ssl)
{
  return (ssl->in_offt == NULL ? 0 : ssl->in_msglen);
}

int
ssl_get_verify_result (const ntbtls_t ssl)
{
  return (ssl->session->verify_result);
}


/*
 * Return the name of the current ciphersuite
 */
const char *
_ntbtls_get_ciphersuite (const ntbtls_t tls)
{
  if (!tls || !tls->session)
    return NULL;

  return _ntbtls_ciphersuite_get_name (tls->session->ciphersuite);
}


/* const x509_crt * */
/* ssl_get_peer_chain (const ntbtls_t ssl) */
/* { */
/*   if (ssl == NULL || ssl->session == NULL) */
/*     return (NULL); */

/*   return (ssl->session->peer_chain); */
/* } */


/* Save session in order to resume it later (client-side only).
   Session data is copied to presented session structure.  */
gpg_error_t
_ntbtls_get_session (const ntbtls_t tls, session_t dst)
{
  if (!tls || !dst || !tls->session || !tls->is_client)
    {
      return gpg_error (GPG_ERR_INV_ARG);
    }

  return session_copy (dst, tls->session);
}


/*
 * Perform a single step of the SSL handshake
 */
static gpg_error_t
handshake_step (ntbtls_t tls)
{
  gpg_error_t err;

  if (tls->is_client)
    err = _ntbtls_handshake_client_step (tls);
  else
    err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
          /*_ntbtls_handshake_server_step (tls);*/

  return err;
}


/*
 * Perform the SSL handshake
 */
gpg_error_t
_ntbtls_handshake (ntbtls_t tls)
{
  gpg_error_t err = 0;

  debug_msg (2, "handshake");

  while (tls->state != TLS_HANDSHAKE_OVER)
    {
      err = handshake_step (tls);
      if (err)
        break;
    }

  debug_msg (2, "handshake ready");

  return err;
}


/*
 * Write HelloRequest to request renegotiation on server
 */
static int
write_hello_request (ntbtls_t ssl)
{
  int ret;

  debug_msg (2, "write hello_request");

  ssl->out_msglen = 4;
  ssl->out_msgtype = TLS_MSG_HANDSHAKE;
  ssl->out_msg[0] = TLS_HS_HELLO_REQUEST;

  ret = _ntbtls_write_record (ssl);
  if (ret)
    {
      debug_ret (1, "write_record", ret);
      return ret;
    }

  ssl->renegotiation = TLS_RENEGOTIATION_PENDING;

  return (0);
}


/*
 * Actually renegotiate current connection, triggered by either:
 * - calling ssl_renegotiate() on client,
 * - receiving a HelloRequest on client during ssl_read(),
 * - receiving any handshake message on server during ssl_read() after the
 *   initial handshake is completed
 * If the handshake doesn't complete due to waiting for I/O, it will continue
 * during the next calls to ssl_renegotiate() or ssl_read() respectively.
 */
static gpg_error_t
start_renegotiation (ntbtls_t tls)
{
  gpg_error_t err;

  debug_msg (2, "renegotiate");

  err = handshake_init (tls);
  if (err)
    return err;

  tls->state = TLS_HELLO_REQUEST;
  tls->renegotiation = TLS_RENEGOTIATION;

  err = _ntbtls_handshake (tls);
  if (err)
    {
      debug_ret (1, "handshake", err);
      return err;
    }

  return 0;
}


/*
 * Renegotiate current connection on client,
 * or request renegotiation on server
 */
int
ssl_renegotiate (ntbtls_t ssl)
{
  int ret = gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  /* On server, just send the request */
  if (!ssl->is_client)
    {
      if (ssl->state != TLS_HANDSHAKE_OVER)
        return gpg_error (GPG_ERR_INV_ARG);

      return write_hello_request (ssl);
    }

  /*
   * On client, either start the renegotiation process or,
   * if already in progress, continue the handshake
   */
  if (ssl->renegotiation != TLS_RENEGOTIATION)
    {
      if (ssl->state != TLS_HANDSHAKE_OVER)
        return gpg_error (GPG_ERR_INV_ARG);

      if ((ret = start_renegotiation (ssl)) != 0)
        {
          debug_ret (1, "start_renegotiation", ret);
          return (ret);
        }
    }
  else
    {
      if ((ret = _ntbtls_handshake (ssl)) != 0)
        {
          debug_ret (1, "handshake", ret);
          return (ret);
        }
    }

  return (ret);
}


/*
 * Notify the peer that the connection is being closed
 */
gpg_error_t
_ntbtls_close_notify (ntbtls_t tls)
{
  gpg_error_t err;

  debug_msg (2, "write close_notify");

  err = _ntbtls_flush_output (tls);
  if (err)
    {
      debug_ret (1, "flush_output", err);
      return err;
    }

  if (tls->state == TLS_HANDSHAKE_OVER)
    {
      err = _ntbtls_send_alert_message (tls, TLS_ALERT_LEVEL_WARNING,
                                        TLS_ALERT_MSG_CLOSE_NOTIFY);
      if (err)
        return err;
    }

  return err;
}


/* static void */
/* ssl_key_cert_free (ssl_key_cert * key_cert) */
/* { */
/*   ssl_key_cert *cur = key_cert, *next; */

/*   while (cur != NULL) */
/*     { */
/*       next = cur->next; */

/*       if (cur->key_own_alloc) */
/*         { */
/*           pk_free (cur->key); */
/*           polarssl_free (cur->key); */
/*         } */
/*       polarssl_free (cur); */

/*       cur = next; */
/*     } */
/* } */


/*
 * Map gcrypt algo number to TLS algo number, return ANON if the algo
 * is not supported.
 */
//FIXME:
// unsigned char
// ssl_sig_from_pk (pk_context * pk)
// {
//   if (pk_can_do (pk, POLARSSL_PK_RSA))
//     return (SSL_SIG_RSA);
// #endif
// #if defined(POLARSSL_ECDSA_C)
//   if (pk_can_do (pk, POLARSSL_PK_ECDSA))
//     return (SSL_SIG_ECDSA);
// #endif
//   return (SSL_SIG_ANON);
// }


/*
 * Map TLS signature algorithm number to a gcrypt algo number.
 */
pk_algo_t
_ntbtls_pk_alg_from_sig (unsigned char sig)
{
  switch (sig)
    {
    case TLS_SIG_ANON:   return 0;
    case TLS_SIG_RSA:    return GCRY_PK_RSA;
    case TLS_SIG_ECDSA:  return GCRY_PK_ECC;
    }
  return 0;
}


/*
 * Map TLS hash algorithm number to a gcrypt algo number.
 */
md_algo_t
_ntbtls_md_alg_from_hash (unsigned char hash)
{
  switch (hash)
    {
    case TLS_HASH_SHA1:   return GCRY_MD_SHA1;
    case TLS_HASH_SHA224: return GCRY_MD_SHA224;
    case TLS_HASH_SHA256: return GCRY_MD_SHA256;
    case TLS_HASH_SHA384: return GCRY_MD_SHA384;
    case TLS_HASH_SHA512: return GCRY_MD_SHA512;
    }
  return 0;
}


/*
 * Check is a curve proposed by the peer is in our list.
 * Return 1 if we're willing to use it, 0 otherwise.
 */
/* int */
/* ssl_curve_is_acceptable (const ntbtls_t ssl, ecp_group_id grp_id) */
/* { */
/*   const ecp_group_id *gid; */

/*   for (gid = ssl->curve_list; *gid != POLARSSL_ECP_DP_NONE; gid++) */
/*     if (*gid == grp_id) */
/*       return (1); */

/*   return (0); */
/* } */


/* int */
/* ssl_check_cert_usage (const x509_crt * cert, */
/*                       const ssl_ciphersuite_t * ciphersuite, */
/*                       int is_client) */
/* { */
/*   int usage = 0; */
/*   const char *ext_oid; */
/*   size_t ext_len; */

/*   if (!is_client) */
/*     { */
/*       /\* Server part of the key exchange *\/ */
/*       switch (ciphersuite->key_exchange) */
/*         { */
/*         case KEY_EXCHANGE_RSA: */
/*         case KEY_EXCHANGE_RSA_PSK: */
/*           usage = KU_KEY_ENCIPHERMENT; */
/*           break; */

/*         case KEY_EXCHANGE_DHE_RSA: */
/*         case KEY_EXCHANGE_ECDHE_RSA: */
/*         case KEY_EXCHANGE_ECDHE_ECDSA: */
/*           usage = KU_DIGITAL_SIGNATURE; */
/*           break; */

/*         case KEY_EXCHANGE_ECDH_RSA: */
/*         case KEY_EXCHANGE_ECDH_ECDSA: */
/*           usage = KU_KEY_AGREEMENT; */
/*           break; */

/*           /\* Don't use default: we want warnings when adding new values *\/ */
/*         case KEY_EXCHANGE_NONE: */
/*         case KEY_EXCHANGE_PSK: */
/*         case KEY_EXCHANGE_DHE_PSK: */
/*         case KEY_EXCHANGE_ECDHE_PSK: */
/*           usage = 0; */
/*           break; */
/*         } */
/*     } */
/*   else */
/*     { */
/*       /\* Client auth: we only implement rsa_sign and ecdsa_sign for now *\/ */
/*       usage = KU_DIGITAL_SIGNATURE; */
/*     } */

/*   if (x509_crt_check_key_usage (cert, usage) != 0) */
/*     return (-1); */

/*   if (!is_client) */
/*     { */
/*       ext_oid = OID_SERVER_AUTH; */
/*       ext_len = OID_SIZE (OID_SERVER_AUTH); */
/*     } */
/*   else */
/*     { */
/*       ext_oid = OID_CLIENT_AUTH; */
/*       ext_len = OID_SIZE (OID_CLIENT_AUTH); */
/*     } */

/*   if (x509_crt_check_extended_key_usage (cert, ext_oid, ext_len) != 0) */
/*     return (-1); */

/*   return (0); */
/* } */


/*
 * Receive application data decrypted from the SSL layer
 */
static gpg_error_t
tls_read (ntbtls_t tls, unsigned char *buf, size_t len, size_t *nread)
{
  gpg_error_t err;
  size_t n;

  *nread = 0;

  debug_msg (2, "tls read");

  if (tls->state != TLS_HANDSHAKE_OVER)
    {
      err = _ntbtls_handshake (tls);
      if (err)
        {
          debug_ret (1, "handshake", err);
          return err;
        }
    }

  if (!tls->in_offt)
    {
      err = _ntbtls_read_record (tls);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EOF)
            return 0;

          debug_ret (1, "read_record", err);
          return err;
        }

      if (!tls->in_msglen && tls->in_msgtype == TLS_MSG_APPLICATION_DATA)
        {
          /*
           * OpenSSL sends empty messages to randomize the IV
           */
          err = _ntbtls_read_record (tls);
          if (err)
            {
              if (gpg_err_code (err) == GPG_ERR_EOF)
                return 0;

              debug_ret (1, "read_record", err);
              return err;
            }
        }

      if (tls->in_msgtype == TLS_MSG_HANDSHAKE)
        {
          debug_msg (1, "received handshake message");

          if (tls->is_client
              && (tls->in_msg[0] != TLS_HS_HELLO_REQUEST || tls->in_hslen != 4))
            {
              debug_msg (1, "handshake received (not HelloRequest)");
              return gpg_error (GPG_ERR_UNEXPECTED_MSG);
            }

          if (tls->disable_renegotiation == TLS_RENEGOTIATION_DISABLED
              || (tls->secure_renegotiation == TLS_LEGACY_RENEGOTIATION
                  && (tls->allow_legacy_renegotiation
                      == TLS_LEGACY_NO_RENEGOTIATION)))
            {
              debug_msg (3, "ignoring renegotiation, sending alert");

              if (tls->minor_ver >= TLS_MINOR_VERSION_1)
                {
                  err = _ntbtls_send_alert_message
                    (tls, TLS_ALERT_LEVEL_WARNING,
                     TLS_ALERT_MSG_NO_RENEGOTIATION);
                  if (err)
                    {
                      return err;
                    }
                }
              else
                {
                  debug_bug ();
                  return gpg_error (GPG_ERR_INTERNAL);
                }
            }
          else
            {
              err = start_renegotiation (tls);
              if (err)
                {
                  debug_ret (1, "start_renegotiation", err);
                  return err;
                }

              return gpg_error (GPG_ERR_EAGAIN);
            }
        }
      else if (tls->renegotiation == TLS_RENEGOTIATION_PENDING)
        {
          tls->renego_records_seen++;

          if (tls->renego_max_records >= 0
              && tls->renego_records_seen > tls->renego_max_records)
            {
              debug_msg (1, "renegotiation requested, "
                         "but not honored by client");
              return gpg_error (GPG_ERR_UNEXPECTED_MSG);
            }
        }
      else if (tls->in_msgtype != TLS_MSG_APPLICATION_DATA)
        {
          debug_msg (1, "bad application data message");
          return gpg_error (GPG_ERR_UNEXPECTED_MSG);
        }

      tls->in_offt = tls->in_msg;
    }

  if (!len) /* Check only for pending bytes.  */
    {
      return tls->in_msglen? 0 : gpg_error (GPG_ERR_EOF);
    }

  n = (len < tls->in_msglen) ? len : tls->in_msglen;

  memcpy (buf, tls->in_offt, n);
  tls->in_msglen -= n;

  if (!tls->in_msglen) /* All bytes consumed.  */
    tls->in_offt = NULL;
  else /* More data available.  */
    tls->in_offt += n;

  debug_msg (2, "tls read ready");

  *nread = n;
  return 0;
}


/*
 * Send application data to be encrypted by the TLS layer.
 */
static gpg_error_t
tls_write (ntbtls_t tls, const unsigned char *buf, size_t len, size_t *nwritten)
{
  gpg_error_t err;
  size_t n;
  unsigned int max_len = TLS_MAX_CONTENT_LEN;

  *nwritten = 0;

  debug_msg (2, "tls write");

  if (tls->state != TLS_HANDSHAKE_OVER)
    {
      err = _ntbtls_handshake (tls);
      if (err)
        {
          debug_ret (1, "handshake", err);
          return err;
        }
    }

  /*
   * Assume mfl_code is correct since it was checked when set
   */
  max_len = mfl_code_to_length[tls->mfl_code];

  /*
   * Check if a smaller max length was negotiated
   */
  if (tls->session_out
      && mfl_code_to_length[tls->session_out->mfl_code] < max_len)
    {
      max_len = mfl_code_to_length[tls->session_out->mfl_code];
    }

  n = (len < max_len) ? len : max_len;

  if (tls->out_left)
    {
      err = _ntbtls_flush_output (tls);
      if (err)
        {
          debug_ret (1, "flush_output", err);
          return err;
        }
    }
  else
    {
      tls->out_msglen = n;
      tls->out_msgtype = TLS_MSG_APPLICATION_DATA;
      memcpy (tls->out_msg, buf, n);

      err = _ntbtls_write_record (tls);
      if (err)
        {
          debug_ret (1, "write_record", err);
          return err;
        }
    }

  debug_msg (2, "tls write ready");

  *nwritten = n;
  return 0;
}



/* Read handler for estream.  */
static gpgrt_ssize_t
cookie_read (void *cookie, void *buffer, size_t size)
{
  ntbtls_t tls = cookie;
  gpg_error_t err;
  size_t nread;

 again:
  err = tls_read (tls, buffer, size, &nread);
  if (err)
    {
      if (gpg_err_code (err) == GPG_ERR_EAGAIN
          && gpg_err_source (err) == GPG_ERR_SOURCE_TLS)
        goto again; /* I.e. renegotiation.  */
      if (!size && gpg_err_code (err) == GPG_ERR_EOF)
        return -1; /* Nope, no pending bytes.  */

      debug_ret (1, "tls_read", err);
      /* Fixme: We shoud extend estream to allow setting extended
         errors.  */
      gpg_err_set_errno (EIO);
      return -1;
    }
  else if (!size)
    nread = 0; /* Yep, there are pending bytes.  */

  return nread;
}


/* Write handler for estream.  */
static gpgrt_ssize_t
cookie_write (void *cookie, const void *buffer_arg, size_t size)
{
  ntbtls_t tls = cookie;
  const char *buffer = buffer_arg;
  gpg_error_t err;
  size_t nwritten = 0;
  int nleft = size;

 again:
  while (nleft > 0)
    {
      err = tls_write (tls, buffer, nleft, &nwritten);
      if (err)
        {
          if (gpg_err_code (err) == GPG_ERR_EAGAIN
              && gpg_err_source (err) == GPG_ERR_SOURCE_TLS)
            goto again; /* I.e. renegotiation.  */
          debug_ret (1, "tls_write", err);
          gpg_err_set_errno (EIO);
          return -1;
        }
      nleft -= nwritten;
      buffer += nwritten;
    }

  return nwritten;
}


static gpgrt_cookie_io_functions_t cookie_functions =
  {
    cookie_read,
    cookie_write,
    NULL,
    NULL
  };


/* Return the two streams used to read and write the plaintext.  The
   streams are valid as long as TLS is valid and may thus not be used
   after TLS has been destroyed.  Note: After adding a "fullduplex"
   feature to estream we will allow to pass NULL for r_writefp to
   make use of that feature.  */
gpg_error_t
_ntbtls_get_stream (ntbtls_t tls, estream_t *r_readfp, estream_t *r_writefp)
{
  gpg_error_t err;

  if (!tls || !r_readfp || !r_writefp)
    return gpg_error (GPG_ERR_INV_ARG);

  *r_readfp = NULL;
  *r_writefp = NULL;

  if ((!tls->readfp ^ !tls->writefp))
    return gpg_error (GPG_ERR_INTERNAL);

  if (!tls->readfp)
    {
      if ((tls->flags & NTBTLS_SAMETRHEAD))
        tls->readfp = es_fopencookie (tls, "r,samethread", cookie_functions);
      else
        tls->readfp = es_fopencookie (tls, "r", cookie_functions);
      if (!tls->readfp)
        {
          err = gpg_error_from_syserror ();
          return err;
        }
    }

  if (!tls->writefp)
    {
      if ((tls->flags & NTBTLS_SAMETRHEAD))
        tls->writefp = es_fopencookie (tls, "w,samethread", cookie_functions);
      else
        tls->writefp = es_fopencookie (tls, "w", cookie_functions);
      if (!tls->writefp)
        {
          err = gpg_error_from_syserror ();
          es_fclose  (tls->readfp);
          tls->readfp = NULL;
          return err;
        }
    }

  *r_readfp = tls->readfp;
  *r_writefp = tls->writefp;

  return 0;
}
