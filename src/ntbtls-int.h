/* ntbtls-int.h - Internal version of ntbtls.h
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

#ifndef NTBTLS_NTBTLS_INT_H
#define NTBTLS_NTBTLS_INT_H

#ifdef _NTBTLS_H
#error ntbtls.h already included
#endif

#include <gcrypt.h>

#include "ntbtls.h"
#include "util.h"

/*
 * Macros to help building with different crypto library versions.
 */
#undef SUPPORT_X25519
#undef SUPPORT_X448
#if GCRYPT_VERSION_NUMBER >= 0x010900  /* >= 1.9 */
#define SUPPORT_X25519 1
#define SUPPORT_X448 1
#endif


/*
 * Various constants
 */
#define TLS_MAJOR_VERSION_3             3
#define TLS_MINOR_VERSION_0             0       /* SSL v3.0 */
#define TLS_MINOR_VERSION_1             1       /* TLS v1.0 */
#define TLS_MINOR_VERSION_2             2       /* TLS v1.1 */
#define TLS_MINOR_VERSION_3             3       /* TLS v1.2 */

/* Define minimum and maximum supported versions.  This is currently
   TLS v1.2 only but we may support newer versions of TLS as soon as
   they are standardized. */
#define TLS_MIN_MAJOR_VERSION           TLS_MAJOR_VERSION_3
#define TLS_MIN_MINOR_VERSION           TLS_MINOR_VERSION_3
#define TLS_MAX_MAJOR_VERSION           TLS_MAJOR_VERSION_3
#define TLS_MAX_MINOR_VERSION           TLS_MINOR_VERSION_3


#define TLS_RENEGO_MAX_RECORDS_DEFAULT  16


#define TLS_RENEGOTIATION_DISABLED      0
#define TLS_RENEGOTIATION_ENABLED       1
#define TLS_RENEGOTIATION_NOT_ENFORCED  -1

#define TLS_COMPRESS_NULL               0
#define TLS_COMPRESS_DEFLATE            1

#define TLS_VERIFY_NONE                 0
#define TLS_VERIFY_OPTIONAL             1
#define TLS_VERIFY_REQUIRED             2

#define TLS_LEGACY_RENEGOTIATION        0
#define TLS_SECURE_RENEGOTIATION        1

#define TLS_LEGACY_NO_RENEGOTIATION     0
#define TLS_LEGACY_ALLOW_RENEGOTIATION  1
#define TLS_LEGACY_BREAK_HANDSHAKE      2

#define TLS_TRUNCATED_HMAC_LEN          10 /* 80 bits, rfc 6066 section 7 */


/* Lifetime of session tickets in seconds.  */
#define TLS_DEFAULT_TICKET_LIFETIME  86400

/* Maximum size of a MAC.  */
#define TLS_MAX_MAC_SIZE   48


/*
 * Size of the input/output buffer.  Note: the RFC defines the default
 * size of TLS messages.  If you change the value here, other
 * clients/servers may not be able to communicate with you anymore.
 * Only change this value if you control both sides of the connection
 * and have it reduced at both sides, or if you're using the Max
 * Fragment Length extension and you know all your peers are using it
 * too!
 */
#define TLS_MAX_CONTENT_LEN  16384

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#define TLS_COMPRESSION_ADD 1024
#define TLS_MAC_ADD           48  /* SHA-384 used for HMAC */
#define TLS_PADDING_ADD      256
#define TLS_BUFFER_LEN  (TLS_MAX_CONTENT_LEN                    \
                         + TLS_COMPRESSION_ADD                  \
                         + 29 /* counter + header + IV */       \
                         + TLS_MAC_ADD                          \
                         + TLS_PADDING_ADD                      \
                         )

/*
 * The size of the premaster secret.
 */

#define TLS_MPI_MAX_SIZE  512   /* 4096 bits */

#define TLS_ECP_MAX_BITS  521
#define TLS_ECP_MAX_BYTES ((TLS_ECP_MAX_BITS + 7)/8)

#define TLS_PSK_MAX_LEN   32    /* 256 bits */


/* Dummy type used only for its size */
union premaster_secret_u
{
  unsigned char _pms_rsa[48];                           /* RFC 5246 8.1.1 */
  unsigned char _pms_dhm[TLS_MPI_MAX_SIZE];             /* RFC 5246 8.1.2 */
  unsigned char _pms_ecdh[TLS_ECP_MAX_BYTES];           /* RFC 4492 5.10 */
  unsigned char _pms_psk[4 + 2 * TLS_PSK_MAX_LEN];      /* RFC 4279 2 */
  unsigned char _pms_dhe_psk[4 + TLS_MPI_MAX_SIZE
                             + TLS_PSK_MAX_LEN];        /* RFC 4279 3 */
  unsigned char _pms_rsa_psk[52 + TLS_PSK_MAX_LEN];     /* RFC 4279 4 */
  unsigned char _pms_ecdhe_psk[4 + TLS_ECP_MAX_BYTES
                               + TLS_PSK_MAX_LEN];      /* RFC 5489 2 */
};
#define TLS_PREMASTER_SIZE     sizeof( union premaster_secret_u )


/* RFC 6066 section 4, see also mfl_code_to_length in protocol.c.
 * NONE must be zero so that memset()ing structure to zero works. */
#define TLS_MAX_FRAG_LEN_NONE           0  /*!< don't use this extension   */
#define TLS_MAX_FRAG_LEN_512            1  /*!< MaxFragmentLength 2^9      */
#define TLS_MAX_FRAG_LEN_1024           2  /*!< MaxFragmentLength 2^10     */
#define TLS_MAX_FRAG_LEN_2048           3  /*!< MaxFragmentLength 2^11     */
#define TLS_MAX_FRAG_LEN_4096           4  /*!< MaxFragmentLength 2^12     */


/*
 * Supported hash and signature algorithms (for TLS 1.2).
 * RFC 5246 section 7.4.1.4.1
 */
#define TLS_HASH_NONE                0
#define TLS_HASH_SHA1                2
#define TLS_HASH_SHA224              3
#define TLS_HASH_SHA256              4
#define TLS_HASH_SHA384              5
#define TLS_HASH_SHA512              6

#define TLS_SIG_ANON                 0
#define TLS_SIG_RSA                  1
#define TLS_SIG_ECDSA                3

/*
 * Client Certificate Types
 * RFC 5246 section 7.4.4 plus RFC 4492 section 5.5
 */
#define TLS_CERT_TYPE_RSA_SIGN       1
#define TLS_CERT_TYPE_ECDSA_SIGN    64

/*
 * Message, alert and handshake types
 */
#define TLS_MSG_CHANGE_CIPHER_SPEC     20
#define TLS_MSG_ALERT                  21
#define TLS_MSG_HANDSHAKE              22
#define TLS_MSG_APPLICATION_DATA       23

#define TLS_ALERT_LEVEL_WARNING         1
#define TLS_ALERT_LEVEL_FATAL           2

#define TLS_ALERT_MSG_CLOSE_NOTIFY              0  /* 0x00 */
#define TLS_ALERT_MSG_UNEXPECTED_MESSAGE       10  /* 0x0A */
#define TLS_ALERT_MSG_BAD_RECORD_MAC           20  /* 0x14 */
#define TLS_ALERT_MSG_DECRYPTION_FAILED        21  /* 0x15 */
#define TLS_ALERT_MSG_RECORD_OVERFLOW          22  /* 0x16 */
#define TLS_ALERT_MSG_DECOMPRESSION_FAILURE    30  /* 0x1E */
#define TLS_ALERT_MSG_HANDSHAKE_FAILURE        40  /* 0x28 */
#define TLS_ALERT_MSG_NO_CERT                  41  /* 0x29 */
#define TLS_ALERT_MSG_BAD_CERT                 42  /* 0x2A */
#define TLS_ALERT_MSG_UNSUPPORTED_CERT         43  /* 0x2B */
#define TLS_ALERT_MSG_CERT_REVOKED             44  /* 0x2C */
#define TLS_ALERT_MSG_CERT_EXPIRED             45  /* 0x2D */
#define TLS_ALERT_MSG_CERT_UNKNOWN             46  /* 0x2E */
#define TLS_ALERT_MSG_ILLEGAL_PARAMETER        47  /* 0x2F */
#define TLS_ALERT_MSG_UNKNOWN_CA               48  /* 0x30 */
#define TLS_ALERT_MSG_ACCESS_DENIED            49  /* 0x31 */
#define TLS_ALERT_MSG_DECODE_ERROR             50  /* 0x32 */
#define TLS_ALERT_MSG_DECRYPT_ERROR            51  /* 0x33 */
#define TLS_ALERT_MSG_EXPORT_RESTRICTION       60  /* 0x3C */
#define TLS_ALERT_MSG_PROTOCOL_VERSION         70  /* 0x46 */
#define TLS_ALERT_MSG_INSUFFICIENT_SECURITY    71  /* 0x47 */
#define TLS_ALERT_MSG_INTERNAL_ERROR           80  /* 0x50 */
#define TLS_ALERT_MSG_USER_CANCELED            90  /* 0x5A */
#define TLS_ALERT_MSG_NO_RENEGOTIATION        100  /* 0x64 */
#define TLS_ALERT_MSG_UNSUPPORTED_EXT         110  /* 0x6E */
#define TLS_ALERT_MSG_UNRECOGNIZED_NAME       112  /* 0x70 */
#define TLS_ALERT_MSG_UNKNOWN_PSK_IDENTITY    115  /* 0x73 */
#define TLS_ALERT_MSG_NO_APPLICATION_PROTOCOL 120  /* 0x78 */

#define TLS_HS_HELLO_REQUEST            0
#define TLS_HS_CLIENT_HELLO             1
#define TLS_HS_SERVER_HELLO             2
#define TLS_HS_NEW_SESSION_TICKET       4
#define TLS_HS_CERTIFICATE             11
#define TLS_HS_SERVER_KEY_EXCHANGE     12
#define TLS_HS_CERTIFICATE_REQUEST     13
#define TLS_HS_SERVER_HELLO_DONE       14
#define TLS_HS_CERTIFICATE_VERIFY      15
#define TLS_HS_CLIENT_KEY_EXCHANGE     16
#define TLS_HS_FINISHED                20

/*
 * TLS extensions
 */
#define TLS_EXT_SERVERNAME                   0
#define TLS_EXT_MAX_FRAGMENT_LENGTH          1
#define TLS_EXT_TRUNCATED_HMAC               4
#define TLS_EXT_SUPPORTED_ELLIPTIC_CURVES   10
#define TLS_EXT_SUPPORTED_POINT_FORMATS     11
#define TLS_EXT_SIG_ALG                     13
#define TLS_EXT_ALPN                        16
#define TLS_EXT_SESSION_TICKET              35
#define TLS_EXT_RENEGOTIATION_INFO      0xFF01

/* TLS extension flags (for extensions with outgoing ServerHello
 * content that need it (e.g. for RENEGOTIATION_INFO the server
 * already knows because of state of the renegotiation flag, so no
 * indicator is required).  */
#define TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)


/*
 * Signaling ciphersuite values (SCSV)
 */
#define TLS_EMPTY_RENEGOTIATION_INFO    0xFF



/*
 * The structure definitions are in a separate file.
 */

#include "context.h"

/*
 *  Inline functions etc.
 */

/* Return the private key object from the context object or NULL if
   there is none.  */
static inline x509_privkey_t
tls_own_key (ntbtls_t tls)
{
  return tls->handshake->key_cert? tls->handshake->key_cert->key : NULL;
}


/* Return the certifciate key object from the context object or NULL
   if there is none.  */
static inline x509_cert_t
tls_own_cert (ntbtls_t tls)
{
  return tls->handshake->key_cert? tls->handshake->key_cert->cert : NULL;
}




/*
 * Prototypes
 */

/*-- util.c --*/
const char *_ntbtls_check_version (const char *req_version);
char *_ntbtls_trim_trailing_spaces (char *string);
int _ntbtls_ascii_strcasecmp (const char *a, const char *b);

/*-- protocol.c --*/
const char *_ntbtls_state2str (tls_state_t state);

gpg_error_t _ntbtls_fetch_input (ntbtls_t tls, size_t nb_want);
gpg_error_t _ntbtls_flush_output (ntbtls_t tls);

gpg_error_t _ntbtls_write_record (ntbtls_t tls);
gpg_error_t _ntbtls_read_record (ntbtls_t tls);
gpg_error_t _ntbtls_send_fatal_handshake_failure (ntbtls_t tls);
gpg_error_t _ntbtls_send_alert_message (ntbtls_t tls, unsigned char level,
                                        unsigned char message);

pk_algo_t _ntbtls_pk_alg_from_sig (unsigned char sig);
md_algo_t _ntbtls_md_alg_from_hash (unsigned char hash);

gpg_error_t _ntbtls_derive_keys (ntbtls_t tls);

void _ntbtls_optimize_checksum (ntbtls_t tls,
                                const ciphersuite_t ciphersuite_info);

gpg_error_t _ntbtls_psk_derive_premaster (ntbtls_t tls,
                                          key_exchange_type_t kex);
gpg_error_t _ntbtls_write_certificate (ntbtls_t tls);
gpg_error_t _ntbtls_read_certificate (ntbtls_t tls);
gpg_error_t _ntbtls_write_change_cipher_spec (ntbtls_t tls);
gpg_error_t _ntbtls_read_change_cipher_spec (ntbtls_t tls);
gpg_error_t _ntbtls_write_finished (ntbtls_t tls);
gpg_error_t _ntbtls_read_finished (ntbtls_t tls);

void _ntbtls_handshake_wrapup (ntbtls_t tls);


/* Functions directly used by the public API.  */
gpg_error_t _ntbtls_new (ntbtls_t *r_tls, unsigned int flags);
void _ntbtls_release (ntbtls_t tls);

const char *_ntbtls_get_last_alert (ntbtls_t tls, unsigned int *r_level,
                                    unsigned int *r_type);
gpg_error_t _ntbtls_set_transport (ntbtls_t tls,
                                   gpgrt_stream_t inbound,
                                   gpgrt_stream_t outbound);
gpg_error_t _ntbtls_get_stream (ntbtls_t tls,
                                gpgrt_stream_t *r_readfp,
                                gpgrt_stream_t *r_writefp);

gpg_error_t _ntbtls_set_verify_cb (ntbtls_t tls,
                                   ntbtls_verify_cb_t cb, void *cb_value);

gpg_error_t _ntbtls_set_hostname (ntbtls_t tls, const char *hostname);
const char *_ntbtls_get_hostname (ntbtls_t tls);

gpg_error_t _ntbtls_handshake (ntbtls_t tls);



/*-- protocol-srv.c --*/
gpg_error_t _ntbtls_handshake_server_step (ntbtls_t tls);

/*-- protocol-cli.c --*/
gpg_error_t _ntbtls_handshake_client_step (ntbtls_t tls);


/*-- pkglue.c --*/
gpg_error_t _ntbtls_pk_verify (x509_cert_t chain,
                               pk_algo_t pk_alg, md_algo_t md_alg,
                               const unsigned char *hash, size_t hashlen,
                               const unsigned char *sig, size_t siglen);

gpg_error_t _ntbtls_pk_encrypt (x509_cert_t chain, const unsigned char *input,
                                size_t ilen, unsigned char *output,
                                size_t *olen, size_t osize);

/*-- x509.c --*/

/*
 *X509 Verify codes  - FIXME: Replace them by ksba stuff.
 */
#define BADCERT_EXPIRED             0x01  /* The certificate validity has expired. */
#define BADCERT_REVOKED             0x02  /* The certificate has been revoked (is on a CRL). */
#define BADCERT_CN_MISMATCH         0x04  /* The certificate Common Name (CN) does not match with the expected CN. */
#define BADCERT_NOT_TRUSTED         0x08  /* The certificate is not correctly signed by the trusted CA. */
#define BADCRL_NOT_TRUSTED          0x10  /* CRL is not correctly signed by the trusted CA. */
#define BADCRL_EXPIRED              0x20  /* CRL is expired. */
#define BADCERT_MISSING             0x40  /* Certificate was missing. */
#define BADCERT_SKIP_VERIFY         0x80  /* Certificate verification was skipped. */
#define BADCERT_OTHER             0x0100  /* Other reason (can be used by verify callback) */
#define BADCERT_FUTURE            0x0200  /* The certificate validity starts in the future. */
#define BADCRL_FUTURE             0x0400  /* The CRL is from the future */


gpg_error_t _ntbtls_x509_cert_new (x509_cert_t *r_cert);
void _ntbtls_x509_cert_release (x509_cert_t crt);
gpg_error_t _ntbtls_x509_append_cert (x509_cert_t cert,
                                      const void *der, size_t derlen);
void _ntbtls_x509_log_cert (const char *text, x509_cert_t chain, int full);
const unsigned char *_ntbtls_x509_get_cert (x509_cert_t cert, int idx,
                                            size_t *r_derlen);
ksba_cert_t _ntbtls_x509_get_peer_cert (ntbtls_t tls, int idx);
gpg_error_t _ntbtls_x509_get_pk (x509_cert_t cert, int idx, gcry_sexp_t *r_pk);


int _ntbtls_x509_can_do (x509_privkey_t privkey, pk_algo_t pkalgo);

gpg_error_t _ntbtls_x509_check_hostname (x509_cert_t cert,
                                         const char *hostname);


/*-- dhm.c --*/
gpg_error_t _ntbtls_dhm_new (dhm_context_t *r_dhm);
void _ntbtls_dhm_release (dhm_context_t dhm);
gpg_error_t _ntbtls_dhm_read_params (dhm_context_t dhm,
                                     const void *der, size_t derlen,
                                     size_t *r_nparsed);
unsigned int _ntbtls_dhm_get_nbits (dhm_context_t dhm);
gpg_error_t _ntbtls_dhm_make_public (dhm_context_t dhm,
                                     unsigned char *outbuf, size_t outbufsize,
                                     size_t *r_outbuflen);
gpg_error_t _ntbtls_dhm_calc_secret (dhm_context_t dhm,
                                     unsigned char *outbuf, size_t outbufsize,
                                     size_t *r_outbuflen);

/*-- ecdh.c --*/
gpg_error_t _ntbtls_ecdh_new (ecdh_context_t *r_ecdh);
void _ntbtls_ecdh_release (ecdh_context_t ecdh);
gpg_error_t _ntbtls_ecdh_read_params (ecdh_context_t ecdh,
                                      const void *der, size_t derlen,
                                      size_t *r_nparsed);
gpg_error_t _ntbtls_ecdh_make_public (ecdh_context_t ecdh,
                                      unsigned char *outbuf, size_t outbufsize,
                                      size_t *r_outbuflen);
gpg_error_t _ntbtls_ecdh_calc_secret (ecdh_context_t ecdh,
                                      unsigned char *outbuf, size_t outbufsize,
                                      size_t *r_outbuflen);



#endif /*NTBTLS_NTBTLS_INT_H*/
