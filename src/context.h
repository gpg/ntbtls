/* context.h - the context object
 * Copyright (C) 2006-2014, Brainspark B.V.
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

#ifndef NTBTLS_CONTEXT_H
#define NTBTLS_CONTEXT_H

#include <zlib.h>


typedef enum gcry_md_algos md_algo_t;
typedef enum gcry_mac_algos mac_algo_t;
typedef enum gcry_cipher_algos cipher_algo_t;
typedef enum gcry_cipher_modes cipher_mode_t;
typedef enum gcry_pk_algos pk_algo_t;

/*
 * TLS states  (note that the order of the states is important)
 */
typedef enum
  {
    TLS_HELLO_REQUEST,
    TLS_CLIENT_HELLO,
    TLS_SERVER_HELLO,
    TLS_SERVER_CERTIFICATE,
    TLS_SERVER_KEY_EXCHANGE,
    TLS_CERTIFICATE_REQUEST,
    TLS_SERVER_HELLO_DONE,
    TLS_CLIENT_CERTIFICATE,
    TLS_CLIENT_KEY_EXCHANGE,
    TLS_CERTIFICATE_VERIFY,
    TLS_CLIENT_CHANGE_CIPHER_SPEC,
    TLS_CLIENT_FINISHED,
    TLS_SERVER_CHANGE_CIPHER_SPEC,
    TLS_SERVER_FINISHED,
    TLS_FLUSH_BUFFERS,
    TLS_HANDSHAKE_WRAPUP,
    TLS_HANDSHAKE_OVER,
    TLS_SERVER_NEW_SESSION_TICKET

  } tls_state_t;


/*
 * Renegotiation states
 */
typedef enum
  {
    TLS_INITIAL_HANDSHAKE =  0,
    TLS_RENEGOTIATION,           /* In progress */
    TLS_RENEGOTIATION_DONE,      /* Done */
    TLS_RENEGOTIATION_PENDING    /* Requested (server only) */

  } tls_renegotiation_state_t;



/*
 * Key exchange protocols
 *
 * Reminder: Update premaster_secret_u when adding a new key exchange.
 */
typedef enum
  {
    KEY_EXCHANGE_NONE = 0,
    KEY_EXCHANGE_RSA,
    KEY_EXCHANGE_DHE_RSA,
    KEY_EXCHANGE_ECDHE_RSA,
    KEY_EXCHANGE_ECDHE_ECDSA,
    KEY_EXCHANGE_PSK,
    KEY_EXCHANGE_DHE_PSK,
    KEY_EXCHANGE_RSA_PSK,
    KEY_EXCHANGE_ECDHE_PSK,
    KEY_EXCHANGE_ECDH_RSA,
    KEY_EXCHANGE_ECDH_ECDSA

  } key_exchange_type_t;


/*
 * Object to hold an X.509 CRL.
 */
struct x509_crl_s;
typedef struct x509_crl_s *x509_crl_t;


/*
 * Object to hold an X.509 private key.
 */
struct x509_privkey_s;
typedef struct x509_privkey_s *x509_privkey_t;


/*
 * Object to hold an DHM context.
 */
struct dhm_context_s;
typedef struct dhm_context_s *dhm_context_t;


/*
 * Object to hold an ECDH context.
 */
struct ecdh_context_s;
typedef struct ecdh_context_s *ecdh_context_t;


/*
 * This structure is used for storing current session data.
 */
struct _ntbtls_session_s
{
  time_t start;                 /*!< starting time      */
  int ciphersuite;              /*!< chosen ciphersuite */
  int compression;              /*!< chosen compression */
  size_t length;                /*!< session id length  */
  unsigned char id[32];         /*!< session identifier */
  unsigned char master[48];     /*!< the master secret  */

  x509_cert_t peer_chain;       /*!< peer X.509 cert chain */
  int verify_result;            /*!<  verification result     */

  unsigned char *ticket;        /*!< RFC 5077 session ticket */
  size_t ticket_len;            /*!< session ticket length   */
  uint32_t ticket_lifetime;     /*!< ticket lifetime hint    */

  unsigned char mfl_code;       /*!< MaxFragmentLength negotiated by peer */

  int use_trunc_hmac;           /* Flag for truncated hmac activation.   */
};

typedef struct _ntbtls_session_s *session_t;


/*
 * This structure is used for storing ciphersuite information
 */
struct _ntbtls_ciphersuite_s;
typedef const struct _ntbtls_ciphersuite_s *ciphersuite_t;


/*
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 */
struct _ntbtls_transform_s
{
  /*
   * Session specific crypto layer
   */
  ciphersuite_t ciphersuite;    /*!<  Chosen cipersuite_info  */
  unsigned int keylen;          /*!<  symmetric key length    */
  size_t minlen;                /*!<  min. ciphertext length  */
  size_t ivlen;                 /*!<  IV length               */
  size_t fixed_ivlen;           /*!<  Fixed part of IV (AEAD) */
  size_t maclen;                /* MAC length in bytes        */

  unsigned char iv_enc[16];     /*!<  IV (encryption)         */
  unsigned char iv_dec[16];     /*!<  IV (decryption)         */

  gcry_mac_hd_t mac_ctx_enc;    /* MAC (encryption)           */
  gcry_mac_hd_t mac_ctx_dec;    /* MAC (decryption)           */

  gcry_cipher_hd_t cipher_ctx_enc; /* Encryption context.     */
  cipher_mode_t    cipher_mode_enc;/* Mode for encryption.    */
  gcry_cipher_hd_t cipher_ctx_dec; /* Decryption context.     */
  cipher_mode_t    cipher_mode_dec;/* Mode for encryption.    */

  /*
   * Session specific compression layer
   */
  z_stream ctx_deflate;         /*!<  compression context     */
  z_stream ctx_inflate;         /*!<  decompression context   */
};

typedef struct _ntbtls_transform_s *transform_t;


/*
 * List of certificate + private key pairs
 */
struct _ntbtls_key_cert_s
{
  struct _ntbtls_key_cert_s *next;
  x509_cert_t  cert;
  x509_privkey_t key;
};

typedef struct _ntbtls_key_cert_s *key_cert_t;


/*
 * This structure contains the parameters only needed during handshake.
 */
struct _ntbtls_handshake_params_s
{
  /*
   * Handshake specific crypto variables
   */
  int sig_alg;                  /*!<  Hash algorithm for signature   */
  int cert_type;                /*!<  Requested cert type            */
  int verify_sig_alg;           /*!<  Signature algorithm for verify */
  dhm_context_t dhm_ctx;        /* DHM key exchange info.   */
  ecdh_context_t ecdh_ctx;      /* ECDH key exchange info.  */
  const /*ecp_curve_info*/void **curves;/*!<  Supported elliptic curves */
  /**
   * //FIXME: Better explain this
   * Current key/cert or key/cert list.
   * On client: pointer to ssl->key_cert, only the first entry used.
   * On server: starts as a pointer to ssl->key_cert, then becomes
   * a pointer to the chosen key from this list or the SNI list.
   */
  key_cert_t key_cert;
  key_cert_t sni_key_cert;      /*!<  key/cert list from SNI  */

  /*
   * Checksum contexts
   */
  gcry_md_hd_t fin_sha256;     /* Checksum of all handshake messages.  */
  gcry_md_hd_t fin_sha512;     /* Ditto.  */

  void (*update_checksum) (ntbtls_t, const unsigned char *, size_t);
  void (*calc_verify) (ntbtls_t, unsigned char *);
  void (*calc_finished) (ntbtls_t, unsigned char *, int);
  gpg_error_t (*tls_prf) (const unsigned char *, size_t, const char *,
                          const unsigned char *, size_t, unsigned char *,
                          size_t);

  size_t pmslen;                /*!<  premaster length        */

  unsigned char randbytes[64];  /*!<  random bytes            */
  unsigned char premaster[TLS_PREMASTER_SIZE]; /*!<  premaster secret */

  int resume;                   /*!<  session resume indicator */
  int max_major_ver;            /*!< max. major version client */
  int max_minor_ver;            /*!< max. minor version client */
  int cli_exts;                 /*!< client extension presence */

  int new_session_ticket;       /*!< use NewSessionTicket?    */
};

typedef struct _ntbtls_handshake_params_s *handshake_params_t;


/*
 * Parameters needed to secure session tickets
 */
struct _ntbtls_ticket_keys_s
{
  unsigned char key_name[16];   /*!< name to quickly discard bad tickets */
  gcry_cipher_hd_t enc;         /*!< encryption context                  */
  gcry_cipher_hd_t dec;         /*!< decryption context                  */
  unsigned char mac_key[16];    /*!< authentication key                  */
};

typedef struct _ntbtls_ticket_keys_s *ticket_keys_t;




#if SIZEOF_UNSIGNED_LONG == 8
# define NTBTLS_CONTEXT_MAGIC 0x6e7462746c736378 /* "ntbtlscx" */
#else
# define NTBTLS_CONTEXT_MAGIC 0x6e746243         /* "ntbC" */
#endif

/*
 * The TLS context object.
 */
struct _ntbtls_context_s
{
  unsigned long magic;

  /*
   * Miscellaneous
   */
  int major_ver;                /*!< equal to  SSL_MAJOR_VERSION_3    */
  int minor_ver;                /*!< either 0 (SSL3) or 1 (TLS1.0)    */

  int max_major_ver;            /*!< max. major version used          */
  int max_minor_ver;            /*!< max. minor version used          */
  int min_major_ver;            /*!< min. major version used          */
  int min_minor_ver;            /*!< min. minor version used          */

  tls_state_t state;            /* Current state of the handshake.    */
  tls_renegotiation_state_t renegotiation; /*!< Initial or renegotiation  */
  int renego_records_seen;      /*!< Records since renego request     */

  struct {
    unsigned char any;
    unsigned char level;
    unsigned char type;
  } last_alert;                 /* Info about the last received alert.  */

  /*
   * Callbacks (RNG, debug, I/O, verification)
   */
  void (*f_dbg) (void *, int, const char *);
  int (*f_recv) (void *, unsigned char *, size_t);
  int (*f_send) (void *, const unsigned char *, size_t);
  int (*f_get_cache) (void *, session_t);
  int (*f_set_cache) (void *, const session_t);

  void *p_dbg;                  /*!< context for the debug function   */
  void *p_recv;                 /*!< context for reading operations   */
  void *p_send;                 /*!< context for writing operations   */
  void *p_get_cache;            /*!< context for cache retrieval      */
  void *p_set_cache;            /*!< context for cache store          */
  void *p_hw_data;              /*!< context for HW acceleration      */

  int (*f_sni) (void *, ntbtls_t, const unsigned char *, size_t);
  void *p_sni;                  /*!< context for SNI extension        */

  int (*f_vrfy) (void *, x509_cert_t, int, int *);
  void *p_vrfy;                 /*!< context for verification         */

  int (*f_psk) (void *, ntbtls_t, const unsigned char *, size_t);
  void *p_psk;                  /*!< context for PSK retrieval         */

  /*
   * Session layer
   */
  session_t session_in;         /*!<  current session data (in)   */
  session_t session_out;        /*!<  current session data (out)  */
  session_t session;            /*!<  negotiated session data     */
  session_t session_negotiate;  /* Session data in negotiation.  */

  handshake_params_t handshake; /* Params required only during the
                                   handshake process.  */

  /*
   * Record layer transformations
   */
  transform_t transform_in;     /*!<  current transform params (in)   */
  transform_t transform_out;    /*!<  current transform params (in)   */
  transform_t transform;        /*!<  negotiated transform params     */
  transform_t transform_negotiate;  /* Transform params in
                                          negotiation.  */

  /*
   * Record layer (incoming data)
   */
  estream_t inbound;            /* Stream used to receive TLS data.  */
  unsigned char *in_ctr;        /*!< 64-bit incoming message counter  */
  unsigned char *in_hdr;        /*!< 5-byte record header (in_ctr+8)  */
  unsigned char *in_iv;         /*!< ivlen-byte IV (in_hdr+5)         */
  unsigned char *in_msg;        /*!< message contents (in_iv+ivlen)   */
  unsigned char *in_offt;       /*!< read offset in application data  */

  int in_msgtype;               /*!< record header: message type      */
  size_t in_msglen;             /*!< record header: message length    */
  size_t in_left;               /* Amount of data read so far.   */

  size_t in_hslen;              /*!< current handshake message length */
  int nb_zero;                  /*!< # of 0-length encrypted messages */
  int record_read;              /*!< record is already present        */

  /*
   * Record layer (outgoing data)
   */
  estream_t outbound;           /* Stream used to send TLS data.      */
  unsigned char *out_ctr;       /*!< 64-bit outgoing message counter  */
  unsigned char *out_hdr;       /*!< 5-byte record header (out_ctr+8) */
  unsigned char *out_iv;        /*!< ivlen-byte IV (out_hdr+5)        */
  unsigned char *out_msg;       /*!< message contents (out_iv+ivlen)  */

  int out_msgtype;              /*!< record header: message type      */
  size_t out_msglen;            /* Record header: message length.     */
  size_t out_left;              /* Amount of data not yet written.    */

  unsigned char *compress_buf;  /*!<  zlib data buffer        */
  unsigned char mfl_code;       /*!< MaxFragmentLength chosen by us   */

  /*
   * Layer to the TLS encrypted data
   */
  estream_t readfp;             /* Estream to read from the peer.  */
  estream_t writefp;            /* Estream to write to the peer.   */

  /*
   * PKI layer
   */
  key_cert_t key_cert;          /*!<  own certificate(s)/key(s) */

  ntbtls_verify_cb_t verify_cb; /*!<  the verify callback              */
  void *verify_cb_value;;       /*!<  the first arg passed to this cb  */

  /*
   * Support for generating and checking session tickets
   */
  ticket_keys_t ticket_keys;    /*!<  keys for ticket encryption */

  /*
   * User settings
   */
  int is_client;                /* True if we are in client mode.  */
  unsigned int flags;           /* All flags from ntbtls_new.  */

  int authmode;                 /*!<  verification mode       */
  int client_auth;              /*!<  flag for client auth.   */
  int verify_result;            /*!<  verification result     */
  int disable_renegotiation;    /*!<  enable/disable renegotiation   */
  int allow_legacy_renegotiation;       /*!<  allow legacy renegotiation     */
  int renego_max_records;       /*!<  grace period for renegotiation */
  const int *ciphersuite_list[4];       /*!<  allowed ciphersuites / version */
  const /*ecp_group_id*/ void *curve_list;   /*!<  allowed curves        */
  int use_trunc_hmac;           /* Use truncated HMAC flag.   */
  int use_session_tickets;      /* Use session tickets flag.  */
  int ticket_lifetime;          /*!<  session ticket lifetime */

  gcry_mpi_t dhm_P;             /*!<  prime modulus for DHM   */
  gcry_mpi_t dhm_G;             /*!<  generator for DHM       */

  char *hostname;               /*!< expected peer CN for verification
                                    and SNI                            */

  /*
   * PSK values
   */
  unsigned char *psk;
  size_t psk_len;
  unsigned char *psk_identity;
  size_t psk_identity_len;

  /*
   * ALPN extension
   */
  const char **alpn_list;       /*!<  ordered list of supported protocols   */
  const char *alpn_chosen;      /*!<  negotiated protocol                   */

  /*
   * Secure renegotiation
   */
  int secure_renegotiation;     /*!<  does peer support legacy or
                                   secure renegotiation           */
  size_t verify_data_len;       /*!<  length of verify data stored   */
  char own_verify_data[36];     /*!<  previous handshake verify data */
  char peer_verify_data[36];    /*!<  previous handshake verify data */
};


#endif /*NTBTLS_CONTEXT_H*/
