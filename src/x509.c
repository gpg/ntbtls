/* x509.c - X.509 functions
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
#include <ksba.h>

#include "ntbtls-int.h"


/* While running the validation function we need to keep track of the
   certificates and the validation outcome of each.  We use this type
   for it.  */
struct x509_cert_s
{
  x509_cert_t next;
  ksba_cert_t crt;       /* The actual certificate object.  */
  unsigned char fpr[20]; /* Fingerprint of the certificate.  */
  int is_self_signed:1;  /* This certificate is self-signed.  */
  int is_valid:1;        /* The certifiate is valid except for revocations.  */
};


/* The object tostore a private key.  */
struct x509_privkey_s
{
  char dummy[32];
};



/* Create a new X.509 certificate chain object and store it at R_CERT.
   Returns an error code and stores NULL at R_CERT on error. */
gpg_error_t
_ntbtls_x509_cert_new (x509_cert_t *r_cert)
{
  x509_cert_t cert;

  *r_cert = NULL;

  cert = calloc (1, sizeof *cert);
  if (!cert)
    return gpg_error_from_syserror ();

  *r_cert = cert;

  return 0;
}


/* Release an X.509 certificate chain.  */
void
_ntbtls_x509_cert_release (x509_cert_t cert)
{
  while (cert)
    {
      x509_cert_t next = cert->next;
      ksba_cert_release (cert->crt);
      free (cert);
      cert = next;
    }
}


/* Parse a DER encoded certifciate in buffer DER of length DERLEN and
   append it to the CERT object.  */
gpg_error_t
_ntbtls_x509_append_cert (x509_cert_t cert, const void *der, size_t derlen)
{
  gpg_error_t err;

  if (!cert)
    return gpg_error (GPG_ERR_INV_ARG);

  /* Walk to the last certifciate of the chain.  */
  while (cert->next)
    cert = cert->next;

  /* If the node is already filled with a certificate append a new
     node.  */
  if (cert->crt)
    {
      x509_cert_t ncert;

      err = _ntbtls_x509_cert_new (&ncert);
      if (err)
        return err;
      cert->next = ncert;
      cert = ncert;
    }

  /* Allocate KSBA object and fill it with the parsed certificate.  */
  err = ksba_cert_new (&cert->crt);
  if (err)
    {
      free (cert);
      return err;
    }
  err = ksba_cert_init_from_mem (cert->crt, der, derlen);
  if (err)
    {
      ksba_cert_release (cert->crt);
      cert->crt = NULL;
      return err;
    }

  return 0;
}


static void
x509_log_serial (const char *text, ksba_sexp_t sn)
{
  const char *p = (const char *)sn;
  unsigned long n;
  char *endp;

  if (!p)
    _ntbtls_debug_msg (-1, "%s: none", text);
  else if (*p != '(')
    _ntbtls_debug_msg (-1, "%s: [Internal error - not an S-expression]", text);
  else
    {
      p++;
      n = strtoul (p, &endp, 10);
      p = endp;
      if (*p++ != ':')
        _ntbtls_debug_msg (-1, "%s: [Internal error - invalid S-expression]",
                           text);
      else
        {
          _ntbtls_debug_msg (-1, "\b%s: ", text);
          gcry_log_debughex ("", p, n);
        }
    }
}


static void
x509_log_time (const char *text, ksba_isotime_t t)
{
  if (!t || !*t)
    _ntbtls_debug_msg (-1, "%s: none", text);
  else
    _ntbtls_debug_msg (-1, "%s: %.4s-%.2s-%.2s %.2s:%.2s:%s",
                       text, t, t+4, t+6, t+9, t+11, t+13);
}


void
_ntbtls_x509_log_cert (const char *text, x509_cert_t chain_arg, int full)
{
  gpg_error_t err;
  x509_cert_t chain;
  ksba_cert_t cert;
  ksba_sexp_t sexp;
  int idx;
  char *dn;
  ksba_isotime_t t;
  const char *oid;

  for (idx=0, chain= chain_arg; chain && (cert = chain->crt);
       chain = chain->next)
    idx++;

  _ntbtls_debug_msg (-1, "%s: chain length=%d", text, idx);
  for (chain = chain_arg; full && chain && (cert = chain->crt);
       chain = chain->next)
    {
      sexp = ksba_cert_get_serial (cert);
      x509_log_serial ("     serial", sexp);
      ksba_free (sexp);

      for (idx = 0; (dn = ksba_cert_get_issuer (cert, idx)); idx++)
        {
          if (!idx)
            _ntbtls_debug_msg (-1, "     issuer: %s\n", dn);
          else
            _ntbtls_debug_msg (-1, "        aka: %s\n", dn);
          ksba_free (dn);
        }

      for (idx = 0; (dn = ksba_cert_get_subject (cert, idx)); idx++)
        {
          if (!idx)
            _ntbtls_debug_msg (-1, "    subject: %s\n", dn);
          else
            _ntbtls_debug_msg (-1, "        aka: %s\n", dn);
          ksba_free (dn);
        }

      ksba_cert_get_validity (cert, 0, t);
      x509_log_time ("  notBefore", t);
      ksba_cert_get_validity (cert, 1, t);
      x509_log_time ("   notAfter", t);

      oid = ksba_cert_get_digest_algo (cert);
      _ntbtls_debug_msg (-1, "  hashAlgo: %s", oid);
    }
}


/* Return a pointer to the DER encoding of the certificate and store
   its length at R_DERLEN.  IDX is the requested number of the
   certificate; ie.  IDX of 0 return the first certificate stored
   with _ntbtls_x509_append_cert, 1, the next one,etc.  NULL is
   returned if no certificate is available at IDX or on error (which
   should not happen).  */
const unsigned char *
_ntbtls_x509_get_cert (x509_cert_t cert, int idx, size_t *r_derlen)
{
  for (; cert && idx >= 0; cert = cert->next, idx--)
    ;
  if (!cert)
    return NULL;

  return ksba_cert_get_image (cert->crt, r_derlen);
}


/* Return the public key from the certificate with index IDX in CERT
   and store it as an S-expression at R_PK.  On error return an error
   code and store NULL at R_PK.  */
gpg_error_t
_ntbtls_x509_get_pk (x509_cert_t cert, int idx, gcry_sexp_t *r_pk)
{
  gpg_error_t err;
  ksba_sexp_t pk;
  size_t pklen;
  gcry_sexp_t s_pk;

  if (!r_pk)
    return gpg_error (GPG_ERR_INV_ARG);
  *r_pk = NULL;

  if (idx < 0)
    gpg_error (GPG_ERR_INV_INDEX);
  for (; cert && idx; cert = cert->next, idx--)
    ;
  if (!cert)
    return gpg_error (GPG_ERR_NO_DATA);

  pk = ksba_cert_get_public_key (cert->crt);
  pklen = gcry_sexp_canon_len (pk, 0, NULL, NULL);
  if (!pklen)
    {
      /* CRT is NULL or other problem.  */
      ksba_free (pk);
      return gpg_error (GPG_ERR_NO_PUBKEY);
    }

  err = gcry_sexp_sscan (&s_pk, NULL, pk, pklen);
  ksba_free (pk);
  if (err)
    {
      debug_ret (1, "gcry_sexp_scan", err);
      return err;
    }
  *r_pk = s_pk;
  return 0;
}



gpg_error_t
_ntbtls_x509_verify (x509_cert_t chain, x509_cert_t trust_ca, x509_crl_t ca_crl,
                     const char *cn, int *r_flags)
{
  //FIXME:

  return 0;
}


/* Return true if PRIVKEY can do an operation using the public key
   algorithm PKALGO.  */
int
_ntbtls_x509_can_do (x509_privkey_t privkey, pk_algo_t pk_alg)
{
  if (!privkey)
    return 0;

  /* FIXME: Check that PRIVKEY matches PKALGO.  */
  return 1;
}
