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
_ntbtls_x509_new (x509_cert_t *r_cert)
{
  gpg_error_t err;
  x509_cert_t cert;

  *r_cert = NULL;

  cert = calloc (1, sizeof *cert);
  if (!cert)
    return gpg_error_from_syserror ();

  return 0;
}


/* Release an X.509 certificate chain.  */
void
_ntbtls_x509_release (x509_cert_t cert)
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
  ksba_cert_t crt;

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

      err = _ntbtls_x509_new (&ncert);
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


/* Return a pointer to the DER encoding of the certificate and store
   its length at R_DERLEN.  IDX is the requested number of the
   certificate; ie.  IDX of 0 return the first certificate stored
   with _ntbtls_x509_append_cert, 1, the next one,etc.  NULL is
   returned if no certificate is available at IDX or on error (which
   should not happen).  */
const unsigned char *
_ntbtls_x509_get_cert (x509_cert_t cert, int idx, size_t *r_derlen)
{
  for (; cert && idx; cert = cert->next, idx--)
    ;
  if (!cert)
    return NULL;

  return ksba_cert_get_image (cert->crt, r_derlen);
}



gpg_error_t
_ntbtls_x509_verify (x509_cert_t cert, x509_cert_t trust_ca, x509_crl_t ca_crl,
                     const char *cn, int *r_flags)
{
  //FIXME:

  return 0;
}


/* Return true if PRIVKEY can do an operation using the public key
   algorithm PKALGO.  */
int
_ntbtls_x509_can_do (x509_privkey_t privkey, pk_algo_t pkalgo)
{
  if (!privkey)
    return 0;

  /* FIXME: Check that PRIVKEY matches PKALGO.  */
  return 1;
}
