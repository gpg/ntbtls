/* pkglue.c - Public key fucntions
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


static const char *
md_alg_string (md_algo_t md_alg)
{
  switch (md_alg)
    {
    case GCRY_MD_SHA1:   return "sha1";
    case GCRY_MD_SHA224: return "sha224";
    case GCRY_MD_SHA256: return "sha256";
    case GCRY_MD_SHA384: return "sha384";
    case GCRY_MD_SHA512: return "sha512";
    case GCRY_MD_RMD160: return "rmd160";
    default: return NULL;
    }
}


/* Return the public key algorithm id from the S-expression PKEY.
   FIXME: libgcrypt should provide such a function.  Note that this
   implementation uses the names as used by libksba.  */
static pk_algo_t
pk_algo_from_sexp (gcry_sexp_t pkey)
{
  gcry_sexp_t l1, l2;
  const char *name;
  size_t n;
  pk_algo_t algo;

  l1 = gcry_sexp_find_token (pkey, "public-key", 0);
  if (!l1)
    return 0; /* Not found.  */
  l2 = gcry_sexp_cadr (l1);
  gcry_sexp_release (l1);

  name = gcry_sexp_nth_data (l2, 0, &n);
  if (!name)
    algo = 0; /* Not found. */
  else if (n==3 && !memcmp (name, "rsa", 3))
    algo = GCRY_PK_RSA;
  else if (n==3 && !memcmp (name, "dsa", 3))
    algo = GCRY_PK_DSA;
  else if (n==3 && !memcmp (name, "ecc", 3))
    algo = GCRY_PK_ECC;
  else if (n==13 && !memcmp (name, "ambiguous-rsa", 13))
    algo = GCRY_PK_RSA;
  else
    algo = 0;
  gcry_sexp_release (l2);
  return algo;
}


gpg_error_t
_ntbtls_pk_verify (x509_cert_t chain, pk_algo_t pk_alg, md_algo_t md_alg,
                   const unsigned char *hash, size_t hashlen,
                   const unsigned char *sig, size_t siglen)
{
  gpg_error_t err;
  gcry_sexp_t s_pk = NULL;
  gcry_sexp_t s_hash = NULL;
  gcry_sexp_t s_sig = NULL;
  const char *md_alg_str;

  if (!chain ||!md_alg || !hashlen || !sig || !siglen)
    return gpg_error (GPG_ERR_INV_ARG);

  md_alg_str = md_alg_string (md_alg);
  if (!md_alg_str)
    return gpg_error (GPG_ERR_DIGEST_ALGO);

  /* Get the public key from the first certificate.  */
  err = _ntbtls_x509_get_pk (chain, 0, &s_pk);
  if (err)
    goto leave;

  /* Check the Public key algorithm.  */
  {
    pk_algo_t alg;

    alg = pk_algo_from_sexp (s_pk);
    if (!alg)
      err = gpg_error (GPG_ERR_PUBKEY_ALGO);
    else if (alg != pk_alg)
      err = gpg_error (GPG_ERR_WRONG_PUBKEY_ALGO);  /* Does not match. */

    if (err)
      goto leave;
  }

  /* Put the hash into an s-expression.  */
  err = gcry_sexp_build (&s_hash, NULL, "(data(flags pkcs1)(hash %s %b))",
                         md_alg_str, (int)hashlen, hash);
  if (err)
    goto leave;

  /* Put the signature into an s-expression. */
  switch (pk_alg)
    {
    case GCRY_PK_RSA:
      err = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%b)))",
                             (int)siglen, sig);
      break;

    /* case GCRY_PK_DSA: */
    /*   err = gcry_sexp_build (&s_sig, NULL, "(sig-val(dsa(r%m)(s%m)))", */
    /*                          data[0], data[1]); */
    /*   break; */

    /* case PUBKEY_PK_ECC: */
    /*   err = gcry_sexp_build (&s_sig, NULL, "(sig-val(ecdsa(r%m)(s%m)))", */
    /*                          data[0], data[1]); */
    /*   break; */

    default:
      err = gpg_error (GPG_ERR_NOT_IMPLEMENTED);
      break;
    }
  if (err)
    goto leave;

  debug_sxp (4, "sig ", s_sig);
  debug_sxp (4, "hash", s_hash);
  debug_sxp (4, "pk  ", s_pk);

  err = gcry_pk_verify (s_sig, s_hash, s_pk);


 leave:
  gcry_sexp_release (s_pk);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_sig);
  return err;
}
