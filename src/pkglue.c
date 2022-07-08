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

  /* Put the hash and the signature into s-expressions. */
  switch (pk_alg)
    {
    case GCRY_PK_RSA:
      err = gcry_sexp_build (&s_hash, NULL, "(data(flags pkcs1)(hash %s %b))",
                             md_alg_str, (int)hashlen, hash);
      if (!err)
        err = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%b)))",
                               (int)siglen, sig);
      break;

    case GCRY_PK_ECC:
      {
        unsigned int qbits0, qbits;
        const unsigned char *r, *s;
        int rlen, slen;

        qbits0 = gcry_pk_get_nbits (s_pk);
        qbits = qbits0 == 521? 512 : qbits0;

        if ((qbits%8))
          {
            debug_msg (1, "qbits are not a multiple of 8 bits");
            err = gpg_error (GPG_ERR_INTERNAL);
            goto leave;
          }

        if (qbits < 224)
          {
            debug_msg (1, "key uses an unsafe (%u bit) hash\n", qbits0);
            err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
            goto leave;
          }

        /*
         * For TLS 1.2, it is possible for a server to use SHA256 with
         * secpr384 key.  See RFC8422 section 5.10.
         */
        if (0 && hashlen < qbits/8)
          {
            debug_msg (1, "a %u bit hash is not valid for a %u bit ECC key",
                       (unsigned int)hashlen*8, qbits);
            err = gpg_error (GPG_ERR_DIGEST_ALGO);
            goto leave;
          }

        if (hashlen > qbits/8)
          hashlen = qbits/8; /* Truncate.  */

        err = gcry_sexp_build (&s_hash, NULL, "(data (flags raw)(value %b))",
                               (int)hashlen, hash);
        if (err)
          goto leave;
        /* 3045    -- SEQUENCE with length 0x45
         *   0220  -- INTEGER with length 0x20
         *     3045bcceccda9464c1d340a225e55e3d045e17ce004c0508a2cd61dd
         *     23a63ba6
         *   0221  -- INTEGER with length 0x21 (due to 0x00 prefix)
         *     00e39b404793be76e87089ff3b5c306246a9f8cb52d94c77c624c3bf
         *     118e2418e8
         */
        if (siglen < 6 || sig[0] != 0x30 || sig[1] != siglen - 2
            || sig[2] != 0x02)
          {
            err = gpg_error (GPG_ERR_INV_BER);
            goto leave;
          }
        siglen -= 2;
        sig += 2;
        rlen = sig[1];
        if ((rlen != 32 && rlen != 33
             && rlen != 48 && rlen != 49
             && rlen != 64 && rlen != 65)
            || (rlen + 2 > siglen))
          {
            /* The signature length is not 256, 384 or 512 bit. The
             * odd values are to handle an extra zero prefix.  Or
             * the length is larger than the entire frame.  */
            err = gpg_error (GPG_ERR_INV_LENGTH);
            goto leave;
          }
        r = sig + 2;
        sig = r + rlen;
        siglen -= rlen + 2;
        if (siglen < 3 || sig[0] != 0x02)
          {
            err = gpg_error (GPG_ERR_INV_BER);
            goto leave;
          }
        siglen -= 2;
        slen = sig[1];
        if ((slen > siglen) || ((rlen & ~1) != (slen & ~1)))
          {
            /* The length of S does not match the length of R.  Or
             * the length is larger than the entire frame.  */
            err = gpg_error (GPG_ERR_INV_LENGTH);
            goto leave;
          }
        s = sig + 2;
        err = gcry_sexp_build (&s_sig, NULL, "(sig-val(ecdsa(r%b)(s%b)))",
                               rlen, r, slen, s);
      }
      break;

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
  debug_msg (4, "res=%d", err);

 leave:
  gcry_sexp_release (s_pk);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_sig);
  return err;
}


gpg_error_t
_ntbtls_pk_encrypt (x509_cert_t chain,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize)
{
  gpg_error_t err;
  gcry_sexp_t s_pk = NULL;
  gcry_sexp_t s_data = NULL;
  gcry_sexp_t s_ciph = NULL;
  size_t len;
  const char *data;

  /* Get the public key from the first certificate.  */
  err = _ntbtls_x509_get_pk (chain, 0, &s_pk);
  if (err)
    return err;

  err = gcry_sexp_build (&s_data, NULL, "(data (flags pkcs1) (value %b))",
                         (int)ilen, input);
  if (err)
    {
      gcry_sexp_release (s_pk);
      return err;
    }

  err = gcry_pk_encrypt (&s_ciph, s_data, s_pk);
  gcry_sexp_release (s_data);
  s_data = NULL;
  gcry_sexp_release (s_pk);
  s_pk = NULL;
  if (err)
    return err;

  s_data = gcry_sexp_find_token (s_ciph, "a", 0);
  data = gcry_sexp_nth_data (s_data, 1, &len);
  if (data == NULL)
    err = gpg_error (GPG_ERR_BAD_MPI);
  else if (osize < len)
    err = gpg_error (GPG_ERR_TOO_SHORT);
  else
    {
      *olen = len;
      memcpy (output, data, len);
    }

  gcry_sexp_release (s_data);
  gcry_sexp_release (s_ciph);
  return err;
}
