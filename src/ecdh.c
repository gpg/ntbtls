/* ecdh.c - EC Diffie-Hellman key exchange
 * Copyright (C) 2014, 2017 g10 Code GmbH
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
 * certificates and the validation outcome of each.  We use this type
 * for it.  */
struct ecdh_context_s
{
  const char *curve_name;  /* Only for display purposes.  */
  gcry_ctx_t ecctx;        /* The initialized context for the curve.
                            * This also holds the secre D and our
                            * public key Q.  */
  gcry_mpi_point_t Qpeer;  /* The peer's public value  */
};



/* Create a new ECDH context.  */
gpg_error_t
_ntbtls_ecdh_new (ecdh_context_t *r_ecdh)
{
  ecdh_context_t ecdh;

  *r_ecdh = NULL;

  ecdh = calloc (1, sizeof *ecdh);
  if (!ecdh)
    return gpg_error_from_syserror ();

  *r_ecdh = ecdh;

  return 0;
}


/* Release an ECDH context.  */
void
_ntbtls_ecdh_release (ecdh_context_t ecdh)
{
  if (!ecdh)
    return;
  gcry_ctx_release (ecdh->ecctx);
  gcry_mpi_point_release (ecdh->Qpeer);
  free (ecdh);
}


/* Parse the TLS ECDHE parameters and store them in ECDH.  DER is the
 * buffer with the params of length DERLEN.  The number of actual
 * parsed bytes is stored at R_NPARSED.  */
gpg_error_t
_ntbtls_ecdh_read_params (ecdh_context_t ecdh,
                          const void *_der, size_t derlen,
                          size_t *r_nparsed)
{
  gpg_error_t err;
  const unsigned char *derstart = _der;
  const unsigned char *der = _der;
  size_t n;
  gcry_mpi_t tmpmpi;

  if (r_nparsed)
    *r_nparsed = 0;

  if (!ecdh || !der)
    return gpg_error (GPG_ERR_INV_ARG);

  ecdh->curve_name = NULL;
  gcry_ctx_release (ecdh->ecctx); ecdh->ecctx = NULL;
  gcry_mpi_point_release (ecdh->Qpeer); ecdh->Qpeer = NULL;

  /* struct {
   *     ECParameters curve_params;
   *     ECPoint      public;
   * } ServerECDHParams;
   */

  /* Parse ECParameters.  */
  if (derlen < 3)
    return gpg_error (GPG_ERR_TOO_SHORT);
  /* We only support named curves (3).  */
  if (*der != 3)
    return gpg_error (GPG_ERR_UNKNOWN_CURVE);
  der++;
  derlen--;

  switch (buf16_to_uint (der))
    {
    case 23: ecdh->curve_name = "secp256r1"; break;
    case 24: ecdh->curve_name = "secp384r1"; break;
    case 25: ecdh->curve_name = "secp521r1"; break;
    case 26: ecdh->curve_name = "brainpoolP256r1"; break;
    case 27: ecdh->curve_name = "brainpoolP384r1"; break;
    case 28: ecdh->curve_name = "brainpoolP512r1"; break;
#ifdef SUPPORT_X25519
    case 29: ecdh->curve_name = "X25519"; break;
#endif
#ifdef SUPPORT_X448
    case 30: ecdh->curve_name = "X448"; break;
#endif
    default:
      return gpg_error (GPG_ERR_UNKNOWN_CURVE);
    }
  der += 2;
  derlen -= 2;

  err = gcry_mpi_ec_new (&ecdh->ecctx, NULL, ecdh->curve_name);
  if (err)
    return err;

  /* Parse ECPoint.  */
  if (derlen < 2)
    return gpg_error (GPG_ERR_TOO_SHORT);
  n = *der++; derlen--;
  if (!n)
    return gpg_error (GPG_ERR_INV_OBJ);
  if (n > derlen)
    return gpg_error (GPG_ERR_TOO_LARGE);

  tmpmpi = gcry_mpi_set_opaque_copy (NULL, der, 8*n);
  if (!tmpmpi)
    return gpg_error_from_syserror ();
  der += n;
  derlen -= n;

  ecdh->Qpeer = gcry_mpi_point_new (0);
  err = gcry_mpi_ec_decode_point (ecdh->Qpeer, tmpmpi, ecdh->ecctx);
  gcry_mpi_release (tmpmpi);
  if (err)
    {
      gcry_mpi_point_release (ecdh->Qpeer);
      ecdh->Qpeer = NULL;
      return err;
    }

  if (r_nparsed)
    *r_nparsed = (der - derstart);

  debug_msg (3, "ECDH curve: %s", ecdh->curve_name);
  if (ecdh->curve_name[0] != 'X')
    debug_pnt (3, "ECDH Qpeer", ecdh->Qpeer, ecdh->ecctx);
  /* FIXME: debug print the point for Montgomery curve.  */

  return 0;
}


/* Generate the secret D with 0 < D < N.  */
static gcry_mpi_t
gen_d (ecdh_context_t ecdh)
{
  unsigned int nbits;
  gcry_mpi_t n, d;

  if (ecdh->curve_name[0] == 'X')
    {
      gcry_mpi_t p;
      unsigned int pbits;
      void *rnd;
      int len;

      p = gcry_mpi_ec_get_mpi ("p", ecdh->ecctx, 0);
      if (!p)
        return NULL;
      pbits  = gcry_mpi_get_nbits (p);
      len = (pbits+7)/8;
      gcry_mpi_release (p);

      rnd = gcry_random_bytes_secure (len, GCRY_STRONG_RANDOM);
      d = gcry_mpi_set_opaque (NULL, rnd, pbits);
      return d;
    }

  n = gcry_mpi_ec_get_mpi ("n", ecdh->ecctx, 0);
  if (!n)
    return NULL;
  nbits  = gcry_mpi_get_nbits (n);
  d = gcry_mpi_snew (nbits);

  for (;;)
    {
      /* FIXME: For the second and further iterations we use too much
       * random.  It would be better to get just a few bits and use
       * set/clear_bit to insert that into the D.  Or implement a
       * suitable gen_d function in libgcrypt. */
      gcry_mpi_randomize (d, nbits, GCRY_STRONG_RANDOM);

      /* Make sure we have the requested number of bits.  The code
       * looks a bit weird but it is easy to understand if you
       * consider that mpi_set_highbit clears all higher bits. */
      if (mpi_test_bit (d, nbits-1))
        mpi_set_highbit (d, nbits-1);
      else
        mpi_clear_highbit (d, nbits-1);

      if (mpi_cmp (d, n) < 0        /* check: D < N */
          && mpi_cmp_ui (d, 0) > 0) /* check: D > 0 */
        break;	/* okay */
    }

  gcry_mpi_release (n);
  return d;
}


/* Create our own private value D and a public key.  Store the public
   key in OUTBUF.  OUTBUFSIZE is the available length of OUTBUF.  On
   success the actual length of OUTBUF is stored at R_OUTBUFLEN.  */
gpg_error_t
_ntbtls_ecdh_make_public (ecdh_context_t ecdh,
                          unsigned char *outbuf, size_t outbufsize,
                          size_t *r_outbuflen)
{
  gpg_error_t err;
  size_t n;

  if (!ecdh || !outbuf || !r_outbuflen || outbufsize < 2)
    return gpg_error (GPG_ERR_INV_ARG);

  *r_outbuflen = 0;

  if (!ecdh->curve_name || !ecdh->ecctx || !ecdh->Qpeer)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  /* Create a secret and store it in the context.  */
  {
    gcry_mpi_t d;

    d = gen_d (ecdh);
    if (!d)
      return gpg_error (GPG_ERR_INV_OBJ);

    gcry_mpi_ec_set_mpi ("d", d, ecdh->ecctx);
    debug_mpi (3, "ECDH d    ", d);
    gcry_mpi_release (d);
  }

  if (ecdh->curve_name[0] == 'X')
    {
      gcry_mpi_t p;
      unsigned int pbits;
      gcry_mpi_point_t Q;
      gcry_mpi_t x;
      int i;
      int len;

      p = gcry_mpi_ec_get_mpi ("p", ecdh->ecctx, 0);
      if (!p)
        return gpg_error (GPG_ERR_INTERNAL);
      pbits  = gcry_mpi_get_nbits (p);
      len = (pbits+7)/8;
      gcry_mpi_release (p);
      if (len > 255)
        return gpg_error (GPG_ERR_INV_DATA);

      x = gcry_mpi_new (0);
      Q = gcry_mpi_ec_get_point ("q", ecdh->ecctx, 0);
      if (!Q)
        {
          gcry_mpi_release (x);
          return gpg_error (GPG_ERR_INTERNAL);
        }
      if (gcry_mpi_ec_get_affine (x, NULL, Q, ecdh->ecctx))
        {
          gcry_mpi_point_release (Q);
          return gpg_error (GPG_ERR_INV_DATA);
        }

      gcry_mpi_point_release (Q);
      debug_mpi (3, "ECDH Qour (in big-endian)", x);

      err = gcry_mpi_print (GCRYMPI_FMT_USG, outbuf+1, outbufsize-1, &n, x);
      gcry_mpi_release (x);
      if (err)
        return err;
      /* Fill zero, if shorter.  */
      if (n < len)
        {
          memmove (outbuf+1+len-n, outbuf+1, n);
          memset (outbuf+1, 0, len - n);
        }
      /* Reverse the buffer */
      for (i = 0; i < len/2; i++)
        {
          unsigned int tmp;

          tmp = outbuf[i+1];
          outbuf[i+1] = outbuf[len-i];
          outbuf[len-i] = tmp;
        }
      outbuf[0] = len;
      n = len + 1;
    }
  else
    {
      gcry_mpi_t Q;

      /* Note that "q" is computed by the get function and returned in
       * uncompressed form.  */
      Q = gcry_mpi_ec_get_mpi ("q", ecdh->ecctx, 0);
      if (!Q)
        {
          return gpg_error (GPG_ERR_INTERNAL);
        }
      debug_mpi (3, "ECDH Qour ", Q);

      /* Write as an ECPoint, that is prefix it with a one octet length.  */
      err = gcry_mpi_print (GCRYMPI_FMT_USG, outbuf+1, outbufsize-1, &n, Q);
      gcry_mpi_release (Q);
      if (err)
        return err;
      if (n > 255)
        return gpg_error (GPG_ERR_INV_DATA);
      outbuf[0] = n;
      n++;
    }

  *r_outbuflen = n;

  return 0;
}


/* Derive the shared secret Z and store it in OUTBUF.  OUTBUFSIZE is
 * the available length of OUTBUF.  On success the actual length of
 * OUTBUF is stored at R_OUTBUFLEN.  */
gpg_error_t
_ntbtls_ecdh_calc_secret (ecdh_context_t ecdh,
                          unsigned char *outbuf, size_t outbufsize,
                          size_t *r_outbuflen)
{
  gpg_error_t err;
  gcry_mpi_point_t P = NULL;
  gcry_mpi_t d = NULL;
  gcry_mpi_t x = NULL;
  size_t n;

  if (!ecdh || !outbuf || !r_outbuflen)
    return gpg_error (GPG_ERR_INV_ARG);

  *r_outbuflen = 0;

  if (!ecdh->curve_name || !ecdh->ecctx || !ecdh->Qpeer)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  /* 1. Check that Q_peer is on the curve
   * 2. Compute:  P = d * Q_peer
   * 2. Check that P is not the point at infinity.
   * 3. Copy the x-coordinate of P to the output.
   */

  if (!gcry_mpi_ec_curve_point (ecdh->Qpeer, ecdh->ecctx))
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  d = gcry_mpi_ec_get_mpi ("d", ecdh->ecctx, 0);
  if (!d)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  P = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (P, d, ecdh->Qpeer, ecdh->ecctx);

  x = gcry_mpi_new (0);
  if (gcry_mpi_ec_get_affine (x, NULL, P, ecdh->ecctx))
    {
      err = gpg_error (GPG_ERR_INV_DATA);
      goto leave;
    }

  err = gcry_mpi_print (GCRYMPI_FMT_USG, outbuf, outbufsize, &n, x);
  if (err)
    goto leave;

  if (ecdh->curve_name[0] == 'X')
    {
      gcry_mpi_t p;
      unsigned int pbits;
      int i;
      int len;

      p = gcry_mpi_ec_get_mpi ("p", ecdh->ecctx, 0);
      if (!p)
        {
          err = gpg_error (GPG_ERR_INTERNAL);
          goto leave;
        }
      pbits  = gcry_mpi_get_nbits (p);
      len = (pbits+7)/8;
      gcry_mpi_release (p);
      if (len > 255)
        {
          err = gpg_error (GPG_ERR_INV_DATA);
          goto leave;
        }

      /* Fill zero, if shorter.  */
      if (n < len)
        {
          memmove (outbuf+len-n, outbuf, n);
          memset (outbuf, 0, len - n);
        }
      /* Reverse the buffer */
      for (i = 0; i < len/2; i++)
        {
          unsigned int tmp;

          tmp = outbuf[i];
          outbuf[i] = outbuf[len-i-1];
          outbuf[len-i-1] = tmp;
        }
      n = len;
    }

  *r_outbuflen = n;

 leave:
  gcry_mpi_release (d);
  gcry_mpi_release (x);
  gcry_mpi_point_release (P);
  return err;
}
