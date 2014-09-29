/* dhm.c - Diffie-Hellman-Merkle key exchange
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
struct dhm_context_s
{
  gcry_mpi_t dh_p;  /* The prime modulus used for the DH operation.  */
  gcry_mpi_t dh_g;  /* The generator used for the DH operation.      */
  gcry_mpi_t dh_Gy; /* The peer's DH public value (g^y mod p).  The
                       value has been checked to fulfill the size
                       requirements.                                 */
  gcry_mpi_t dh_x;  /* Our secret.                                   */
  gcry_mpi_t dh_Gx; /* Our own DH public value (g^x mod p).          */
};



/* Create a new DHM context.  */
gpg_error_t
_ntbtls_dhm_new (dhm_context_t *r_dhm)
{
  dhm_context_t dhm;

  *r_dhm = NULL;

  dhm = calloc (1, sizeof *dhm);
  if (!dhm)
    return gpg_error_from_syserror ();

  *r_dhm = dhm;

  return 0;
}


/* Release a DHM context.  */
void
_ntbtls_dhm_release (dhm_context_t dhm)
{
  if (!dhm)
    return;
  gcry_mpi_release (dhm->dh_p);
  gcry_mpi_release (dhm->dh_g);
  gcry_mpi_release (dhm->dh_Gy);
  gcry_mpi_release (dhm->dh_x);
  gcry_mpi_release (dhm->dh_Gx);
  free (dhm);
}


static gpg_error_t
read_mpi (const unsigned char *data, size_t datalen,
          gcry_mpi_t *r_mpi, size_t *r_nscanned)
{
  size_t n;

  if (datalen < 2)
    return gpg_error (GPG_ERR_TOO_SHORT);
  n = ((data[0] << 8) | data[1]);
  data += 2;
  datalen -= 2;
  if (n > datalen)
    return gpg_error (GPG_ERR_TOO_LARGE);
  *r_nscanned = 2 + n;
  return gcry_mpi_scan (r_mpi, GCRYMPI_FMT_USG, data, n, NULL);
}



/* Parse the TLS ServerDHParams and store it in DHM.  DER is the
 * buffer with the params of length DERLEN.  The number of actual
 * parsed bytes is stored at R_NPARSED.  */
gpg_error_t
_ntbtls_dhm_read_params (dhm_context_t dhm, const void *_der, size_t derlen,
                         size_t *r_nparsed)
{
  gpg_error_t err;
  const unsigned char *der = _der;
  size_t n;
  gcry_mpi_t a = NULL;

  if (r_nparsed)
    *r_nparsed = 0;

  if (!dhm || !der)
    return gpg_error (GPG_ERR_INV_ARG);

  gcry_mpi_release (dhm->dh_p);  dhm->dh_p = NULL;
  gcry_mpi_release (dhm->dh_g);  dhm->dh_g = NULL;
  gcry_mpi_release (dhm->dh_Gy); dhm->dh_Gy = NULL;

  /*   struct {
   *       opaque dh_p<1..2^16-1>;
   *       opaque dh_g<1..2^16-1>;
   *       opaque dh_Ys<1..2^16-1>;
   *   } ServerDHParams;
   */
  err = read_mpi (der, derlen, &dhm->dh_p, &n);
  if (err)
    goto leave;
  debug_mpi (3, "DHM  p", dhm->dh_p);
  if (r_nparsed)
    *r_nparsed += n;
  der += n;
  derlen -= n;

  err = read_mpi (der, derlen, &dhm->dh_g, &n);
  if (err)
    goto leave;
  debug_mpi (3, "DHM  g", dhm->dh_g);
  if (r_nparsed)
    *r_nparsed += n;
  der += n;
  derlen -= n;

  err = read_mpi (der, derlen, &dhm->dh_Gy, &n);
  if (err)
    goto leave;
  debug_mpi (3, "DHM Ys", dhm->dh_Gy);
  if (r_nparsed)
    *r_nparsed += n;

  /* Check for: 2 <= Ys <= P - 2.  */
  if (gcry_mpi_cmp_ui (dhm->dh_Gy, 2) < 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  a = gcry_mpi_new (0);
  gcry_mpi_sub_ui (a, dhm->dh_p, 2);
  if (gcry_mpi_cmp (dhm->dh_Gy, a) > 0)
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }

  err = 0;

 leave:
  gcry_mpi_release (a);
  if (err)
    {
      gcry_mpi_release (dhm->dh_p);  dhm->dh_p = NULL;
      gcry_mpi_release (dhm->dh_g);  dhm->dh_g = NULL;
      gcry_mpi_release (dhm->dh_Gy); dhm->dh_Gy = NULL;
    }

  return err;
}


/* Return the size of the prime modulus in bits.  */
unsigned int
_ntbtls_dhm_get_nbits (dhm_context_t dhm)
{
  if (!dhm || !dhm->dh_p)
    return 0;
  return gcry_mpi_get_nbits (dhm->dh_p);
}




/* Create our own private value X and store G^X in OUTBUF.  OUTBUFSIZE
   is the available length of OUTBUF.  On success the actual length of
   OUTBUF is stored at R_OUTBUFLEN.  */
gpg_error_t
_ntbtls_dhm_make_public (dhm_context_t dhm,
                         unsigned char *outbuf, size_t outbufsize,
                         size_t *r_outbuflen)
{
  gpg_error_t err;
  unsigned int nbits, nbytes;
  size_t n;
  gcry_mpi_t dh_pm2;

  if (!dhm || !outbuf || !r_outbuflen)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!dhm->dh_p)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  nbits = gcry_mpi_get_nbits (dhm->dh_p);
  if (nbits < 512)
    return gpg_error (GPG_ERR_INTERNAL);  /* Ooops.  */
  nbytes = (nbits +7)/8;

  if (outbufsize < 2 + nbytes)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);

  if (!dhm->dh_Gx)
    dhm->dh_Gx = gcry_mpi_new (nbits);

  /* Create the random value X and make sure that 2 <= X <= P-2.
     Because we truncate X to NBITS-1, it is highly unlikely that this
     will ever loop for creating X.  Computing Gx is also checked that
     it fits into the range and it is also unlikely to loop agains.
     Thus we simply allocate a new random value if we ever need to
     loop.  */
  dh_pm2 = gcry_mpi_new (nbits);
  gcry_mpi_sub_ui (dh_pm2, dhm->dh_p, 2);

  if (!dhm->dh_x)
    dhm->dh_x = gcry_mpi_snew (nbits);
  do
    {
      do
        {
          gcry_mpi_randomize (dhm->dh_x, nbits-1, GCRY_STRONG_RANDOM);
          gcry_mpi_clear_highbit (dhm->dh_x, nbits);
        }
      while (gcry_mpi_cmp_ui (dhm->dh_x, 2) < 0
             || gcry_mpi_cmp (dhm->dh_x, dh_pm2) > 0);

      gcry_mpi_powm (dhm->dh_Gx, dhm->dh_g, dhm->dh_x, dhm->dh_p);
    }
  while (gcry_mpi_cmp_ui (dhm->dh_Gx, 2) < 0
         || gcry_mpi_cmp (dhm->dh_Gx, dh_pm2) > 0);

  gcry_mpi_release (dh_pm2);

  debug_mpi (4, "DHM  x", dhm->dh_x);
  debug_mpi (3, "DHM Gx", dhm->dh_Gx);

  outbuf[0] = nbytes >> 8;
  outbuf[1] = nbytes;
  err = gcry_mpi_print (GCRYMPI_FMT_USG, outbuf+2,outbufsize-2, &n, dhm->dh_Gx);
  if (err)
    return err;

  *r_outbuflen = 2 + n;
  return 0;
}


/* Derive the shared secret (G^Y)^X mod P and store it in OUTBUF.
   OUTBUFSIZE is the available length of OUTBUF.  On success the
   actual length of OUTBUF is stored at R_OUTBUFLEN.   */
gpg_error_t
_ntbtls_dhm_calc_secret (dhm_context_t dhm,
                         unsigned char *outbuf, size_t outbufsize,
                         size_t *r_outbuflen)
{
  gpg_error_t err;
  unsigned int nbits, nbytes;
  size_t n;
  gcry_mpi_t dh_Gyx;

  if (!dhm || !outbuf || !r_outbuflen)
    return gpg_error (GPG_ERR_INV_ARG);

  if (!dhm->dh_p || !dhm->dh_x)
    return gpg_error (GPG_ERR_NOT_INITIALIZED);

  nbits = gcry_mpi_get_nbits (dhm->dh_p);
  if (nbits < 512)
    return gpg_error (GPG_ERR_INTERNAL);  /* Ooops.  */
  nbytes = (nbits +7)/8;

  if (outbufsize < nbytes)
    return gpg_error (GPG_ERR_BUFFER_TOO_SHORT);

  //FIXME: Add blinding
  dh_Gyx = gcry_mpi_new (nbits);
  gcry_mpi_powm (dh_Gyx, dhm->dh_Gy, dhm->dh_x, dhm->dh_p);

  debug_mpi (3, "DHMGyx", dh_Gyx);

  err = gcry_mpi_print (GCRYMPI_FMT_USG, outbuf, outbufsize, &n, dh_Gyx);
  gcry_mpi_release (dh_Gyx);
  if (err)
    return err;

  *r_outbuflen = n;
  return 0;
}
