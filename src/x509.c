/* x509.c - X.509 functions
 * Copyright (C) 2001-2010, 2014-2015, 2017  g10 Code GmbH
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
};


/* The object tostore a private key.  */
struct x509_privkey_s
{
  char dummy[32];
};


/* Object to hold a parsed DN. */
struct dn_array_s
{
  char *key;
  char *value;
  int   multivalued;
  int   done;
};


static void
release_dn_array (struct dn_array_s *dnparts)
{
  int i;

  if (!dnparts)
    return;
  for (i=0; dnparts[i].key; i++)
    {
      free (dnparts[i].key);
      free (dnparts[i].value);
    }
  free (dnparts);
}


/* Helper for parse_dn.  */
static const unsigned char *
parse_dn_part (struct dn_array_s *array, const unsigned char *string)
{
  static struct {
    const char *label;
    const char *oid;
  } label_map[] = {
    /* Warning: When adding new labels, make sure that the buffer
       below we be allocated large enough. */
    {"EMail",        "1.2.840.113549.1.9.1" },
    {"T",            "2.5.4.12" },
    {"GN",           "2.5.4.42" },
    {"SN",           "2.5.4.4" },
    {"NameDistinguisher", "0.2.262.1.10.7.20"},
    {"ADDR",         "2.5.4.16" },
    {"BC",           "2.5.4.15" },
    {"D",            "2.5.4.13" },
    {"PostalCode",   "2.5.4.17" },
    {"Pseudo",       "2.5.4.65" },
    {"SerialNumber", "2.5.4.5" },
    {NULL, NULL}
  };
  const unsigned char *s, *s1;
  size_t n;
  char *p;
  int i;

  /* Parse attributeType */
  for (s = string+1; *s && *s != '='; s++)
    ;
  if (!*s)
    return NULL; /* error */
  n = s - string;
  if (!n)
    return NULL; /* empty key */

  /* We need to allocate a few bytes more due to the possible mapping
     from the shorter OID to the longer label. */
  array->key = p = malloc (n+10);
  if (!array->key)
    return NULL;
  memcpy (p, string, n);
  p[n] = 0;
  _ntbtls_trim_trailing_spaces (p);

  if (digitp (p))
    {
      for (i=0; label_map[i].label; i++ )
        if ( !strcmp (p, label_map[i].oid) )
          {
            strcpy (p, label_map[i].label);
            break;
          }
    }
  string = s + 1;

  if (*string == '#')
    { /* hexstring */
      string++;
      for (s=string; hexdigitp (s); s++)
        s++;
      n = s - string;
      if (!n || (n & 1))
        return NULL; /* Empty or odd number of digits. */
      n /= 2;
      array->value = p = malloc (n+1);
      if (!p)
        return NULL;
      for (s1=string; n; s1 += 2, n--, p++)
        {
          *(unsigned char *)p = xtoi_2 (s1);
          if (!*p)
            *p = 0x01; /* Better print a wrong value than truncating
                          the string. */
        }
      *p = 0;
   }
  else
    { /* regular v3 quoted string */
      for (n=0, s=string; *s; s++)
        {
          if (*s == '\\')
            { /* pair */
              s++;
              if (*s == ',' || *s == '=' || *s == '+'
                  || *s == '<' || *s == '>' || *s == '#' || *s == ';'
                  || *s == '\\' || *s == '\"' || *s == ' ')
                n++;
              else if (hexdigitp (s) && hexdigitp (s+1))
                {
                  s++;
                  n++;
                }
              else
                return NULL; /* invalid escape sequence */
            }
          else if (*s == '\"')
            return NULL; /* invalid encoding */
          else if (*s == ',' || *s == '=' || *s == '+'
                   || *s == '<' || *s == '>' || *s == ';' )
            break;
          else
            n++;
        }

      array->value = p = malloc (n+1);
      if (!p)
        return NULL;
      for (s=string; n; s++, n--)
        {
          if (*s == '\\')
            {
              s++;
              if (hexdigitp (s))
                {
                  *(unsigned char *)p++ = xtoi_2 (s);
                  s++;
                }
              else
                *p++ = *s;
            }
          else
            *p++ = *s;
        }
      *p = 0;
    }
  return s;
}


/* Parse a DN and return an array-ized one.  This is not a validating
 * parser and it does not support any old-stylish syntax; KSBA is
 * expected to return only rfc2253 compatible strings.  Returns NULL
 * on error.  */
static struct dn_array_s *
parse_dn (const unsigned char *string)
{
  struct dn_array_s *array;
  size_t arrayidx, arraysize;
  int i;

  arraysize = 7; /* C,ST,L,O,OU,CN,email */
  arrayidx = 0;
  array = malloc ((arraysize+1) * sizeof *array);
  if (!array)
    return NULL;
  while (*string)
    {
      while (*string == ' ')
        string++;
      if (!*string)
        break; /* ready */
      if (arrayidx >= arraysize)
        {
          struct dn_array_s *a2;

          arraysize += 5;
          a2 = realloc (array, (arraysize+1) * sizeof *array);
          if (!a2)
            goto failure;
          array = a2;
        }
      array[arrayidx].key = NULL;
      array[arrayidx].value = NULL;
      string = parse_dn_part (array+arrayidx, string);
      if (!string)
        goto failure;
      while (*string == ' ')
        string++;
      array[arrayidx].multivalued = (*string == '+');
      array[arrayidx].done = 0;
      arrayidx++;
      if (*string && *string != ',' && *string != ';' && *string != '+')
        goto failure; /* invalid delimiter */
      if (*string)
        string++;
    }
  array[arrayidx].key = NULL;
  array[arrayidx].value = NULL;
  return array;

 failure:
  for (i=0; i < arrayidx; i++)
    {
      free (array[i].key);
      free (array[i].value);
    }
  free (array);
  return NULL;
}


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

  /* Walk to the last certificate of the chain.  */
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
  if (idx < 0)
    return NULL;
  for (; cert && idx; cert = cert->next, idx--)
    ;
  if (!cert)
    return NULL;

  return ksba_cert_get_image (cert->crt, r_derlen);
}


/* Return the peer's certificates.  A value of 0 for IDX returns the
 * host's certificate.  To enumerate all other certificates IDX needs
 * to be incremented until the function returns NULL.  The caller
 * must release the returned certificate. */
ksba_cert_t
_ntbtls_x509_get_peer_cert (ntbtls_t tls, int idx)
{
  x509_cert_t cert;

  if (!tls || !tls->session_negotiate || idx < 0)
    return NULL;
  for (cert = tls->session_negotiate->peer_chain;
       cert && idx;
       cert = cert->next, idx--)
    ;
  if (!cert || !cert->crt)
    return NULL;

  ksba_cert_ref (cert->crt);
  return cert->crt;
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


/* Return true if PRIVKEY can do an operation using the public key
   algorithm PKALGO.  */
int
_ntbtls_x509_can_do (x509_privkey_t privkey, pk_algo_t pk_alg)
{
  (void)pk_alg;

  if (!privkey)
    return 0;

  /* FIXME: Check that PRIVKEY matches PKALGO.  */
  return 1;
}


/* Return the number of labels in the DNS NAME.  NAME is invalid 0 is
 * returned. */
static int
count_labels (const char *name)
{
  const char *s;
  int count = 0;

  if (*name == '.')
    name++; /* Skip a leading dot.  */
  if (*name == '.')
    return 0; /* Zero length labels at the start - invalid.  */
  for (s = name; *s; s++)
    {
      if (*s == '.' && s[1] == '.')
        return 0; /* Zero length label - invalid.  */
      else if (*s == '.')
        count++;
    }
  if (s > name && s[-1] == '.')
    return 0; /* Trailing dot - invalid.  */

  return count + 1; /* (NB. We are counting dots).  */
}

/* Check that CERT_NAME matches the hostname WANT_NAME.  Returns 0 if
 * they match, GPG_ERR_WRONG_NAME if they don't match, or an other
 * error code for a bad CERT_NAME.  */
static gpg_err_code_t
check_hostname (const char *cert_name, const char *want_name)
{
  const char *s;
  int wildcard = 0;
  int n_cert = 0;
  int n_want = 0;

  _ntbtls_debug_msg (1, "comparing hostname '%s' to '%s'\n",
                     cert_name, want_name);

  if (*cert_name == '*' && cert_name[1] == '.')
    {
      wildcard = 1;
      cert_name += 2; /* Skip over the wildcard. */

      n_cert = count_labels (cert_name);
      n_want = count_labels (want_name);

      if (n_cert < 2 || n_want < 2)
        return GPG_ERR_WRONG_NAME; /* Less than 2 labels - no wildcards. */
    }

  /* Check that CERT_NAME looks like a valid hostname.  We check the
   * LDH rule, no empty label, and no leading or trailing hyphen.  We
   * do not check digit-only names.  We also check that the hostname
   * does not end in a dot.  */
  if (!*cert_name || *cert_name == '-')
    return GPG_ERR_INV_NAME;

  for (s = cert_name; *s; s++)
    {
      if (!(alnump (s) || strchr ("-.", *s)))
        return GPG_ERR_INV_NAME;
      else if (*s == '.' && s[1] == '.')
        return GPG_ERR_INV_NAME;
    }

  if (s[-1] == '-' || s[-1] == '.')
    return GPG_ERR_INV_NAME;

  if (strstr (cert_name, ".."))
    return GPG_ERR_INV_NAME;

  /* In case of wildcards prepare our name for the strcmp.  */
  if (wildcard)
    {
      if (n_cert == n_want)
        ; /* Compare direct.  */
      else if (n_cert + 1 == n_want)
        {
          /* We know that n_want has at least one dot.  */
          want_name = strchr (want_name, '.');
          if (!want_name)
            return GPG_ERR_BUG;
          want_name++;
        }
      else
        return GPG_ERR_WRONG_NAME;  /* max one label may be wild - no match.  */
    }

  /* Now do the actual strcmp.  */
  if (_ntbtls_ascii_strcasecmp (cert_name, want_name))
    return GPG_ERR_WRONG_NAME;

  return 0; /* Match.  */
}


/* Check that  HOSTNAME is in CERT.  */
gpg_error_t
_ntbtls_x509_check_hostname (x509_cert_t cert, const char *hostname)
{
  gpg_err_code_t ec;
  gpg_error_t err;
  int idx;
  struct dn_array_s *dnparts = NULL;
  char *dn = NULL;
  char *endp, *name;
  char *p;
  int n, cn_count;

  if (!cert || !cert->crt)
    return gpg_error (GPG_ERR_MISSING_CERT);

  /* First we look at the subjectAltNames.  */
  for (idx=1; (dn = ksba_cert_get_subject (cert->crt, idx)); idx++)
    {
      if (!strncmp (dn, "(8:dns-name", 11))
        {
          n = strtol (dn + 11, &endp, 10);
          if (n < 1 || *endp != ':' || endp[1+n] != ')')
            {
              err = gpg_error (GPG_ERR_INV_SEXP);
              goto leave;
            }
          name = endp+1;
          /* Make sure that thare is no embedded nul and trun it into
           * a string.  */
          for (p = name; n; p++, n--)
            if (!*p)
              *p = '\x01'; /* Replace by invalid DNS character.  */
          *p = 0;  /* Replace the final ')'.  */
          ec = check_hostname (name, hostname);
          if (ec != GPG_ERR_WRONG_NAME)
            {
              err = gpg_error (ec);
              goto leave;
            }
        }
      ksba_free (dn);
    }

  /* Then we look at the CN of the subject.  */
  dn = ksba_cert_get_subject (cert->crt, 0);
  if (!dn)
    {
      err = gpg_error (GPG_ERR_BAD_CERT);
      goto leave;
    }

  dnparts = parse_dn (dn);
  if (!dnparts)
    {
      err = gpg_error (GPG_ERR_BAD_CERT);  /* Or out of mem.  */
      goto leave;
    }

  for (idx=cn_count=0; dnparts[idx].key; idx++)
    if (!strcmp (dnparts[idx].key, "CN")
        && ++cn_count > 1)
      {
        err = gpg_error (GPG_ERR_BAD_CERT);
        goto leave;
      }

  for (idx=0; dnparts[idx].key; idx++)
    if (!strcmp (dnparts[idx].key, "CN"))
      break;
  if (dnparts[idx].key)
    err = gpg_error (check_hostname (dnparts[idx].value, hostname));
  else
    err = gpg_error (GPG_ERR_WRONG_NAME);

 leave:
  release_dn_array (dnparts);
  ksba_free (dn);
  return err;
}
