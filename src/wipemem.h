/* wipemem.h - wipememory macros
 * Copyright (C) 2013 Jussi Kivilinna
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

#ifndef NTBTLS_WIPEMEM_H
#define NTBTLS_WIPEMEM_H

/* To avoid that a compiler optimizes certain memset calls away, these
   macros may be used instead. */
#ifdef HAVE_STDINT_H
# include <stdint.h>

/* Following architectures can handle unaligned accesses fast.  */
# if defined(__i386__) || defined(__x86_64__) || \
     defined(__powerpc__) || defined(__powerpc64__) || \
     (defined(__arm__) && defined(__ARM_FEATURE_UNALIGNED)) || \
     defined(__aarch64__)
#  define _fast_wipememory2_unaligned_head(_ptr,_set,_len) /*do nothing*/
# else
#define FASTWIPE_T uint64_t
#  define _fast_wipememory2_unaligned_head(_vptr,_vset,_vlen) do     \
    {                                                                \
      while((size_t)(_vptr)&(sizeof(FASTWIPE_T)-1) && _vlen)         \
        { *_vptr=(_vset); _vptr++; _vlen--; }                        \
    } while(0)
# endif

/* _fast_wipememory2 may leave tail bytes unhandled, in which case
   tail bytes are handled by wipememory2. */
# define _fast_wipememory2(_vptr,_vset,_vlen) do                        \
    {                                                                   \
      uint64_t _vset_long = _vset;                                      \
      _fast_wipememory2_unaligned_head(_vptr,_vset,_vlen);              \
      if (_vlen < sizeof(uint64_t))                                     \
        break;                                                          \
      _vset_long *= UINT64_C(0x0101010101010101);                          \
      do {                                                              \
        volatile uint64_t *_vptr_long = (volatile void *)_vptr;         \
        *_vptr_long = _vset_long;                                       \
        _vlen -= sizeof(uint64_t);                                      \
        _vptr += sizeof(uint64_t);                                      \
      } while (_vlen >= sizeof(uint64_t));                              \
    } while (0)


# define wipememory2(_ptr,_set,_len) do                          \
    {                                                            \
      volatile char *_vptr=(volatile char *)(_ptr);              \
      size_t _vlen=(_len);                                       \
      unsigned char _vset=(_set);                                \
      _fast_wipememory2(_vptr,_vset,_vlen);                      \
      while(_vlen) { *_vptr=(_vset); _vptr++; _vlen--; }         \
    } while (0)

#else /*!HAVE_STDINT_H*/

# define wipememory2(_ptr,_set,_len) do                         \
    {                                                           \
      volatile char *_vptr=(volatile char *)(_ptr);             \
      size_t _vlen=(_len);                                      \
      while(_vlen) { *_vptr=(_set); _vptr++; _vlen--; }         \
    } while (0)


#endif /*!HAVE_STDINT_H*/

#define wipememory(_ptr,_len) wipememory2(_ptr,0,_len)

#endif /*NTBTLS_WIPEMEM_H*/
