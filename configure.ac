# configure.ac - for the Not Too Bad TLS library
# Copyright (C) 2014-2017 g10 Code GmbH
#
# This file is part of NTBTLS
#
# NTBTLS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# NTBTLS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# (git tag -s gnupg-2.n.m) and run "./autogen.sh --force".  Please
# bump the version number immediately *after* the release and do
# another commit and push so that the git magic is able to work.
m4_define([mym4_package],[ntbtls])
m4_define([mym4_major], [0])
m4_define([mym4_minor], [3])
m4_define([mym4_micro], [2])

# To start a new development series, i.e a new major or minor number
# you need to mark an arbitrary commit before the first beta release
# with an annotated tag.  For example the 1.2 branch starts off with
# the tag "ntbtls-1.2-base".  This is used as the base for counting
# beta numbers before the first release of a series.

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isbeta).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_verslist], m4_split(m4_esyscmd([./autogen.sh --find-version] \
                           mym4_package mym4_major mym4_minor mym4_micro),[:]))
m4_define([mym4_isbeta],       m4_argn(2, mym4_verslist))
m4_define([mym4_version],      m4_argn(4, mym4_verslist))
m4_define([mym4_revision],     m4_argn(7, mym4_verslist))
m4_define([mym4_revision_dec], m4_argn(8, mym4_verslist))
m4_esyscmd([echo ]mym4_version[>VERSION])
AC_INIT([mym4_package],[mym4_version],[https://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBNTBTLS_LT_CURRENT=1
LIBNTBTLS_LT_AGE=1
LIBNTBTLS_LT_REVISION=3

# If the API is changed in an incompatible way: increment the next counter.
NTBTLS_CONFIG_API_VERSION=1

# Minimum versions for required libraries

NEED_GPG_ERROR_VERSION=1.25

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.8.0

NEED_KSBA_API=1
NEED_KSBA_VERSION=1.2.0


# End of config section

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/ntbtls.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

# Some status variables.
have_gpg_error=no
have_libgcrypt=no
have_ksba=no
use_zip=yes

AC_SUBST(LIBNTBTLS_LT_CURRENT)
AC_SUBST(LIBNTBTLS_LT_AGE)
AC_SUBST(LIBNTBTLS_LT_REVISION)

VERSION_NUMBER=m4_esyscmd(printf "0x%02x%02x%02x" mym4_major \
                          mym4_minor mym4_micro)
AC_SUBST(VERSION_NUMBER)


AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION, "$NEED_LIBGCRYPT_VERSION",
                                       [Required version of Libgcrypt])
AC_DEFINE_UNQUOTED(NEED_KSBA_VERSION, "$NEED_KSBA_VERSION",
                                       [Required version of Libksba])




#
# To avoid double inclusion of config.h which might happen at some
# places, we add the usual double inclusion protection at the top of
# config.h.
#
AH_TOP([
#ifndef NTBTLS_CONFIG_H_INCLUDED
#define NTBTLS_CONFIG_H_INCLUDED
])

#
# Stuff which goes at the bottom of config.h.
#
AH_BOTTOM([
/* If the configure check for endianness has been disabled, get it from
   OS macros.  This is intended for making fat binary builds on OS X.  */
#ifdef DISABLED_ENDIAN_CHECK
# if defined(__BIG_ENDIAN__)
#  define WORDS_BIGENDIAN 1
# elif defined(__LITTLE_ENDIAN__)
#  undef WORDS_BIGENDIAN
# else
#  error "No endianness found"
# endif
#endif /*DISABLED_ENDIAN_CHECK*/

/* Provide the es_ macro for estream.  */
#define GPGRT_ENABLE_ES_MACROS 1

/* Tell libgcrypt not to use its own libgpg-error implementation. */
#define USE_LIBGPG_ERROR 1

/* Tell Libgcrypt not to include deprecated definitions.  */
#define GCRYPT_NO_DEPRECATED 1

#endif /*NTBTLS_CONFIG_H_INCLUDED*/
])


# Substitutions to set generated files in a Emacs buffer to read-only.
AC_SUBST(emacs_local_vars_begin, ['Local Variables:'])
AC_SUBST(emacs_local_vars_read_only, ['buffer-read-only: t'])
AC_SUBST(emacs_local_vars_end, ['End:'])


AM_MAINTAINER_MODE

AC_ARG_VAR(SYSROOT,[locate config scripts also below that directory])


# Checks for programs.
AC_MSG_NOTICE([checking for programs])
AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AM_SILENT_RULES
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AC_CHECK_TOOL(AR, ar, :)
AC_PATH_PROG(PERL,"perl")
AC_CHECK_TOOL(WINDRES, windres, :)
AC_SEARCH_LIBS([strerror],[cposix])

# We need to compile and run a program on the build machine.  A
# comment in libgpg-error says that the AC_PROG_CC_FOR_BUILD macro in
# the AC archive is broken for autoconf 2.57.  Given that there is no
# newer version of that macro, we assume that it is also broken for
# autoconf 2.61 and thus we use a simple but usually sufficient
# approach.
AC_MSG_CHECKING(for cc for build)
if test "$cross_compiling" = "yes"; then
  CC_FOR_BUILD="${CC_FOR_BUILD-cc}"
else
  CC_FOR_BUILD="${CC_FOR_BUILD-$CC}"
fi
AC_MSG_RESULT($CC_FOR_BUILD)
AC_ARG_VAR(CC_FOR_BUILD,[build system C compiler])

LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])


have_dosish_system=no
have_w32_system=no
have_w32ce_system=no
have_android_system=no
run_tests=yes
case "${host}" in
    *-mingw32*)
        # special stuff for Windoze NT
        have_dosish_system=yes
        have_w32_system=yes
        run_tests=no
        ;;
    *-linux-androideabi)
        have_android_system=yes
        run_tests=no
        ;;
    *-apple-darwin*)
        AC_DEFINE(_DARWIN_C_SOURCE, 1,
                  Expose all libc features (__DARWIN_C_FULL).)
        ;;
    *)
       ;;
esac

if test "$have_dosish_system" = yes; then
   AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
             [Defined if we run on some of the PCDOS like systems
              (DOS, Windoze. OS/2) with special properties like
              no file modes, case insensitive file names and preferred
              use of backslashes as directory name separators.])
fi
AM_CONDITIONAL(HAVE_DOSISH_SYSTEM, test "$have_dosish_system" = yes)

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
   AC_CHECK_HEADERS([winsock2.h])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)

if test "$have_android_system" = yes; then
   AC_DEFINE(HAVE_ANDROID_SYSTEM,1, [Defined if we build for an Android system])
fi
AM_CONDITIONAL(HAVE_ANDROID_SYSTEM, test "$have_android_system" = yes)

if test "$run_tests" = yes; then
   AC_DEFINE(RUN_TESTS,1, [Defined if we should run the tests])
fi
AM_CONDITIONAL(RUN_TESTS, test "$run_tests" = yes)


#
# Checks for libraries.
#
AC_MSG_NOTICE([checking for libraries])


#
# libgpg-error is a library with common runtime functions like error
# codes, simple mutexes, and the estream functions.
#
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_TLS,
          [The default error source for NTBTLS.])

AM_CONDITIONAL(USE_GPGRT_CONFIG, [test -n "$GPGRT_CONFIG" \
                                  -a "$ac_cv_path_GPG_ERROR_CONFIG" = no])

#
# Libgcrypt is our generic crypto library
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
                  have_libgcrypt=yes,have_libgcrypt=no)


#
# libksba is our X.509 support library
#
AM_PATH_KSBA("$NEED_KSBA_API:$NEED_KSBA_VERSION",have_ksba=yes,have_ksba=no)



AC_MSG_NOTICE([checking for networking options])

#
# Must check for network library requirements before doing link tests
# for ldap, for example. If ldap libs are static (or dynamic and without
# ELF runtime link paths), then link will fail and LDAP support won't
# be detected.
#
AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))


#
# Checks for header files.
#
AC_MSG_NOTICE([checking for header files])
AC_CHECK_HEADERS([string.h unistd.h stdint.h])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_MSG_NOTICE([checking for system characteristics])
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_CHECK_SIZEOF(unsigned long)
AC_TYPE_SIZE_T
AC_TYPE_MODE_T

# For some systems we know that we have ld_version scripts.
# Use it then as default.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
esac

AC_ARG_ENABLE([ld-version-script],
              AS_HELP_STRING([--enable-ld-version-script],
                             [enable/disable use of linker version script.
                              (default is system dependent)]),
              [have_ld_version_script=$enableval],
              [ : ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

#
# Specify how we support our local modification of libtool for Windows
# 64-bit.  Options are:
#
# (1) apply: when appying patch fails, it results failure of entire build
# (2) never: never apply the patch (no try)
# (3) try: use patched if it goes well, use original if fails
#
AC_ARG_WITH([libtool-modification],
  AS_HELP_STRING([--with-libtool-modification=apply|never|try],
                 [how to handle libtool modification (default=never)]),
                 build_libtool_modification=$withval,
                 build_libtool_modification=never)

#
# Apply a patch (locally maintained one of ours) to libtool
#
case $host in
  x86_64-*mingw32*)
AC_CONFIG_COMMANDS([libtool-patch],[[
  if test "$build_selection" = never; then
    echo "patch not applied"
  elif (mv -f libtool libtool.orig; \
        sed -f $srcdir/build-aux/libtool-patch.sed libtool.orig >libtool); then
    echo "applied successfully"
  elif test "$build_selection" = try; then
    mv -f libtool.orig libtool
    echo "patch failed, thus, using original"
  else
    echo "patch failed"
    as_fn_exit 1
  fi
]],[build_selection=$build_libtool_modification])
  ;;
  *)
  ;;
esac

AC_ARG_ENABLE(endian-check,
              AS_HELP_STRING([--disable-endian-check],
              [disable the endian check and trust the OS provided macros]),
	      endiancheck=$enableval,endiancheck=yes)
if test x"$endiancheck" = xyes ; then
  AC_C_BIGENDIAN
else
  AC_DEFINE(DISABLED_ENDIAN_CHECK,1,[configure did not test for endianess])
fi

#
# Checks for library functions.
#
AC_MSG_NOTICE([checking for library functions])
AC_CHECK_FUNCS([strlwr flockfile])



#
# Check for ELF visibility support.
#
AC_CACHE_CHECK(whether the visibility attribute is supported,
       ntbtls_cv_visibility_attribute,
       [ntbtls_cv_visibility_attribute=no
        AC_LANG_CONFTEST([AC_LANG_SOURCE(
          [[int foo __attribute__ ((visibility ("hidden"))) = 1;
            int bar __attribute__ ((visibility ("protected"))) = 1;
          ]])])

        if ${CC-cc} -Werror -S conftest.c -o conftest.s \
                  1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD ; then
            if grep '\.hidden.*foo' conftest.s >/dev/null 2>&1 ; then
                if grep '\.protected.*bar' conftest.s >/dev/null 2>&1; then
                    ntbtls_cv_visibility_attribute=yes
                fi
            fi
        fi
       ])
if test "$ntbtls_cv_visibility_attribute" = "yes"; then
    AC_CACHE_CHECK(for broken visibility attribute,
       ntbtls_cv_broken_visibility_attribute,
       [ntbtls_cv_broken_visibility_attribute=yes
        AC_LANG_CONFTEST([AC_LANG_SOURCE(
          [[int foo (int x);
            int bar (int x) __asm__ ("foo")
                            __attribute__ ((visibility ("hidden")));
            int bar (int x) { return x; }
          ]])])

        if ${CC-cc} -Werror -S conftest.c -o conftest.s \
                  1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD ; then
           if grep '\.hidden@<:@ 	_@:>@foo' conftest.s >/dev/null 2>&1;
            then
               ntbtls_cv_broken_visibility_attribute=no
           fi
        fi
       ])
fi
if test "$ntbtls_cv_visibility_attribute" = "yes"; then
    AC_CACHE_CHECK(for broken alias attribute,
       ntbtls_cv_broken_alias_attribute,
       [ntbtls_cv_broken_alias_attribute=yes
        AC_LANG_CONFTEST([AC_LANG_SOURCE(
          [[extern int foo (int x) __asm ("xyzzy");
            int bar (int x) { return x; }
            extern __typeof (bar) foo __attribute ((weak, alias ("bar")));
            extern int dfoo;
            extern __typeof (dfoo) dfoo __asm ("abccb");
            int dfoo = 1;
          ]])])

        if ${CC-cc} -Werror -S conftest.c -o conftest.s \
                  1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD ; then
           if grep 'xyzzy' conftest.s >/dev/null 2>&1 && \
              grep 'abccb' conftest.s >/dev/null 2>&1; then
              ntbtls_cv_broken_alias_attribute=no
           fi
        fi
        ])
fi
if test "$ntbtls_cv_visibility_attribute" = "yes"; then
    AC_CACHE_CHECK(if gcc supports -fvisibility=hidden,
       ntbtls_cv_gcc_has_f_visibility,
       [ntbtls_cv_gcc_has_f_visibility=no
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-fvisibility=hidden"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                          ntbtls_cv_gcc_has_f_visibility=yes)
        CFLAGS=$_gcc_cflags_save;
       ])
fi
if test "$ntbtls_cv_visibility_attribute" = "yes" \
   && test "$ntbtls_cv_broken_visibility_attribute" != "yes" \
   && test "$ntbtls_cv_broken_alias_attribute" != "yes" \
   && test "$ntbtls_cv_gcc_has_f_visibility" = "yes"
 then
   AC_DEFINE(NTBTLS_USE_VISIBILITY, 1,
               [Define to use the GNU C visibility attribute.])
   CFLAGS="$CFLAGS -fvisibility=hidden"
fi


#
# Do we have zlib? Must do it here because Solaris failed
# when compiling a conftest (due to the "-lz" from LIBS).
# Note that we combine zlib and bzlib2 in ZLIBS.
#
if test "$use_zip" = yes ; then
  _cppflags="${CPPFLAGS}"
  _ldflags="${LDFLAGS}"
  AC_ARG_WITH(zlib,
    [  --with-zlib=DIR         use libz in DIR],[
      if test -d "$withval"; then
        CPPFLAGS="${CPPFLAGS} -I$withval/include"
        LDFLAGS="${LDFLAGS} -L$withval/lib"
      fi
    ])

  AC_CHECK_HEADER(zlib.h,
     AC_CHECK_LIB(z, deflateInit2_,
       [
       ZLIBS="-lz"
       AC_DEFINE(HAVE_ZIP,1, [Defined if ZIP and ZLIB are supported])
       ],
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})
fi



AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

# Add some extra libs here so that previous tests don't fail for
# mysterious reasons - the final link step should bail out.
# W32SOCKLIBS is also defined so that if can be used for tools not
# requiring any network stuff but linking to code in libcommon which
# tracks in winsock stuff (e.g. init_common_subsystems).
if test "$have_w32_system" = yes; then
   if test "$have_w32ce_system" = yes; then
     W32SOCKLIBS="-lws2"
   else
     W32SOCKLIBS="-lws2_32"
   fi
   NETLIBS="${NETLIBS} ${W32SOCKLIBS}"
fi

AC_SUBST(NETLIBS)
AC_SUBST(W32SOCKLIBS)

#
# Setup gcc specific options
#
AC_MSG_NOTICE([checking for cc features])
if test "$GCC" = yes; then
    # Check whether gcc does not emit a diagnositc for unknow -Wno-*
    # options.  This is the case for gcc >= 4.6
    AC_MSG_CHECKING([if gcc ignores unknown -Wno-* options])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6 )
#kickerror
#endif]],[])],[_gcc_silent_wno=yes],[_gcc_silent_wno=no])
    AC_MSG_RESULT($_gcc_silent_wno)

    # Note that it is okay to use CFLAGS here because these are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -O3 -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wformat -Wno-format-y2k -Wformat-security"
        if test x"$_gcc_silent_wno" = xyes ; then
          _gcc_wopt=yes
        else
          AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
          _gcc_cflags_save=$CFLAGS
          CFLAGS="-Wno-missing-field-initializers"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                            [_gcc_wopt=yes],[_gcc_wopt=no])
          AC_MSG_RESULT($_gcc_wopt)
          CFLAGS=$_gcc_cflags_save;
        fi
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -W -Wno-sign-compare -Wno-missing-field-initializers"
        fi

        AC_MSG_CHECKING([if gcc supports -Wdeclaration-after-statement])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wdeclaration-after-statement"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -Wdeclaration-after-statement"
        fi
    else
        CFLAGS="$CFLAGS -Wall"
    fi

    if test x"$_gcc_silent_wno" = xyes ; then
      _gcc_psign=yes
    else
      AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
      _gcc_cflags_save=$CFLAGS
      CFLAGS="-Wno-pointer-sign"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                        [_gcc_psign=yes],[_gcc_psign=no])
      AC_MSG_RESULT($_gcc_psign)
      CFLAGS=$_gcc_cflags_save;
    fi
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi
fi


#
# This is handy for debugging so the compiler doesn't rearrange
# things and eliminate variables.
#
AC_ARG_ENABLE(optimization,
   AS_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed s/-O[[1-9]]\ /-O0\ /g`
                   fi])

#
# Set variables for use by automake makefiles.
#



#
# Set variables for use by ntbtls-config.
#
NTBTLS_CONFIG_LIBS="-lntbtls"
NTBTLS_CONFIG_CFLAGS=""
NTBTLS_CONFIG_HOST="$host"

AC_SUBST(NTBTLS_CONFIG_API_VERSION)
AC_SUBST(NTBTLS_CONFIG_LIBS)
AC_SUBST(NTBTLS_CONFIG_CFLAGS)
AC_SUBST(NTBTLS_CONFIG_HOST)


#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
AC_SUBST(BUILD_REVISION)
AC_DEFINE_UNQUOTED(BUILD_REVISION, "$BUILD_REVISION",
                   [GIT commit id revision used to build this package])

changequote(,)dnl
BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
changequote([,])dnl
BUILD_FILEVERSION="${BUILD_FILEVERSION}mym4_revision_dec"
AC_SUBST(BUILD_FILEVERSION)
AC_ARG_ENABLE([build-timestamp],
  AS_HELP_STRING([--enable-build-timestamp],
                 [set an explicit build timestamp for reproducibility.
                  (default is the current time in ISO-8601 format)]),
     [if test "$enableval" = "yes"; then
        BUILD_TIMESTAMP=`date -u +%Y-%m-%dT%H:%M+0000 2>/dev/null || date`
      else
        BUILD_TIMESTAMP="$enableval"
      fi],
     [BUILD_TIMESTAMP="<none>"])
AC_SUBST(BUILD_TIMESTAMP)
AC_DEFINE_UNQUOTED(BUILD_TIMESTAMP, "$BUILD_TIMESTAMP",
                   [The time this package was configured for a build])
BUILD_HOSTNAME="$ac_hostname"
AC_SUBST(BUILD_HOSTNAME)


#
# Print errors here so that they are visible all
# together and the user can acquire them all together.
#
die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libgpg-error to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libgcrypt" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libgcrypt to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION (API $NEED_LIBGCRYPT_API) is required.)
***]])
fi
if test "$have_ksba" = "no"; then
    die=yes
    AC_MSG_NOTICE([[
***
*** You need libksba to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libksba/
*** (at least version $NEED_KSBA_VERSION using API $NEED_KSBA_API is required).
***]])
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi



AC_CONFIG_FILES([
Makefile
m4/Makefile
src/Makefile
src/ntbtls.h
src/ntbtls-config
src/ntbtls.pc
src/versioninfo.rc
])
AC_CONFIG_COMMANDS([ntbtls-conf],[[
chmod +x src/ntbtls-config
]])


AC_OUTPUT

echo "
        NTBTLS v${VERSION} has been configured as follows:

        Revision:  mym4_revision  (mym4_revision_dec)
        Platform:  $host

"
if test "x${gpg_config_script_warn}" != x; then
cat <<G10EOF
        Mismatches between the target platform and the to
        be used libraries have been been detected for:
         ${gpg_config_script_warn}
        Please check above for warning messages.

G10EOF
fi
