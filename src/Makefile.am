# src/Makefile.am - for NTBTLS
# Copyright (C) 2014 g10 Code GmbH
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

## Process this file with automake to produce Makefile.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ntbtls.pc

EXTRA_DIST = ntbtls.h.in ntbtls.m4 libntbtls.vers libntbtls.def \
             versioninfo.rc.in ntbtls.pc.in
if USE_GPGRT_CONFIG
noinst_SCRIPTS = ntbtls-config
else
bin_SCRIPTS = ntbtls-config
endif
include_HEADERS = ntbtls.h
lib_LTLIBRARIES = libntbtls.la
noinst_PROGRAMS = ntbtls-cli

m4datadir = $(datadir)/aclocal
m4data_DATA = ntbtls.m4

AM_CPPFLAGS =
AM_CFLAGS = $(GPG_ERROR_CFLAGS) $(KSBA_CFLAGS) $(LIBGCRYPT_CFLAGS)

if HAVE_LD_VERSION_SCRIPT
  libntbtls_version_script_cmd = -Wl,--version-script=$(srcdir)/libntbtls.vers
else
  libntbtls_version_script_cmd =
endif


if HAVE_W32_SYSTEM
RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
            $(libntbtls_la_CPPFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

ntbtls_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/libntbtls.def

install-def-file:
	$(INSTALL) $(srcdir)/libntbtls.def $(DESTDIR)$(libdir)/libntbtls.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/libntbtls.def

ntbtls_deps = $(ntbtls_res) libntbtls.def

else !HAVE_W32_SYSTEM
ntbtls_res =
no_undefined =
export_symbols =
ntbtls_deps =
install-def-file:
uninstall-def-file:
endif !HAVE_W32_SYSTEM


libntbtls_la_LDFLAGS = $(no_undefined) $(export_symbols) \
      $(libntbtls_version_script_cmd) -version-info \
      @LIBNTBTLS_LT_CURRENT@:@LIBNTBTLS_LT_REVISION@:@LIBNTBTLS_LT_AGE@
libntbtls_la_INCLUDES = -I$(top_srcdir)/lib
libntbtls_la_DEPENDENCIES = $(srcdir)/libntbtls.vers $(ntbtls_deps)
libntbtls_la_LIBADD = $(ntbtls_res) $(LTLIBOBJS) $(LIBGCRYPT_LIBS) \
                      $(KSBA_LIBS) $(GPG_ERROR_LIBS)


libntbtls_la_SOURCES = \
	ntbtls.h \
        visibility.c visibility.h \
	context.h ntbtls-int.h wipemem.h \
	util.c util.h \
	protocol.c \
	protocol-cli.c \
	ciphersuites.c ciphersuites.h \
	pkglue.c x509.c dhm.c ecdh.c \
	debug.c

# protocol-srv.c

install-data-local: install-def-file

uninstall-local: uninstall-def-file


# Sample programs

ntbtls_cli_CFLAGS = $(LIBGCRYPT_CFLAGS) $(KSBA_CFLAGS) $(GPG_ERROR_CFLAGS)
if HAVE_W32_SYSTEM
ntbtls_cli_LDFLAGS = -no-fast-install
else
ntbtls_cli_LDFLAGS = -no-install
endif
ntbtls_cli_LDADD = libntbtls.la $(LIBGCRYPT_LIBS) $(KSBA_LIBS) \
                   $(GPG_ERROR_LIBS) $(NETLIBS)
