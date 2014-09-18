# Makefile - for NTBTLS
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

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2
DISTCHECK_CONFIGURE_FLAGS =

# (A suitable gitlog-to-changelog script can be found in GnuPG master.)
GITLOG_TO_CHANGELOG=gitlog-to-changelog

DIST_SUBDIRS = m4 src
SUBDIRS =         src

EXTRA_DIST = autogen.sh autogen.rc README.GIT VERSION 	               \
             build-aux/git-log-footer build-aux/git-log-fix

DISTCLEANFILES =


.PHONY: gen-ChangeLog
gen-ChangeLog:
	if test -d $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	    $(GITLOG_TO_CHANGELOG) --append-dot --tear-off		\
	    --amend=build-aux/git-log-fix	 			\
	    ) > $(distdir)/cl-t;		                        \
          cat $(top_srcdir)/build-aux/git-log-footer >> $(distdir)/cl-t;\
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi
