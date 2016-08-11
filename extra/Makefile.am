ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

# the below files are implicitly included in EXTRA_DIST if present
# but autoreconf -isvf won't install them here because it finds them
# in the parent dir.  this means they must be explicitly copied from 
# the parent to this source dir after the autoreconf step when doing
# distcheck.  this situation also necessitates adding DISTCLEANFILES
# to keep distcheck happy even w/o EXTRA_DIST.

EXTRA_DIST = \
config.guess \
config.sub \
install-sh \
ltmain.sh \
missing \
depcomp

DISTCLEANFILES = $(EXTRA_DIST)

SUBDIRS = src
