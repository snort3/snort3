ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
src \
lua \
tools \
doc \
daqs

EXTRA_DIST = \
snort.pc.in \
README.md \
COPYING \
LICENSE

DISTCLEANFILES = \
stamp-h.in \
cflags.out \
cppflags.out

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = snort.pc

# Code coverage
@CODE_COVERAGE_RULES@
