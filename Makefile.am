ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
src \
lua \
tools \
daqs

if MAKE_DOC
SUBDIRS += \
doc
endif

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
