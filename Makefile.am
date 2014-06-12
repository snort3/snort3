AUTOMAKE_OPTIONS=foreign no-dependencies

SUBDIRS = \
src \
lua \
doc \
etc \
tools

AM_CXXFLAGS = @AM_CXXFLAGS@

EXTRA_DIST = \
ChangeLog \
snort.pc.in

DISTCLEANFILES = \
stamp-h.in \
cflags.out \
cppflags.out

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = snort.pc
