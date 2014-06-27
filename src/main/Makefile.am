AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/main

noinst_LIBRARIES = libmain.a

x_include_HEADERS = \
snort_debug.h \
snort_types.h \
thread.h

libmain_a_SOURCES = \
analyzer.cc \
analyzer.h \
build.h \
modules.cc \
modules.h \
policy.cc \
policy.h \
snort.cc \
snort.h \
snort_config.cc \
snort_config.h \
snort_debug.cc \
thread.cc

AM_CXXFLAGS = @AM_CXXFLAGS@
