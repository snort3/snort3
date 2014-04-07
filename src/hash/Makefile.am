AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libhash.a

x_includedir = $(pkgincludedir)/hash

x_include_HEADERS = \
sfghash.h \
sfxhash.h \
sfhashfcn.h

libhash_a_SOURCES = \
sfghash.cc \
sfhashfcn.cc \
sfprimetable.cc sfprimetable.h \
sfxhash.cc \
zhash.cc zhash.h

AM_CXXFLAGS = @AM_CXXFLAGS@

