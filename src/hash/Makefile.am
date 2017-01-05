
noinst_LIBRARIES = libhash.a

x_includedir = $(pkgincludedir)/hash

x_include_HEADERS = \
hashes.h \
sfghash.h \
sfxhash.h \
sfhashfcn.h

libhash_a_SOURCES = \
hashes.cc \
lru_cache_shared.cc \
lru_cache_shared.h \
sfghash.cc \
sfhashfcn.cc \
sfprimetable.cc sfprimetable.h \
sfxhash.cc \
zhash.cc zhash.h

if BUILD_CPPUTESTS
SUBDIRS = test
endif

