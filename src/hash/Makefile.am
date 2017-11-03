
noinst_LIBRARIES = libhash.a

x_includedir = $(pkgincludedir)/hash

x_include_HEADERS = \
hashes.h \
ghash.h \
xhash.h \
hashfcn.h

libhash_a_SOURCES = \
hashes.cc \
lru_cache_shared.cc \
lru_cache_shared.h \
ghash.cc \
hashfcn.cc \
primetable.cc primetable.h \
xhash.cc \
zhash.cc zhash.h

if BUILD_CPPUTESTS
SUBDIRS = test
endif

