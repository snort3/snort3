
noinst_LIBRARIES = libhash.a

x_includedir = $(pkgincludedir)/hash

x_include_HEADERS = \
hashes.h \
sfghash.h \
sfxhash.h \
sfhashfcn.h

libhash_a_SOURCES = \
hashes.cc \
sfghash.cc \
sfhashfcn.cc \
sfprimetable.cc sfprimetable.h \
sfxhash.cc \
zhash.cc zhash.h

if BUILD_SSL_MD5
libhash_a_SOURCES += md5.c md5.h
endif

if BUILD_SSL_SHA
libhash_a_SOURCES += sha2.c sha2.h
endif

