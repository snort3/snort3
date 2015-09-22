
noinst_LIBRARIES = libutils.a

x_includedir = $(pkgincludedir)/utils

x_include_HEADERS = \
bitop.h \
dnet_header.h \
segment_mem.h \
sflsq.h \
sfmemcap.h \
snort_bounds.h \
stats.h \
util.h

libutils_a_SOURCES = \
boyer_moore.cc boyer_moore.h \
dyn_array.cc dyn_array.h \
kmap.cc kmap.h \
segment_mem.cc \
sflsq.cc \
sfmemcap.cc \
sfsnprintfappend.cc sfsnprintfappend.h \
snort_bounds.h \
stats.cc \
strvec.cc strvec.h \
util.cc \
util_jsnorm.cc util_jsnorm.h \
util_math.cc util_math.h \
util_net.cc util_net.h \
util_unfold.cc util_unfold.h \
util_utf.cc util_utf.h \
xmalloc.cc xmalloc.h

libutil_a_CXXFLAGS = $(AM_CXXFLAGS) -fvisibility=default

AM_CXXFLAGS = @AM_CXXFLAGS@

if BUILD_UNIT_TESTS
SUBDIRS = test
endif

