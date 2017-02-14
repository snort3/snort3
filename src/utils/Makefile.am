
noinst_LIBRARIES = libutils.a

x_includedir = $(pkgincludedir)/utils

x_include_HEADERS = \
bitop.h \
cpp_macros.h \
kmap.h  \
safec.h \
segment_mem.h \
sflsq.h \
sfmemcap.h \
stats.h \
util.h \
util_cstring.h \
util_jsnorm.h \
util_unfold.h \
util_utf.h

libutils_a_SOURCES = \
boyer_moore.cc boyer_moore.h \
dnet_header.h \
dyn_array.cc dyn_array.h \
kmap.cc \
segment_mem.cc \
sflsq.cc \
sfmemcap.cc \
snort_bounds.h \
stats.cc \
util.cc \
util_cstring.cc \
util_jsnorm.cc \
util_net.cc util_net.h \
util_unfold.cc \
util_utf.cc

if ENABLE_UNIT_TESTS
libutils_a_SOURCES += bitop_test.cc
endif
