AUTOMAKE_OPTIONS=foreign no-dependencies

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
ring.h ring_logic.h \
segment_mem.cc \
sf_base64decode.cc sf_base64decode.h \
sf_email_attach_decode.cc sf_email_attach_decode.h \
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
util_str.cc util_str.h \
util_unfold.cc util_unfold.h \
util_utf.cc util_utf.h

libutil_a_CXXFLAGS = $(AM_CXXFLAGS) -fvisibility=default

AM_CXXFLAGS = @AM_CXXFLAGS@

