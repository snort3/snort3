AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_token_ringlibdir = $(pkglibdir)/codecs

cd_token_ringlib_LTLIBRARIES = libcd_token_ring.la
libcd_token_ring_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_token_ring_la_LDFLAGS = -export-dynamic -shared
libcd_token_ring_la_SOURCES = cd_token_ring.cc
