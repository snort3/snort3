cd_token_ringlibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_token_ringlib_LTLIBRARIES = cd_token_ring.la
cd_token_ring_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_token_ring_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_token_ring_la_SOURCES  = cd_token_ring.cc
