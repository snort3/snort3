cd_pbblibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_pbblib_LTLIBRARIES = cd_pbb.la
cd_pbb_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_pbb_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_pbb_la_SOURCES  = cd_pbb.cc
