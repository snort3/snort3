cd_raw4libdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_raw4lib_LTLIBRARIES = cd_raw4.la
cd_raw4_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_raw4_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_raw4_la_SOURCES  = cd_raw4.cc
