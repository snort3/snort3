cd_nulllibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_nulllib_LTLIBRARIES = cd_null.la
cd_null_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_null_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_null_la_SOURCES  = cd_null.cc
