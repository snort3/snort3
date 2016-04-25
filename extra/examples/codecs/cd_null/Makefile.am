cd_nulllibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_nulllib_LTLIBRARIES = libcd_null.la
libcd_null_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_null_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libcd_null_la_SOURCES  = cd_null.cc
