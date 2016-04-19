AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_nulllibdir = $(pkglibdir)/codecs

cd_nulllib_LTLIBRARIES = libcd_null.la
libcd_null_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_null_la_LDFLAGS = -export-dynamic -shared
libcd_null_la_SOURCES = cd_null.cc
