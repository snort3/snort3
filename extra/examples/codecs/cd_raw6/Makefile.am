AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_raw6libdir = $(pkglibdir)/codecs

cd_raw6lib_LTLIBRARIES = libcd_raw6.la
libcd_raw6_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_raw6_la_LDFLAGS = -export-dynamic -shared
libcd_raw6_la_SOURCES = cd_raw6.cc
