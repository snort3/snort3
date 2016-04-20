cd_raw4libdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_raw4lib_LTLIBRARIES = libcd_raw4.la
libcd_raw4_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_raw4_la_LDFLAGS  = -export-dynamic -shared
libcd_raw4_la_SOURCES  = cd_raw4.cc
