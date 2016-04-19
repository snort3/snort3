AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

dpxlibdir = $(pkglibdir)/inspectors

dpxlib_LTLIBRARIES = libdpx.la
libdpx_la_CXXFLAGS = $(AM_CXXFLAGS)
libdpx_la_LDFLAGS = -export-dynamic -shared
libdpx_la_SOURCES = dpx.cc
