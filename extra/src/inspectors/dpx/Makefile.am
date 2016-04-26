dpxlibdir = $(pkglibdir)/inspectors

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

dpxlib_LTLIBRARIES = libdpx.la
libdpx_la_CXXFLAGS = $(AM_CXXFLAGS)
libdpx_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libdpx_la_SOURCES  = dpx.cc
