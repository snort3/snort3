dpxlibdir = $(pkglibdir)/inspectors

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

dpxlib_LTLIBRARIES = dpx.la
dpx_la_CXXFLAGS = $(AM_CXXFLAGS)
dpx_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
dpx_la_SOURCES  = dpx.cc
