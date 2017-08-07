unified2xlibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

unified2xlib_LTLIBRARIES = unified2x.la
unified2x_la_CXXFLAGS = $(AM_CXXFLAGS)
unified2x_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
unified2x_la_SOURCES  = unified2x.cc unified2x.h
