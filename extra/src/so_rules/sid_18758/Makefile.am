sid_18758libdir = $(pkglibdir)/so_rules

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

sid_18758lib_LTLIBRARIES = sid_18758.la
sid_18758_la_CXXFLAGS = $(AM_CXXFLAGS)
sid_18758_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
sid_18758_la_SOURCES  = sid_18758.cc sid_18758.h

EXTRA_DIST = sid_18758.txt
