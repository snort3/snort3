sid_18758libdir = $(pkglibdir)/so_rules

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

sid_18758lib_LTLIBRARIES = libsid_18758.la
libsid_18758_la_CXXFLAGS = $(AM_CXXFLAGS)
libsid_18758_la_LDFLAGS  = -export-dynamic -shared
libsid_18758_la_SOURCES  = sid_18758.cc sid_18758.h
