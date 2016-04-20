cd_pfloglibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_pfloglib_LTLIBRARIES = libcd_pflog.la
libcd_pflog_la_CXXFLAGS = $(AM_CXXFLAGS)
libcd_pflog_la_LDFLAGS  = -export-dynamic -shared
libcd_pflog_la_SOURCES  = cd_pflog.cc
