cd_pfloglibdir = $(pkglibdir)/codecs

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

cd_pfloglib_LTLIBRARIES = cd_pflog.la
cd_pflog_la_CXXFLAGS = $(AM_CXXFLAGS)
cd_pflog_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
cd_pflog_la_SOURCES  = cd_pflog.cc
