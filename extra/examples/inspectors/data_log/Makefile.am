AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

data_loglibdir = $(pkglibdir)/inspectors

data_loglib_LTLIBRARIES = libdata_log.la
libdata_log_la_CXXFLAGS = $(AM_CXXFLAGS)
libdata_log_la_LDFLAGS = -export-dynamic -shared
libdata_log_la_SOURCES = data_log.cc
