data_loglibdir = $(pkglibdir)/inspectors

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

data_loglib_LTLIBRARIES = libdata_log.la
libdata_log_la_CXXFLAGS = $(AM_CXXFLAGS)
libdata_log_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libdata_log_la_SOURCES  = data_log.cc
