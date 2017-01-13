data_loglibdir = $(pkglibdir)/inspectors

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

data_loglib_LTLIBRARIES = data_log.la
data_log_la_CXXFLAGS = $(AM_CXXFLAGS)
data_log_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
data_log_la_SOURCES  = data_log.cc
