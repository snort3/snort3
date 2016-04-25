log_nulllibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

log_nulllib_LTLIBRARIES = liblog_null.la
liblog_null_la_CXXFLAGS = $(AM_CXXFLAGS)
liblog_null_la_LDFLAGS  = -export-dynamic -shared -avoid-version
liblog_null_la_SOURCES  = log_null.cc
