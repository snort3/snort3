AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

log_nulllibdir = $(pkglibdir)/loggers

log_nulllib_LTLIBRARIES = liblog_null.la
liblog_null_la_CXXFLAGS = $(AM_CXXFLAGS)
liblog_null_la_LDFLAGS = -export-dynamic -shared
liblog_null_la_SOURCES = log_null.cc
