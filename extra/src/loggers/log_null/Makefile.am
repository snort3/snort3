log_nulllibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

log_nulllib_LTLIBRARIES = log_null.la
log_null_la_CXXFLAGS = $(AM_CXXFLAGS)
log_null_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
log_null_la_SOURCES  = log_null.cc
