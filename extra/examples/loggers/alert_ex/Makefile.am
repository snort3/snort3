alert_exlibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

alert_exlib_LTLIBRARIES = libalert_ex.la
libalert_ex_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_ex_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libalert_ex_la_SOURCES  = alert_ex.cc
