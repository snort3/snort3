alert_exlibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

alert_exlib_LTLIBRARIES = alert_ex.la
alert_ex_la_CXXFLAGS = $(AM_CXXFLAGS)
alert_ex_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
alert_ex_la_SOURCES  = alert_ex.cc
