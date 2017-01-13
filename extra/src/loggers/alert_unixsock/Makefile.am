alert_unixsocklibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

alert_unixsocklib_LTLIBRARIES = alert_unixsock.la
alert_unixsock_la_CXXFLAGS = $(AM_CXXFLAGS)
alert_unixsock_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
alert_unixsock_la_SOURCES  = alert_unixsock.cc
