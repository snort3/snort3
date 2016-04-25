alert_unixsocklibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

alert_unixsocklib_LTLIBRARIES = libalert_unixsock.la
libalert_unixsock_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_unixsock_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libalert_unixsock_la_SOURCES  = alert_unixsock.cc
