AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

alert_unixsocklibdir = $(pkglibdir)/loggers

alert_unixsocklib_LTLIBRARIES = libalert_unixsock.la
libalert_unixsock_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_unixsock_la_LDFLAGS = -export-dynamic -shared
libalert_unixsock_la_SOURCES = alert_unixsock.cc
