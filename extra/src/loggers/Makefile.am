
loglibdir = $(pkglibdir)/loggers

loglib_LTLIBRARIES = libalert_ex.la
libalert_ex_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_ex_la_LDFLAGS = -export-dynamic -shared
libalert_ex_la_SOURCES = alert_ex.cc

loglib_LTLIBRARIES += libalert_unixsock.la
libalert_unixsock_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_unixsock_la_LDFLAGS = -export-dynamic -shared
libalert_unixsock_la_SOURCES = alert_unixsock.cc

loglib_LTLIBRARIES += liblog_null.la
liblog_null_la_CXXFLAGS = $(AM_CXXFLAGS)
liblog_null_la_LDFLAGS = -export-dynamic -shared
liblog_null_la_SOURCES = log_null.cc

dist_loglib_SCRIPTS = alert.lua

AM_CXXFLAGS = @AM_CXXFLAGS@

