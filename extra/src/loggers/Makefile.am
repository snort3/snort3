AUTOMAKE_OPTIONS=foreign

loglibdir = $(pkglibdir)/loggers

loglib_LTLIBRARIES = libalert_ex.la
libalert_ex_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_ex_la_LDFLAGS = -export-dynamic -shared
libalert_ex_la_SOURCES = alert_ex.cc

loglib_LTLIBRARIES += liblog_hext.la
liblog_hext_la_CXXFLAGS = $(AM_CXXFLAGS)
liblog_hext_la_LDFLAGS = -export-dynamic -shared
liblog_hext_la_SOURCES = log_hext.cc

dist_loglib_SCRIPTS = alert.lua

AM_CXXFLAGS = @AM_CXXFLAGS@

