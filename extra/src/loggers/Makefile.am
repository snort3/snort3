AUTOMAKE_OPTIONS=foreign

loglibdir = $(pkglibdir)/loggers

loglib_LTLIBRARIES = libalert_ex.la
libalert_ex_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_ex_la_LDFLAGS = -export-dynamic -shared
libalert_ex_la_SOURCES = alert_ex.cc

loglib_LTLIBRARIES += liblog_user.la
liblog_user_la_CXXFLAGS = $(AM_CXXFLAGS)
liblog_user_la_LDFLAGS = -export-dynamic -shared
liblog_user_la_SOURCES = log_user.cc

dist_loglib_SCRIPTS = alert.lua

AM_CXXFLAGS = @AM_CXXFLAGS@

