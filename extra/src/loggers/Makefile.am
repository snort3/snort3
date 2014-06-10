AUTOMAKE_OPTIONS=foreign

ehlibdir = $(pkglibdir)/loggers
ehlib_LTLIBRARIES = libalert_ex.la
libalert_ex_la_CXXFLAGS = $(AM_CXXFLAGS)
libalert_ex_la_LDFLAGS = -export-dynamic -shared
libalert_ex_la_SOURCES = alert_ex.cc

AM_CXXFLAGS = @AM_CXXFLAGS@

