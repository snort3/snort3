alert_jsonlibdir = $(pkglibdir)/loggers

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

alert_jsonlib_LTLIBRARIES = alert_json.la
alert_json_la_CXXFLAGS = $(AM_CXXFLAGS)
alert_json_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
alert_json_la_SOURCES  = alert_json.cc
