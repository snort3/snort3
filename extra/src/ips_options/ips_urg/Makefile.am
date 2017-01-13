ips_urglibdir = $(pkglibdir)/ips_options

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_urglib_LTLIBRARIES = ips_urg.la
ips_urg_la_CXXFLAGS = $(AM_CXXFLAGS)
ips_urg_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
ips_urg_la_SOURCES  = ips_urg.cc
