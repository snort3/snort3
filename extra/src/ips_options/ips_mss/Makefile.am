ips_msslibdir = $(pkglibdir)/ips_options

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_msslib_LTLIBRARIES = ips_mss.la
ips_mss_la_CXXFLAGS = $(AM_CXXFLAGS)
ips_mss_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
ips_mss_la_SOURCES  = ips_mss.cc
