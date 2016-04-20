ips_urglibdir = $(pkglibdir)/ips_options

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_urglib_LTLIBRARIES = libips_urg.la
libips_urg_la_CXXFLAGS = $(AM_CXXFLAGS)
libips_urg_la_LDFLAGS  = -export-dynamic -shared
libips_urg_la_SOURCES  = ips_urg.cc
