ips_wscalelibdir = $(pkglibdir)/ips_options

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_wscalelib_LTLIBRARIES = ips_wscale.la
ips_wscale_la_CXXFLAGS = $(AM_CXXFLAGS)
ips_wscale_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
ips_wscale_la_SOURCES  = ips_wscale.cc
