ips_pkt_numlibdir = $(pkglibdir)/ips_options

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_pkt_numlib_LTLIBRARIES = ips_pkt_num.la
ips_pkt_num_la_CXXFLAGS = $(AM_CXXFLAGS)
ips_pkt_num_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
ips_pkt_num_la_SOURCES  = ips_pkt_num.cc
