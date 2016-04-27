ips_pkt_numlibdir = $(pkglibdir)/ips_options

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_pkt_numlib_LTLIBRARIES = libips_pkt_num.la
libips_pkt_num_la_CXXFLAGS = $(AM_CXXFLAGS)
libips_pkt_num_la_LDFLAGS  = -export-dynamic -shared -avoid-version
libips_pkt_num_la_SOURCES  = ips_pkt_num.cc
