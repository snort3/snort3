AM_CPPFLAGS = @SNORT3_CFLAGS@
AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

ips_pkt_numlibdir = $(pkglibdir)/ips_options

ips_pkt_numlib_LTLIBRARIES = libips_pkt_num.la
libips_pkt_num_la_CXXFLAGS = $(AM_CXXFLAGS)
libips_pkt_num_la_LDFLAGS = -export-dynamic -shared
libips_pkt_num_la_SOURCES = ips_pkt_num.cc
