
optlibdir = $(pkglibdir)/ips_options

optlib_LTLIBRARIES = libips_pkt_num.la
libips_pkt_num_la_CXXFLAGS = $(AM_CXXFLAGS)
libips_pkt_num_la_LDFLAGS = -export-dynamic -shared
libips_pkt_num_la_SOURCES = ips_pkt_num.cc

optlib_LTLIBRARIES += libips_urg.la
libips_urg_la_CXXFLAGS = $(AM_CXXFLAGS)
libips_urg_la_LDFLAGS = -export-dynamic -shared
libips_urg_la_SOURCES = ips_urg.cc

dist_optlib_SCRIPTS = find.lua

AM_CXXFLAGS = @AM_CXXFLAGS@

