
file_list = \
dns.cc \
dns.h \
dns_module.cc \
dns_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libdns.a
libdns_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libdns.la
libdns_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libdns_la_LDFLAGS = -export-dynamic -shared
libdns_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

