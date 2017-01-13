
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
shlib_LTLIBRARIES = dns.la
dns_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
dns_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
dns_la_SOURCES = $(file_list)
endif

