
file_list = \
arp_spoof.cc \
arp_module.cc \
arp_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libarp_spoof.a
libarp_spoof_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libarp_spoof.la
libarp_spoof_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libarp_spoof_la_LDFLAGS = -export-dynamic -shared
libarp_spoof_la_SOURCES = $(file_list)
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

