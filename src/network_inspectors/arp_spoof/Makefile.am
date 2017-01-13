
file_list = \
arp_spoof.cc \
arp_module.cc \
arp_module.h

if STATIC_INSPECTORS
noinst_LIBRARIES = libarp_spoof.a
libarp_spoof_a_SOURCES = $(file_list)
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = arp_spoof.la
arp_spoof_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
arp_spoof_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
arp_spoof_la_SOURCES = $(file_list)
endif
