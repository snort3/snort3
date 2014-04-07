## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libnetwork_inspectors.a

libnetwork_inspectors_a_SOURCES = \
network_inspectors.cc \
network_inspectors.h

# FIXIT LIBADD here causes undefineds
#libnetwork_inspectors_a_LIBADD = \
#arp_spoof/libarp_spoof.a \
#defrag/libdefrag.a \
#normalize/libnormalize.a \
#perf_monitor/libperf_monitor.a \
#port_scan/libport_scan.a \
#stream5/libstream5.a

SUBDIRS = \
arp_spoof \
defrag \
normalize \
perf_monitor \
port_scan \
stream5

AM_CXXFLAGS = @AM_CXXFLAGS@

