
file_list = \
port_scan.cc \
ps_detect.cc \
ps_detect.h \
ps_inspect.h \
ps_module.cc \
ps_module.h \
ipobj.cc \
ipobj.h

# static due to dependance on functions throughout Snort++
#if STATIC_INSPECTORS

noinst_LIBRARIES = libport_scan.a
libport_scan_a_SOURCES = $(file_list)

#else
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = libport_scan.la
#libport_scan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#libport_scan_la_LDFLAGS = -export-dynamic -shared
#libport_scan_la_SOURCES = $(file_list)
#endif

AM_CXXFLAGS = @AM_CXXFLAGS@

