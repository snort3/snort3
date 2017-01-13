
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
#shlib_LTLIBRARIES = port_scan.la
#port_scan_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#port_scan_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
#port_scan_la_SOURCES = $(file_list)
#endif
