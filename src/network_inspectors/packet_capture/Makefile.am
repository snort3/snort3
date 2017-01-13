
file_list = \
capture_module.cc capture_module.h \
packet_capture.cc packet_capture.h 

if STATIC_INSPECTORS
noinst_LIBRARIES = libpacket_capture.a
libpacket_capture_a_SOURCES = ${file_list}
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = packet_capture.la
packet_capture_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
packet_capture_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
packet_capture_la_SOURCES = $(file_list)
endif

