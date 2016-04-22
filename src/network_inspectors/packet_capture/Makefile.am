
file_list = \
capture_module.cc capture_module.h \
packet_capture.cc packet_capture.h 

if STATIC_INSPECTORS
noinst_LIBRARIES = libpacket_capture.a
libpacket_capture_a_SOURCES = ${file_list}
else
shlibdir = $(pkglibdir)/inspectors
shlib_LTLIBRARIES = libpacket_capture.la
libpacket_capture_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpacket_capture_la_LDFLAGS = $(AM_LDFLAGS) -export-dynamic -shared
libpacket_capture_la_SOURCES = $(file_list)
endif

