AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libstream.a libstream_api.a

x_includedir = $(pkgincludedir)/stream

x_include_HEADERS = \
stream_api.h

libstream_a_SOURCES = \
stream.cc \
stream_common.h \
stream_global.cc stream_global.h \
stream_icmp.cc stream_icmp.h \
stream_ip.cc stream_ip.h \
stream_paf.cc stream_paf.h \
stream_tcp.cc stream_tcp.h \
stream_udp.cc stream_udp.h \
stream_module.cc stream_module.h

if BUILD_HA
libstream_a_SOURCES += \
stream_ha.cc stream_ha.h
endif

libstream_api_a_SOURCES = \
stream_api.cc

#libstream_a_LIBADD = libstream_api.a
libstream_api_a_CXXFLAGS = $(AM_CXXFLAGS) -fvisibility=default

AM_CXXFLAGS = @AM_CXXFLAGS@

