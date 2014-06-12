AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/codecs

noinst_LIBRARIES = libcodecs.a
noinst_LIBRARIES += libcodec_utils.a

x_include_HEADERS = \
sf_protocols.h

libcodecs_a_SOURCES = \
codec_api.cc \
codec_api.h \
decode_module.h

libcodec_utils_a_SOURCES = \
codec_events.cc \
codec_events.h \
ipv6_util.h \
ipv6_util.cc  \
checksum.h \
checksum.cc

SUBDIRS = \
ip \
link \
misc \
root

AM_CXXFLAGS = @AM_CXXFLAGS@

