AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libcodecs.a
noinst_LIBRARIES += libcodec_utils.a

libcodecs_a_SOURCES = \
codec_api.cc \
codec_api.h \
decode.cc \
decode.h \
decode_module.cc \
decode_module.h \
encode.cc \
encode.h \
layer.h \
sf_protocols.h

libcodec_utils_a_SOURCES = \
codec_events.cc \
codec_events.h \
ipv6_util.h \
ipv6_util.cc


SUBDIRS = \
ip \
link \
misc \
root

AM_CXXFLAGS = @AM_CXXFLAGS@

