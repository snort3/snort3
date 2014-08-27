AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/codecs

noinst_LIBRARIES = libcodecs.a

x_include_HEADERS = \
codec_events.h \
decode_module.h \
sf_protocols.h

libcodecs_a_SOURCES = \
codec_api.cc \
codec_api.h \
sf_protocols.h


SUBDIRS = \
ip \
link \
misc \
root

AM_CXXFLAGS = @AM_CXXFLAGS@

