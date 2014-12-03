AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/codecs

noinst_LIBRARIES = libcodecs.a libcodec_module.a

x_include_HEADERS = \
codec_events.h \
codec_module.h

libcodecs_a_SOURCES = \
codec_api.cc \
codec_api.h

libcodec_module_a_SOURCES = \
codec_module.cc


SUBDIRS = \
ip \
link \
misc \
root

AM_CXXFLAGS = @AM_CXXFLAGS@

