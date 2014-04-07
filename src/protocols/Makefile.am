AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libprotocols.a

x_includedir = $(pkgincludedir)/protocols

x_include_HEADERS = \
packet.h \
sf_protocols.h

libprotocols_a_SOURCES = \
checksum.h \
decode.cc \
decode.h \
decode_module.cc \
decode_module.h \
encode.cc \
encode.h

AM_CXXFLAGS = @AM_CXXFLAGS@

