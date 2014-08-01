AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/framework

noinst_LIBRARIES = libframework.a

x_include_HEADERS = \
base_api.h \
bits.h \
codec.h \
cursor.h \
logger.h \
inspector.h \
ips_option.h \
module.h \
mpse.h \
parameter.h \
plug_data.h \
share.h \
so_rule.h \
value.h

libframework_a_SOURCES = \
cursor.cc \
inspector.cc \
ips_option.cc \
parameter.cc \
module.cc \
mpse.cc \
value.cc

AM_CXXFLAGS = @AM_CXXFLAGS@

