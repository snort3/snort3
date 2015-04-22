AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/framework

noinst_LIBRARIES = libframework.a

x_include_HEADERS = \
api_options.h \
base_api.h \
bits.h \
codec.h \
counts.h \
cursor.h \
decode_data.h \
logger.h \
inspector.h \
ips_action.h \
ips_option.h \
module.h \
mpse.h \
parameter.h \
range.h \
so_rule.h \
value.h

libframework_a_SOURCES = \
codec.cc \
cursor.cc \
inspector.cc \
ips_option.cc \
parameter.cc \
module.cc \
mpse.cc \
range.cc \
value.cc

AM_CXXFLAGS = @AM_CXXFLAGS@

