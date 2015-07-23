
noinst_LIBRARIES = libflow.a

x_includedir = $(pkgincludedir)/flow

x_include_HEADERS = \
flow.h \
flow_config.h \
flow_key.h \
memcap.h

libflow_a_SOURCES = \
flow.cc \
flow_key.cc \
flow_cache.cc flow_cache.h \
expect_cache.cc expect_cache.h \
flow_control.cc flow_control.h \
session.h

libflow_a_CXXFLAGS = $(AM_CXXFLAGS) -fvisibility=default

AM_CXXFLAGS = @AM_CXXFLAGS@

