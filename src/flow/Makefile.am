noinst_LIBRARIES = libflow.a

x_includedir = $(pkgincludedir)/flow

x_include_HEADERS = \
flow.h \
flow_key.h

libflow_a_SOURCES = \
expect_cache.cc expect_cache.h \
flow.cc \
flow_key.cc \
flow_cache.cc flow_cache.h \
flow_config.h \
flow_control.cc flow_control.h \
ha.cc ha.h \
ha_module.cc ha_module.h \
prune_stats.h \
session.h

AM_CXXFLAGS = @AM_CXXFLAGS@

if ENABLE_UNIT_TESTS
SUBDIRS = test
endif

