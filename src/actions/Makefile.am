AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/actions

noinst_LIBRARIES = libactions.a

x_include_HEADERS = \
actions.h

plugin_list = \
act_reject.cc

libactions_a_SOURCES = \
actions.cc \
ips_actions.cc \
ips_actions.h

if STATIC_IPS_ACTIONS
libactions_a_SOURCES += $(plugin_list)
else
optlibdir = $(pkglibdir)/ips_options

optlib_LTLIBRARIES = libact_reject.la
libact_reject_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libact_reject_la_LDFLAGS = -export-dynamic -shared
libact_reject_la_SOURCES = act_reject.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

