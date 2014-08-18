AUTOMAKE_OPTIONS=foreign no-dependencies

x_includedir = $(pkgincludedir)/actions

noinst_LIBRARIES = libips_actions.a

x_include_HEADERS = \
actions.h

plugin_list = \
act_react.cc \
act_reject.cc \
act_replace.cc \
act_replace.h

libips_actions_a_SOURCES = \
actions.cc \
ips_actions.cc \
ips_actions.h

if STATIC_IPS_ACTIONS
libips_actions_a_SOURCES += $(plugin_list)
else
actlibdir = $(pkglibdir)/ips_actions

actlib_LTLIBRARIES = libact_react.la
libact_react_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libact_react_la_LDFLAGS = -export-dynamic -shared
libact_react_la_SOURCES = act_react.cc

actlib_LTLIBRARIES += libact_reject.la
libact_reject_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libact_reject_la_LDFLAGS = -export-dynamic -shared
libact_reject_la_SOURCES = act_reject.cc

actlib_LTLIBRARIES += libact_replace.la
libact_replace_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libact_replace_la_LDFLAGS = -export-dynamic -shared
libact_replace_la_SOURCES = act_replace.cc act_replace.h
endif

AM_CXXFLAGS = @AM_CXXFLAGS@

