
x_includedir = $(pkgincludedir)/actions

noinst_LIBRARIES = libips_actions.a

x_include_HEADERS = \
actions.h

plugin_list = \
act_react.cc \
act_reject.cc

libips_actions_a_SOURCES = \
actions.cc \
ips_actions.cc \
ips_actions.h \
act_replace.cc \
act_replace.h

if STATIC_IPS_ACTIONS
libips_actions_a_SOURCES += $(plugin_list)
else
actlibdir = $(pkglibdir)/ips_actions

actlib_LTLIBRARIES = act_react.la
act_react_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
act_react_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
act_react_la_SOURCES = act_react.cc

actlib_LTLIBRARIES += act_reject.la
act_reject_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
act_reject_la_LDFLAGS = $(AM_LDFLAGS) -module -export-dynamic -avoid-version -shared
act_reject_la_SOURCES = act_reject.cc
endif
