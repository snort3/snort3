AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libpiglet_plugins.a
libpiglet_plugins_a_SOURCES = \
piglet_plugins.cc \
piglet_plugins.h \
piglet_plugin_common.cc \
piglet_plugin_common.h

# FIXIT-L: plugin list should be automatically generated, as in the CMake build
plugin_list = \
pp_codec.cc \
pp_inspector.cc \
pp_ips_action.cc \
pp_ips_option.cc \
pp_logger.cc \
pp_mpse.cc

if STATIC_PIGLETS
libpiglet_plugins_a_SOURCES += $(plugin_list)

else
pplibdir = $(pkglibdir)/piglet_plugins

pplib_LTLIBRARIES = libpp_codec.la
libpp_codec_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpp_codec_la_LDFLAGS = -export-dynamic -shared
libpp_codec_la_SOURCES = pp_codec.cc

pplib_LTLIBRARIES += libpp_inspector.la
libpp_inspector_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpp_inspector_la_LDFLAGS = -export-dynamic -shared
libpp_inspector_la_SOURCES = pp_inspector.cc

pplib_LTLIBRARIES += libpp_ips_action.la
libpp_ips_action_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpp_ips_action_la_LDFLAGS = -export-dynamic -shared
libpp_ips_action_la_SOURCES = pp_ips_action.cc

pplib_LTLIBRARIES += libpp_ips_option.la
libpp_ips_option_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpp_ips_option_la_LDFLAGS = -export-dynamic -shared
libpp_ips_option_la_SOURCES = pp_ips_option.cc

pplib_LTLIBRARIES += libpp_logger.la
libpp_logger_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpp_logger_la_LDFLAGS = -export-dynamic -shared
libpp_logger_la_SOURCES = pp_logger.cc

pplib_LTLIBRARIES += libpp_mpse.la
libpp_mpse_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
libpp_mpse_la_LDFLAGS = -export-dynamic -shared
libpp_mpse_la_SOURCES = pp_mpse.cc
endif

AM_CXXFLAGS = @AM_CXXFLAGS@
