AUTOMAKE_OPTIONS=foreign no-dependencies

x_luadir = $(pkgincludedir)/lua

noinst_LIBRARIES = libmanagers.a

x_lua_HEADERS = \
snort_config.lua \
snort_plugin.lua

libmanagers_a_SOURCES = \
action_manager.cc action_manager.h \
data_manager.cc data_manager.h \
event_manager.cc event_manager.h \
inspector_manager.cc inspector_manager.h \
ips_manager.cc ips_manager.h \
module_manager.cc module_manager.h \
mpse_manager.cc mpse_manager.h \
packet_manager.cc packet_manager.h \
plugin_manager.cc plugin_manager.h \
script_manager.cc script_manager.h \
so_manager.cc so_manager.h \
shell.cc shell.h

AM_CXXFLAGS = @AM_CXXFLAGS@

