
AM_CPPFLAGS+=-I$(top_srcdir)/src/network_inspectors/appid

file_list = \
app_forecast.cc \
app_forecast.h \
appid_api.cc \
appid_api.h \
appid_config.cc \
appid_config.h \
appid_flow_data.cc \
appid_flow_data.h \
appid.h \
appid_inspector.cc \
appid_inspector.h \
appid_module.cc \
appid_module.h \
appid_stats.cc \
appid_stats.h \
app_info_table.cc \
app_info_table.h \
application_ids.h \
dns_defs.h \
flow_error.h \
fw_appid.cc \
fw_appid.h \
host_port_app_cache.cc \
host_port_app_cache.h \
http_common.h \
length_app_cache.cc \
length_app_cache.h \
lua_detector_api.cc \
lua_detector_api.h \
lua_detector_flow_api.cc \
lua_detector_flow_api.h \
lua_detector_module.cc \
lua_detector_module.h \
lua_detector_util.h \
service_state.cc \
service_state.h \
sfaddr_temp.h \
thirdparty_appid_api.h \
thirdparty_appid_types.h \
thirdparty_appid_utils.cc \
thirdparty_appid_utils.h

noinst_LIBRARIES = libappid.a
libappid_a_SOURCES = $(file_list)

SUBDIRS = \
client_plugins \
detector_plugins \
service_plugins \
util

#if BUILD_CPPUTESTS
#SUBDIRS += test
#endif


