http_serverlibdir = $(pkglibdir)/inspectors

AM_CXXFLAGS = @SNORT3_CFLAGS@ -std=c++11

http_serverlib_LTLIBRARIES = http_server.la
http_server_la_CXXFLAGS = $(AM_CXXFLAGS)
http_server_la_LDFLAGS  = -module -export-dynamic -avoid-version -shared
http_server_la_SOURCES  = hi_ad.cc hi_ad.h hi_client.cc hi_client.h hi_client_init.cc hi_client_norm.cc hi_client_norm.h hi_cmd_lookup.cc hi_cmd_lookup.h hi_events.cc hi_events.h hi_include.h hi_main.cc hi_main.h hi_mi.cc hi_mi.h hi_module.cc hi_module.h hi_norm.cc hi_norm.h hi_reqmethod_check.h hi_return_codes.h hi_server.cc hi_server.h hi_server_norm.cc hi_server_norm.h hi_si.cc hi_si.h hi_stream_splitter.cc hi_stream_splitter.h hi_ui_config.cc hi_ui_config.h hi_ui_iis_unicode_map.cc hi_ui_iis_unicode_map.h hi_util.h http_inspect.cc ips_http.cc ips_http_header.cc

EXTRA_DIST = dev_notes.txt
