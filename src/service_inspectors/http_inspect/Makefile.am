
file_list = \
http_inspect.cc \
hi_main.cc hi_main.h \
hi_ad.cc hi_ad.h \
hi_client.cc hi_client.h \
hi_client_norm.cc hi_client_norm.h \
hi_cmd_lookup.cc hi_cmd_lookup.h \
hi_events.cc hi_events.h \
hi_include.h \
hi_mi.cc hi_mi.h \
hi_module.cc hi_module.h \
hi_norm.cc hi_norm.h \
hi_reqmethod_check.h \
hi_return_codes.h \
hi_server.cc hi_server.h \
hi_server_norm.cc hi_server_norm.h \
hi_si.cc hi_si.h \
hi_stream_splitter.cc hi_stream_splitter.h \
hi_ui_config.cc hi_ui_config.h \
hi_ui_iis_unicode_map.cc hi_ui_iis_unicode_map.h \
hi_util.h

# can't be built dynamically yet
#if STATIC_INSPECTORS
noinst_LIBRARIES = libhttp_inspect.a
libhttp_inspect_a_SOURCES = $(file_list)
#else
#shlibdir = $(pkglibdir)/inspectors
#shlib_LTLIBRARIES = libhttp_inspect.la
#libhttp_inspect_la_CXXFLAGS = $(AM_CXXFLAGS) -DBUILDING_SO
#libhttp_inspect_la_LDFLAGS = -export-dynamic -shared
#libhttp_inspect_la_SOURCES = $(file_list)
#endif

AM_CXXFLAGS = @AM_CXXFLAGS@

