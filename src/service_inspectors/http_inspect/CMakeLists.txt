
set (FILE_LIST
    http_inspect.cc
    hi_main.cc
    hi_main.h
    hi_ad.cc
    hi_ad.h
    hi_client.cc
    hi_client.h
    hi_client_norm.cc
    hi_client_norm.h
    hi_cmd_lookup.cc
    hi_cmd_lookup.h
    hi_events.cc
    hi_events.h
    hi_include.h
    hi_mi.cc
    hi_mi.h
    hi_norm.cc
    hi_norm.h
    hi_module.cc
    hi_module.h
    hi_reqmethod_check.h
    hi_return_codes.h
    hi_server.cc
    hi_server.h
    hi_server_norm.cc
    hi_server_norm.h
    hi_si.cc
    hi_si.h
    hi_stream_splitter.cc
    hi_stream_splitter.h
    hi_ui_config.cc
    hi_ui_config.h
    hi_ui_iis_unicode_map.cc
    hi_ui_iis_unicode_map.h
    hi_util.h
)

# can't be be linked dynamically yet
#if (STATIC_INSPECTORS)
    add_library(http_inspect STATIC ${FILE_LIST})

#else (STATIC_INSPECTORS)
#    add_shared_library(http_inspect inspectors ${FILE_LIST})

#endif (STATIC_INSPECTORS)
