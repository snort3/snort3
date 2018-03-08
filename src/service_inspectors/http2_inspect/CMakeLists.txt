
set (FILE_LIST
    http2_api.cc
    http2_api.h
    http2_enum.h
    http2_flow_data.cc
    http2_flow_data.h
    http2_inspect.cc
    http2_inspect_impl.cc
    http2_inspect.h
    http2_module.cc
    http2_module.h
    http2_stream_splitter.cc
    http2_stream_splitter_impl.cc
    http2_stream_splitter.h
    http2_tables.cc
    ips_http2.cc
    ips_http2.h
)

#if (STATIC_INSPECTORS)
    add_library(http2_inspect OBJECT ${FILE_LIST})

#else(STATIC_INSPECTORS)
    #add_dynamic_module(http2_inspect inspectors ${FILE_LIST})

#endif(STATIC_INSPECTORS)

add_subdirectory ( test )

