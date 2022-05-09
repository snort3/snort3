
set (FILE_LIST
    http2_api.cc
    http2_api.h
    http2_data_frame.cc
    http2_data_frame.h
    http2_data_cutter.cc
    http2_data_cutter.h
    http2_enum.h
    http2_flow_data.cc
    http2_flow_data.h
    http2_frame.cc
    http2_frame.h
    http2_headers_frame.cc
    http2_headers_frame.h
    http2_headers_frame_header.cc
    http2_headers_frame_header.h
    http2_headers_frame_trailer.cc
    http2_headers_frame_trailer.h
    http2_headers_frame_with_startline.cc
    http2_headers_frame_with_startline.h
    http2_hpack.cc
    http2_hpack.h
    http2_hpack_dynamic_table.cc
    http2_hpack_dynamic_table.h
    http2_varlen_int_decode.h
    http2_varlen_int_decode_impl.h
    http2_varlen_string_decode.h
    http2_varlen_string_decode_impl.h
    http2_hpack_int_decode.h
    http2_hpack_string_decode.h
    http2_hpack_table.cc
    http2_hpack_table.h
    http2_huffman_state_machine.cc
    http2_huffman_state_machine.h
    http2_inspect.cc
    http2_inspect.h
    http2_module.cc
    http2_module.h
    http2_ping_frame.h
    http2_push_promise_frame.cc
    http2_push_promise_frame.h
    http2_request_line.cc
    http2_request_line.h
    http2_rst_stream_frame.cc
    http2_rst_stream_frame.h
    http2_settings_frame.cc
    http2_settings_frame.h
    http2_start_line.cc
    http2_start_line.h
    http2_status_line.cc
    http2_status_line.h
    http2_stream.cc
    http2_stream.h
    http2_stream_splitter.cc
    http2_stream_splitter_impl.cc
    http2_stream_splitter.h
    http2_tables.cc
    http2_utils.cc
    http2_utils.h
    http2_window_update_frame.cc
    http2_window_update_frame.h
    ips_http2.cc
    ips_http2.h
)

#if (STATIC_INSPECTORS)
    add_library(http2_inspect OBJECT ${FILE_LIST})

#else(STATIC_INSPECTORS)
    #add_dynamic_module(http2_inspect inspectors ${FILE_LIST})

#endif(STATIC_INSPECTORS)

add_subdirectory ( test )

