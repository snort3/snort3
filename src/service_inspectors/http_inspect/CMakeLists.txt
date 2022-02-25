
set (FILE_LIST
    ips_http.cc
    ips_http.h
    http_buffer_info.h
    http_buffer_info.cc
    http_inspect.cc
    http_inspect.h
    http_msg_section.cc
    http_msg_section.h
    http_msg_start.cc
    http_msg_start.h
    http_msg_request.cc
    http_msg_request.h
    http_msg_status.cc
    http_msg_status.h
    http_msg_head_shared.cc
    http_msg_head_shared_util.cc
    http_msg_head_shared.h
    http_msg_header.cc
    http_msg_header.h
    http_msg_body.cc
    http_msg_body.h
    http_msg_body_chunk.cc
    http_msg_body_chunk.h
    http_msg_body_cl.cc
    http_msg_body_cl.h
    http_msg_body_h2.cc
    http_msg_body_h2.h
    http_msg_body_old.cc
    http_msg_body_old.h
    http_msg_trailer.cc
    http_msg_trailer.h
    http_param.h
    http_query_parser.cc
    http_query_parser.h
    http_normalized_header.cc
    http_normalized_header.h
    http_uri.cc
    http_uri.h
    http_uri_norm.cc
    http_uri_norm.h
    http_normalizers.cc
    http_normalizers.h
    http_str_to_code.cc
    http_str_to_code.h
    http_api.cc
    http_api.h
    http_tables.cc
    http_module.cc
    http_module.h
    http_test_input.cc
    http_test_input.h
    http_flow_data.cc
    http_flow_data.h
    http_context_data.cc
    http_context_data.h
    http_cursor_data.h
    http_transaction.cc
    http_transaction.h
    http_test_manager.cc
    http_test_manager.h
    http_enum.h
    http_field.cc
    http_field.h
    http_stream_splitter_finish.cc
    http_stream_splitter_reassemble.cc
    http_stream_splitter_scan.cc
    http_stream_splitter.h
    http_cutter.cc
    http_cutter.h
    http_event.h
    http_js_norm.cc
    http_js_norm.h
    ips_http_buffer.cc
    ips_http_buffer.h
    ips_http_num_hdrs.cc
    ips_http_num_hdrs.h
    ips_http_param.cc
    ips_http_param.h
    ips_http_test.cc
    ips_http_test.h
    ips_http_version.cc
    ips_http_version.h
)

#if (STATIC_INSPECTORS)
    add_library(http_inspect OBJECT ${FILE_LIST})

#else(STATIC_INSPECTORS)
    #add_dynamic_module(http_inspect inspectors ${FILE_LIST})

#endif(STATIC_INSPECTORS)

add_subdirectory ( test )

