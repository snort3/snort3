
set (FILE_LIST
    nhttp_inspect.cc
    nhttp_inspect.h
    nhttp_msg_section.cc
    nhttp_msg_section.h
    nhttp_msg_start.cc
    nhttp_msg_start.h
    nhttp_msg_request.cc
    nhttp_msg_request.h
    nhttp_msg_status.cc
    nhttp_msg_status.h
    nhttp_msg_head_shared.cc
    nhttp_msg_head_shared.h
    nhttp_msg_head.cc
    nhttp_msg_head.h
    nhttp_msg_body.cc
    nhttp_msg_body.h
    nhttp_msg_chunk_head.cc
    nhttp_msg_chunk_head.h
    nhttp_msg_chunk_body.cc
    nhttp_msg_chunk_body.h
    nhttp_msg_trailer.cc
    nhttp_msg_trailer.h
    nhttp_head_norm.cc
    nhttp_head_norm.h
    nhttp_uri_norm.cc
    nhttp_uri_norm.h
    nhttp_normalizers.cc
    nhttp_normalizers.h
    nhttp_str_to_code.cc
    nhttp_str_to_code.h
    nhttp_api.cc nhttp_api.h
    nhttp_tables.cc
    nhttp_uri_tables.cc
    nhttp_module.cc
    nhttp_module.h
    nhttp_test_input.cc
    nhttp_test_input.h
    nhttp_flow_data.cc
    nhttp_flow_data.h
    nhttp_scratch_pad.h
    nhttp_enum.h
    nhttp_stream_splitter.cc
    nhttp_stream_splitter.h
)

#if (STATIC_INSPECTORS)
    add_library(nhttp_inspect STATIC ${FILE_LIST})
#else()
#    add_shared_library(nhttp_inspect inspectors ${FILE_LIST})
#endif()
