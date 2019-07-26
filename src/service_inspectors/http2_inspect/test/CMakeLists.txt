add_cpputest( http2_inspect_impl_test
    SOURCES
        ../http2_flow_data.cc
        ../http2_inspect_impl.cc
        ../http2_module.cc
        ../http2_tables.cc
        ../../../framework/module.cc
)
add_cpputest( http2_stream_splitter_impl_test
    SOURCES
        ../http2_flow_data.cc
        ../http2_stream_splitter_impl.cc
        ../http2_module.cc
        ../http2_tables.cc
        ../../../framework/module.cc
)
add_cpputest( http2_hpack_int_decode_test
    SOURCES
        ../http2_hpack_int_decode.cc
)
add_cpputest( http2_hpack_string_decode_test
  SOURCES
        ../http2_huffman_state_machine.cc
        ../http2_hpack_int_decode.cc
        ../http2_hpack_string_decode.cc
)
