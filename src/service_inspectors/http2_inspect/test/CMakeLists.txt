add_cpputest( http2_hpack_int_decode_test )

add_cpputest( http2_hpack_string_decode_test
  SOURCES
        ../http2_huffman_state_machine.cc
)

add_cpputest( http2_hpack_test
  SOURCES
        ../../http_inspect/http_field.cc
        ../http2_hpack_table.cc
        ../http2_hpack_dynamic_table.cc
        ../http2_huffman_state_machine.cc
        ../http2_start_line.cc
        ../http2_request_line.cc
        ../http2_hpack_cookie_header_buffer.cc
        ../http2_hpack.cc
)
