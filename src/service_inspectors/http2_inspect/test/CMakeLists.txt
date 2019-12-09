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
