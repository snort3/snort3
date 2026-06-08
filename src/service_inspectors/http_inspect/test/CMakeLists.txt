set(HTTP_DECOMPRESSION_TEST_SOURCES
    ../http_compress_stream.cc
    ../http_cutter.cc
    ../http_flow_data.cc
    ../http_tables.cc
    ../http_test_input.cc
    ../http_test_manager.cc
)

set(HTTP_COMPRESSION_LIBS ${ZLIB_LIBRARIES})

if ( HAVE_BROTLI )
    list(APPEND HTTP_COMPRESSION_LIBS ${BROTLI_LIBRARIES})

    add_cpputest( http_brotli_decompression_test
        SOURCES
            ${HTTP_DECOMPRESSION_TEST_SOURCES}
        LIBS ${HTTP_COMPRESSION_LIBS}
    )
endif()

add_cpputest( http_cutter_decompression_test
    SOURCES
        ${HTTP_DECOMPRESSION_TEST_SOURCES}
    LIBS ${HTTP_COMPRESSION_LIBS}
)

add_cpputest( http_module_test
    SOURCES
        ../http_module.cc
        ../http_tables.cc
        ../http_normalizers.cc
        ../http_uri_norm.cc
        ../http_field.cc
        ../../../framework/module.cc
)

add_cpputest( http_msg_head_shared_util_test
    SOURCES
        ../http_msg_head_shared_util.cc
        ../http_field.cc
        ../http_str_to_code.cc
        ../http_tables.cc
)

add_cpputest( http_msg_head_shared_find_next_header_test
    SOURCES
        ../http_field.cc
        ../http_msg_head_shared.cc
        ../http_str_to_code.cc
        ../http_tables.cc
)

add_cpputest( http_normalizers_test
    SOURCES
        ../http_normalizers.cc
        ../http_field.cc
)

add_cpputest( http_transaction_test
    SOURCES
        ../http_transaction.cc
        ../http_flow_data.cc
        ../http_test_manager.cc
        ../http_test_input.cc
        ../http_compress_stream.cc
    LIBS ${HTTP_COMPRESSION_LIBS}
)

add_cpputest( http_uri_norm_test
    SOURCES
        ../http_uri_norm.cc
        ../http_module.cc
        ../http_test_manager.cc
        ../http_test_input.cc
        ../http_normalizers.cc
        ../http_str_to_code.cc
        ../http_field.cc
        ../http_tables.cc
        ../../../framework/module.cc
)
