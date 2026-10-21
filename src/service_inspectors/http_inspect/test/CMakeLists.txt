set(HTTP_DECOMPRESSION_TEST_SOURCES
    ../http_compress_stream.cc
    ../http_cutter.cc
    ../http_field.cc
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
        ../http_field.cc
        ../http_module.cc
        ../http_normalizers.cc
        ../http_tables.cc
        ../http_uri_norm.cc
        ../../../framework/module.cc
)

add_cpputest( http_msg_head_shared_util_test
    SOURCES
        ../http_field.cc
        ../http_msg_head_shared_util.cc
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

add_cpputest( http_event_test )

FLEX ( pdf_tokenizer
    ${CMAKE_SOURCE_DIR}/src/js_norm/pdf_tokenizer.l
    ${CMAKE_BINARY_DIR}/src/js_norm/pdf_tokenizer.cc
)

if ( HAVE_SAFEC )
    set(HTTP_JS_NORM_TEST_LIBS ${SAFEC_LIBRARIES})
endif ()

add_cpputest( http_js_norm_attr_test
    SOURCES
        ${pdf_tokenizer_OUTPUTS}
        ../http_field.cc
        ../http_str_to_code.cc
        ../http_tables.cc
        ../../../helpers/streambuf.cc
        ../../../js_norm/js_pdf_norm.cc
        ../../../utils/util_cstring.cc
    LIBS ${HTTP_JS_NORM_TEST_LIBS}
)

add_cpputest( http_context_data_test
    SOURCES
        ../http_context_data.cc
        ../http_field.cc
)

add_cpputest( http_field_buffer_test
    SOURCES
        ../http_context_data.cc
        ../http_field.cc
        ../http_field_buffer.cc
        ../http_tables.cc
)

add_cpputest( http_normalizers_test
    SOURCES
        ../http_field.cc
        ../http_normalizers.cc
)

add_cpputest( http_transaction_test
    SOURCES
        ../http_compress_stream.cc
        ../http_context_data.cc
        ../http_field.cc
        ../http_flow_data.cc
        ../http_test_input.cc
        ../http_test_manager.cc
        ../http_transaction.cc
    LIBS ${HTTP_COMPRESSION_LIBS}
)

add_cpputest( http_uri_norm_test
    SOURCES
        ../http_field.cc
        ../http_module.cc
        ../http_normalizers.cc
        ../http_str_to_code.cc
        ../http_tables.cc
        ../http_test_manager.cc
        ../http_test_input.cc
        ../http_uri_norm.cc
        ../../../framework/module.cc
)
