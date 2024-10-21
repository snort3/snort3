FLEX ( js_tokenizer
    ${CMAKE_CURRENT_SOURCE_DIR}/../js_tokenizer.l
    ${CMAKE_CURRENT_BINARY_DIR}/../js_tokenizer.cc
)

FLEX ( pdf_tokenizer
    ${CMAKE_CURRENT_SOURCE_DIR}/../pdf_tokenizer.l
    ${CMAKE_CURRENT_BINARY_DIR}/../pdf_tokenizer.cc
)

add_catch_test( js_normalizer_test
    SOURCES
        ${js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_normalizer.cc
        ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
        ${CMAKE_SOURCE_DIR}/src/utils/util_cstring.cc
        js_test_options.cc
        js_test_stubs.cc
        js_test_utils.cc
)

add_catch_test( js_dealias_test
    SOURCES
        ${js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_normalizer.cc
        ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
        ${CMAKE_SOURCE_DIR}/src/utils/util_cstring.cc
        js_test_options.cc
        js_test_stubs.cc
        js_test_utils.cc
)

add_catch_test( js_unescape_test
    SOURCES
        ${js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_normalizer.cc
        ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
        ${CMAKE_SOURCE_DIR}/src/utils/util_cstring.cc
        js_test_options.cc
        js_test_stubs.cc
        js_test_utils.cc
)

add_catch_test( js_identifier_ctx_test
    SOURCES
        ../js_identifier_ctx.cc
        js_test_stubs.cc
)

add_catch_test( jsn_test
    SOURCES
        ${js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_norm.cc
        ../js_normalizer.cc
        ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
        js_test_stubs.cc
)

add_catch_test( pdf_tokenizer_test
    SOURCES
        ${pdf_tokenizer_OUTPUTS}
        ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
        js_test_stubs.cc
)

if (ENABLE_BENCHMARK_TESTS)

    add_catch_test( js_norm_benchmark
        SOURCES
            ${js_tokenizer_OUTPUTS}
            ../js_identifier_ctx.cc
            ../js_normalizer.cc
            ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
            ${CMAKE_SOURCE_DIR}/src/utils/util_cstring.cc
            js_test_options.cc
            js_test_stubs.cc
            js_test_utils.cc
    )

    add_catch_test( pdf_tokenizer_benchmark
        SOURCES
            ${pdf_tokenizer_OUTPUTS}
            ${CMAKE_SOURCE_DIR}/src/helpers/streambuf.cc
            ${CMAKE_SOURCE_DIR}/src/utils/util_cstring.cc
            js_test_stubs.cc
    )

endif(ENABLE_BENCHMARK_TESTS)
