add_cpputest( boyer_moore_test
    SOURCES
        ../boyer_moore.cc
)

add_cpputest( memcap_allocator_test )

FLEX_TARGET ( js_tokenizer ${CMAKE_CURRENT_SOURCE_DIR}/../js_tokenizer.l
    ${CMAKE_CURRENT_BINARY_DIR}/../js_tokenizer.cc
    COMPILE_FLAGS ${FLEX_FLAGS}
)

add_catch_test( js_normalizer_test
    SOURCES
        ${FLEX_js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_normalizer.cc
        ../streambuf.cc
        ../util_cstring.cc
        js_test_options.cc
        js_test_utils.cc
)

if (ENABLE_BENCHMARK_TESTS)
    add_catch_test( js_norm_benchmark
        SOURCES
            ${FLEX_js_tokenizer_OUTPUTS}
            ../js_identifier_ctx.cc
            ../js_normalizer.cc
            ../streambuf.cc
            ../util_cstring.cc
            js_test_options.cc
            js_test_utils.cc
    )
endif(ENABLE_BENCHMARK_TESTS)

add_catch_test( js_dealias_test
    SOURCES
        ${FLEX_js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_normalizer.cc
        ../streambuf.cc
        ../util_cstring.cc
        js_test_options.cc
        js_test_utils.cc
)

add_catch_test( js_unescape_test
    SOURCES
        ${FLEX_js_tokenizer_OUTPUTS}
        ../js_identifier_ctx.cc
        ../js_normalizer.cc
        ../streambuf.cc
        ../util_cstring.cc
        js_test_options.cc
        js_test_utils.cc
)

add_catch_test( js_identifier_ctx_test
    SOURCES
        ../js_identifier_ctx.cc
)

add_catch_test( streambuf_test
    SOURCES
        ../streambuf.cc
)

