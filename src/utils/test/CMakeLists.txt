add_cpputest( boyer_moore_test
    SOURCES
        ../boyer_moore.cc
)

add_cpputest( memcap_allocator_test )

FLEX_TARGET ( js_tokenizer ${CMAKE_CURRENT_SOURCE_DIR}/../js_tokenizer.l
    ${CMAKE_CURRENT_BINARY_DIR}/../js_tokenizer.cc
    COMPILE_FLAGS -Ca
)

add_catch_test( js_normalizer_test
    SOURCES
        ${FLEX_js_tokenizer_OUTPUTS}
        ../js_normalizer.cc
        ../util_cstring.cc
)

