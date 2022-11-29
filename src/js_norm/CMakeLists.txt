FLEX ( pdf_tokenizer
    ${CMAKE_CURRENT_SOURCE_DIR}/pdf_tokenizer.l
    ${CMAKE_CURRENT_BINARY_DIR}/pdf_tokenizer.cc
)

FLEX ( js_tokenizer
    ${CMAKE_CURRENT_SOURCE_DIR}/js_tokenizer.l
    ${CMAKE_CURRENT_BINARY_DIR}/js_tokenizer.cc
)

set ( JS_SOURCES
    ${pdf_tokenizer_OUTPUTS}
    ${js_tokenizer_OUTPUTS}
    js_config.h
    js_enum.h
    js_identifier_ctx.cc
    js_identifier_ctx.h
    js_norm.cc
    js_norm.h
    js_norm_module.cc
    js_norm_module.h
    js_normalizer.cc
    js_normalizer.h
    js_tokenizer.h
    pdf_tokenizer.h
)

add_library(js_norm OBJECT ${JS_SOURCES})

add_subdirectory(test)
