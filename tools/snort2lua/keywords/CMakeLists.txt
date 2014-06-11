
add_library( keywords
    config.cc
    output.cc
    var.cc
    preprocessor.cc
    include.cc
    keywords_api.h
    keywords_api.cc
)

target_link_libraries( keywords
    output
    preprocessor
)