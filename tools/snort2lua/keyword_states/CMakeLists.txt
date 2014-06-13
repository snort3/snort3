
add_library( keyword_states
    kws_config.cc
    kws_output.cc
    kws_var.cc
    kws_preprocessor.cc
    kws_include.cc
    keywords_api.h
    keywords_api.cc
)

target_link_libraries( keyword_states
    output_states
    preprocessor_states
)