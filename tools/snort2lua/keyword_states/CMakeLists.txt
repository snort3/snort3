
add_library( keyword_states
    kws_config.cc
    kws_include.cc
    kws_output.cc
    kws_preprocessor.cc
    kws_rule.cc
    kws_var.cc
    kws_suppress.cc
    keywords_api.h
    keywords_api.cc
)

target_link_libraries( keyword_states
    util
    conversion_data
    output_states
    preprocessor_states
    config_states
    rule_states
)
