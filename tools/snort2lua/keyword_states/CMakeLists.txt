
add_library( keyword_states
    kws_attribute_table.cc
    kws_config.cc
    kws_event_filter.cc
    kws_file.cc
    kws_include.cc
    kws_output.cc
    kws_paths.cc
    kws_preprocessor.cc
    kws_rate_filter.cc
    kws_rule.cc
    kws_rule_state.cc
    kws_ruletype.cc
    kws_var.cc
    kws_suppress.cc
    keywords_api.h
    keywords_api.cc
)

target_link_libraries( keyword_states
    snort2lua_helpers
    conversion_data
    output_states
    preprocessor_states
    config_states
    rule_states
)
