
add_library( rule_states
    rule_content.cc
    rule_api.cc
    rule_api.h
)

target_link_libraries( rule_states
    util
    conversion_data
)
