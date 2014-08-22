
add_library( rule_states
    rule_base64_decode.cc
    rule_content.cc
    rule_file_data.cc
    rule_http_encode.cc
    rule_metadata.cc
    rule_pcre.cc
    rule_react.cc
    rule_resp.cc
    rule_threshold.cc
    rule_unchanged.cc
    rule_urilen.cc
    rule_api.cc
    rule_api.h
)

target_link_libraries( rule_states
    util
    conversion_data
)
