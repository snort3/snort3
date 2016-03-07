
add_library( rule_states
    rule_base64_decode.cc
    rule_content.cc
    rule_convert_comma_list.cc
    rule_dce_iface.cc
    rule_dnp3_obj.cc
    rule_file_data.cc
    rule_http_encode.cc
    rule_isdataat.cc
    rule_metadata.cc
    rule_pcre.cc
    rule_react.cc
    rule_resp.cc
    rule_sd_pattern.cc
    rule_stream_reassemble.cc
    rule_stream_size.cc
    rule_tag.cc
    rule_ttl.cc
    rule_threshold.cc
    rule_unchanged.cc
    rule_urilen.cc
    rule_api.cc
    rule_api.h
)

target_link_libraries( rule_states
    snort2lua_helpers
    conversion_data
)
