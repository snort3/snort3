

add_library( snort2lua_utils
    converter.h
    converter.cc
    s2l_util.h
    s2l_util.cc
    parse_cmd_line.h
    parse_cmd_line.cc
)

target_link_libraries( snort2lua_utils
    conversion_data
)
