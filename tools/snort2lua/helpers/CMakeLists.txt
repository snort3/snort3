
add_library( snort2lua_helpers
    converter.h
    converter.cc
    s2l_util.h
    s2l_util.cc
    parse_cmd_line.h
    parse_cmd_line.cc
    util_binder.h
    util_binder.cc
    s2l_markup.h
    s2l_markup.cc
)

target_link_libraries( snort2lua_helpers
    conversion_data
)
