

add_library( snort2lua_utils
    converter.h
    converter.cc
    snort2lua_util.h
    snort2lua_util.cc
)

target_link_libraries( snort2lua_utils
    conversion_data
)
