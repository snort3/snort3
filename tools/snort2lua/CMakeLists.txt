

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(data)
add_subdirectory(keyword_states)
add_subdirectory(preprocessor_states)
add_subdirectory(output_states)

add_executable(snort2lua
    snort2lua.cc
    converter.h
    converter.cc
    init_state.h
    init_state.cc
    snort2lua_util.h
    snort2lua_util.cc
    conversion_state.h
)

target_link_libraries( snort2lua
    conversion_data
    keyword_states
    output_states
    preprocessor_states
)


install (TARGETS snort2lua
    RUNTIME DESTINATION bin
)
