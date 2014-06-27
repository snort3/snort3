

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(data)
add_subdirectory(keyword_states)
add_subdirectory(preprocessor_states)
add_subdirectory(output_states)
add_subdirectory(config_states)
add_subdirectory(rule_states)
add_subdirectory(util)


add_executable( snort2lua
    conversion_state.h
    option_parser.h
    init_state.h
    snort2lua.cc
    init_state.cc
)

target_link_libraries( snort2lua
    conversion_data
    util
    keyword_states
    output_states
    preprocessor_states
    rule_states
)


install (TARGETS snort2lua
    RUNTIME DESTINATION bin
)
