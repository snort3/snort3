

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(data)
add_subdirectory(keywords)
add_subdirectory(preprocessor)
add_subdirectory(output)

add_executable(snort2lua
    snort2lua.cc
    converter.h
    converter.cc
    init_state.h
    init_state.cc
    snort2lua_util.h
    snort2lua_util.cc
)

target_link_libraries( snort2lua
    data
    keywords
    output
    preprocessor
)


install (TARGETS snort2lua
    RUNTIME DESTINATION bin
)
