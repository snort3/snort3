

#include_directories(${CMAKE_CURRENT_SOURCE_DIRECTORY})

add_subdirectory(keyword_states)

add_executable(snort2lua
    snort2lua.cc
    converter.h
    converter.cc
    init_state.h
    init_state.cc
)

target_link_libraries( snort2lua
    keyword_states
)


install (TARGETS snort2lua
    RUNTIME DESTINATION bin
)
