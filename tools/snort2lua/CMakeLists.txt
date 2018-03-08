
include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(config_states)
add_subdirectory(data)
add_subdirectory(helpers)
add_subdirectory(keyword_states)
add_subdirectory(output_states)
add_subdirectory(preprocessor_states)
add_subdirectory(rule_states)

if (ENABLE_UNIT_TESTS)
if (0)
    add_subdirectory(tests)
endif()
endif()

add_executable( snort2lua
    conversion_state.h
    conversion_defines.h
    init_state.h
    snort2lua.cc
    init_state.cc
    $<TARGET_OBJECTS:config_states>
    $<TARGET_OBJECTS:conversion_data>
    $<TARGET_OBJECTS:data_types>
    $<TARGET_OBJECTS:keyword_states>
    $<TARGET_OBJECTS:output_states>
    $<TARGET_OBJECTS:preprocessor_states>
    $<TARGET_OBJECTS:rule_states>
    $<TARGET_OBJECTS:snort2lua_helpers>
)

install (TARGETS snort2lua
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
