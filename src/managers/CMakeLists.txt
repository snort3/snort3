
set (LUA_INCLUDES
    # required 'header'
    ${CMAKE_CURRENT_BINARY_DIR}/snort_plugin.lua
)

set (CPP_INCLUDES
    ${CMAKE_CURRENT_BINARY_DIR}/lua_coreinit.h
)

add_subdirectory(test)

add_library( managers OBJECT
    ${LUA_INCLUDES}
    ${CPP_INCLUDES}
    action_manager.h
    action_manager.cc
    codec_manager.cc
    codec_manager.h
    event_manager.cc
    event_manager.h
    inspector_manager.cc
    inspector_manager.h
    ips_manager.cc
    ips_manager.h
    lua_plugin_defs.h
    module_manager.cc
    module_manager.h
    mpse_manager.cc
    mpse_manager.h
    plugin_manager.cc
    plugin_manager.h
    policy_selector_manager.cc
    policy_selector_manager.h
    script_manager.cc
    script_manager.h
    so_manager.cc
    so_manager.h
    connector_manager.cc
    connector_manager.h
)

add_custom_command (
    OUTPUT plugffi.lua snort_plugin.lua
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/ffi_wrap.sh ${CMAKE_CURRENT_SOURCE_DIR}/lua_plugin_defs.h > plugffi.lua
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/plugffi.lua ${CMAKE_CURRENT_BINARY_DIR}/snort_plugin.lua
)

add_custom_command (
    OUTPUT lua_coreinit.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../lua_wrap.sh ${CMAKE_CURRENT_SOURCE_DIR} coreinit > lua_coreinit.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/coreinit.lua
)

include_directories (${CMAKE_CURRENT_BINARY_DIR})

install (FILES ${LUA_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/lua"
)

