
set (LUA_INCLUDES
    snort_config.lua
    ${CMAKE_CURRENT_BINARY_DIR}/snort_plugin.lua
)

add_library( managers
    action_manager.h
    action_manager.cc
    codec_manager.h
    codec_manager.cc
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
    script_manager.cc
    script_manager.h
    so_manager.cc
    so_manager.h
    connector_manager.cc
    connector_manager.h
)

target_link_libraries(managers
    framework
    helpers
    loggers
    ips_options
    network_inspectors
    service_inspectors
    search_engines
    parser
    codecs
    ips_actions
)

add_custom_command (
    OUTPUT snort_plugin.lua
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/ffi_wrap.sh ${CMAKE_CURRENT_SOURCE_DIR}/lua_plugin_defs.h > snort_plugin.lua
)

add_custom_target ( snort_plugin DEPENDS snort_plugin.lua )

# FIXIT-L probably not the ideal way to ensure this gets built
add_dependencies ( managers snort_plugin )

install (FILES ${LUA_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/lua"
)
