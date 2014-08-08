
include_directories(${LUAJIT_INCLUDE_DIR})

set (LUA_INCLUDES
    snort_config.lua
    snort_plugin.lua
)

add_library( managers
    action_manager.h
    action_manager.cc
    data_manager.h
    data_manager.cc
    event_manager.cc
    event_manager.h
    inspector_manager.cc
    inspector_manager.h
    ips_manager.cc
    ips_manager.h
    module_manager.cc
    module_manager.h
    mpse_manager.cc
    mpse_manager.h
    packet_manager.cc
    packet_manager.h
    plugin_manager.cc
    plugin_manager.h
    script_manager.cc
    script_manager.h
    so_manager.cc
    so_manager.h
    shell.cc
    shell.h
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
    actions
)

install (FILES ${LUA_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/lua"
)
