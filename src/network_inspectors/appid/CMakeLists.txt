set ( APPID_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR} )

add_subdirectory(client_plugins)
add_subdirectory(detector_plugins)
add_subdirectory(service_plugins)
add_subdirectory(util)
add_subdirectory ( test )

set ( APPID_SOURCES
    app_forecast.cc
    app_forecast.h
    appid_api.cc
    appid_api.h
    appid_config.cc
    appid_config.h
    appid_flow_data.cc
    appid_flow_data.h
    appid.h
    appid_inspector.cc
    appid_inspector.h
    appid_module.cc
    appid_module.h
    appid_stats.cc
    appid_stats.h
    app_info_table.cc
    app_info_table.h
    application_ids.h
    dns_defs.h
    flow_error.h
    fw_appid.cc
    fw_appid.h
    host_port_app_cache.cc
    host_port_app_cache.h
    http_common.h
    length_app_cache.cc
    length_app_cache.h
    lua_detector_api.cc
    lua_detector_api.h
    lua_detector_flow_api.cc
    lua_detector_flow_api.h
    lua_detector_module.cc
    lua_detector_module.h
    lua_detector_util.h
    service_state.cc
    service_state.h
    sfaddr_temp.h
    thirdparty_appid_api.h
    thirdparty_appid_types.h
    thirdparty_appid_utils.cc
    thirdparty_appid_utils.h
    )

add_library ( appid STATIC
    ${APPID_SOURCES}
)

target_include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

target_link_libraries ( appid 
    appid_client_plugins
    appid_detector_plugins
    appid_service_plugins
)

#  FIXIT-H: Add unit tests

#install (FILES ${APPID_INCLUDES}
#    DESTINATION "${INCLUDE_INSTALL_PATH}/appid"
#)
