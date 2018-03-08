
set (FRAMEWORK_INCLUDES
    base_api.h
    bits.h
    codec.h
    counts.h
    cursor.h
    data_bus.h
    decode_data.h
    endianness.h
    inspector.h
    ips_action.h
    ips_option.h
    logger.h
    lua_api.h
    module.h
    mpse.h
    parameter.h
    range.h
    so_rule.h
    value.h
    connector.h
)

add_library ( framework OBJECT
    ${FRAMEWORK_INCLUDES}
    codec.cc
    cursor.cc
    data_bus.cc
    inspector.cc
    ips_option.cc
    parameter.cc
    module.cc
    mpse.cc
    range.cc
    value.cc
)

install (FILES ${FRAMEWORK_INCLUDES} ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
    DESTINATION "${INCLUDE_INSTALL_PATH}/framework"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
    COMMAND grep API_OPTIONS ${CMAKE_BINARY_DIR}/config.h > ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
    DEPENDS ${CMAKE_BINARY_DIR}/config.h
)

add_custom_target(api_options ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/api_options.h)

set_property(
    DIRECTORY
    PROPERTY
    ADDITIONAL_MAKE_CLEAN_FILES api_options.h
)

