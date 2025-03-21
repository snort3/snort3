add_subdirectory(test)

set (FRAMEWORK_INCLUDES
    base_api.h
    codec.h
    connector.h
    counts.h
    cursor.h
    data_bus.h
    decode_data.h
    endianness.h
    inspector.h
    ips_action.h
    ips_option.h
    logger.h
    module.h
    mp_data_bus.h
    mpse.h
    mpse_batch.h
    parameter.h
    pig_pen.h
    pdu_section.h
    policy_selector.h
    plugins.h
    range.h
    so_rule.h
    value.h
)

add_library ( framework OBJECT
    ${FRAMEWORK_INCLUDES}
    act_info.h
    codec.cc
    cursor.cc
    data_bus.cc
    inspector.cc
    ips_info.h
    ips_action.cc
    ips_option.cc
    lua_api.h
    parameter.cc
    pig_pen.cc
    module.cc
    mp_data_bus.cc
    mpse.cc
    mpse_batch.cc
    range.cc
    value.cc
)

install (FILES ${FRAMEWORK_INCLUDES}
    ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
    ${CMAKE_CURRENT_BINARY_DIR}/snort_api.h
    DESTINATION "${INCLUDE_INSTALL_PATH}/framework"
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
    COMMAND grep API_OPTIONS ${CMAKE_BINARY_DIR}/config.h > ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
    DEPENDS ${CMAKE_BINARY_DIR}/config.h
)

add_custom_target(api_options ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/api_options.h)

list(APPEND inc_local ".")
list(APPEND inc_local "${CMAKE_CURRENT_BINARY_DIR}/..")
list(TRANSFORM inc_local PREPEND "-I")

list(APPEND inc_external ${EXTERNAL_INCLUDES})
list(TRANSFORM inc_external PREPEND "-idirafter")

list(APPEND inc_dirs ${inc_local})
list(APPEND inc_dirs ${inc_external})
list(JOIN inc_dirs " " INC_DIRS)

add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/snort_api.h
    COMMAND
        ${CMAKE_CURRENT_SOURCE_DIR}/plug_gen.sh ${CMAKE_CXX_COMPILER} ${CMAKE_CURRENT_SOURCE_DIR} ${INC_DIRS} > ${CMAKE_CURRENT_BINARY_DIR}/snort_api.h
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/plug_gen.sh
        ${CMAKE_CURRENT_SOURCE_DIR}/plugins.h
        ${CMAKE_CURRENT_BINARY_DIR}/api_options.h
)

add_custom_target(snort_api ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/snort_api.h)

set_property(
    DIRECTORY
    PROPERTY
    ADDITIONAL_MAKE_CLEAN_FILES api_options.h snort_api.h
)

add_catch_test( parameter_test
    NO_TEST_SOURCE
    SOURCES
        parameter.cc
    LIBS
        ${DNET_LIBRARIES}
)

add_catch_test( range_test
    NO_TEST_SOURCE
    SOURCES
        range.cc
)

