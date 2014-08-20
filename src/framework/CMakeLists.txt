

set (FRAMEWORK_INCLUDES
    base_api.h
    bits.h
    codec.h
    counts.h
    cursor.h
    logger.h
    inspector.h
    ips_option.h
    module.h
    mpse.h
    parameter.h
    plug_data.h
    so_rule.h
    value.h
)

add_library ( framework STATIC
    ${FRAMEWORK_INCLUDES}
    cursor.cc
    inspector.cc
    ips_option.cc
    parameter.cc
    module.cc
    mpse.cc
    value.cc
)

target_link_libraries( framework
    detection
    ${LUAJIT_LIBRARIES}
)


install (FILES ${FRAMEWORK_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/framework"
)

