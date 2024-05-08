set (SSL_INCLUDES
    ssl_flow_data.h
)

set( FILE_LIST
    ips_ssl_state.cc
    ips_ssl_version.cc
    ssl_config.h
    ssl_inspector.cc
    ssl_inspector.h
    ssl_flow_data.cc
    ssl_module.cc
    ssl_module.h
    ssl_splitter.cc
    ssl_splitter.h
    ${SSL_INCLUDES}
)

if (STATIC_INSPECTORS)
    add_library( ssl OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(ssl inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

install(FILES ${SSL_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/service_inspectors/ssl/"
)
