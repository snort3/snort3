
add_library( file_connector STATIC
    file_connector.cc
    file_connector.h
    file_connector_config.h
    file_connector_module.cc
    file_connector_module.h
)

target_link_libraries(file_connector)
