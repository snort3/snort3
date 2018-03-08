
add_library( file_connector OBJECT
    file_connector.cc
    file_connector.h
    file_connector_config.h
    file_connector_module.cc
    file_connector_module.h
)

add_subdirectory(test)
