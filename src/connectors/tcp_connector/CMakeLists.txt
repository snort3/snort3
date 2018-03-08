
add_library( tcp_connector OBJECT
    tcp_connector.cc
    tcp_connector.h
    tcp_connector_config.h
    tcp_connector_module.cc
    tcp_connector_module.h
)

add_subdirectory(test)
