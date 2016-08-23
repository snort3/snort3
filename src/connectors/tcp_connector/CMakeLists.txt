
add_library( tcp_connector STATIC
    tcp_connector.cc
    tcp_connector.h
    tcp_connector_config.h
    tcp_connector_module.cc
    tcp_connector_module.h
)

target_link_libraries(tcp_connector)
