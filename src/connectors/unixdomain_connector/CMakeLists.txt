
add_library( unixdomain_connector OBJECT
    unixdomain_connector.cc
    unixdomain_connector.h
    unixdomain_connector_config.h
    unixdomain_connector_module.cc
    unixdomain_connector_module.h
)

add_subdirectory(test)
