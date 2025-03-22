add_subdirectory(file_connector)
add_subdirectory(tcp_connector)
add_subdirectory(std_connector)
add_subdirectory(unixdomain_connector)

add_library( connectors OBJECT
    connectors.cc
    connectors.h
)

