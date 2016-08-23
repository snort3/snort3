
add_subdirectory(file_connector)
add_subdirectory(tcp_connector)

add_library( connectors STATIC
    connectors.cc
    connectors.h
)

target_link_libraries(connectors file_connector tcp_connector)

