
add_library( std_connector OBJECT
    std_connector_buffer.cc
    std_connector_buffer.h
    std_connector.cc
    std_connector.h
)

add_subdirectory(test)