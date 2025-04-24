
set( MP_TRANSPORT_INCLUDES
    mp_unix_transport.h
    mp_unix_transport_module.h
)

add_library( mp_unix_transport OBJECT
    ${MP_TRANSPORT_INCLUDES}
    mp_unix_transport.cc
    mp_unix_transport_module.cc
)

install (FILES ${MIME_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/mp_unix_transport"
)

add_dependencies( mp_unix_transport framework )
add_dependencies( mp_unix_transport unixdomain_connector )

find_package(Threads REQUIRED)
target_link_libraries(mp_unix_transport PRIVATE Threads::Threads)
target_link_libraries(mp_unix_transport PRIVATE $<TARGET_OBJECTS:unixdomain_connector>)

add_subdirectory( test )