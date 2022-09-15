set(UDP_STREAM_INCLUDES
   stream_udp.h
   udp_ha.h
   udp_module.h
   udp_session.h
)

add_library( stream_udp OBJECT
    stream_udp.cc
    udp_ha.cc
    udp_module.cc
    udp_session.cc
)

install(FILES ${UDP_STREAM_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/stream/udp"
)