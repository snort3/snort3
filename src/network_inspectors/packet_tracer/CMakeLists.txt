set (PACKET_TRACER_INCLUDES
    packet_tracer.h
)

add_library ( packet_tracer OBJECT
    ${PACKET_TRACER_INCLUDES}
    packet_tracer.cc
    packet_tracer_module.h
    packet_tracer_module.cc
)

install(FILES ${PACKET_TRACER_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/network_inspectors/packet_tracer"
)