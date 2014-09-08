

set (PACKET_IO_INCLUDES
    active.h
)

add_library (packet_io STATIC
    active.cc
    intf.cc
    intf.h
    sfdaq.cc
    sfdaq.h
    trough.cc
    trough.h
    ${PACKET_IO_INCLUDES}
)

install (FILES ${PACKET_IO_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/packet_io"
)
