
set (PROTOCOL_HEADERS
    ipv4.h
    tcp.h
    packet.h
    ipv6.h
    udp.h
    eth.h
    icmp4.h
    icmp6.h
    gre.h
    arp.h
    wlan.h
    teredo.h
    mpls.h
    protocol_ids.h
)

add_library (protocols STATIC
    ${PROTOCOL_HEADERS}
    ../codecs/template.cc  # CMake complains if we don't compile any files.  so use dummy file.  Linux will remove all of the symbols anyways.
)

install (FILES ${PROTOCOL_HEADERS}
    DESTINATION "${INCLUDE_INSTALL_PATH}/protocols"
)
