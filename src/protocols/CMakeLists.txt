
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
    gtp.h
    arp.h
    wlan.h
    teredo.h
    mpls.h
    protocol_ids.h
)

add_library (protocols STATIC
    packet.cc
    checksum.h
    checksum.cc
    ${PROTOCOL_HEADERS}
)

install (FILES ${PROTOCOL_HEADERS}
    DESTINATION "${INCLUDE_INSTALL_PATH}/protocols"
)
