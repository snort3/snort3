
set (PROTOCOL_HEADERS
    arp.h
    eapol.h
    eth.h
    icmp4.h
    icmp6.h
    ip.h
    ipv4.h
    ipv6.h
    gre.h
    layer.h
    linux_sll.h
    mpls.h
    packet.h
    protocol_ids.h
    tcp.h
    teredo.h
    token_ring.h
    udp.h
    wlan.h
    vlan.h
)

add_library (protocols STATIC
    ${PROTOCOL_HEADERS}
    layer.cc
    ip.cc
)

install (FILES ${PROTOCOL_HEADERS}
    DESTINATION "${INCLUDE_INSTALL_PATH}/protocols"
)
