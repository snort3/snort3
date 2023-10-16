
set (PROTOCOL_HEADERS
    arp.h
    bpdu.h
    cdp.h
    cisco_meta_data.h
    eapol.h
    eth.h
    icmp4.h
    icmp6.h
    ip.h
    ipv4.h
    ipv4_options.h
    ipv6.h
    geneve.h
    gre.h
    layer.h
    linux_sll.h
    mpls.h
    packet.h
    packet_manager.h
    protocol_ids.h
    ssl.h
    tcp.h
    tcp_options.h
    teredo.h
    token_ring.h
    udp.h
    wlan.h
    vlan.h
)

add_library (protocols OBJECT
    ${PROTOCOL_HEADERS}
    layer.cc
    packet.cc
    ip.cc
    ipv4_options.cc
    ssl.cc
    tcp_options.cc
    packet_manager.cc
)

add_subdirectory(test)

install (FILES ${PROTOCOL_HEADERS}
    DESTINATION "${INCLUDE_INSTALL_PATH}/protocols"
)
