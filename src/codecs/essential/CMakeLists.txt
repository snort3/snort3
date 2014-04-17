


add_library( essential
    cd_icmp4.cc
    cd_icmp6.cc
    cd_ipv4.cc
    cd_ipv6.cc
    cd_tcp.cc
    cd_udp.cc
    cd_eth.cc
)

target_link_libraries( essential
    protocols
)
