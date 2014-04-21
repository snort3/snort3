


add_library( basic_codecs STATIC
    cd_icmp4.cc
    cd_icmp6.cc
    cd_ipv4.cc
    cd_ipv6.cc
    cd_tcp.cc
    cd_udp.cc
    cd_eth.cc
    cd_esp.cc  # Incluse esp here because it MUST be statically linked due to its dependance on the packet manager
)

target_link_libraries( basic_codecs
    protocols
    framework
)
