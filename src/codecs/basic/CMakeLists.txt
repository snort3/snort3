


add_library( basic_codecs STATIC
    cd_icmp4.cc
    cd_icmp6.cc
    cd_ipv4.cc
    cd_ipv6.cc
    cd_tcp.cc
    cd_udp.cc
    cd_eth.cc
    cd_esp.cc  # due to its dependance on the packet manager, esp must be statically linked.
    cd_null.cc
)

target_link_libraries( basic_codecs
    protocols
    framework
    events
    main
)
