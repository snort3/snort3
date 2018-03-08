
if( STATIC_CODECS )
    set( PLUGIN_SOURCES
        cd_auth.cc
        cd_bad_proto.cc
        cd_dst_opts.cc
        cd_esp.cc
        cd_frag.cc
        cd_gre.cc
        cd_icmp4.cc
        cd_icmp6.cc
        cd_igmp.cc
        cd_ipv6.cc
        cd_no_next.cc
        cd_mobility.cc
        cd_pgm.cc
        cd_routing.cc
        cd_udp.cc
    )

else()
    add_dynamic_module(cd_auth codecs cd_auth.cc)
    add_dynamic_module(cd_bad_proto codecs cd_bad_proto.cc)
    add_dynamic_module(cd_dst_opts codecs cd_dst_opts.cc)
    add_dynamic_module(cd_esp codecs cd_esp.cc)
    add_dynamic_module(cd_frag codecs cd_frag.cc)
    add_dynamic_module(cd_gre codecs cd_gre.cc)
#    add_dynamic_module(cd_hopopts codecs cd_hop_opts.cc)
    add_dynamic_module(cd_icmp4 codecs cd_icmp4.cc checksum.h)
    add_dynamic_module(cd_icmp6 codecs cd_icmp6.cc checksum.h)
    add_dynamic_module(cd_igmp codecs cd_igmp.cc)
#    add_dynamic_module(cd_ipv4 codecs cd_ipv4.cc checksum.h)
    add_dynamic_module(cd_ipv6 codecs cd_ipv6.cc checksum.h)
    add_dynamic_module(cd_mobility codecs cd_mobility.cc)
    add_dynamic_module(cd_no_next codecs cd_no_next.cc)
    add_dynamic_module(cd_pgm codecs cd_pgm.cc checksum.h)
    add_dynamic_module(cd_routing codecs cd_routing.cc)
#    add_dynamic_module(cd_tcp codecs cd_tcp.cc checksum.h)
    add_dynamic_module(cd_udp codecs cd_udp.cc checksum.h)

endif()


add_library( ip_codecs OBJECT
    cd_ipv4.cc # Static due to its dependence on fpdetect
    cd_hop_opts.cc  #  Ensured the symbols CheckIPV6HopOptions && CheckIPv6ExtensionOrder are in the binary.
    cd_tcp.cc  # Only file to use some functions.  Must be included in binary.
    checksum.h
    ${PLUGIN_SOURCES}
)

