


if( STATIC_DECODERS )
    set( PLUGIN_SOURCES
        cd_ah.cc
        cd_dstopts.cc
        cd_frag.cc
        cd_gre.cc
        cd_hopopts.cc
        cd_igmp.cc
        cd_ipv6.cc
        cd_no_next.cc
        cd_pgm.cc
        cd_routing.cc
        cd_swipe.cc
    )

else()
    add_shared_library(cd_ah codecs cd_ah.cc)
    add_shared_library(cd_dstopts codecs cd_dstopts.cc)
    add_shared_library(cd_frag codecs cd_frag.cc)
    add_shared_library(cd_gre codecs cd_gre.cc)
    add_shared_library(cd_hopopts codecs cd_hopopts.cc)
    add_shared_library(cd_igmp codecs cd_igmp.cc)
    add_shared_library(cd_ipv6 codecs cd_ipv6.cc)
    add_shared_library(cd_no_next codecs cd_no_next.cc)
    add_shared_library(cd_pgm codecs cd_pgm.cc)
    add_shared_library(cd_routing codecs cd_routing.cc)
    add_shared_library(cd_swipe codecs cd_swipe.cc)

endif()


add_library( ip_codecs STATIC
    cd_icmp4.cc
    cd_icmp6.cc
    cd_ipv4.cc
    cd_ipv6.cc
    cd_tcp.cc
    cd_udp.cc
    cd_esp.cc  # statically linked due to its dependance on the packet manager.
    ${PLUGIN_SOURCES}
)

target_link_libraries( ip_codecs
    protocols
    framework
    events
    main
    managers
)


