


if( STATIC_CODECS )
    set( PLUGIN_SOURCES
        cd_ah.cc
        cd_ah_module.h
        cd_ah_module.cc
        cd_dstopts.cc
        cd_frag.cc
        cd_gre.cc
        cd_gre_module.h
        cd_gre_module.cc
        cd_hopopts.cc
        cd_igmp.cc
        cd_igmp_module.h
        cd_igmp_module.cc
        cd_no_next.cc
        cd_mobility.cc
        cd_pim.cc
        cd_pgm.cc
        cd_pgm_module.h
        cd_pgm_module.cc
        cd_routing.cc
        cd_sun_nd.cc
        cd_swipe.cc
    )

else()
    add_shared_library(cd_ah codecs cd_ah.cc cd_ah_module.h cd_ah_module.cc)
    add_shared_library(cd_dstopts codecs cd_dstopts.cc)
    add_shared_library(cd_frag codecs cd_frag.cc)
    add_shared_library(cd_gre codecs cd_gre.cc cd_gre_module.h cd_gre_module.cc)
    add_shared_library(cd_hopopts codecs cd_hopopts.cc)
    add_shared_library(cd_igmp codecs cd_igmp.cc cd_igmp_module.h cd_igmp_module.cc)
    add_shared_library(cd_mobility codecs cd_mobility.cc)
    add_shared_library(cd_no_next codecs cd_no_next.cc)
    add_shared_library(cd_pim codecs cd_pim.cc)
    add_shared_library(cd_pgm codecs cd_pgm.cc cd_pgm_module.h cd_pgm_module.cc)
    add_shared_library(cd_routing codecs cd_routing.cc)
    add_shared_library(cd_sun_nd codecs cd_sun_nd.cc)
    add_shared_library(cd_swipe codecs cd_swipe.cc)

endif()


add_library( ip_codecs STATIC
    cd_icmp4.cc
    cd_icmp4_module.h
    cd_icmp4_module.cc
    cd_icmp6.cc
    cd_icmp6_module.h
    cd_icmp6_module.cc
    cd_ipv4.cc
    cd_ipv4_module.h
    cd_ipv4_module.cc
    cd_ipv6.cc
    cd_ipv6_module.h
    cd_ipv6_module.cc
    cd_tcp.cc
    cd_tcp_module.h
    cd_tcp_module.cc
    cd_udp.cc
    cd_udp_module.h
    cd_udp_module.cc
    cd_esp.cc  # statically linked due to its dependance on the packet manager.
    cd_esp_module.h
    cd_esp_module.cc
    ${PLUGIN_SOURCES}
)

target_link_libraries( ip_codecs
    protocols
    framework
    events
    main
    managers
)
