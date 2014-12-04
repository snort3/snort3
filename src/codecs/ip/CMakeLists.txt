
if( STATIC_CODECS )
    set( PLUGIN_SOURCES
        cd_auth.cc
        cd_dst_opts.cc
        cd_esp.cc
        cd_frag.cc
        cd_gre.cc
        cd_hop_opts.cc
        cd_icmp4.cc
        cd_icmp6.cc
        cd_igmp.cc
        cd_ipv6.cc
        cd_no_next.cc
        cd_mobility.cc
        cd_pgm.cc
        cd_routing.cc
        cd_sun_nd.cc
        cd_swipe.cc
        cd_udp.cc
    )

else()
    add_shared_library(cd_auth codecs cd_auth.cc ip_util.h ip_util.cc)
    add_shared_library(cd_dst_opts codecs cd_dst_opts.cc ip_util.h ip_util.cc)
    add_shared_library(cd_esp codecs cd_esp.cc ip_util.h ip_util.cc)
    add_shared_library(cd_frag codecs cd_frag.cc ip_util.h ip_util.cc)
    add_shared_library(cd_gre codecs cd_gre.cc)
    add_shared_library(cd_hop_opts codecs cd_hop_opts.cc ip_util.h ip_util.cc)
    add_shared_library(cd_icmp4 codecs cd_icmp4.cc checksum.h)
    add_shared_library(cd_icmp6 codecs cd_icmp6.cc checksum.h)
    add_shared_library(cd_igmp codecs cd_igmp.cc)
#    add_shared_library(cd_ipv4 codecs cd_ipv4.cc checksum.h)
    add_shared_library(cd_ipv6 codecs cd_ipv6.cc checksum.h ip_util.h ip_util.cc)
    add_shared_library(cd_mobility codecs cd_mobility.cc)
    add_shared_library(cd_no_next codecs cd_no_next.cc ip_util.h ip_util.cc)
    add_shared_library(cd_pgm codecs cd_pgm.cc checksum.h)
    add_shared_library(cd_routing codecs cd_routing.cc ip_util.h ip_util.cc)
    add_shared_library(cd_sun_nd codecs cd_sun_nd.cc)
    add_shared_library(cd_swipe codecs cd_swipe.cc)
#    add_shared_library(cd_tcp codecs cd_tcp.cc checksum.h)
    add_shared_library(cd_udp codecs cd_udp.cc checksum.h)

endif()


add_library( ip_codecs STATIC
    cd_ipv4.cc # Static due to its dependence on fpdetect
    cd_tcp.cc  # Only file to use some functions.  Must be included in binary.
    checksum.h
    ip_util.h
    ip_util.cc # PacketManager
    ${PLUGIN_SOURCES}
)

target_link_libraries( ip_codecs
    protocols
    framework
    events
    main
    managers
    codec_module
)
