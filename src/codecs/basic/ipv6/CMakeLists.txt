

if(STATIC_DECODERS)
    set( IPV6_OPTIONS
        cd_hopopts.cc
        cd_dstopts.cc
        cd_routing.cc
        cd_frag.cc
        cd_no_next.cc
    )
endif()

add_library( ipv6_codecs STATIC
    cd_ipv6.cc
    ipv6_util.h
    ipv6_util.cc
    ${IPV6_OPTIONS}
)

target_link_libraries( ipv6_codecs
    protocols
    events
    main
    detection
)

