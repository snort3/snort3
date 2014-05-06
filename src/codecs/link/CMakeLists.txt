


if( STATIC_DECODERS )
    set( PLUGIN_SOURCES
        cd_eapol.cc
        cd_erspan2.cc
        cd_erspan3.cc
        cd_ethloopback.cc
        cd_mpls.cc
        cd_pppencap.cc
        cd_pppoepkt.cc
        cd_transbridge.cc
        cd_vlan.cc
    )

    if(ENABLE_NON_ETHER_DECODER)
        set( PLUGIN_SOURCES
            ${PLUGIN_SOURCES}
            cd_eapol.cc
        )
    endif()

else()
    add_shared_library(cd_eapol codecs cd_eapol.cc)
    add_shared_library(cd_erspan2 codecs cd_erspan2.cc)
    add_shared_library(cd_erspan3 codecs cd_erspan3.cc)
    add_shared_library(cd_ethloopback codecs cd_ethloopback.cc)
    add_shared_library(cd_mpls codecs cd_mpls.cc)
    add_shared_library(cd_pppencap codecs cd_pppencap.cc)
    add_shared_library(cd_pppoepkt codecs cd_pppoepkt.cc)
    add_shared_library(cd_transbridge codecs cd_transbridge.cc)
    add_shared_library(cd_vlan codecs cd_vlan.cc)

    if(ENABLE_NON_ETHER_DECODER)
        add_shared_library(cd_eapol codecs cd_eapol.cc)
    endif()

endif()


add_library( link_codecs STATIC
    cd_arp.cc
    ${PLUGIN_SOURCES}
)

target_link_libraries( link_codecs
    events
    managers
)

