


if( STATIC_CODECS )
    set( PLUGIN_SOURCES
        cd_erspan2.cc
        cd_erspan2_module.h
        cd_erspan2_module.cc
        cd_erspan3.cc
        cd_erspan3_module.h
        cd_erspan3_module.cc
        cd_ethloopback.cc
        cd_mpls.cc
        cd_mpls_module.h
        cd_mpls_module.cc
        cd_pppencap.cc
        cd_pppoepkt.cc
        cd_pppoepkt_module.h
        cd_pppoepkt_module.cc
        cd_transbridge.cc
        cd_vlan.cc
        cd_vlan_module.h
        cd_vlan_module.cc
    )

    if(ENABLE_NON_ETHER_DECODERS)
        set( PLUGIN_SOURCES
            ${PLUGIN_SOURCES}
            cd_eapol.cc
            cd_eapol_module.h
            cd_eapol_module.cc
        )
    endif()

else()
    add_shared_library(cd_erspan2 codecs cd_erspan2.cc cd_erspan2_module.h cd_erspan2_module.cc)
    add_shared_library(cd_erspan3 codecs cd_erspan3.cc cd_erspan3_module.h cd_erspan3_module.cc)
    add_shared_library(cd_ethloopback codecs cd_ethloopback.cc)
    add_shared_library(cd_mpls codecs cd_mpls.cc cd_mpls_module.h cd_mpls_module.cc)
    add_shared_library(cd_pppencap codecs cd_pppencap.cc)
    add_shared_library(cd_pppoepkt codecs cd_pppoepkt.cc cd_pppoepkt_module.h cd_pppoepkt_module.cc)
    add_shared_library(cd_transbridge codecs cd_transbridge.cc)
    add_shared_library(cd_vlan codecs cd_vlan.cc cd_vlan_module.h cd_vlan_module.cc)

    if(ENABLE_NON_ETHER_DECODER)
        add_shared_library(cd_eapol codecs cd_eapol.cc)
    endif()

endif()


add_library( link_codecs STATIC
    cd_arp.cc
    cd_arp_module.h
    cd_arp_module.cc
    ${PLUGIN_SOURCES}
)

target_link_libraries( link_codecs
    events
    managers
)

