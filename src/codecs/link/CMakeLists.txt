
if(STATIC_CODECS)
    set( PLUGIN_SOURCES
        cd_arp.cc
        cd_erspan2.cc
        cd_erspan3.cc
        cd_fabricpath.cc
        cd_mpls.cc
        cd_ppp_encap.cc
        cd_pppoe.cc
        cd_trans_bridge.cc
        cd_vlan.cc
    )


else(STATIC_CODECS)
    add_shared_library(cd_arp codecs cd_arp.cc)
    add_shared_library(cd_erspan2 codecs cd_erspan2.cc)
    add_shared_library(cd_erspan3 codecs cd_erspan3.cc)
    add_shared_library(cd_fabricpath codecs cd_fabricpath.cc)
    add_shared_library(cd_mpls codecs cd_mpls.cc)
    add_shared_library(cd_ppp_encap codecs cd_ppp_encap.cc)
    add_shared_library(cd_pppoe codecs cd_pppoe.cc)
    add_shared_library(cd_trans_bridge codecs cd_trans_bridge.cc)
    add_shared_library(cd_vlan codecs cd_vlan.cc)

endif(STATIC_CODECS)



# NOTE: if any static libraries need to built, this extra if()
#       MUST be removed.  It is here because cmake sends out
#       a warning if no files exist in the link codecs library

if(STATIC_CODECS)
    add_library( link_codecs STATIC
        ${PLUGIN_SOURCES}
    )


    target_link_libraries( link_codecs
        events
        managers
        codec_module
    )

endif(STATIC_CODECS)
