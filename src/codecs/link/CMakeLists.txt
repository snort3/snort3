
if(STATIC_CODECS)
    set( PLUGIN_SOURCES
        cd_arp.cc
        cd_erspan2.cc
        cd_erspan3.cc
        cd_ciscometadata.cc
        cd_fabricpath.cc
        cd_mpls.cc
        cd_ppp_encap.cc
        cd_pppoe.cc
        cd_trans_bridge.cc
        cd_vlan.cc
    )
else(STATIC_CODECS)
    add_dynamic_module(cd_arp codecs cd_arp.cc)
    add_dynamic_module(cd_erspan2 codecs cd_erspan2.cc)
    add_dynamic_module(cd_erspan3 codecs cd_erspan3.cc)
    add_dynamic_module(cd_ciscometadata codecs cd_ciscometadata.cc)
    add_dynamic_module(cd_fabricpath codecs cd_fabricpath.cc)
    add_dynamic_module(cd_mpls codecs cd_mpls.cc)
    add_dynamic_module(cd_ppp_encap codecs cd_ppp_encap.cc)
    add_dynamic_module(cd_pppoe codecs cd_pppoe.cc)
    add_dynamic_module(cd_trans_bridge codecs cd_trans_bridge.cc)
    add_dynamic_module(cd_vlan codecs cd_vlan.cc)

endif(STATIC_CODECS)

# NOTE: if any static libraries need to built, this extra if()
#       MUST be removed.  It is here because cmake sends out
#       a warning if no files exist in the link codecs library

if(STATIC_CODECS)
    add_library( link_codecs OBJECT
        ${PLUGIN_SOURCES}
    )
endif(STATIC_CODECS)
