
add_library( codec_plugins STATIC
    cd_swipe.cc
    cd_teredo.cc
    cd_gtp.cc
    cd_vlan.cc
    cd_ah.cc
    cd_arp.cc
    cd_ethloopback.cc
    cd_gre.cc
    cd_mpls.cc
    cd_transbridge.cc
    cd_erspan2.cc
    cd_erspan3.cc
    cd_pppencap.cc
    cd_pppoepkt.cc
)


