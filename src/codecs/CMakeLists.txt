

add_subdirectory(basic)
add_subdirectory(plugins)


if (ENABLE_NON_ETHER_DECODERS)
    set( NON_ETHER_DECODERS
        prot_eap.h
        prot_eap.cc
        prot_eapol.h
        prot_eapol.cc
        prot_eapolkey.h
        prot_eapolkey.cc
        prot_ipx.h
        prot_ipx.cc
    )
endif(ENABLE_NON_ETHER_DECODERS)


add_library( codecs STATIC
    codec_events.cc
    codec_events.h
    encode.h
    encode.cc
    decode.h
    decode.cc
    decode_module.h
    decode_module.cc
    codec_api.h
    codec_api.cc
)


target_link_libraries( codecs
    basic_codecs
    codec_plugins
    protocols
    sfip
    framework
)


#add_library (codecs STATIC
#    decode.cc
#    decode.h
#    encode.cc
#    encode.h
#    prot_arp.h
#    prot_arp.cc
#    prot_icmp4.h
#    prot_icmp4.cc
#    prot_icmp6.h
#    prot_icmp6.cc
#    prot_gre.h
#    prot_gre.cc
#    prot_ipv4.h
#    prot_ipv4.cc 
#    prot_ah.h
#    prot_ah.cc
#     prot_tcp.h 
#    prot_tcp.cc
#    prot_udp.h
#    prot_udp.cc
#    prot_ipv6.h
#    prot_ipv6.cc
#    prot_teredo.h
#    prot_teredo.cc
#    prot_gtp.h
#    prot_gtp.cc
#    prot_erspan2.h
#    prot_erspan2.cc
#    prot_erspan3.h
#    prot_erspan3.cc
#    prot_esp.h
#    prot_esp.cc
#    prot_vlan.h
#    prot_vlan.cc
#    prot_transbridge.h
#    prot_transbridge.cc
#    prot_mpls.h
#    prot_mpls.cc
#    prot_ethloopback.h
#    prot_ethloopback.cc
#    prot_ethovermpls.h
#    prot_ethovermpls.cc
#    prot_pppoepkt.h
#    prot_pppoepkt.cc
#    prot_pppencap.cc
#    ${NON_ETHER_DECODERS}
#)
