

include_directories(${PCAP_INCLUDE_DIR})


if (ENABLE_NON_ETHER_DECODERS)
    set( NON_ETHER_DECODERS
        prot_eap.h
        prot_eapol.h
        prot_eapol.cc
        prot_eapolkey.h
        prot_eapolkey.cc
    )
endif(ENABLE_NON_ETHER_DECODERS)

if (ENABLE_NON_ETHER_DECODERS)
    set(NON_ETHER_DECODERS
        cd_trk.cc
        cd_trk_module.h
        cd_trk_module.cc
        root_fddi.cc
        root_linuxsll.cc
        cd_ieee80211.cc
        cd_ieee80211_module.h
        cd_ieee80211_module.cc
        root_slip.cc
        root_i4lrawip.cc
        root_oldpflog.cc
        root_enc.cc
        root_ppp.cc
        root_pflog.cc
        root_pppserial.cc
        root_chdlc.cc
        root_i4lciscoip.cc
        prot_ipx.cc
        prot_eap.cc
    )
endif (ENABLE_NON_ETHER_DECODERS)


add_library(root_codecs STATIC
    cd_eth.cc
    cd_eth_module.h
    cd_eth_module.cc
    cd_raw4.cc
    cd_raw6.cc
    cd_null_root.cc
    ${NON_ETHER_DECODERS}
    ${PCAP_INCLUDE_DIR}/pcap.h  # rebuild if a new libpcap is installed
)

target_link_libraries(root_codecs
    protocols
    managers
    ${PCAP_LIBRARIES}
)
