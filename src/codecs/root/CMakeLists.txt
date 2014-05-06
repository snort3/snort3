

include_directories(${PCAP_INCLUDE_DIR})


if (ENABLE_NON_ETHER_DECODERS)
    set(NON_ETHER_DECODERS
        root_trk.h
        root_trk.cc
        root_fddi.h
        root_fddi.cc
        root_linuxsll.h
        root_linuxsll.cc
        root_ieee80211.h
        root_ieee80211.cc
        root_slip.h
        root_slip.cc
        root_i4lrawip.h
        root_i4lrawip.cc
        root_oldpflog.h
        root_oldpflog.cc
        root_enc.h
        root_enc.cc
        root_ppp.h
        root_ppp.cc
        root_pflog.h
        root_pflog.cc
        root_pppserial.h
        root_pppserial.cc
        root_chdlc.h
        root_chdlc.cc
        root_i4lciscoip.h
        root_i4lciscoip.cc
    )
endif (ENABLE_NON_ETHER_DECODERS)


add_library(root_codecs STATIC
    cd_eth.cc
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
