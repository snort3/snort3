

include_directories(${PCAP_INCLUDE_DIR})


if (STATIC_CODECS)
    if (ENABLE_NON_ETHER_DECODERS)
            set( PLUGIN_LIST
                cd_eth.cc
                cd_eth_module.h
                cd_eth_module.cc
                cd_raw4.cc
                cd_raw6.cc
                cd_null.cc
                cd_linux_sll.cc
                cd_ppp.cc
                cd_wlan.cc
                cd_wlan_module.h
                cd_wlan_module.cc
        #        root_fddi.cc
        #        root_slip.cc
        #        root_i4lrawip.cc
        #        root_oldpflog.cc
        #        root_enc.cc
        #        root_pflog.cc
        #        root_pppserial.cc
        #        root_chdlc.cc
        #        root_i4lciscoip.cc
        #        prot_ipx.cc
        #        prot_eap.cc
            )
    endif (ENABLE_NON_ETHER_DECODERS)

else(STATIC_CODECS)

    if (ENABLE_NON_ETHER_DECODERS)
        add_shared_library(cd_eth codecs cd_eth.cc cd_eth_module.h cd_eth_module.cc)
        add_shared_library(cd_linux_sll codecs cd_linux_sll.cc)
        add_shared_library(cd_ppp codecs cd_ppp.cc)
        add_shared_library(cd_raw4 codecs cd_raw4.cc)
        add_shared_library(cd_raw6 codecs cd_raw6.cc)
        add_shared_library(cd_null codecs cd_null.cc)
        add_shared_library(cd_wlan codecs cd_wlan.cc cd_wlan_module.h cd_wlan_module.cc)
    endif(ENABLE_NON_ETHER_DECODERS)
endif(STATIC_CODECS)


add_library(root_codecs STATIC
    ${PLUGIN_LIST}
    ${PCAP_INCLUDE_DIR}/pcap.h  # rebuild if a new libpcap is installed
)

target_link_libraries(root_codecs
    protocols
    managers
    ${PCAP_LIBRARIES}
)
