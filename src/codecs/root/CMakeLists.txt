
if (STATIC_CODECS)
    set (PLUGIN_LIST
        cd_eth.cc
        cd_i4l_rawip.cc
        cd_linux_sll.cc
        cd_null.cc
        cd_pflog.cc
        cd_ppp.cc
        cd_raw4.cc
        cd_raw6.cc
        cd_slip.cc
        cd_wlan.cc
#        cd_fddi.cc
#        cd_i4lrawip.cc
#        cd_oldpflog.cc
#        cd_enc.cc
#        cd_pppserial.cc
#        cd_chdlc.cc
#        cd_i4lciscoip.cc
#        cd_ipx.cc
#        cd_eap.cc
    )


else (STATIC_CODECS)
    add_shared_library (cd_eth codecs cd_eth.cc)
    add_shared_library (cd_i4l_rawip codecs cd_i4l_rawip.cc)
    add_shared_library (cd_linux_sll codecs cd_linux_sll.cc)
    add_shared_library (cd_null codecs cd_null.cc)
    add_shared_library (cd_pflog codecs cd_pflog.cc)
    add_shared_library (cd_ppp codecs cd_ppp.cc)
    add_shared_library (cd_raw4 codecs cd_raw4.cc)
    add_shared_library (cd_raw6 codecs cd_raw6.cc)
    add_shared_library (cd_slip codecs cd_slip.cc)
    add_shared_library (cd_wlan codecs cd_wlan.cc)

endif (STATIC_CODECS)


if (STATIC_CODECS)
    add_library(root_codecs STATIC
        ${PLUGIN_LIST}
        ${PCAP_INCLUDE_DIR}/pcap.h  # rebuild if a new libpcap is installed
    )

    target_link_libraries( root_codecs
        codec_module
    )

endif (STATIC_CODECS)
