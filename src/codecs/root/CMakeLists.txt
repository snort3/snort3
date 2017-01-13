
if (STATIC_CODECS)
    set (PLUGIN_LIST
        cd_eth.cc
    )


else (STATIC_CODECS)
    add_dynamic_module (cd_eth codecs cd_eth.cc)

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
