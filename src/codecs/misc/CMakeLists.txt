

if(STATIC_CODECS)
    set(PLUGIN_LIST
        cd_ip4_embedded_in_icmp.cc
        cd_ip6_embedded_in_icmp.cc
        cd_prot_embedded_in_icmp.cc
        cd_gtp.cc
        cd_gtp_module.h
        cd_gtp_module.cc
        cd_teredo.cc
    )

else(STATIC_CODECS)
    add_shared_library(cd_gtp codecs cd_gtp.cc cd_gtp_module.h cd_gtp_module.cc)
    add_shared_library(cd_teredo codecs cd_teredo.cc)
    add_shared_library(cd_ip4_embedded_in_icmp codecs cd_ip4_embedded_in_icmp.cc)
    add_shared_library(cd_ip6_embedded_in_icmp codecs cd_ip6_embedded_in_icmp.cc)
    add_shared_library(cd_prot_embedded_in_icmp codecs cd_prot_embedded_in_icmp.cc)

    #  When static codecs NOT enabled, the icmp files will be included in the
    #  ICMP libraries in the other file.

endif(STATIC_CODECS)

add_library( misc_codecs STATIC
    cd_default.cc
    ${PLUGIN_LIST}
)

target_link_libraries( misc_codecs
    protocols
)
