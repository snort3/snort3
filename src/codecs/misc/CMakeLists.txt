
if(STATIC_CODECS)
    set(PLUGIN_LIST
        cd_gtp.cc
        cd_icmp4_ip.cc
        cd_icmp6_ip.cc
        cd_llc.cc
        cd_teredo.cc
        cd_user.cc
    )

else(STATIC_CODECS)
    add_dynamic_module(cd_gtp codecs cd_gtp.cc)
    add_dynamic_module(cd_icmp4_ip codecs cd_icmp4_ip.cc)
    add_dynamic_module(cd_icmp6_ip codecs cd_icmp6_ip.cc)
    add_dynamic_module(cd_llc codecs cd_llc.cc)
    add_dynamic_module(cd_teredo codecs cd_teredo.cc)
    add_dynamic_module(cd_user codecs cd_user.cc)

endif(STATIC_CODECS)

add_library( misc_codecs OBJECT
    cd_default.cc
    ${PLUGIN_LIST}
)

