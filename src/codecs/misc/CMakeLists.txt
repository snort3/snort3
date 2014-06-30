

if(STATIC_CODECS)
    set(PLUGIN_LIST
        cd_gtp.cc
        cd_gtp_module.h
        cd_gtp_module.cc
        cd_teredo.cc
    )

else(STATIC_CODECS)
    add_shared_library(cd_gtp codecs cd_gtp.cc cd_gtp_module.h cd_gtp_module.cc)
    add_shared_library(cd_teredo codecs cd_teredo.cc)

endif(STATIC_CODECS)

add_library( misc_codecs STATIC
    cd_default.cc
    ${PLUGIN_LIST}
)

target_link_libraries( misc_codecs
    protocols
)
