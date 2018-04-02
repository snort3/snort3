
if (STATIC_CODECS)
    set (PLUGIN_LIST
        cd_eth.cc
    )

else (STATIC_CODECS)
    add_dynamic_module (cd_eth codecs cd_eth.cc)

endif (STATIC_CODECS)


if (STATIC_CODECS)
    add_library(root_codecs OBJECT
        ${PLUGIN_LIST}
    )
endif (STATIC_CODECS)
