
add_subdirectory(root)
add_subdirectory(link)
add_subdirectory(ip)
add_subdirectory(misc)

set (CODEC_INCLUDES
    codec_module.h
)

add_library (codecs STATIC
    ${CODEC_INCLUDES}
    codec_api.h
    codec_api.cc
)

add_library (codec_module STATIC
    codec_module.cc
)

if (STATIC_CODECS)
    set (CODEC_PLUGIN_LIBRARIES
        link_codecs
        root_codecs
    )
endif(STATIC_CODECS)

target_link_libraries (codecs
    ${CODEC_PLUGIN_LIBRARIES}
    ip_codecs
    misc_codecs
    protocols
    sfip
    framework
    main
)


install (FILES ${CODEC_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/codecs"
)
