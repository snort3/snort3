

add_subdirectory(root)
add_subdirectory(link)
add_subdirectory(ip)
add_subdirectory(misc)

set(CODEC_INCLUDES
    decode_module.h
    codec_events.h
    sf_protocols.h
)

add_library( codecs STATIC
    ${CODEC_INCLUDES}
    codec_api.h
    codec_api.cc
    template.cc   # for development purposes.  Keep the template up to date
)


if (STATIC_CODECS)
    set (CODEC_PLUGIN_LIBRARIES
        link_codecs
        root_codecs
    )
endif(STATIC_CODECS)

target_link_libraries( codecs
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
