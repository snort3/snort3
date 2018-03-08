
add_subdirectory(root)
add_subdirectory(link)
add_subdirectory(ip)
add_subdirectory(misc)

set (CODEC_INCLUDES
    codec_module.h
)

add_library (codecs OBJECT
    ${CODEC_INCLUDES}
    codec_api.h
    codec_api.cc
    codec_module.cc
)

if (STATIC_CODECS)
    set (STATIC_CODEC_PLUGINS
        $<TARGET_OBJECTS:ip_codecs>
        $<TARGET_OBJECTS:link_codecs>
        $<TARGET_OBJECTS:misc_codecs>
        $<TARGET_OBJECTS:root_codecs>
        CACHE INTERNAL "STATIC_CODEC_PLUGINS"
    )
else()
    set (STATIC_CODEC_PLUGINS
        $<TARGET_OBJECTS:ip_codecs>
        $<TARGET_OBJECTS:misc_codecs>
        CACHE INTERNAL "STATIC_CODEC_PLUGINS"
    )
endif(STATIC_CODECS)

install (FILES ${CODEC_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/codecs"
)
