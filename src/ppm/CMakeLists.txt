set ( PPM_SOURCES ppm.cc ppm_module.cc )
set ( PPM_INCLUDES ppm.h )

add_library ( ppm STATIC
    ${PPM_SOURCES}
    ${PPM_INCLUDES}
)

install (FILES ${PPM_INCLUDES}
    DESTINATION "${INCLUDE_INSTALL_PATH}/ppm"
)
