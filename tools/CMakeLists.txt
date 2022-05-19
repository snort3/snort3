
add_subdirectory(u2boat)
add_subdirectory(u2spewfoo)
add_subdirectory(snort2lua)

install (FILES appid_detector_builder.sh
    PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
