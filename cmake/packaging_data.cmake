
# use this target instead of 'make package_source'
add_custom_target( autotools
    COMMAND autoreconf -isvf #  FIXIT-L J  --  should check for autotools the CMake way
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target( copy_symlinks
    COMMAND
        ${CMAKE_COMMAND} -DSOURCE_DIRECTORY=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_CURRENT_LIST_DIR}/copy_symlinks.cmake
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target( copy_m4_symlinks
    COMMAND
        ${CMAKE_COMMAND}
        -DSOURCE_DIRECTORY=${CMAKE_SOURCE_DIR}/m4
        -P ${CMAKE_CURRENT_LIST_DIR}/copy_symlinks.cmake
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/m4
)

add_custom_target( dist
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target copy_manuals_to_source
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target autotools
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target copy_symlinks
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target copy_m4_symlinks
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target package_source
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target delete_manuals_in_source
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target autotools  # recreate autotool links.
)


set (CPACK_GENERATOR TGZ)
set (CPACK_PACKAGE_NAME "snort")
set (CPACK_PACKAGE_VENDOR "Cisco")
set (CPACK_PACKAGE_VERSION_MAJOR "${SNORT_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${SNORT_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${SNORT_VERSION_BUILD}")
set (CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/doc/images/snort.png")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "snort")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/doc/start.txt")
set (CPACK_SOURCE_IGNORE_FILES "${CMAKE_BINARY_DIR}/;tools/snort2lua/tests/;\\\\.git/;\\\\.gitignore;extra/;")
set (CPACK_SOURCE_GENERATOR TGZ)

include(CPack)
