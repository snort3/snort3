
# use this target instead of 'make package_source'
add_custom_target(dist
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target copy_manuals_to_source
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target package_source
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target delete_manuals_in_source
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
set (CPACK_SOURCE_IGNORE_FILES "${CMAKE_BINARY_DIR}/*;tools/snort2lua/tests*;.git/*;.gitignore;m4/*")
set (CPACK_SOURCE_GENERATOR TGZ)


include(CPack)

