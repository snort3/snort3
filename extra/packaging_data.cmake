
# use this target instead of 'make package_source'
add_custom_target( autotools_binaries
    COMMAND autoreconf -ivf #  FIXIT-L J  --  should check for autotools the CMake way
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target( autotools_symlinks
    COMMAND autoreconf -isvf
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)


add_custom_target(dist
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target autotools_binaries
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target package_source
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target autotools_symlinks
)

set (CPACK_GENERATOR TGZ)
set (CPACK_PACKAGE_NAME "snort_extra")
set (CPACK_PACKAGE_VENDOR "Cisco")
set (CPACK_PACKAGE_VERSION_MAJOR "${EXTRA_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${EXTRA_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${EXTRA_VERSION_BUILD}")
set (CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/doc/images/snort.png")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "snort")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README")
set (CPACK_SOURCE_IGNORE_FILES "${CMAKE_BINARY_DIR}/;autom4te.cache;")
set (CPACK_SOURCE_GENERATOR TGZ)

include(CPack)

