
cmake_minimum_required(VERSION 2.8)
project(snort CXX C)

set(SNORT_VERSION_MAJOR 2)
set(SNORT_VERSION_MINOR 10)
set(SNORT_VERSION_BUILD  073)

# ensure cmake will look in the cmake directory for configuration files
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")


include (cmake/macros.cmake)  
include (cmake/createCommandLineOptions.cmake) 
include (cmake/setConfigureOptions.cmake) 
include (cmake/includePredefinedPackages.cmake)
include (cmake/platforms.cmake)
include (cmake/sanityChecks.cmake)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}")

# include this directory for the config.h file
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(etc)
add_subdirectory(src)
add_subdirectory(tools)
add_subdirectory(lua)
add_subdirectory(doc)


# uninstall target

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)



##  FOO FOR BUILDING ARCHIVE PACKAGES!!

set (CPACK_GENERATOR TGZ ZIP TGZ TZ STGZ)
set (CPACK_PACKAGE_NAME "snort")

# This will always be false unless manually set
if (BUILD_DEBIAN_ARCHIVE)
    list(APPEND CPACK_GENERATOR DEB)
endif()

SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "SNORT-TEAM") #required

# RPM foo
set( CPACK_RPM_PACKAGE_SUMMARY   "The snort RPM package summary")
set( CPACK_RPM_PACKAGE_NAME      "snort-rpm")
set( CPACK_RPM_PACKAGE_VERSION   "${SNORT_VERSION_MAJOR}.${SNORT_VERSION_MINOR}.${SNORT_VERSION_BUILD}")
set( CPACK_RPM_PACKAGE_ARCHITECTURE      "noarch")
set (CPACK_RPM_PACKAGE_RELEASE   1)
set( CPACK_RPM_PACKAGE_LICENSE   "unknown")
#set( CPACK_RPM_PACKAGE_GROUP   "unknown")
set( CPACK_RPM_PACKAGE_VENDOR   "Cisco")
set( CPACK_RPM_PACKAGE_DESCRIPTION "Snort RPM")


include(CPack)

