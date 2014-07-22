
cmake_minimum_required(VERSION 2.8)
project(snort CXX C)

set(SNORT_VERSION_MAJOR 2)
set(SNORT_VERSION_MINOR 10)
set(SNORT_VERSION_BUILD  102)
set(VERSION "${SNORT_VERSION_MAJOR}.${SNORT_VERSION_MINOR}.${SNORT_VERSION_BUILD}")

# ensure cmake will look in the cmake directory for configuration files
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")


include (cmake/macros.cmake)  
include (cmake/createCommandLineOptions.cmake) 
include (cmake/setConfigureOptions.cmake) 
include (cmake/includePredefinedPackages.cmake)
include (cmake/platforms.cmake)
include (cmake/sanityChecks.cmake)
include (cmake/packaging_data.cmake)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX11_COMPILER_FLAGS}")

# include this directory for the config.h file. created in sanityChecks.cmake
include_directories(${PROJECT_BINARY_DIR})

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


# setting and install the pkg-config information

include(cmake/setPkgConfigInfo.cmake)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/snort.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/snort.pc"
    @ONLY)

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/snort.pc
    DESTINATION "lib/pkgconfig/"
)
