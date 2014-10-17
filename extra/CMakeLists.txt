
if (BUILD_EXTRA_PLUGINS)
    set(SNORT_EXECUTABLE $<TARGET_FILE:snort> CACHE INTERNAL "Snort binary" FORCE)
    add_subdirectory(src)

else (BUILD_EXTRA_PLUGINS)

    cmake_minimum_required(VERSION 2.8.8)
    project(snort_extra CXX C)


    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

    # Look for Snort using pkg-config and our own find-snort module

    if (APPLE)
        set(CMAKE_MACOSX_RPATH OFF)
    endif(APPLE)

    find_package(DAQ REQUIRED)
    find_package(SNORT REQUIRED)


    if ((NOT SNORT_FOUND) AND (NOT SNORT_PKG_MODULE_FOUND))
        find_package(SNORT REQUIRED) # to print the helpful Snort message
        message(FATAL_ERROR "Unable to find Snort includes!!")
    endif()

    string (REPLACE ";" " " CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
    string (REPLACE "-DHAVE_CONFIG_H" " " CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
    message(STATUS "${CMAKE_CXX_FLAGS}")


    # Some shared library flags for the two platforms which I am using
    include(CheckCXXCompilerFlag)
    set(CMAKE_REQUIRED_FLAGS "-Wl,-undefined,dynamic_lookup")
    check_cxx_compiler_flag("" HAVE_DYNAMIC_LOOKUP)
    if(HAVE_DYNAMIC_LOOKUP)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-undefined,dynamic_lookup")
    endif()
    unset (CMAKE_REQUIRED_FLAGS)


    set (CMAKE_REQUIRED_FLAGS "-Wl,-export-dynamic")
    check_cxx_compiler_flag ("" HAVE_EXPORT_DYNAMIC)
    if (HAVE_EXPORT_DYNAMIC)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-export-dynamic")
    endif ()
    unset(CMAKE_REQUIRED_FLAGS)


    set (CMAKE_REQUIRED_FLAGS "-Wl,-shared")
    check_cxx_compiler_flag ("" HAVE_SHARED)
    if (HAVE_SHARED)
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-shared")
    endif ()
    unset(CMAKE_REQUIRED_FLAGS)

    add_subdirectory(src)



    # adding make unisntall
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

endif (BUILD_EXTRA_PLUGINS)
