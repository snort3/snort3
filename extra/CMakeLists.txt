if (BUILD_EXTRA_PLUGINS)
    #  This condition is only true if this directory is included as
    #  a subdirectory of the top level source directory.

    set(SNORT_EXECUTABLE $<TARGET_FILE:snort> CACHE INTERNAL "Snort binary" FORCE)
    add_subdirectory(src)

else (BUILD_EXTRA_PLUGINS)

    cmake_minimum_required(VERSION 2.8.8)
    project(snort_extra CXX C)

    set (EXTRA_VERSION_MAJOR 1)
    set (EXTRA_VERSION_MINOR 0)
    set (EXTRA_VERSION_BUILD 0-a1)
    set (VERSION "${EXTRA_VERSION_MAJOR}.${EXTRA_VERSION_MINOR}.${EXTRA_VERSION_BUILD}")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}")

    # Look for Snort using pkg-config and our own find-snort module

    if (APPLE)
        set(CMAKE_MACOSX_RPATH OFF)
    endif(APPLE)

    find_package(DAQ REQUIRED)
    find_package(Snort REQUIRED)
    find_package(LuaJIT REQUIRED)


    #  add Snort++ properties to the current build
    string (REPLACE "-DHAVE_CONFIG_H" " " tmp_cmp_flags  "${SNORT_INTERFACE_COMPILE_OPTIONS}")
    string (REPLACE ";" " " tmp_cmp_flags "${tmp_cmp_flags}")
    string (STRIP "${CMAKE_CXX_FLAGS} ${tmp_cmp_flags}" tmp_cmp_flags)
    set (CMAKE_CXX_FLAGS "${tmp_cmp_flags}" CACHE STRING
        "Flags used by the compiler during all build types." FORCE)

    include_directories(${SNORT_INTERFACE_INCLUDE_DIRECTORIES})

    string(REPLACE ";" " " tmp_link_flags "${SNORT_INTERFACE_LINK_FLAGS}")
    string (STRIP "${CMAKE_EXE_LINKER_FLAGS} ${tmp_link_flags}" tmp_link_flags)
    set (CMAKE_EXE_LINKER_FLAGS "${tmp_link_flags}" CACHE STRING
        "Flags used by the linker. " FORCE)


    include(CheckCXXCompilerFlag)
    set (CMAKE_REQUIRED_FLAGS "-fvisibility=hidden")
    check_cxx_compiler_flag ("" HAVE_VISIBILITY)
    if (HAVE_VISIBILITY)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DHAVE_VISIBILITY")
    endif ()
    unset(CMAKE_REQUIRED_FLAGS)

    # Some shared library flags for the two platforms which I am using
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

    include (packaging_data.cmake)

endif (BUILD_EXTRA_PLUGINS)
