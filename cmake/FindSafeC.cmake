
find_package(PkgConfig)

# LibSafeC is currently incompatible with Clang - https://github.com/rurban/safeclib/issues/58
if (PKG_CONFIG_EXECUTABLE AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --list-all
                    OUTPUT_VARIABLE _pkgconfig_list_result
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "safec-([0-9]+\.[0-9])+" MATCHED ${_pkgconfig_list_result})
    if (MATCHED)
        set(SAFEC_VERSION ${CMAKE_MATCH_1})
        pkg_check_modules(PC_SAFEC safec-${SAFEC_VERSION})

        find_path(SAFEC_INCLUDE_DIR
            NAMES libsafec/safe_lib.h
            HINTS ${PC_SAFEC_INCLUDEDIR} ${PC_SAFEC_INCLUDEDIRS}
            NO_SYSTEM_ENVIRONMENT_PATH
        )
        find_library(SAFEC_LIBRARIES
            NAMES safec-${SAFEC_VERSION}
            HINTS ${PC_SAFEC_LIBDIR} ${PC-SAFEC_LIBRARY_DIRS}
        )
    endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SafeC
    REQUIRED_VARS SAFEC_INCLUDE_DIR SAFEC_LIBRARIES
)

mark_as_advanced(
    SAFEC_INCLUDE_DIR
    SAFEC_LIBRARIES
)
